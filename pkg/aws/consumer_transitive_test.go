package aws

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	gtvcfg "github.com/boogy/aws-oidc-warden/pkg/config"
	gtypes "github.com/boogy/aws-oidc-warden/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAssumeRole_TransitiveTags_SameAccount(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	var captured *sts.AssumeRoleInput
	m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
		captured = in
		return true
	})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"), SessionToken: aws.String("ST"),
	}}, nil).Once()

	cfg := &gtvcfg.Config{TagAuth: &gtvcfg.TagAuth{Enabled: true, TagPrefix: "aow/", TransitiveSessionTags: true}}
	c := NewAwsConsumer(cfg)
	c.AWS = m
	claims := &gtypes.GithubClaims{Repository: "acme/api", Actor: "deploy-bot", Ref: "refs/heads/main", EventName: "push"}

	_, err := c.AssumeRole("arn:aws:iam::111111111111:role/app", "sess", nil, nil, claims)
	require.NoError(t, err)
	require.NotNil(t, captured)
	assert.ElementsMatch(t, []string{"repo", "ref", "actor"}, captured.TransitiveTagKeys)
}

func TestAssumeRole_TransitiveTags_DisabledByDefault(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	var captured *sts.AssumeRoleInput
	m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
		captured = in
		return true
	})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"), SessionToken: aws.String("ST"),
	}}, nil).Once()

	cfg := &gtvcfg.Config{TagAuth: &gtvcfg.TagAuth{Enabled: true, TagPrefix: "aow/"}} // transitive off
	c := NewAwsConsumer(cfg)
	c.AWS = m
	claims := &gtypes.GithubClaims{Repository: "acme/api", Actor: "deploy-bot", Ref: "refs/heads/main"}

	_, err := c.AssumeRole("arn:aws:iam::111111111111:role/app", "sess", nil, nil, claims)
	require.NoError(t, err)
	require.NotNil(t, captured)
	assert.Empty(t, captured.TransitiveTagKeys)
}

// TestAssumeRole_CrossAccountClamp verifies that a cross-account (role-chained)
// assume clamps the session duration to AWS's 1h chaining cap. The target role
// is assumed via AssumeRoleAs using spoke credentials; capture that input.
func TestAssumeRole_CrossAccountClamp(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)

	// Hub assumes the spoke role in the target account.
	spokeExp := time.Now().Add(time.Hour)
	m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
		return *in.RoleArn == "arn:aws:iam::222222222222:role/aow-spoke"
	})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"),
		SessionToken: aws.String("ST"), Expiration: &spokeExp,
	}}, nil).Once()

	// Target role is assumed via AssumeRoleAs; capture its clamped duration.
	var captured *sts.AssumeRoleInput
	targetExp := time.Now().Add(time.Hour)
	m.On("AssumeRoleAs", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
		captured = in
		return *in.RoleArn == "arn:aws:iam::222222222222:role/app"
	}), mock.Anything).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK2"), SecretAccessKey: aws.String("SK2"),
		SessionToken: aws.String("ST2"), Expiration: &targetExp,
	}}, nil).Once()

	cfg := &gtvcfg.Config{TagAuth: &gtvcfg.TagAuth{
		Enabled: true, TagPrefix: "aow/", SpokeRoleName: "aow-spoke",
		SpokeSessionDuration: 15 * time.Minute,
	}}
	c := NewAwsConsumer(cfg)
	c.AWS = m

	var requested int32 = 7200 // > 1h; must be clamped on the chained assume
	_, err := c.AssumeRole("arn:aws:iam::222222222222:role/app", "sess", nil, &requested, nil)
	require.NoError(t, err)
	require.NotNil(t, captured)
	require.NotNil(t, captured.DurationSeconds)
	assert.Equal(t, int32(3600), *captured.DurationSeconds)
	m.AssertExpectations(t)
}

// TestAssumeRole_SameAccountNoClamp verifies the clamp does not apply to a
// same-account assume (creds == nil): the requested duration is preserved.
func TestAssumeRole_SameAccountNoClamp(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	var captured *sts.AssumeRoleInput
	m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
		captured = in
		return true
	})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"), SessionToken: aws.String("ST"),
	}}, nil).Once()

	cfg := &gtvcfg.Config{TagAuth: &gtvcfg.TagAuth{Enabled: true, TagPrefix: "aow/"}}
	c := NewAwsConsumer(cfg)
	c.AWS = m

	var requested int32 = 7200
	_, err := c.AssumeRole("arn:aws:iam::111111111111:role/app", "sess", nil, &requested, nil)
	require.NoError(t, err)
	require.NotNil(t, captured)
	require.NotNil(t, captured.DurationSeconds)
	assert.Equal(t, int32(7200), *captured.DurationSeconds)
}
