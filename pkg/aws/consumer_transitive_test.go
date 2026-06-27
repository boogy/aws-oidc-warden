package aws

import (
	"testing"

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
	assert.Empty(t, captured.TransitiveTagKeys)
}
