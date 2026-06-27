package aws

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	gtvcfg "github.com/boogy/aws-oidc-warden/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func consumerWithAllowed(m *MockAwsServiceWrapper, allowed []string) *AwsConsumer {
	cfg := &gtvcfg.Config{TagAuth: &gtvcfg.TagAuth{
		Enabled: true, TagPrefix: "aow/", SpokeRoleName: "aow-spoke", AllowedAccounts: allowed,
	}}
	c := NewAwsConsumer(cfg)
	c.AWS = m
	return c
}

func TestIsTargetAccountAllowed(t *testing.T) {
	cases := []struct {
		name    string
		allowed []string
		arn     string
		want    bool
	}{
		{"hub always allowed", []string{"222222222222"}, "arn:aws:iam::111111111111:role/app", true},
		{"member in list", []string{"222222222222"}, "arn:aws:iam::222222222222:role/app", true},
		{"member not in list", []string{"333333333333"}, "arn:aws:iam::222222222222:role/app", false},
		{"empty list allows any", nil, "arn:aws:iam::222222222222:role/app", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := new(MockAwsServiceWrapper)
			m.On("GetCallerAccount").Return("111111111111", nil)
			c := consumerWithAllowed(m, tc.allowed)
			ok, err := c.IsTargetAccountAllowed(tc.arn)
			require.NoError(t, err)
			assert.Equal(t, tc.want, ok)
		})
	}
}

// TestIsTargetAccountAllowed_EmptyListFailsOpen documents (and locks in) the
// fail-open default: tag-auth enabled with an empty allowed_accounts permits ANY
// non-hub member account. Config validation only warns; operators must populate
// allowed_accounts in production. A future change must not silently flip this.
func TestIsTargetAccountAllowed_EmptyListFailsOpen(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	c := consumerWithAllowed(m, nil) // enabled, empty allow-list
	ok, err := c.IsTargetAccountAllowed("arn:aws:iam::222222222222:role/anything")
	require.NoError(t, err)
	assert.True(t, ok, "empty allowed_accounts must fail open (any account allowed)")
}

func TestIsTargetAccountAllowed_TagAuthDisabled(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	c := NewAwsConsumer(&gtvcfg.Config{}) // TagAuth nil
	c.AWS = m
	ok, err := c.IsTargetAccountAllowed("arn:aws:iam::222222222222:role/app")
	require.NoError(t, err)
	assert.True(t, ok) // no cross-account possible; nothing to gate
}

func TestIsTargetAccountAllowed_BadARN(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	c := consumerWithAllowed(m, []string{"222222222222"})
	ok, err := c.IsTargetAccountAllowed("not-an-arn")
	require.Error(t, err) // ParseRoleARN error propagated
	assert.False(t, ok)
}

func TestSpokeCredsFor_BlockedAccount(t *testing.T) {
	cfg := &gtvcfg.Config{TagAuth: &gtvcfg.TagAuth{
		Enabled: true, SpokeRoleName: "aow-spoke", AllowedAccounts: []string{"333333333333"},
		SpokeSessionDuration: 15 * time.Minute,
	}}

	// Hub account is always allowed → (nil, nil), no spoke assume.
	mHub := new(MockAwsServiceWrapper)
	mHub.On("GetCallerAccount").Return("111111111111", nil)
	cHub := NewAwsConsumer(cfg)
	cHub.AWS = mHub
	creds, err := cHub.spokeCredsFor("111111111111")
	require.NoError(t, err)
	assert.Nil(t, creds)

	// Non-hub account not in the allow-list → defense-in-depth guard errors.
	mBlocked := new(MockAwsServiceWrapper)
	mBlocked.On("GetCallerAccount").Return("111111111111", nil)
	cBlocked := NewAwsConsumer(cfg)
	cBlocked.AWS = mBlocked
	creds, err = cBlocked.spokeCredsFor("222222222222")
	require.Error(t, err)
	assert.Nil(t, creds)

	// Allowed member proceeds to assume the spoke role.
	mAllowed := new(MockAwsServiceWrapper)
	mAllowed.On("GetCallerAccount").Return("111111111111", nil)
	exp := time.Now().Add(time.Hour)
	mAllowed.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
		return *in.RoleArn == "arn:aws:iam::333333333333:role/aow-spoke"
	})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"),
		SessionToken: aws.String("ST"), Expiration: &exp,
	}}, nil).Once()
	cAllowed := NewAwsConsumer(cfg)
	cAllowed.AWS = mAllowed
	creds, err = cAllowed.spokeCredsFor("333333333333")
	require.NoError(t, err)
	require.NotNil(t, creds)
	mAllowed.AssertExpectations(t)
}
