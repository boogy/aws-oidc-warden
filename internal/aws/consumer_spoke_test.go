package aws

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	gtvcfg "github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newTagAuthConsumer(m *MockAwsServiceWrapper) *AwsConsumer {
	cfg := &gtvcfg.Config{
		TagAuth: &gtvcfg.TagAuth{Enabled: true, TagPrefix: "aow/"},
		CrossAccount: &gtvcfg.CrossAccount{
			Enabled: true, SpokeRoleName: "aow-spoke",
			SpokeSessionDuration: 15 * time.Minute,
		},
	}
	c := NewAwsConsumer(cfg)
	c.AWS = m
	return c
}

func TestSpokeCredsFor_SameAccount_ReturnsNil(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	c := newTagAuthConsumer(m)
	creds, err := c.spokeCredsFor("111111111111")
	require.NoError(t, err)
	assert.Nil(t, creds)
}

func TestSpokeCredsFor_CrossAccount_AssumesSpokeAndCaches(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	exp := time.Now().Add(time.Hour)
	m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
		return *in.RoleArn == "arn:aws:iam::222222222222:role/aow-spoke"
	})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"),
		SessionToken: aws.String("ST"), Expiration: &exp,
	}}, nil).Once()

	c := newTagAuthConsumer(m)
	creds1, err := c.spokeCredsFor("222222222222")
	require.NoError(t, err)
	require.NotNil(t, creds1)
	// Second call served from cache → AssumeRole still called Once.
	creds2, err := c.spokeCredsFor("222222222222")
	require.NoError(t, err)
	require.NotNil(t, creds2)
	m.AssertExpectations(t)
}

func TestSpokeCredsFor_Disabled_ReturnsNil(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	c := NewAwsConsumer(&gtvcfg.Config{}) // CrossAccount nil
	c.AWS = m
	creds, err := c.spokeCredsFor("222222222222")
	require.NoError(t, err)
	assert.Nil(t, creds)
}

func TestSpokeCredsFor_CrossAccountOnly_TagAuthDisabled(t *testing.T) {
	// The spoke transport must work with tag-auth off: explicit role_mappings
	// can target member accounts without enabling the tag-auth fallback.
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	exp := time.Now().Add(time.Hour)
	m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
		return *in.RoleArn == "arn:aws:iam::222222222222:role/aow-spoke"
	})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"),
		SessionToken: aws.String("ST"), Expiration: &exp,
	}}, nil).Once()

	c := NewAwsConsumer(&gtvcfg.Config{
		CrossAccount: &gtvcfg.CrossAccount{
			Enabled: true, SpokeRoleName: "aow-spoke",
			SpokeSessionDuration: 15 * time.Minute,
		},
	})
	c.AWS = m
	creds, err := c.spokeCredsFor("222222222222")
	require.NoError(t, err)
	require.NotNil(t, creds)
	m.AssertExpectations(t)
}

// TestAssumeRole_CrossAccount_DirectTransport verifies that a cross-account
// assume (enabled + allowed) goes directly from hub to target with hub creds
// in a single STS AssumeRole call — the spoke role is never involved in
// AssumeRole, only in GetRoleTags reads.
func TestAssumeRole_CrossAccount_DirectTransport(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerIdentityInfo").Return("111111111111", false, nil)

	var captured *sts.AssumeRoleInput
	targetExp := time.Now().Add(time.Hour)
	m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
		captured = in
		return *in.RoleArn == "arn:aws:iam::222222222222:role/app"
	})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK2"), SecretAccessKey: aws.String("SK2"),
		SessionToken: aws.String("ST2"), Expiration: &targetExp,
	}}, nil).Once()

	c := newTagAuthConsumer(m)
	creds, err := c.AssumeRole("arn:aws:iam::222222222222:role/app", "sess", nil, nil, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "AK2", *creds.AccessKeyId)
	require.NotNil(t, captured)
	assert.Equal(t, "arn:aws:iam::222222222222:role/app", *captured.RoleArn, "no spoke-role ARN should ever appear in an AssumeRole input")
	m.AssertExpectations(t) // exactly one AssumeRole call (Once()), so no spoke-role assume happened
}

// TestAssumeRoleCrossAccountDisabledFailsClosed verifies that AssumeRole hard-
// errors on a non-hub-account target when cross-account transport is
// disabled (or unconfigured) — it must never fall through to a direct assume.
func TestAssumeRoleCrossAccountDisabledFailsClosed(t *testing.T) {
	for name, cfg := range map[string]*gtvcfg.Config{
		"CrossAccount nil":            {},
		"CrossAccount explicit false": {CrossAccount: &gtvcfg.CrossAccount{Enabled: false}},
	} {
		t.Run(name, func(t *testing.T) {
			m := new(MockAwsServiceWrapper)
			m.On("GetCallerIdentityInfo").Return("111111111111", false, nil)
			c := NewAwsConsumer(cfg)
			c.AWS = m

			_, err := c.AssumeRole("arn:aws:iam::222222222222:role/app", "sess", nil, nil, nil, nil)
			require.Error(t, err)
			m.AssertNotCalled(t, "AssumeRole", mock.Anything)
		})
	}
}

// TestAssumeRoleUnparseableARNFailsClosed verifies a malformed role ARN is
// rejected before any STS call is made.
func TestAssumeRoleUnparseableARNFailsClosed(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	c := NewAwsConsumer(&gtvcfg.Config{})
	c.AWS = m

	_, err := c.AssumeRole("not-an-arn", "sess", nil, nil, nil, nil)
	require.Error(t, err)
	m.AssertNotCalled(t, "AssumeRole", mock.Anything)
	m.AssertNotCalled(t, "GetCallerIdentityInfo")
}

// TestSpokeCredsFor_ClampsDurationOver1h verifies the hub->spoke assume never
// requests more than 3600s: the spoke hop is role chaining on Lambda and STS
// fails (not clamps) chained sessions over 1h, which would silently break
// cross-account tag-auth.
func TestSpokeCredsFor_ClampsDurationOver1h(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	exp := time.Now().Add(time.Hour)
	var captured *sts.AssumeRoleInput
	m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
		captured = in
		return *in.RoleArn == "arn:aws:iam::222222222222:role/aow-spoke"
	})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"),
		SessionToken: aws.String("ST"), Expiration: &exp,
	}}, nil).Once()

	c := NewAwsConsumer(&gtvcfg.Config{
		CrossAccount: &gtvcfg.CrossAccount{
			Enabled: true, SpokeRoleName: "aow-spoke",
			SpokeSessionDuration: 2 * time.Hour,
		},
	})
	c.AWS = m
	_, err := c.spokeCredsFor("222222222222")
	require.NoError(t, err)
	require.NotNil(t, captured)
	assert.Equal(t, int32(3600), *captured.DurationSeconds)
}

// TestAssumeRoleCrossAccountNotAllowedFailsClosed verifies the consumer-level
// defense-in-depth allow-list check: enabled cross-account with a target
// account outside allowed_accounts must error before any STS call, even
// though the processor guards the same condition upstream.
func TestAssumeRoleCrossAccountNotAllowedFailsClosed(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerIdentityInfo").Return("111111111111", true, nil)
	c := NewAwsConsumer(&gtvcfg.Config{
		CrossAccount: &gtvcfg.CrossAccount{
			Enabled: true, SpokeRoleName: "aow-spoke",
			SpokeSessionDuration: 15 * time.Minute,
			AllowedAccounts:      []string{"333333333333"},
		},
	})
	c.AWS = m

	_, err := c.AssumeRole("arn:aws:iam::222222222222:role/app", "sess", nil, nil, nil, nil)
	require.Error(t, err)
	m.AssertNotCalled(t, "AssumeRole", mock.Anything)
}

// TestAssumeRoleClampBoundary pins the clamp threshold: with role-session
// creds, exactly 3600 passes through untouched and 3601 clamps to 3600.
func TestAssumeRoleClampBoundary(t *testing.T) {
	for name, tc := range map[string]struct {
		requested int32
		want      int32
	}{
		"exactly 3600 not clamped": {requested: 3600, want: 3600},
		"3601 clamped":             {requested: 3601, want: 3600},
	} {
		t.Run(name, func(t *testing.T) {
			m := new(MockAwsServiceWrapper)
			m.On("GetCallerIdentityInfo").Return("111111111111", true, nil)
			exp := time.Now().Add(time.Hour)
			var captured *sts.AssumeRoleInput
			m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
				captured = in
				return true
			})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
				AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"),
				SessionToken: aws.String("ST"), Expiration: &exp,
			}}, nil).Once()

			c := NewAwsConsumer(&gtvcfg.Config{})
			c.AWS = m
			dur := tc.requested
			_, err := c.AssumeRole("arn:aws:iam::111111111111:role/app", "sess", nil, &dur, nil, nil)
			require.NoError(t, err)
			require.NotNil(t, captured)
			assert.Equal(t, tc.want, *captured.DurationSeconds)
		})
	}
}

// TestGetRoleTagsCrossAccountDisabledFailsClosed verifies GetRoleTags refuses
// to read a member-account role's tags when cross-account transport is
// disabled — it must never silently read a same-named role in the hub
// account. Calling it twice must error both times with zero GetRole calls,
// confirming nothing was cached on the failure path.
func TestGetRoleTagsCrossAccountDisabledFailsClosed(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	c := NewAwsConsumer(&gtvcfg.Config{}) // CrossAccount nil
	c.AWS = m

	_, err := c.GetRoleTags("arn:aws:iam::222222222222:role/app")
	require.Error(t, err)
	_, err = c.GetRoleTags("arn:aws:iam::222222222222:role/app")
	require.Error(t, err)

	m.AssertNotCalled(t, "GetRole", mock.Anything)
	m.AssertNotCalled(t, "GetRoleAs", mock.Anything, mock.Anything)
}
