package aws

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	gtvcfg "github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestAudit_RoleTagCacheNoCrossAccountCollision is the central claim of this
// audit: role "deploy" in account 111 (hub) and role "deploy" in account 222
// must never share a roleTagCache entry. If the cache were keyed by role NAME,
// the hub role's tags would authorize assumption of the member-account role.
func TestAudit_RoleTagCacheNoCrossAccountCollision(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)

	// Hub read: same-account path -> GetRole with hub clients.
	m.On("GetRole", mock.MatchedBy(func(in *iam.GetRoleInput) bool {
		return *in.RoleName == "deploy"
	})).Return(&iam.GetRoleOutput{Role: &iamtypes.Role{
		Tags: []iamtypes.Tag{{Key: aws.String("aow/repo"), Value: aws.String("acme/hub")}},
	}}, nil).Once()

	// Spoke assume for 222 + cross-account read.
	exp := time.Now().Add(time.Hour)
	m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
		return *in.RoleArn == "arn:aws:iam::222222222222:role/aow-spoke"
	})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"),
		SessionToken: aws.String("ST"), Expiration: &exp,
	}}, nil).Once()
	m.On("GetRoleAs", mock.MatchedBy(func(in *iam.GetRoleInput) bool {
		return *in.RoleName == "deploy"
	}), mock.Anything).Return(&iam.GetRoleOutput{Role: &iamtypes.Role{
		Tags: []iamtypes.Tag{{Key: aws.String("aow/repo"), Value: aws.String("acme/member")}},
	}}, nil).Once()

	c := newTagAuthConsumer(m)

	hubTags, err := c.GetRoleTags("arn:aws:iam::111111111111:role/deploy")
	require.NoError(t, err)
	assert.Equal(t, "acme/hub", hubTags["aow/repo"])

	memberTags, err := c.GetRoleTags("arn:aws:iam::222222222222:role/deploy")
	require.NoError(t, err)
	assert.Equal(t, "acme/member", memberTags["aow/repo"],
		"member-account role must NOT be served the hub role's cached tags")

	// Both entries coexist, keyed by full ARN.
	assert.Len(t, c.roleTagCache, 2)
	_, okHub := c.roleTagCache["arn:aws:iam::111111111111:role/deploy"]
	_, okMember := c.roleTagCache["arn:aws:iam::222222222222:role/deploy"]
	assert.True(t, okHub && okMember, "cache keys must be full ARNs, not role names")
	_, okName := c.roleTagCache["deploy"]
	assert.False(t, okName, "no bare role-name key may exist")

	m.AssertExpectations(t)
}

// TestAudit_RoleTagCacheExpiryEnforcedOnRead proves stale tags cannot outlive
// roleTagCacheTTL: after the clock advances past the TTL the role is re-read
// and the new (revoked) tag set is what the caller sees.
func TestAudit_RoleTagCacheExpiryEnforcedOnRead(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)

	call := 0
	m.On("GetRole", mock.Anything).Return(&iam.GetRoleOutput{Role: &iamtypes.Role{
		Tags: []iamtypes.Tag{{Key: aws.String("aow/repo"), Value: aws.String("acme/api")}},
	}}, nil).Run(func(mock.Arguments) { call++ }).Once()
	m.On("GetRole", mock.Anything).Return(&iam.GetRoleOutput{Role: &iamtypes.Role{
		Tags: nil, // tags revoked
	}}, nil).Run(func(mock.Arguments) { call++ }).Once()

	c := newTagAuthConsumer(m)
	base := time.Now()
	clock := base
	c.now = func() time.Time { return clock }

	tags, err := c.GetRoleTags("arn:aws:iam::111111111111:role/app")
	require.NoError(t, err)
	require.Equal(t, "acme/api", tags["aow/repo"])

	// Still inside the TTL -> cached.
	clock = base.Add(roleTagCacheTTL - time.Second)
	tags, err = c.GetRoleTags("arn:aws:iam::111111111111:role/app")
	require.NoError(t, err)
	assert.Equal(t, "acme/api", tags["aow/repo"])
	assert.Equal(t, 1, call, "within TTL must be served from cache")

	// Past the TTL -> re-read, revoked tags observed.
	clock = base.Add(roleTagCacheTTL + time.Second)
	tags, err = c.GetRoleTags("arn:aws:iam::111111111111:role/app")
	require.NoError(t, err)
	assert.Empty(t, tags, "revoked tags must be observed once the TTL lapses")
	assert.Equal(t, 2, call)
	assert.Equal(t, 60*time.Second, roleTagCacheTTL, "stale-tag window is bounded at 60s")
}

// TestAudit_SpokeCacheNoCrossAccountReuse proves spoke credentials minted for
// one account are never handed back for a different account, and that each
// account's spoke assume targets that account's own spoke role ARN.
func TestAudit_SpokeCacheNoCrossAccountReuse(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)

	exp := time.Now().Add(time.Hour)
	var seenArns []string
	// Encode the target account into the access key so provider identity is
	// distinguishable; one expectation per account ARN.
	for _, acct := range []string{"222222222222", "333333333333"} {
		arn := "arn:aws:iam::" + acct + ":role/aow-spoke"
		m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
			return *in.RoleArn == arn
		})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
			AccessKeyId: aws.String("AK-" + acct), SecretAccessKey: aws.String("SK"),
			SessionToken: aws.String("ST"), Expiration: &exp,
		}}, nil).Run(func(args mock.Arguments) {
			seenArns = append(seenArns, *args.Get(0).(*sts.AssumeRoleInput).RoleArn)
		}).Once()
	}

	c := NewAwsConsumer(&gtvcfg.Config{
		CrossAccount: &gtvcfg.CrossAccount{
			Enabled: true, SpokeRoleName: "aow-spoke",
			SpokeSessionDuration: 15 * time.Minute,
			ExternalID:           "ext-secret-123",
		},
	})
	c.AWS = m

	p222, err := c.spokeCredsFor("222222222222")
	require.NoError(t, err)
	p333, err := c.spokeCredsFor("333333333333")
	require.NoError(t, err)

	cr222, err := p222.Retrieve(t.Context())
	require.NoError(t, err)
	cr333, err := p333.Retrieve(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "AK-222222222222", cr222.AccessKeyID)
	assert.Equal(t, "AK-333333333333", cr333.AccessKeyID,
		"account 333 must not receive account 222's cached spoke credentials")

	assert.Equal(t, []string{
		"arn:aws:iam::222222222222:role/aow-spoke",
		"arn:aws:iam::333333333333:role/aow-spoke",
	}, seenArns)
	assert.Len(t, c.spokeCache, 2)
}

// TestAudit_SpokeExternalIDAndDuration pins that the configured ExternalID is
// attached to the hub->spoke assume and the session is bounded.
func TestAudit_SpokeExternalIDAndDuration(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	exp := time.Now().Add(time.Hour)
	var captured *sts.AssumeRoleInput
	m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
		captured = in
		return true
	})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"),
		SessionToken: aws.String("ST"), Expiration: &exp,
	}}, nil).Once()

	c := NewAwsConsumer(&gtvcfg.Config{
		CrossAccount: &gtvcfg.CrossAccount{
			Enabled: true, SpokeRoleName: "aow-spoke",
			SpokeSessionDuration: 15 * time.Minute,
			ExternalID:           "ext-secret-123",
		},
	})
	c.AWS = m

	_, err := c.spokeCredsFor("222222222222")
	require.NoError(t, err)
	require.NotNil(t, captured)
	require.NotNil(t, captured.ExternalId)
	assert.Equal(t, "ext-secret-123", *captured.ExternalId)
	assert.Equal(t, int32(900), *captured.DurationSeconds)
}

// TestAudit_SpokeCredsExpiryEnforced proves a cached spoke provider is not
// reused past its refresh margin (Expiration - 5m).
func TestAudit_SpokeCredsExpiryEnforced(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)

	base := time.Now()
	clock := base
	n := 0
	// Each spoke session lasts 15m from the moment it is minted; the cache
	// entry is meant to lapse 5m earlier (refresh margin).
	e1 := base.Add(15 * time.Minute)
	e2 := base.Add(11*time.Minute + 15*time.Minute)
	for _, e := range []time.Time{e1, e2} {
		m.On("AssumeRole", mock.Anything).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
			AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"),
			SessionToken: aws.String("ST"), Expiration: &e,
		}}, nil).Run(func(mock.Arguments) { n++ }).Once()
	}

	c := NewAwsConsumer(&gtvcfg.Config{
		CrossAccount: &gtvcfg.CrossAccount{
			Enabled: true, SpokeRoleName: "aow-spoke",
			SpokeSessionDuration: 15 * time.Minute,
		},
	})
	c.AWS = m
	c.now = func() time.Time { return clock }

	_, err := c.spokeCredsFor("222222222222")
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	clock = base.Add(9 * time.Minute) // inside margin (expires at base+10m)
	_, err = c.spokeCredsFor("222222222222")
	require.NoError(t, err)
	assert.Equal(t, 1, n, "still cached inside the refresh margin")

	clock = base.Add(11 * time.Minute) // past margin, before real expiry
	_, err = c.spokeCredsFor("222222222222")
	require.NoError(t, err)
	assert.Equal(t, 2, n, "must re-assume once the refresh margin lapses")
}

// TestAudit_SpokeCacheHitStillRevalidatesAllowList proves that revoking an
// account from cross_account.allowed_accounts takes effect immediately even
// though warm spoke credentials for it are cached (allow-list check precedes
// the cache lookup).
func TestAudit_SpokeCacheHitStillRevalidatesAllowList(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	exp := time.Now().Add(time.Hour)
	m.On("AssumeRole", mock.Anything).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"),
		SessionToken: aws.String("ST"), Expiration: &exp,
	}}, nil).Once()

	live := &gtvcfg.Config{
		CrossAccount: &gtvcfg.CrossAccount{
			Enabled: true, SpokeRoleName: "aow-spoke",
			SpokeSessionDuration: 15 * time.Minute,
			AllowedAccounts:      []string{"222222222222"},
		},
	}
	c := NewAwsConsumer(live)
	c.SetConfigSource(func() *gtvcfg.Config { return live })

	c.AWS = m
	_, err := c.spokeCredsFor("222222222222")
	require.NoError(t, err)
	require.NotEmpty(t, c.spokeCache, "credentials are warm in the cache")

	// Hot-reload: 222 revoked.
	live = &gtvcfg.Config{
		CrossAccount: &gtvcfg.CrossAccount{
			Enabled: true, SpokeRoleName: "aow-spoke",
			SpokeSessionDuration: 15 * time.Minute,
			AllowedAccounts:      []string{"333333333333"},
		},
	}
	_, err = c.spokeCredsFor("222222222222")
	require.Error(t, err, "warm cache must not bypass the allow-list re-check")
}

// TestAudit_RoleTagCacheHitBypassesAccountChecks documents that a warm
// roleTagCache entry is returned without re-running the cross-account /
// allow-list checks. This is safe only because the processor gates every
// request on IsTargetAccountAllowed before reaching GetRoleTags; the test
// pins the (bounded, 60s) behavior so a future refactor notices it.
func TestAudit_RoleTagCacheHitBypassesAccountChecks(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	exp := time.Now().Add(time.Hour)
	m.On("AssumeRole", mock.Anything).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"),
		SessionToken: aws.String("ST"), Expiration: &exp,
	}}, nil).Once()
	m.On("GetRoleAs", mock.Anything, mock.Anything).Return(&iam.GetRoleOutput{Role: &iamtypes.Role{
		Tags: []iamtypes.Tag{{Key: aws.String("aow/repo"), Value: aws.String("acme/api")}},
	}}, nil).Once()

	live := &gtvcfg.Config{
		TagAuth: &gtvcfg.TagAuth{Enabled: true, TagPrefix: "aow/"},
		CrossAccount: &gtvcfg.CrossAccount{
			Enabled: true, SpokeRoleName: "aow-spoke",
			SpokeSessionDuration: 15 * time.Minute,
			AllowedAccounts:      []string{"222222222222"},
		},
	}
	c := NewAwsConsumer(live)
	c.SetConfigSource(func() *gtvcfg.Config { return live })
	c.AWS = m

	base := time.Now()
	clock := base
	c.now = func() time.Time { return clock }

	_, err := c.GetRoleTags("arn:aws:iam::222222222222:role/app")
	require.NoError(t, err)

	// Revoke the account entirely (cross-account off).
	live = &gtvcfg.Config{TagAuth: &gtvcfg.TagAuth{Enabled: true, TagPrefix: "aow/"}}

	tags, err := c.GetRoleTags("arn:aws:iam::222222222222:role/app")
	require.NoError(t, err, "warm entry served without re-checking config")
	assert.Equal(t, "acme/api", tags["aow/repo"])

	// ...but bounded by the TTL: after 60s it fails closed.
	clock = base.Add(roleTagCacheTTL + time.Second)
	_, err = c.GetRoleTags("arn:aws:iam::222222222222:role/app")
	require.Error(t, err, "after the TTL the revoked config must fail closed")
}
