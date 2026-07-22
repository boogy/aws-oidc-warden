package aws

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	gtvcfg "github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// GetRoleAs must refuse a nil credentials provider rather than silently falling
// back to the hub credentials the client was built from. Doing so would read a
// same-named role in the HUB account while the caller believes it read a member
// account's — the confused deputy GetRoleTags explicitly guards against.
//
// Unreachable through its one caller today; the point is that the guarantee
// should not depend on that caller staying correct.
func TestGetRoleAs_RejectsNilCredentials(t *testing.T) {
	s := &AwsServiceWrapper{defaultTimeout: time.Second}

	// A nil iamClient would panic if the guard let execution continue, so this
	// also proves the guard returns BEFORE any client use.
	out, err := s.GetRoleAs(&iam.GetRoleInput{RoleName: aws.String("deploy")}, nil)

	require.Error(t, err, "nil credentials must be refused")
	assert.Nil(t, out)
	assert.Contains(t, err.Error(), "refusing to fall back to hub credentials")
}

// GetRoleTags hands back a COPY of its cached tag map. Returning the cached map
// itself lets any caller that mutates the result poison every later
// authorization decision for that role — a silent, cross-request failure. The
// sole caller (TagAuth.Authorize) only reads, so this pins the defensive
// property rather than a live bug.
func TestGetRoleTags_CachedMapIsNotAliased(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	// .Once(): a second IAM read would mean we missed the cache and the test
	// would be proving nothing about the cached map.
	m.On("GetRole", mock.Anything).Return(&iam.GetRoleOutput{Role: &iamtypes.Role{
		Tags: []iamtypes.Tag{{Key: aws.String("aow/subject"), Value: aws.String("acme/app")}},
	}}, nil).Once()

	cfg := &gtvcfg.Config{TagAuth: &gtvcfg.TagAuth{Enabled: true, TagPrefix: "aow/"}}
	c := NewAwsConsumer(cfg)
	c.SetConfigSource(func() *gtvcfg.Config { return cfg })
	c.AWS = m
	c.now = time.Now

	const arn = "arn:aws:iam::111111111111:role/app"

	first, err := c.GetRoleTags(arn)
	require.NoError(t, err)
	require.Equal(t, "acme/app", first["aow/subject"])

	// Poison the returned map as a careless consumer might.
	first["aow/subject"] = "attacker/repo"
	delete(first, "aow/subject")
	first["aow/issuer"] = "https://evil.example"

	// The next read is a cache hit and must be unaffected.
	second, err := c.GetRoleTags(arn)
	require.NoError(t, err)
	assert.Equal(t, "acme/app", second["aow/subject"],
		"mutating a returned map corrupted the cached tags")
	assert.NotContains(t, second, "aow/issuer",
		"a key injected into a returned map leaked into the cache")

	m.AssertExpectations(t)
}
