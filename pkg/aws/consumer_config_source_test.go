package aws

import (
	"testing"

	gtvcfg "github.com/boogy/aws-oidc-warden/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfigSource_ReflectsLiveConfig verifies the consumer enforces the
// currently active configuration (e.g. after hot-reload) rather than the
// construction-time snapshot. Without this, tightening allowed_accounts or
// toggling tag-auth via reload would silently fail to take effect.
func TestConfigSource_ReflectsLiveConfig(t *testing.T) {
	member := "arn:aws:iam::222222222222:role/app"

	// Construction-time config allows the member account.
	base := &gtvcfg.Config{TagAuth: &gtvcfg.TagAuth{
		Enabled: true, TagPrefix: "aow/", SpokeRoleName: "aow-spoke",
		AllowedAccounts: []string{"222222222222"},
	}}

	// Live config (post-reload) removes the member account.
	live := &gtvcfg.Config{TagAuth: &gtvcfg.TagAuth{
		Enabled: true, TagPrefix: "aow/", SpokeRoleName: "aow-spoke",
		AllowedAccounts: []string{"333333333333"},
	}}

	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)

	c := NewAwsConsumer(base)
	c.AWS = m

	// Before wiring a source, the base config governs: member allowed.
	ok, err := c.IsTargetAccountAllowed(member)
	require.NoError(t, err)
	assert.True(t, ok, "base config should allow the member account")

	// Wire a live-config getter that returns the reloaded (tighter) config.
	c.SetConfigSource(func() *gtvcfg.Config { return live })

	ok, err = c.IsTargetAccountAllowed(member)
	require.NoError(t, err)
	assert.False(t, ok, "live config removed the member account; must be rejected")
}

// TestConfigSource_ToggleEnabled verifies enabling/disabling tag-auth via the
// live getter is reflected by the consumer's cross-account gate.
func TestConfigSource_ToggleEnabled(t *testing.T) {
	member := "arn:aws:iam::222222222222:role/app"

	disabled := &gtvcfg.Config{TagAuth: &gtvcfg.TagAuth{Enabled: false}}
	enabled := &gtvcfg.Config{TagAuth: &gtvcfg.TagAuth{
		Enabled: true, TagPrefix: "aow/", SpokeRoleName: "aow-spoke",
		AllowedAccounts: []string{"333333333333"},
	}}

	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)

	current := disabled
	c := NewAwsConsumer(&gtvcfg.Config{})
	c.AWS = m
	c.SetConfigSource(func() *gtvcfg.Config { return current })

	// Disabled: no cross-account path, gate returns true (nothing to enforce).
	ok, err := c.IsTargetAccountAllowed(member)
	require.NoError(t, err)
	assert.True(t, ok)

	// Reload enables tag-auth with an allow-list excluding the member.
	current = enabled
	ok, err = c.IsTargetAccountAllowed(member)
	require.NoError(t, err)
	assert.False(t, ok, "after enabling tag-auth, member not in allow-list must be rejected")
}

// TestConfigSource_FallsBackToConfig verifies that with no source wired the
// consumer behaves exactly as before (uses the construction-time Config).
func TestConfigSource_FallsBackToConfig(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)

	c := consumerWithAllowed(m, []string{"333333333333"})
	// nil configSource → fall back to a.Config.
	ok, err := c.IsTargetAccountAllowed("arn:aws:iam::222222222222:role/app")
	require.NoError(t, err)
	assert.False(t, ok)
}
