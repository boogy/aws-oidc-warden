package config

import (
	"os"
	"sync"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTagAuthTransitive_CrossAccountAllowedAccounts_Env(t *testing.T) {
	viper.Reset()
	once = sync.Once{}
	for _, k := range []string{"AOW_TAG_AUTH_ENABLED", "AOW_TAG_AUTH_TRANSITIVE_SESSION_TAGS", "AOW_CROSS_ACCOUNT_ENABLED", "AOW_CROSS_ACCOUNT_ALLOWED_ACCOUNTS", "CONFIG_NAME"} {
		orig := os.Getenv(k)
		t.Cleanup(func() { _ = os.Setenv(k, orig) })
	}
	_ = os.Setenv("AOW_TAG_AUTH_ENABLED", "true")
	_ = os.Setenv("AOW_TAG_AUTH_TRANSITIVE_SESSION_TAGS", "true")
	_ = os.Setenv("AOW_CROSS_ACCOUNT_ENABLED", "true")
	_ = os.Setenv("AOW_CROSS_ACCOUNT_ALLOWED_ACCOUNTS", "111111111111, 222222222222")
	_ = os.Setenv("CONFIG_NAME", "nonexistent-config-file")

	c := &Config{}
	require.NoError(t, c.LoadConfig())
	require.NotNil(t, c.TagAuth)
	assert.True(t, c.TagAuth.TransitiveSessionTags)
	require.NotNil(t, c.CrossAccount)
	assert.True(t, c.CrossAccount.Enabled)
	assert.Equal(t, []string{"111111111111", "222222222222"}, c.CrossAccount.AllowedAccounts)
}

func TestMergeBytes_EnvTagAuthTransitiveAndCrossAccountAllowedAccounts(t *testing.T) {
	t.Setenv("AOW_TAG_AUTH_TRANSITIVE_SESSION_TAGS", "true")
	t.Setenv("AOW_CROSS_ACCOUNT_ALLOWED_ACCOUNTS", "111111111111, 222222222222")

	c := &Config{
		Issuers:         singleIssuer("https://token.actions.githubusercontent.com", "sts.amazonaws.com"),
		RoleSessionName: "base-session",
		Cache:           &Cache{Type: "memory", TTL: 3600000000000},
	}
	require.NoError(t, c.Validate())

	// S3 payload enables tag_auth and cross_account but does not set the other
	// keys; the env vars must survive the hot-reload via reapplyEnvOverrides.
	yaml := []byte("tag_auth:\n  enabled: true\ncross_account:\n  enabled: true\n")
	require.NoError(t, c.MergeBytes(yaml, "yaml"))

	require.NotNil(t, c.TagAuth)
	assert.True(t, c.TagAuth.TransitiveSessionTags, "AOW_TAG_AUTH_TRANSITIVE_SESSION_TAGS must survive S3 hot-reload")
	require.NotNil(t, c.CrossAccount)
	assert.Equal(t, []string{"111111111111", "222222222222"}, c.CrossAccount.AllowedAccounts, "AOW_CROSS_ACCOUNT_ALLOWED_ACCOUNTS must survive S3 hot-reload, whitespace-trimmed")
}

func TestCrossAccount_AllowedAccounts_RejectsMalformed(t *testing.T) {
	c := &Config{
		Issuers: singleIssuer("https://x", "a"), RoleSessionName: "s",
		CrossAccount: &CrossAccount{Enabled: true, AllowedAccounts: []string{"123"}},
	}
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "allowed_accounts")
}

func TestCrossAccount_DefaultsNormalizedOnValidate(t *testing.T) {
	c := &Config{
		Issuers: singleIssuer("https://x", "a"), RoleSessionName: "s",
		CrossAccount: &CrossAccount{Enabled: true},
	}
	require.NoError(t, c.Validate())
	assert.Equal(t, "aow-spoke", c.CrossAccount.SpokeRoleName)
	assert.Equal(t, "15m0s", c.CrossAccount.SpokeSessionDuration.String())
}
