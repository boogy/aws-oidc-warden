package config

import (
	"os"
	"sync"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTagAuth_TransitiveAndAllowedAccounts_Env(t *testing.T) {
	viper.Reset()
	once = sync.Once{}
	for _, k := range []string{"AOW_TAG_AUTH_ENABLED", "AOW_TAG_AUTH_TRANSITIVE_SESSION_TAGS", "AOW_TAG_AUTH_ALLOWED_ACCOUNTS", "CONFIG_NAME"} {
		orig := os.Getenv(k)
		t.Cleanup(func() { _ = os.Setenv(k, orig) })
	}
	_ = os.Setenv("AOW_TAG_AUTH_ENABLED", "true")
	_ = os.Setenv("AOW_TAG_AUTH_TRANSITIVE_SESSION_TAGS", "true")
	_ = os.Setenv("AOW_TAG_AUTH_ALLOWED_ACCOUNTS", "111111111111, 222222222222")
	_ = os.Setenv("CONFIG_NAME", "nonexistent-config-file")

	c := &Config{}
	require.NoError(t, c.LoadConfig())
	require.NotNil(t, c.TagAuth)
	assert.True(t, c.TagAuth.TransitiveSessionTags)
	assert.Equal(t, []string{"111111111111", "222222222222"}, c.TagAuth.AllowedAccounts)
}

func TestMergeBytes_EnvTagAuthTransitiveAndAllowedAccounts(t *testing.T) {
	t.Setenv("AOW_TAG_AUTH_TRANSITIVE_SESSION_TAGS", "true")
	t.Setenv("AOW_TAG_AUTH_ALLOWED_ACCOUNTS", "111111111111, 222222222222")

	c := &Config{
		Issuer:          "https://token.actions.githubusercontent.com",
		Audiences:       []string{"sts.amazonaws.com"},
		RoleSessionName: "base-session",
		Cache:           &Cache{Type: "memory", TTL: 3600000000000},
	}
	require.NoError(t, c.Validate())

	// S3 payload enables tag_auth but does not set the new keys; the env vars
	// must survive the hot-reload via reapplyEnvOverrides.
	yaml := []byte("tag_auth:\n  enabled: true\n")
	require.NoError(t, c.MergeBytes(yaml, "yaml"))

	require.NotNil(t, c.TagAuth)
	assert.True(t, c.TagAuth.TransitiveSessionTags, "AOW_TAG_AUTH_TRANSITIVE_SESSION_TAGS must survive S3 hot-reload")
	assert.Equal(t, []string{"111111111111", "222222222222"}, c.TagAuth.AllowedAccounts, "AOW_TAG_AUTH_ALLOWED_ACCOUNTS must survive S3 hot-reload, whitespace-trimmed")
}

func TestTagAuth_AllowedAccounts_RejectsMalformed(t *testing.T) {
	c := &Config{
		Issuer: "https://x", Audiences: []string{"a"}, RoleSessionName: "s",
		TagAuth: &TagAuth{Enabled: true, AllowedAccounts: []string{"123"}},
	}
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "allowed_accounts")
}
