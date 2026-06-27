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

func TestTagAuth_AllowedAccounts_RejectsMalformed(t *testing.T) {
	c := &Config{
		Issuer: "https://x", Audiences: []string{"a"}, RoleSessionName: "s",
		TagAuth: &TagAuth{Enabled: true, AllowedAccounts: []string{"123"}},
	}
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "allowed_accounts")
}
