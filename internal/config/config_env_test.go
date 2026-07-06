package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeBytes_EnvVarWinsOverS3Value(t *testing.T) {
	t.Setenv("AOW_ROLE_SESSION_NAME", "env-session")
	t.Setenv("AOW_LOG_BUCKET", "env-log-bucket")

	c := &Config{
		Issuers:         singleIssuer("https://token.actions.githubusercontent.com", "sts.amazonaws.com"),
		RoleSessionName: "base-session",
		Cache:           &Cache{Type: "memory", TTL: 3600000000000},
	}
	require.NoError(t, c.Validate())

	// S3 payload tries to override both fields.
	yaml := []byte(`
role_session_name: s3-session
log_bucket: s3-log-bucket
`)
	require.NoError(t, c.MergeBytes(yaml, "yaml"))

	// Env vars must win over S3 values.
	assert.Equal(t, "env-session", c.RoleSessionName, "AOW_ROLE_SESSION_NAME must take precedence over S3 value")
	assert.Equal(t, "env-log-bucket", c.LogBucket, "AOW_LOG_BUCKET must take precedence over S3 value")
}

func TestMergeBytes_S3ValueAppliedWhenNoEnvOverride(t *testing.T) {
	c := &Config{
		Issuers:         singleIssuer("https://token.actions.githubusercontent.com", "sts.amazonaws.com"),
		RoleSessionName: "base-session",
		Cache:           &Cache{Type: "memory", TTL: 3600000000000},
	}
	require.NoError(t, c.Validate())

	yaml := []byte(`role_session_name: s3-session`)
	require.NoError(t, c.MergeBytes(yaml, "yaml"))

	assert.Equal(t, "s3-session", c.RoleSessionName, "S3 value should apply when no env var is set")
}

func TestMergeBytes_EnvTagAuthDefaultOrgWinsOverS3(t *testing.T) {
	t.Setenv("AOW_TAG_AUTH_DEFAULT_ORG", "env-org")

	c := &Config{
		Issuers:         singleIssuer("https://token.actions.githubusercontent.com", "sts.amazonaws.com"),
		RoleSessionName: "base-session",
		Cache:           &Cache{Type: "memory", TTL: 5 * time.Minute},
		TagAuth:         &TagAuth{Enabled: true, TagPrefix: "aow/", DefaultOrg: "base-org"},
	}
	require.NoError(t, c.Validate())

	// S3 payload tries to override default_org; the env var must win.
	require.NoError(t, c.MergeBytes([]byte("tag_auth:\n  default_org: s3-org\n"), "yaml"))

	assert.Equal(t, "env-org", c.TagAuth.DefaultOrg, "AOW_TAG_AUTH_DEFAULT_ORG must take precedence over S3 value")
}

func TestMergeBytes_EnvCacheTTLWinsOverS3(t *testing.T) {
	t.Setenv("AOW_CACHE_TTL", "10m")

	c := &Config{
		Issuers:         singleIssuer("https://token.actions.githubusercontent.com", "sts.amazonaws.com"),
		RoleSessionName: "base-session",
		Cache:           &Cache{Type: "memory", TTL: 5 * time.Minute},
	}
	require.NoError(t, c.Validate())

	yamlData := []byte("cache:\n  ttl: 5m\n")
	require.NoError(t, c.MergeBytes(yamlData, "yaml"))

	assert.Equal(t, 10*time.Minute, c.Cache.TTL, "AOW_CACHE_TTL must take precedence over S3 value")
}
