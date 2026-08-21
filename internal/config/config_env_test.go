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

// baseConfigForEnv returns a minimal validated config with audit_required on,
// matching the 2.4.0 default.
func baseConfigForEnv(t *testing.T) *Config {
	t.Helper()
	c := &Config{
		Issuers:         singleIssuer("https://token.actions.githubusercontent.com", "sts.amazonaws.com"),
		RoleSessionName: "base-session",
		Cache:           &Cache{Type: "memory", TTL: 5 * time.Minute},
		LogToS3:         true,
		LogBucket:       "audit-bucket",
		AuditRequired:   true,
	}
	require.NoError(t, c.Validate())
	return c
}

// TestMergeBytes_BoolEnvAcceptsEveryParseBoolForm pins the fix for the parser
// divergence: boot used viper's cast.ToBool (== strconv.ParseBool) while the
// reload path used a hand-rolled truthy check that recognized only
// "true"/"1"/"True"/"TRUE". AOW_AUDIT_REQUIRED=t was therefore true at boot and
// silently false after the first remote-config refresh, downgrading the
// fail-closed audit contract with nothing in the logs.
func TestMergeBytes_BoolEnvAcceptsEveryParseBoolForm(t *testing.T) {
	for _, v := range []string{"t", "T", "TRUE", "True", "true", "1"} {
		t.Run("true/"+v, func(t *testing.T) {
			t.Setenv("AOW_AUDIT_REQUIRED", v)
			c := baseConfigForEnv(t)

			require.NoError(t, c.MergeBytes([]byte("audit_required: false\n"), "yaml"))

			assert.True(t, c.AuditRequired, "AOW_AUDIT_REQUIRED=%q must stay true across a refresh", v)
			assert.True(t, c.AuditEnforced(), "enforcement must survive the refresh")
		})
	}

	for _, v := range []string{"f", "F", "FALSE", "False", "false", "0"} {
		t.Run("false/"+v, func(t *testing.T) {
			t.Setenv("AOW_AUDIT_REQUIRED", v)
			c := baseConfigForEnv(t)

			require.NoError(t, c.MergeBytes([]byte("audit_required: true\n"), "yaml"))

			assert.False(t, c.AuditRequired, "AOW_AUDIT_REQUIRED=%q must turn enforcement off", v)
		})
	}
}

// TestMergeBytes_UnparseableBoolEnvKeepsCurrentValue: a typo must not quietly
// disable a security control. The old truthy check mapped every unrecognized
// value to false; the shared parser warns and leaves the value alone.
func TestMergeBytes_UnparseableBoolEnvKeepsCurrentValue(t *testing.T) {
	t.Setenv("AOW_AUDIT_REQUIRED", "yes")
	c := baseConfigForEnv(t)

	require.NoError(t, c.MergeBytes([]byte("log_bucket: other-bucket\n"), "yaml"))

	assert.True(t, c.AuditRequired, "an unparseable AOW_AUDIT_REQUIRED must not silently disable audit enforcement")
}

// TestMergeBytes_BoolEnvFormsAppliedToEveryBoolKey covers the remaining boolean
// knobs so the fix cannot regress on one binding while the audit one keeps
// passing.
func TestMergeBytes_BoolEnvFormsAppliedToEveryBoolKey(t *testing.T) {
	t.Setenv("AOW_LOG_CLAIM_VALUES", "f")
	t.Setenv("AOW_ALLOW_INSECURE_ISSUERS", "t")
	t.Setenv("AOW_SESSION_TAGS_TRANSITIVE", "t")
	t.Setenv("AOW_CACHE_S3_CLEANUP", "t")
	t.Setenv("AOW_TAG_AUTH_ENABLED", "t")
	t.Setenv("AOW_TAG_AUTH_TRANSITIVE_SESSION_TAGS", "t")
	t.Setenv("AOW_CROSS_ACCOUNT_ENABLED", "t")

	c := baseConfigForEnv(t)
	c.LogClaimValues = true
	c.TagAuth = &TagAuth{TagPrefix: "aow/"}

	require.NoError(t, c.MergeBytes([]byte("log_bucket: audit-bucket\n"), "yaml"))

	assert.False(t, c.LogClaimValues, "AOW_LOG_CLAIM_VALUES=f")
	assert.True(t, c.AllowInsecureIssuers, "AOW_ALLOW_INSECURE_ISSUERS=t")
	assert.True(t, c.SessionTagsTransitive, "AOW_SESSION_TAGS_TRANSITIVE=t")
	assert.True(t, c.Cache.S3Cleanup, "AOW_CACHE_S3_CLEANUP=t")
	require.NotNil(t, c.TagAuth)
	assert.True(t, c.TagAuth.Enabled, "AOW_TAG_AUTH_ENABLED=t")
	assert.True(t, c.TagAuth.TransitiveSessionTags, "AOW_TAG_AUTH_TRANSITIVE_SESSION_TAGS=t")
	require.NotNil(t, c.CrossAccount)
	assert.True(t, c.CrossAccount.Enabled, "AOW_CROSS_ACCOUNT_ENABLED=t")
}
