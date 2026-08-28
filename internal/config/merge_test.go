package config

// MergeBytes: the remote-overlay path. Only keys present in the overlay are
// written, an env var still outranks what S3 says, and a null-valued key
// leaves the base value alone.

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/spf13/viper"
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

// TestMergeBytesNullKeysDoNotClobberBase pins the blast radius of DecodeNil.
//
// decoderOptions sets DecodeNil so the decode hooks see a key written with no
// value — the only way to tell `conditions:` (a gate that gates nothing) from
// an omitted key. The flag is global to the decoder, so what matters as much
// as what it enables is what it must NOT change: a remote overlay (MergeBytes,
// the S3 config path) that writes an unrelated key as null still leaves the
// base value alone. A generator that emits explicit nulls for unset keys would
// otherwise silently disarm audit enforcement on the next reload.
//
// The reason it holds is one level below this package: viper's AllSettings()
// — what Unmarshal decodes — drops a null-valued TOP-LEVEL key entirely
// (AllKeys() still reports it, which is why MergeBytes uses AllKeys for the
// issuers check). Nulls nested inside a non-null value, such as a mapping's
// `conditions:`, are carried through as raw data and do reach the hooks. So
// this is a characterization test: it fails if that boundary moves — e.g. if
// MergeBytes ever decodes the raw parsed map instead of AllSettings — not if
// DecodeNil is toggled.
func TestMergeBytesNullKeysDoNotClobberBase(t *testing.T) {
	base := func(t *testing.T) *Config {
		t.Helper()
		c := &Config{}
		require.NoError(t, c.MergeBytes([]byte(`
role_session_name: "aow"
audit_required: true
log_to_s3: true
log_bucket: "audit-bucket"
cache:
  type: "memory"
  ttl: "1h"
issuers:
  - issuer: "https://token.actions.githubusercontent.com"
    provider: github
    audiences: ["sts.amazonaws.com"]
`), "yaml"))
		return c
	}

	t.Run("null bool keeps the declared audit intent", func(t *testing.T) {
		c := base(t)
		require.NoError(t, c.MergeBytes([]byte("audit_required: null\n"), "yaml"))
		require.True(t, c.AuditRequired)
		require.True(t, c.AuditEnforced())
	})

	t.Run("null string keeps the audit bucket", func(t *testing.T) {
		c := base(t)
		require.NoError(t, c.MergeBytes([]byte("log_bucket: null\n"), "yaml"))
		require.Equal(t, "audit-bucket", c.LogBucket)
		require.True(t, c.AuditEnforced())
	})

	t.Run("null struct pointer keeps the cache config", func(t *testing.T) {
		c := base(t)
		require.NoError(t, c.MergeBytes([]byte("cache: null\n"), "yaml"))
		require.NotNil(t, c.Cache)
		require.Equal(t, "memory", c.Cache.Type)
	})

	t.Run("null duration keeps the leeway default", func(t *testing.T) {
		c := base(t)
		require.NoError(t, c.MergeBytes([]byte("jwt_leeway: null\n"), "yaml"))
		require.Equal(t, defaultJWTLeeway, c.LeewayOrDefault())
	})
}

// TestMergeBytesExplicitNullIssuersRejectsSeed pins the other half of the
// same "issuers declared ⇒ replace the seed" invariant: v.InConfig("issuers")
// returns false for an explicitly null value (viper can't tell "absent" from
// "present but nil" apart), so "issuers: null" used to fall through to the
// additive merge, keep the zero-config GitHub seed, and boot open trusting
// GitHub Actions tokens. It must now be treated as declared, same as any
// other value, and rejected by Validate()'s zero-issuers check.
func TestMergeBytesExplicitNullIssuersRejectsSeed(t *testing.T) {
	viper.Reset()
	once = sync.Once{}

	origName := os.Getenv("CONFIG_NAME")
	defer func() {
		if origName == "" {
			_ = os.Unsetenv("CONFIG_NAME")
		} else {
			_ = os.Setenv("CONFIG_NAME", origName)
		}
	}()
	t.Setenv("CONFIG_NAME", "nonexistent-config-file")

	c := &Config{}
	require.NoError(t, c.LoadConfig())
	require.Len(t, c.Issuers, 1) // the GitHub seed, the trap this test pins.

	err := c.MergeBytes([]byte("issuers: null\n"), "yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one issuer is required")
}

// TestFindRoleSessionName_ComesFromAuthorizingMapping pins that the session
// name travels with the grant, exactly as the session policy does. A broad
// mapping declared first must not shadow the narrow mapping that granted the
// role — that is the bug FindSessionPolicy's doc comment describes.

func TestMergeBytesDeclaredSlicesReplaceRatherThanIndexMerge(t *testing.T) {
	base := func(t *testing.T) *Config {
		t.Helper()
		c := &Config{}
		require.NoError(t, c.MergeBytes([]byte(`
role_session_name: "aow"
issuers:
  - issuer: "https://token.actions.githubusercontent.com"
    provider: github
    audiences: ["sts.amazonaws.com"]
role_mappings:
  - subject: "myorg/admin-repo"
    roles: ["arn:aws:iam::111111111111:role/AdminRole"]
    conditions:
      ref: "refs/heads/main"
  - subject: "myorg/other-repo"
    roles: ["arn:aws:iam::111111111111:role/OtherRole"]
role_groups:
  - subjects: ["myorg/grouped-repo"]
    defaults:
      roles: ["arn:aws:iam::111111111111:role/GroupRole"]
`), "yaml"))
		return c
	}

	const (
		issuer    = "https://token.actions.githubusercontent.com"
		adminRole = "arn:aws:iam::111111111111:role/AdminRole"
		groupRole = "arn:aws:iam::111111111111:role/GroupRole"
	)

	t.Run("role_mappings entry without roles inherits nothing", func(t *testing.T) {
		c := base(t)
		err := c.MergeBytes([]byte(`{"role_mappings":[{"subject":"myorg/lowpriv-repo","roles":["arn:aws:iam::111111111111:role/LowPrivRole"]}]}`), "json")
		require.NoError(t, err)
		require.Len(t, c.RoleMappings, 1)

		matched, roles := c.AuthorizeRoles(issuer, "myorg/lowpriv-repo", map[string]any{})
		require.True(t, matched)
		assert.NotContains(t, roles, adminRole)
		assert.Equal(t, []string{"arn:aws:iam::111111111111:role/LowPrivRole"}, roles)

		matched, _ = c.AuthorizeRoles(issuer, "myorg/admin-repo", map[string]any{})
		assert.False(t, matched, "the replaced mapping must be gone")
	})

	t.Run("role_mappings entry without conditions inherits none", func(t *testing.T) {
		c := base(t)
		require.NoError(t, c.MergeBytes([]byte(`{"role_mappings":[{"subject":"myorg/admin-repo","roles":["`+adminRole+`"]}]}`), "json"))
		require.Len(t, c.RoleMappings, 1)
		assert.Nil(t, c.RoleMappings[0].Conditions)
	})

	t.Run("role_mappings entry omitting roles is rejected, not inherited", func(t *testing.T) {
		c := base(t)
		err := c.MergeBytes([]byte(`{"role_mappings":[{"subject":"myorg/lowpriv-repo"}]}`), "json")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "subject and roles are required")
	})

	t.Run("role_groups entry omitting roles is rejected, not inherited", func(t *testing.T) {
		c := base(t)
		err := c.MergeBytes([]byte(`{"role_groups":[{"subjects":["myorg/new-repo"]}]}`), "json")
		require.Error(t, err)
		assert.NotContains(t, err.Error(), groupRole)
	})

	t.Run("role_groups entry replaces the base group", func(t *testing.T) {
		c := base(t)
		require.NoError(t, c.MergeBytes([]byte(`{"role_groups":[{"subjects":["myorg/new-repo"],"defaults":{"roles":["arn:aws:iam::111111111111:role/NewRole"]}}]}`), "json"))
		require.Len(t, c.RoleGroups, 1)

		matched, roles := c.AuthorizeRoles(issuer, "myorg/new-repo", map[string]any{})
		require.True(t, matched)
		assert.NotContains(t, roles, groupRole)

		matched, _ = c.AuthorizeRoles(issuer, "myorg/grouped-repo", map[string]any{})
		assert.False(t, matched, "the replaced group must be gone")
	})

	t.Run("explicit null role_mappings clears the base grants", func(t *testing.T) {
		c := base(t)
		require.NoError(t, c.MergeBytes([]byte("role_mappings: null\n"), "yaml"))
		assert.Empty(t, c.RoleMappings)

		matched, _ := c.AuthorizeRoles(issuer, "myorg/admin-repo", map[string]any{"ref": "refs/heads/main"})
		assert.False(t, matched)
	})

	t.Run("config_fragment_checksums entry omitting checksum is rejected, not inherited", func(t *testing.T) {
		c := &Config{}
		require.NoError(t, c.MergeBytes([]byte(`
role_session_name: "aow"
issuers:
  - issuer: "`+issuer+`"
    provider: github
    audiences: ["sts.amazonaws.com"]
config_fragments: ["s3://cfg/a.yaml", "s3://cfg/b.yaml"]
config_fragment_checksums:
  - uri: "s3://cfg/a.yaml"
    checksum: "sha256:aaaa"
`), "yaml"))

		err := c.MergeBytes([]byte(`{"config_fragment_checksums":[{"uri":"s3://cfg/b.yaml"}]}`), "json")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "checksum is required")
	})

	t.Run("a struct key still merges field-wise", func(t *testing.T) {
		c := base(t)
		require.NoError(t, c.MergeBytes([]byte(`
cross_account:
  enabled: true
  allowed_accounts: ["111111111111"]
`), "yaml"))
		require.NoError(t, c.MergeBytes([]byte(`{"cross_account":{"spoke_role_name":"aow-spoke"}}`), "json"))
		require.NotNil(t, c.CrossAccount)
		assert.True(t, c.CrossAccount.Enabled)
		assert.Equal(t, []string{"111111111111"}, c.CrossAccount.AllowedAccounts)
	})

	t.Run("an undeclared slice is left alone", func(t *testing.T) {
		c := base(t)
		require.NoError(t, c.MergeBytes([]byte(`{"log_bucket":"other-bucket"}`), "json"))
		require.Len(t, c.RoleMappings, 2)
		matched, roles := c.AuthorizeRoles(issuer, "myorg/admin-repo", map[string]any{"ref": "refs/heads/main"})
		require.True(t, matched)
		assert.Contains(t, roles, adminRole)
	})
}
