package config

import (
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConfig(t *testing.T) {
	// Both resets are needed. `once` alone leaves viper holding every config
	// path an earlier test registered — AddConfigPath accumulates and is never
	// cleared by LoadConfig — so this test would try to read a t.TempDir() that
	// has already been removed and fail on a file it never asked for.
	viper.Reset()
	once = sync.Once{}

	cfg, err := NewConfig()
	assert.NoError(t, err)
	assert.NotNil(t, cfg)

	// Test singleton behavior
	cfg2, err := NewConfig()
	assert.NoError(t, err)
	assert.Equal(t, cfg, cfg2, "Expected NewConfig to return the same instance")
}

func TestLoadConfig(t *testing.T) {
	// Reset viper completely
	viper.Reset()

	// Create a temporary config file
	tmpFile, err := os.CreateTemp("", "config_*.yaml")
	assert.NoError(t, err)
	defer func() {
		if err := os.Remove(tmpFile.Name()); err != nil {
			t.Logf("Failed to remove temp file: %v", err)
		}
	}()

	// Write test config content
	configContent := `issuers:
  - issuer: "https://test.issuer.com"
    audiences: ["test-audience"]
role_session_name: "test-session"
role_mappings:
  - subject: "org/repo1"
    session_policy: "policy1"
    roles:
      - "role1"
      - "role2"
  - subject: "org/repo2"
    session_policy: "policy2"
    roles:
      - "role3"
cache_type: "memory"
`
	_, err = tmpFile.WriteString(configContent)
	assert.NoError(t, err)
	err = tmpFile.Close()
	assert.NoError(t, err)

	// Create a custom loadConfig function that explicitly loads our test file
	customLoadConfig := func(cfg *Config) error {
		v := viper.New() // Use a fresh viper instance
		v.SetConfigFile(tmpFile.Name())

		if err := v.ReadInConfig(); err != nil {
			t.Logf("Failed to read config file: %v", err)
			return err
		}

		// Check if config was really read
		t.Logf("Config file used: %s", v.ConfigFileUsed())

		// Extract values from viper
		if err := v.Unmarshal(cfg); err != nil {
			return err
		}

		return nil
	}

	// Test loading config with our custom function
	cfg := &Config{}
	err = customLoadConfig(cfg)
	assert.NoError(t, err)

	// Print debug info to see what's actually in the config
	t.Logf("Loaded config: issuers=%d, roleSessionName=%s, mappings=%d",
		len(cfg.Issuers), cfg.RoleSessionName, len(cfg.RoleMappings))

	// Now we should have the test values, not defaults
	require.Len(t, cfg.Issuers, 1)
	assert.Equal(t, "https://test.issuer.com", cfg.Issuers[0].Issuer)
	assert.Equal(t, []string{"test-audience"}, cfg.Issuers[0].Audiences)
	assert.Equal(t, "test-session", cfg.RoleSessionName)
	assert.Equal(t, 2, len(cfg.RoleMappings))
	assert.Equal(t, "org/repo1", cfg.RoleMappings[0].Subject)
	assert.Equal(t, "policy1", cfg.RoleMappings[0].SessionPolicy)
	assert.Equal(t, []string{"role1", "role2"}, cfg.RoleMappings[0].Roles)
}

func TestLoadConfigDefaults(t *testing.T) {
	// Reset viper
	viper.Reset()

	// Create a config pointing to a non-existent file
	viper.SetConfigName("non-existent-config")
	viper.AddConfigPath("/tmp/non-existent-path")

	// Test loading config with defaults
	cfg := &Config{}
	err := cfg.LoadConfig()
	assert.NoError(t, err)

	// Verify default values, including the zero-config GitHub issuer seed.
	require.Len(t, cfg.Issuers, 1)
	assert.Equal(t, "https://token.actions.githubusercontent.com", cfg.Issuers[0].Issuer)
	assert.Equal(t, "github", cfg.Issuers[0].Provider)
	assert.Equal(t, []string{"sts.amazonaws.com"}, cfg.Issuers[0].Audiences)
	assert.Equal(t, []string{"repository"}, cfg.Issuers[0].RequiredClaims)
	assert.Equal(t, "aws-oidc-warden", cfg.RoleSessionName)
	assert.Equal(t, "memory", cfg.Cache.Type)
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		expectErr bool
	}{
		{
			name: "valid config",
			config: Config{
				Issuers:         singleIssuer("https://issuer.com", "audience"),
				RoleSessionName: "session",
				RoleMappings: []RoleMapping{
					{
						Subject:       "org/repo",
						SessionPolicy: "policy",
						Roles:         []string{"role1"},
					},
				},
			},
			expectErr: false,
		},
		{
			name: "valid config with multiple audiences",
			config: Config{
				Issuers:         singleIssuer("https://issuer.com", "audience1", "audience2"),
				RoleSessionName: "session",
				RoleMappings: []RoleMapping{
					{
						Subject:       "org/repo",
						SessionPolicy: "policy",
						Roles:         []string{"role1"},
					},
				},
			},
			expectErr: false,
		},
		{
			name: "valid config with multiple issuers",
			config: Config{
				Issuers: []IssuerConfig{
					{Issuer: "https://issuer-a.com", Provider: "github", Audiences: []string{"audience"}},
					{Issuer: "https://issuer-b.com", Provider: "github", Audiences: []string{"audience"}},
				},
				RoleSessionName: "session",
			},
			expectErr: false,
		},
		{
			name:      "missing issuers",
			config:    Config{RoleSessionName: "session"},
			expectErr: true,
		},
		{
			name: "duplicate issuer",
			config: Config{
				Issuers: []IssuerConfig{
					{Issuer: "https://issuer.com", Audiences: []string{"audience"}},
					{Issuer: "https://issuer.com", Audiences: []string{"other"}},
				},
				RoleSessionName: "session",
			},
			expectErr: true,
		},
		{
			name: "missing audience",
			config: Config{
				Issuers:         []IssuerConfig{{Issuer: "https://issuer.com"}},
				RoleSessionName: "session",
			},
			expectErr: true,
		},
		{
			name: "empty-string audience element is rejected",
			config: Config{
				Issuers:         []IssuerConfig{{Issuer: "https://issuer.com", Audiences: []string{""}}},
				RoleSessionName: "session",
			},
			expectErr: true,
		},
		{
			name: "missing role session name",
			config: Config{
				Issuers: singleIssuer("https://issuer.com", "audience"),
			},
			expectErr: true,
		},
		{
			// The KEY side is NOT constrained. "sub" is not a canonical field
			// the validator reads, but a non-subject entry still contributes
			// its value to the issuer's auditable-claim set, so it is a
			// meaningful config, not a no-op. The pre-3.0.0 guard rejected
			// this shape while checking the wrong side of the map entirely:
			// keys are field names, and no key can shadow a verified claim.
			name: "claim_mappings key that is not a canonical field is allowed",
			config: Config{
				Issuers: []IssuerConfig{{
					Issuer:        "https://issuer.com",
					Provider:      "github",
					Audiences:     []string{"audience"},
					ClaimMappings: map[string]string{"sub": "some_claim"},
				}},
				RoleSessionName: "session",
			},
			expectErr: false,
		},
		{
			// The VALUE side is where the security risk actually lives: `iss`
			// is byte-identical in every token this issuer mints, so making it
			// the canonical subject gives every caller the same subject and any
			// one of them matches any other's subject pattern.
			name: "claim_mappings.subject targets iss (identity collapse)",
			config: Config{
				Issuers: []IssuerConfig{{
					Issuer:        "https://gitlab.example.com",
					Provider:      "generic",
					Audiences:     []string{"audience"},
					ClaimMappings: map[string]string{"subject": "iss"},
				}},
				RoleSessionName: "session",
			},
			expectErr: true,
		},
		{
			name: "claim_mappings.subject targets aud (identity collapse)",
			config: Config{
				Issuers: []IssuerConfig{{
					Issuer:        "https://gitlab.example.com",
					Provider:      "generic",
					Audiences:     []string{"audience"},
					ClaimMappings: map[string]string{"subject": "aud"},
				}},
				RoleSessionName: "session",
			},
			expectErr: true,
		},
		{
			// `sub` must stay ALLOWED: it is the ordinary canonical subject for
			// most non-GitHub IdPs. claim_mappings is a read-only projection
			// over already-verified claims, so naming `sub` shadows nothing.
			name: "claim_mappings.subject targets sub (the normal generic case)",
			config: Config{
				Issuers: []IssuerConfig{{
					Issuer:        "https://gitlab.example.com",
					Provider:      "generic",
					Audiences:     []string{"audience"},
					ClaimMappings: map[string]string{"subject": "sub"},
				}},
				RoleSessionName: "session",
			},
			expectErr: false,
		},
		{
			name: "non-github provider without claim_mappings.subject",
			config: Config{
				Issuers: []IssuerConfig{{
					Issuer:    "https://gitlab.example.com",
					Provider:  "gitlab",
					Audiences: []string{"audience"},
				}},
				RoleSessionName: "session",
			},
			expectErr: true,
		},
		{
			name: "generic provider with claim_mappings.subject is valid",
			config: Config{
				Issuers: []IssuerConfig{{
					Issuer:        "https://issuer.com",
					Provider:      "generic",
					Audiences:     []string{"audience"},
					ClaimMappings: map[string]string{"subject": "project_path"},
				}},
				RoleSessionName: "session",
			},
			expectErr: false,
		},
		{
			name: "invalid session_tags key charset",
			config: Config{
				Issuers: []IssuerConfig{{
					Issuer:      "https://issuer.com",
					Provider:    "github",
					Audiences:   []string{"audience"},
					SessionTags: map[string]string{"bad key!": "actor"},
				}},
				RoleSessionName: "session",
			},
			expectErr: true,
		},
		{
			name: "jwt_leeway over 120s is rejected",
			config: Config{
				Issuers:         singleIssuer("https://issuer.com", "audience"),
				RoleSessionName: "session",
				JWTLeeway:       durationPtr(200 * time.Second),
			},
			expectErr: true,
		},
		{
			name: "invalid mapping - missing subject",
			config: Config{
				Issuers:         singleIssuer("https://issuer.com", "audience"),
				RoleSessionName: "session",
				RoleMappings: []RoleMapping{
					{
						SessionPolicy: "policy",
						Roles:         []string{"role1"},
					},
				},
			},
			expectErr: true,
		},
		{
			name: "valid config - missing session policy",
			config: Config{
				Issuers:         singleIssuer("https://issuer.com", "audience"),
				RoleSessionName: "session",
				RoleMappings: []RoleMapping{
					{
						Subject: "org/repo",
						Roles:   []string{"role1"},
					},
				},
			},
			expectErr: false,
		},
		{
			name: "invalid mapping - empty roles",
			config: Config{
				Issuers:         singleIssuer("https://issuer.com", "audience"),
				RoleSessionName: "session",
				RoleMappings: []RoleMapping{
					{
						Subject:       "org/repo",
						SessionPolicy: "policy",
						Roles:         []string{},
					},
				},
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestAuditEnforced_DerivedNotMutated pins that audit_required is never
// written back to. Validate() previously downgraded it to false when no
// bucket was configured; because Provider.refresh clones the pristine base,
// that downgrade was permanent and a later reload supplying log_to_s3 +
// log_bucket could never re-engage the fail-closed guarantee.
func TestAuditEnforced_DerivedNotMutated(t *testing.T) {
	base := func() Config {
		return Config{
			Issuers:         singleIssuer("https://issuer.com", "aud"),
			RoleSessionName: "test",
			AuditRequired:   true,
		}
	}

	t.Run("no bucket: declared intent preserved, not enforced", func(t *testing.T) {
		cfg := base()
		require.NoError(t, cfg.Validate())
		assert.True(t, cfg.AuditRequired, "declared value must survive Validate()")
		assert.False(t, cfg.AuditEnforced(), "cannot enforce without a destination")
	})

	t.Run("bucket configured: enforced", func(t *testing.T) {
		cfg := base()
		cfg.LogToS3 = true
		cfg.LogBucket = "audit-bucket"
		require.NoError(t, cfg.Validate())
		assert.True(t, cfg.AuditEnforced())
	})

	t.Run("explicitly disabled: never enforced", func(t *testing.T) {
		cfg := base()
		cfg.AuditRequired = false
		cfg.LogToS3 = true
		cfg.LogBucket = "audit-bucket"
		require.NoError(t, cfg.Validate())
		assert.False(t, cfg.AuditEnforced())
	})

	// The regression that motivated this task.
	t.Run("reload supplying the bucket re-engages enforcement", func(t *testing.T) {
		cfg := base()
		require.NoError(t, cfg.Validate())
		require.False(t, cfg.AuditEnforced())

		require.NoError(t, cfg.MergeBytes([]byte(
			"log_to_s3: true\nlog_bucket: audit-bucket\n"), "yaml"))

		assert.True(t, cfg.AuditEnforced(),
			"bucket is now configured; enforcement must engage without restating audit_required")
	})
}

// TestJWTLeewayExplicitZero verifies that an explicit jwt_leeway: 0 is
// distinguishable from unset and is preserved as-is (not coerced to the
// default), since JWTLeeway is a *time.Duration (nil = unset).
func TestJWTLeewayExplicitZero(t *testing.T) {
	cfg := Config{
		Issuers:         singleIssuer("https://issuer.com", "audience"),
		RoleSessionName: "session",
		JWTLeeway:       durationPtr(0),
	}
	require.NoError(t, cfg.Validate())
	require.NotNil(t, cfg.JWTLeeway)
	assert.Equal(t, time.Duration(0), *cfg.JWTLeeway)
	assert.Equal(t, time.Duration(0), cfg.LeewayOrDefault())
}

// TestJWTLeewayUnsetDefaults verifies that a nil (unset) jwt_leeway is
// defaulted to defaultJWTLeeway by Validate/LeewayOrDefault.
func TestJWTLeewayUnsetDefaults(t *testing.T) {
	cfg := Config{
		Issuers:         singleIssuer("https://issuer.com", "audience"),
		RoleSessionName: "session",
	}
	require.NoError(t, cfg.Validate())
	require.NotNil(t, cfg.JWTLeeway)
	assert.Equal(t, defaultJWTLeeway, *cfg.JWTLeeway)
	assert.Equal(t, defaultJWTLeeway, cfg.LeewayOrDefault())
}

// TestMaxTokenLifetimeAndAgeDefaults verifies that an unset (zero-value)
// max_token_lifetime/max_token_age is defaulted to 1h by Validate(), since
// leaving them uncapped by default would let a stolen/leaked long-lived
// token remain usable indefinitely.
func TestMaxTokenLifetimeAndAgeDefaults(t *testing.T) {
	cfg := Config{
		Issuers:         singleIssuer("https://issuer.com", "audience"),
		RoleSessionName: "session",
	}
	require.NoError(t, cfg.Validate())
	assert.Equal(t, defaultMaxTokenLifetime, cfg.MaxTokenLifetime)
	assert.Equal(t, defaultMaxTokenAge, cfg.MaxTokenAge)
}

// TestMaxTokenLifetimeAndAgeExplicitValuesPreserved verifies that an explicit
// non-zero max_token_lifetime/max_token_age is preserved as-is, not
// overwritten by the default.
func TestMaxTokenLifetimeAndAgeExplicitValuesPreserved(t *testing.T) {
	cfg := Config{
		Issuers:          singleIssuer("https://issuer.com", "audience"),
		RoleSessionName:  "session",
		MaxTokenLifetime: 15 * time.Minute,
		MaxTokenAge:      5 * time.Minute,
	}
	require.NoError(t, cfg.Validate())
	assert.Equal(t, 15*time.Minute, cfg.MaxTokenLifetime)
	assert.Equal(t, 5*time.Minute, cfg.MaxTokenAge)
}

func TestFindSessionPolicy(t *testing.T) {
	const iss = "https://issuer.com"
	cfg := &Config{
		Issuers:         singleIssuer(iss, "audience"),
		RoleSessionName: "session",
		RoleMappings: []RoleMapping{
			{
				Subject:       "org/repo1",
				SessionPolicy: "policy1",
				Roles:         []string{"role1"},
			},
			{
				Subject:       "org/repo2.*",
				SessionPolicy: "policy2",
				Roles:         []string{"role2"},
			},
		},
	}
	require.NoError(t, cfg.Validate())

	tests := []struct {
		name       string
		subject    string
		role       string
		wantPolicy *string
	}{
		{
			name:       "exact match",
			subject:    "org/repo1",
			role:       "role1",
			wantPolicy: strPtr("policy1"),
		},
		{
			name:       "regex match",
			subject:    "org/repo2-staging",
			role:       "role2",
			wantPolicy: strPtr("policy2"),
		},
		{
			name:       "no match",
			subject:    "org/repo3",
			role:       "role1",
			wantPolicy: nil,
		},
		{
			name:       "subject matches but role not granted by that mapping",
			subject:    "org/repo1",
			role:       "role2",
			wantPolicy: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy, policyFile := cfg.FindSessionPolicy(iss, tt.subject, tt.role, nil)

			if tt.wantPolicy == nil {
				assert.Nil(t, policy)
			} else {
				assert.NotNil(t, policy)
				assert.Equal(t, *tt.wantPolicy, *policy)
			}

			// We're not testing policyFile in this test
			assert.Nil(t, policyFile)
		})
	}
}

func TestAuthorizeRoles(t *testing.T) {
	const iss = "https://issuer.com"
	cfg := &Config{
		Issuers:         singleIssuer(iss, "audience"),
		RoleSessionName: "session",
		RoleMappings: []RoleMapping{
			{
				Subject: "org/repo1",
				Roles:   []string{"role1", "role2"},
			},
			{
				Subject: "org/repo2.*",
				Roles:   []string{"role3"},
			},
			{
				Subject: "org/shared-.*",
				Roles:   []string{"shared-role"},
			},
		},
	}
	require.NoError(t, cfg.Validate())

	tests := []struct {
		name        string
		subject     string
		wantMatched bool
		wantRoles   []string
	}{
		{
			name:        "exact match",
			subject:     "org/repo1",
			wantMatched: true,
			wantRoles:   []string{"role1", "role2"},
		},
		{
			name:        "regex match",
			subject:     "org/repo2-staging",
			wantMatched: true,
			wantRoles:   []string{"role3"},
		},
		{
			name:        "multiple matches - check implementation",
			subject:     "org/shared-repo2-staging",
			wantMatched: true,
			// The actual implementation may only match the first or most specific pattern
			// Adjust this based on your actual implementation behavior
			wantRoles: []string{"shared-role"},
		},
		{
			name:        "no match",
			subject:     "org/repo3",
			wantMatched: false,
			wantRoles:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, roles := cfg.AuthorizeRoles(iss, tt.subject, nil)

			assert.Equal(t, tt.wantMatched, matched)

			if tt.wantRoles == nil {
				assert.Empty(t, roles)
			} else {
				// Since the order of roles isn't guaranteed, check that all expected roles are present
				for _, expectedRole := range tt.wantRoles {
					assert.Contains(t, roles, expectedRole)
				}
				assert.Equal(t, len(tt.wantRoles), len(roles))
			}
		})
	}
}

// TestLoadConfigFromEnvVars verifies that configuration can be properly loaded from environment variables
func TestLoadConfigFromEnvVars(t *testing.T) {
	// Reset viper
	viper.Reset()
	// Reset singleton
	once = sync.Once{}

	// Save original env vars to restore later
	originalEnvVars := make(map[string]string)
	envVarsToSet := []string{
		"AOW_ROLE_SESSION_NAME",
		"AOW_S3_CONFIG_BUCKET",
		"AOW_S3_CONFIG_PATH",
		"AOW_SESSION_POLICY_BUCKET",
		"AOW_CACHE_TYPE",
		"AOW_CACHE_TTL",
		"AOW_CACHE_MAX_LOCAL_SIZE",
		"AOW_CACHE_DYNAMODB_TABLE",
		"AOW_CACHE_S3_BUCKET",
		"AOW_CACHE_S3_PREFIX",
		"AOW_CACHE_S3_CLEANUP",
		"AOW_LOG_TO_S3",
		"AOW_LOG_BUCKET",
		"AOW_LOG_PREFIX",
		// CONFIG_NAME is set below to force the env-var path. It belongs in
		// this list: without it the "nonexistent-config-file" value leaked for
		// the rest of the binary, so every later test that loads a real
		// config.yaml found none, silently loaded an empty config, and
		// authorized nothing. That is why this package failed under
		// `go test -shuffle`.
		"CONFIG_NAME",
	}

	for _, env := range envVarsToSet {
		originalEnvVars[env] = os.Getenv(env)
	}

	// Clean up env vars after test
	defer func() {
		for env, val := range originalEnvVars {
			if val == "" {
				_ = os.Unsetenv(env)
			} else {
				_ = os.Setenv(env, val)
			}
		}
	}()

	// Set env vars for testing
	_ = os.Setenv("AOW_ROLE_SESSION_NAME", "env-test-session")
	_ = os.Setenv("AOW_S3_CONFIG_BUCKET", "env-config-bucket")
	_ = os.Setenv("AOW_S3_CONFIG_PATH", "env-config/path.yml")
	_ = os.Setenv("AOW_SESSION_POLICY_BUCKET", "env-policy-bucket")
	_ = os.Setenv("AOW_CACHE_TYPE", "dynamodb")
	_ = os.Setenv("AOW_CACHE_TTL", "2h")
	_ = os.Setenv("AOW_CACHE_MAX_LOCAL_SIZE", "20")
	_ = os.Setenv("AOW_CACHE_DYNAMODB_TABLE", "env-dynamo-table")
	_ = os.Setenv("AOW_CACHE_S3_BUCKET", "env-cache-bucket")
	_ = os.Setenv("AOW_CACHE_S3_PREFIX", "env-cache/")
	_ = os.Setenv("AOW_CACHE_S3_CLEANUP", "true")
	_ = os.Setenv("AOW_LOG_TO_S3", "true")
	_ = os.Setenv("AOW_LOG_BUCKET", "env-log-bucket")
	_ = os.Setenv("AOW_LOG_PREFIX", "env-logs/")

	// Point to a non-existent config file to ensure we use env vars
	_ = os.Setenv("CONFIG_NAME", "nonexistent-config-file")

	// Load config
	cfg, err := NewConfig()
	assert.NoError(t, err)
	assert.NotNil(t, cfg)

	// Verify config values match environment variables
	// No config file and no issuer-related env vars: the zero-config GitHub
	// issuer seed applies (issuers are not settable via flat env vars).
	require.Len(t, cfg.Issuers, 1)
	assert.Equal(t, "https://token.actions.githubusercontent.com", cfg.Issuers[0].Issuer, "Issuer should be the zero-config GitHub seed")
	assert.Equal(t, "env-test-session", cfg.RoleSessionName, "RoleSessionName should match env var")
	assert.Equal(t, "env-config-bucket", cfg.S3ConfigBucket, "S3ConfigBucket should match env var")
	assert.Equal(t, "env-config/path.yml", cfg.S3ConfigPath, "S3ConfigPath should match env var")
	assert.Equal(t, "env-policy-bucket", cfg.S3SessionPolicyBucket, "S3SessionPolicyBucket should match env var")

	// Cache settings
	assert.Equal(t, "dynamodb", cfg.Cache.Type, "Cache type should match env var")
	assert.Equal(t, 2*time.Hour, cfg.Cache.TTL, "Cache TTL should match env var")
	assert.Equal(t, 20, cfg.Cache.MaxLocalSize, "Cache max local size should match env var")
	assert.Equal(t, "env-dynamo-table", cfg.Cache.DynamoDBTable, "DynamoDB table should match env var")
	assert.Equal(t, "env-cache-bucket", cfg.Cache.S3Bucket, "S3 cache bucket should match env var")
	assert.Equal(t, "env-cache/", cfg.Cache.S3Prefix, "S3 cache prefix should match env var")
	assert.Equal(t, true, cfg.Cache.S3Cleanup, "S3 cleanup should match env var")

	// Logging settings
	assert.Equal(t, true, cfg.LogToS3, "Log to S3 should match env var")
	assert.Equal(t, "env-log-bucket", cfg.LogBucket, "Log bucket should match env var")
	assert.Equal(t, "env-logs/", cfg.LogPrefix, "Log prefix should match env var")
}

// Helper function to convert string to pointer
func strPtr(s string) *string {
	return &s
}

// Helper function to convert time.Duration to pointer
func durationPtr(d time.Duration) *time.Duration {
	return &d
}

// singleIssuer builds a one-entry Issuers slice for tests that only care
// about a single trusted issuer, mirroring the pre-v2 single-issuer shape
// (which always did native GitHub claim unmarshal, i.e. provider: github —
// no claim_mappings.subject needed).
func singleIssuer(issuer string, audiences ...string) []IssuerConfig {
	return []IssuerConfig{{Issuer: issuer, Provider: "github", Audiences: audiences}}
}

func TestValidate_TagAuthDefaultOrg(t *testing.T) {
	base := func(org string) *Config {
		return &Config{
			Issuers:         singleIssuer("https://token.actions.githubusercontent.com", "sts.amazonaws.com"),
			RoleSessionName: "aow",
			TagAuth:         &TagAuth{Enabled: true, TagPrefix: "aow/", DefaultOrg: org},
		}
	}
	require.NoError(t, base("acme").Validate())
	require.NoError(t, base("").Validate())
	require.Error(t, base("acme/api").Validate())
	require.Error(t, base("acme org").Validate())
	require.Error(t, base("acme\torg").Validate())
	require.Error(t, base("acme\norg").Validate())
	require.Error(t, base("acme\rorg").Validate())

	// default_org is validated even when tag-auth is disabled (ungated check).
	require.Error(t, (&Config{
		Issuers:         singleIssuer("https://token.actions.githubusercontent.com", "sts.amazonaws.com"),
		RoleSessionName: "aow",
		TagAuth:         &TagAuth{Enabled: false, DefaultOrg: "bad/org"},
	}).Validate())
}

func TestTagAuthDefaults(t *testing.T) {
	viper.Reset()
	once = sync.Once{}

	orig := os.Getenv("AOW_TAG_AUTH_ENABLED")
	origName := os.Getenv("CONFIG_NAME")
	defer func() {
		if orig == "" {
			_ = os.Unsetenv("AOW_TAG_AUTH_ENABLED")
		} else {
			_ = os.Setenv("AOW_TAG_AUTH_ENABLED", orig)
		}
		if origName == "" {
			_ = os.Unsetenv("CONFIG_NAME")
		} else {
			_ = os.Setenv("CONFIG_NAME", origName)
		}
	}()

	_ = os.Setenv("AOW_TAG_AUTH_ENABLED", "true")
	_ = os.Setenv("CONFIG_NAME", "nonexistent-config-file")

	c := &Config{}
	require.NoError(t, c.LoadConfig())
	require.NotNil(t, c.TagAuth)
	assert.True(t, c.TagAuth.Enabled)
	assert.Equal(t, "aow/", c.TagAuth.TagPrefix)
	require.NotNil(t, c.CrossAccount)
	assert.Equal(t, "aow-spoke", c.CrossAccount.SpokeRoleName)
}

func TestReapplyEnvOverrides_JWTValidation(t *testing.T) {
	// AOW_JWT_VALIDATION_ALB_EXPECTED_SIGNER must survive a MergeBytes hot-reload.
	// Without the fix, MergeBytes would silently drop env-var overrides for these
	// fields, potentially removing the cross-ALB signer guard.
	const signer = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/abc123"

	t.Setenv("AOW_JWT_VALIDATION_MODE", "alb")
	t.Setenv("AOW_JWT_VALIDATION_ALB_EXPECTED_SIGNER", signer)

	cfg := &Config{
		Issuers:         singleIssuer("https://token.actions.githubusercontent.com", "sts.amazonaws.com"),
		RoleSessionName: "test-session",
		JWTValidation: JWTValidation{
			Mode:              "alb",
			ALBExpectedSigner: signer,
		},
	}

	// Simulate a remote config reload that omits jwt_validation entirely
	// (the S3 document doesn't include it, so it would revert to zero values
	// without reapplyEnvOverrides).
	payload := []byte(`{"role_session_name":"test-session"}`)
	err := cfg.MergeBytes(payload, "json")
	require.NoError(t, err)

	assert.Equal(t, "alb", cfg.JWTValidation.Mode)
	assert.Equal(t, signer, cfg.JWTValidation.ALBExpectedSigner)
}

func TestJWTValidationConfig(t *testing.T) {
	tests := []struct {
		name       string
		env        map[string]string
		wantErr    bool
		wantMode   string
		wantSigner string
	}{
		{"default self", nil, false, "self", ""},
		{"apigw mode", map[string]string{"AOW_JWT_VALIDATION_MODE": "apigw"}, false, "apigw", ""},
		{"invalid mode", map[string]string{"AOW_JWT_VALIDATION_MODE": "bad"}, true, "", ""},
		{"alb missing signer", map[string]string{"AOW_JWT_VALIDATION_MODE": "alb"}, true, "", ""},
		{"alb with signer", map[string]string{
			"AOW_JWT_VALIDATION_MODE":                "alb",
			"AOW_JWT_VALIDATION_ALB_EXPECTED_SIGNER": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/x/y",
		}, false, "alb", "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/x/y"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset viper and singleton to ensure clean state for this test
			viper.Reset()
			once = sync.Once{}

			// Save and restore CONFIG_NAME to avoid config file lookups
			origConfigName := os.Getenv("CONFIG_NAME")
			defer func() {
				if origConfigName == "" {
					_ = os.Unsetenv("CONFIG_NAME")
				} else {
					_ = os.Setenv("CONFIG_NAME", origConfigName)
				}
			}()

			// Point to nonexistent config file to force defaults
			t.Setenv("CONFIG_NAME", "nonexistent-config-file")

			// Set required fields and JWT validation env vars. No config file and
			// no issuer overrides means the zero-config GitHub issuer is seeded.
			t.Setenv("AOW_ROLE_SESSION_NAME", "test-session")

			// Set test-specific JWT validation env vars
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			// Load config through viper so env vars flow through the binding path.
			// LoadConfig() calls Validate() internally, so validation errors occur here.
			cfg := &Config{}
			err := cfg.LoadConfig()

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantMode, cfg.JWTValidation.Mode)
			assert.Equal(t, tt.wantSigner, cfg.JWTValidation.ALBExpectedSigner)
		})
	}
}

// TestGoldenMultiIssuerConfigBoots pins the real boot path against the two
// findings that slipped through it: a multi-issuer config where a
// role_mappings entry has neither `issuer` nor `default_issuer` (the golden
// fixture supplies both, one per mapping) must validate, and the zero-config
// GitHub seed must not leak its required_claims/session_tags into issuers[0]
// via MergeBytes. testdata/golden_multi_issuer_config.yaml is the same shape
// deploy/opentofu/templates/config.yaml.tftpl renders; LoadConfig() then
// MergeBytes() is exactly what internal/config/provider.go does for the S3
// config source.
func TestGoldenMultiIssuerConfigBoots(t *testing.T) {
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
	// LoadConfig seeded the zero-config GitHub issuer — the trap this test pins.
	require.Len(t, c.Issuers, 1)

	data, err := os.ReadFile("testdata/golden_multi_issuer_config.yaml")
	require.NoError(t, err)
	require.NoError(t, c.MergeBytes(data, "yaml"))

	// Exactly what the golden file declared, nothing leaked from the seed.
	want := []IssuerConfig{
		{
			Issuer:        "https://acme.example.com",
			Provider:      "generic",
			Audiences:     []string{"aws-oidc-warden"},
			ClaimMappings: map[string]string{"subject": "project_path"},
			SessionTags:   map[string]string{"project": "project_path"},
		},
		{
			Issuer:      "https://token.actions.githubusercontent.com",
			Provider:    "github",
			Audiences:   []string{"sts.amazonaws.com"},
			SessionTags: map[string]string{"repo": "repository"},
		},
	}
	assert.Equal(t, want, c.Issuers)

	// Both role_mappings resolved against a real issuer — one via its own
	// `issuer`, the other via `default_issuer` — proving neither was
	// rejected by the "issuer must be set explicitly" boot failure.
	matched, roles := c.AuthorizeRoles("https://acme.example.com", "acme-org/service-a", nil)
	assert.True(t, matched)
	assert.Equal(t, []string{"arn:aws:iam::111122223333:role/acme-deploy"}, roles)

	matched, roles = c.AuthorizeRoles("https://token.actions.githubusercontent.com", "my-org/my-repo", nil)
	assert.True(t, matched)
	assert.Equal(t, []string{"arn:aws:iam::111122223333:role/github-actions-example"}, roles)
}

func TestFindRoleSessionName_ComesFromAuthorizingMapping(t *testing.T) {
	const iss = "https://token.actions.githubusercontent.com"
	cfg := &Config{
		Issuers:         singleIssuer(iss, "sts.amazonaws.com"),
		RoleSessionName: "aws-oidc-warden",
		RoleMappings: []RoleMapping{
			// Declared first (lowest order) but does NOT grant the role below.
			{Subject: "acme/.+", Roles: []string{"arn:aws:iam::111122223333:role/other"}},
			{Subject: "acme/api", Roles: []string{"arn:aws:iam::111122223333:role/deploy"},
				RoleSessionName: "acme-api-deploy"},
		},
	}
	require.NoError(t, cfg.Validate())

	got := cfg.FindRoleSessionName(iss, "acme/api", "arn:aws:iam::111122223333:role/deploy", nil)
	assert.Equal(t, "acme-api-deploy", got,
		"name must come from the mapping that granted the role, not the first that matched the subject")

	// A role granted by a mapping with no override falls back to the global name.
	got = cfg.FindRoleSessionName(iss, "acme/api", "arn:aws:iam::111122223333:role/other", nil)
	assert.Empty(t, got, "no override on the authorizing mapping -> caller uses the global default")

	// A role no mapping grants (e.g. tag-auth) resolves to nothing.
	got = cfg.FindRoleSessionName(iss, "acme/api", "arn:aws:iam::111122223333:role/unknown", nil)
	assert.Empty(t, got)
}

// TestFindRoleSessionName_RespectsConditions pins that a mapping whose
// conditions fail cannot supply the session name.
func TestFindRoleSessionName_RespectsConditions(t *testing.T) {
	const iss = "https://token.actions.githubusercontent.com"
	const role = "arn:aws:iam::111122223333:role/deploy"
	cfg := &Config{
		Issuers:         singleIssuer(iss, "sts.amazonaws.com"),
		RoleSessionName: "aws-oidc-warden",
		RoleMappings: []RoleMapping{
			{Subject: "acme/api", Roles: []string{role}, RoleSessionName: "prod-only",
				Conditions: &Condition{Claims: map[string]Patterns{"ref": {"refs/heads/main"}}}},
		},
	}
	require.NoError(t, cfg.Validate())

	assert.Equal(t, "prod-only",
		cfg.FindRoleSessionName(iss, "acme/api", role, map[string]any{"ref": "refs/heads/main"}))
	assert.Empty(t,
		cfg.FindRoleSessionName(iss, "acme/api", role, map[string]any{"ref": "refs/heads/dev"}),
		"conditions must gate the session name as they gate the grant")
}

// TestRoleSessionName_RejectedAtValidate pins that an unusable name fails at
// boot rather than being silently mangled into CloudTrail. This mirrors the
// session-tag rule in internal/aws/consumer.go:309 — illegal values are
// refused, never coerced.
func TestRoleSessionName_RejectedAtValidate(t *testing.T) {
	for _, tc := range []struct{ name, sessionName string }{
		{"slash is not permitted by STS", "acme/api"},
		{"space is not permitted", "acme api"},
		{"over 64 chars", strings.Repeat("a", 65)},
		{"sanitizes to empty", "///"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				Issuers:         singleIssuer("https://issuer.com", "aud"),
				RoleSessionName: "aws-oidc-warden",
				RoleMappings: []RoleMapping{{
					Subject: "acme/api", Roles: []string{"arn:aws:iam::111122223333:role/deploy"},
					RoleSessionName: tc.sessionName,
				}},
			}
			err := cfg.Validate()
			require.Error(t, err, "an unusable session name must fail closed at boot")
			assert.Contains(t, err.Error(), "role_session_name")
		})
	}
}

// TestRoleGroupDefaults_PropagateRoleSessionName pins that role_groups can set
// the name for every subject they expand to.
func TestRoleGroupDefaults_PropagateRoleSessionName(t *testing.T) {
	const iss = "https://token.actions.githubusercontent.com"
	const role = "arn:aws:iam::111122223333:role/deploy"
	cfg := &Config{
		Issuers:         singleIssuer(iss, "sts.amazonaws.com"),
		RoleSessionName: "aws-oidc-warden",
		RoleGroups: []RoleGroup{{
			Subjects: []string{"acme/api", "acme/web"},
			Defaults: RoleGroupDefaults{Roles: []string{role}, RoleSessionName: "acme-team"},
		}},
	}
	require.NoError(t, cfg.Validate())

	assert.Equal(t, "acme-team", cfg.FindRoleSessionName(iss, "acme/api", role, nil))
	assert.Equal(t, "acme-team", cfg.FindRoleSessionName(iss, "acme/web", role, nil))
}

// TestGlobalRoleSessionName_RejectedAtValidate pins that the top-level
// role_session_name is validated exactly like a per-mapping override. Without
// this, an operator-set global name that STS would refuse (or the runtime
// sanitizer would have to reshape) boots successfully and is silently mangled
// on every request instead of failing once at config load.
func TestGlobalRoleSessionName_RejectedAtValidate(t *testing.T) {
	cfg := &Config{
		Issuers:         singleIssuer("https://issuer.com", "aud"),
		RoleSessionName: "my/service",
	}
	err := cfg.Validate()
	require.Error(t, err, "an unusable global session name must fail closed at boot")
	assert.Contains(t, err.Error(), "role_session_name")
}

// gitlabLikeConfig builds a two-issuer config where neither issuer is GitHub,
// so every assertion below exercises the provider-neutral path rather than the
// `provider: github` native-unmarshal shortcut.
func gitlabLikeConfig() *Config {
	return &Config{
		RoleSessionName: "aow-session",
		Issuers: []IssuerConfig{
			{
				Issuer:        "https://gitlab.com",
				Provider:      "generic",
				Audiences:     []string{"aow"},
				ClaimMappings: map[string]string{"subject": "project_path"},
				SessionTags: map[string]string{
					"project":   "project_path",
					"namespace": "namespace_path",
				},
			},
			{
				Issuer:        "https://token.example.buildkite.com",
				Provider:      "generic",
				Audiences:     []string{"aow"},
				ClaimMappings: map[string]string{"subject": "pipeline_slug"},
				SessionTags:   map[string]string{"pipeline": "pipeline_slug"},
			},
		},
	}
}

// TestIssuerSessionTags_PerIssuerIsolation pins the contract the session-tag
// lookup relies on: the spec returned is the one declared by the issuer that
// actually verified the token, and an issuer the config does not know gets
// nothing. Without this, a token from issuer A could be tagged with issuer B's
// spec and reach STS carrying claims A never asserted.
func TestIssuerSessionTags_PerIssuerIsolation(t *testing.T) {
	cfg := gitlabLikeConfig()

	gitlab := cfg.IssuerSessionTags("https://gitlab.com")
	if got, want := gitlab["project"], "project_path"; got != want {
		t.Fatalf("gitlab project tag = %q, want %q", got, want)
	}
	if _, leaked := gitlab["pipeline"]; leaked {
		t.Fatalf("gitlab spec leaked the buildkite tag key: %v", gitlab)
	}

	buildkite := cfg.IssuerSessionTags("https://token.example.buildkite.com")
	if got, want := buildkite["pipeline"], "pipeline_slug"; got != want {
		t.Fatalf("buildkite pipeline tag = %q, want %q", got, want)
	}
	if len(buildkite) != 1 {
		t.Fatalf("buildkite spec = %v, want exactly one entry", buildkite)
	}
}

// TestIssuerSessionTags_UnknownIssuerGetsNoSpec covers the fail-closed branch:
// an issuer string that is not configured must return nil, never the first
// issuer's spec as a fallback.
func TestIssuerSessionTags_UnknownIssuerGetsNoSpec(t *testing.T) {
	cfg := gitlabLikeConfig()
	if got := cfg.IssuerSessionTags("https://token.actions.githubusercontent.com"); got != nil {
		t.Fatalf("unknown issuer returned a spec: %v", got)
	}
}

// TestIssuerSessionTags_MatchIsExact mirrors the validator's exact-match issuer
// policy. A trailing slash or a case change is a different issuer everywhere
// else in the pipeline, so it must be a different issuer here too.
func TestIssuerSessionTags_MatchIsExact(t *testing.T) {
	cfg := gitlabLikeConfig()
	for _, near := range []string{
		"https://gitlab.com/",
		"https://GitLab.com",
		" https://gitlab.com",
	} {
		if got := cfg.IssuerSessionTags(near); got != nil {
			t.Errorf("near-miss issuer %q returned a spec: %v", near, got)
		}
	}
}

// TestIssuerSessionTags_NoSpecDeclared covers an issuer that declares no
// session_tags at all: the lookup returns an empty spec, which BuildSessionTags
// treats as "attach nothing".
func TestIssuerSessionTags_NoSpecDeclared(t *testing.T) {
	cfg := &Config{
		RoleSessionName: "aow-session",
		Issuers: []IssuerConfig{{
			Issuer:        "https://oidc.circleci.com/org/abc",
			Provider:      "generic",
			Audiences:     []string{"aow"},
			ClaimMappings: map[string]string{"subject": "oidc.circleci.com/project-id"},
		}},
	}
	if got := cfg.IssuerSessionTags("https://oidc.circleci.com/org/abc"); len(got) != 0 {
		t.Fatalf("issuer with no session_tags returned %v, want empty", got)
	}
}

// TestValidate_GenericIssuerMustDeclareSubjectMapping proves the provider-neutral
// guardrail: a non-github issuer has no native struct to derive a canonical
// subject from, so booting without claim_mappings.subject must be rejected
// rather than silently authorizing on an empty subject.
func TestValidate_GenericIssuerMustDeclareSubjectMapping(t *testing.T) {
	cfg := &Config{
		RoleSessionName: "aow-session",
		Issuers: []IssuerConfig{{
			Issuer:    "https://gitlab.com",
			Provider:  "generic",
			Audiences: []string{"aow"},
		}},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate accepted a generic issuer with no claim_mappings.subject")
	}
	if !strings.Contains(err.Error(), "claim_mappings.subject") {
		t.Fatalf("error does not name the missing key: %v", err)
	}
}

// TestValidate_ProviderDefaultsToGeneric pins the default: omitting `provider`
// selects the provider-neutral adapter, not GitHub. It also proves the default
// is written back through the pointer, since the same loop then enforces the
// generic-only claim_mappings.subject rule against it.
func TestValidate_ProviderDefaultsToGeneric(t *testing.T) {
	cfg := &Config{
		RoleSessionName: "aow-session",
		Issuers: []IssuerConfig{{
			Issuer:        "https://gitlab.com",
			Audiences:     []string{"aow"},
			ClaimMappings: map[string]string{"subject": "project_path"},
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := cfg.Issuers[0].Provider; got != "generic" {
		t.Fatalf("provider defaulted to %q, want %q", got, "generic")
	}
}

// TestValidate_RejectsUnknownProvider keeps the adapter registry closed: an
// unregistered provider name must fail at boot, not at the first token, where
// normalizeClaims would reject every request instead.
func TestValidate_RejectsUnknownProvider(t *testing.T) {
	for _, provider := range []string{"gitlab", "GitHub", "Generic", "GITHUB"} {
		cfg := &Config{
			RoleSessionName: "aow-session",
			Issuers: []IssuerConfig{{
				Issuer:        "https://gitlab.com",
				Provider:      provider,
				Audiences:     []string{"aow"},
				ClaimMappings: map[string]string{"subject": "project_path"},
			}},
		}
		if err := cfg.Validate(); err == nil {
			t.Errorf("Validate accepted provider %q", provider)
		}
	}
}
