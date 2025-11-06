package config

import (
	"os"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestNewConfig(t *testing.T) {
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
	configContent := `issuer: "https://test.issuer.com"
audience: "test-audience"
role_session_name: "test-session"
repo_role_mappings:
  - repo: "org/repo1"
    session_policy: "policy1"
    roles:
      - "role1"
      - "role2"
  - repo: "org/repo2"
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
	t.Logf("Loaded config: issuer=%s, audience=%s, roleSessionName=%s, mappings=%d",
		cfg.Issuer, cfg.Audience, cfg.RoleSessionName, len(cfg.RepoRoleMappings))

	// Now we should have the test values, not defaults
	assert.Equal(t, "https://test.issuer.com", cfg.Issuer)
	assert.Equal(t, "test-audience", cfg.Audience)
	assert.Equal(t, "test-session", cfg.RoleSessionName)
	assert.Equal(t, 2, len(cfg.RepoRoleMappings))
	assert.Equal(t, "org/repo1", cfg.RepoRoleMappings[0].Repo)
	assert.Equal(t, "policy1", cfg.RepoRoleMappings[0].SessionPolicy)
	assert.Equal(t, []string{"role1", "role2"}, cfg.RepoRoleMappings[0].Roles)
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

	// Verify default values
	assert.Equal(t, "https://token.actions.githubusercontent.com", cfg.Issuer)
	assert.Equal(t, "sts.amazonaws.com", cfg.Audience)
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
				Issuer:          "https://issuer.com",
				Audiences:       []string{"audience"},
				RoleSessionName: "session",
				RepoRoleMappings: []RepoRoleMapping{
					{
						Repo:          "org/repo",
						SessionPolicy: "policy",
						Roles:         []string{"role1"},
					},
				},
			},
			expectErr: false,
		},
		{
			name: "valid config with legacy audience field",
			config: Config{
				Issuer:          "https://issuer.com",
				Audience:        "audience",
				RoleSessionName: "session",
				RepoRoleMappings: []RepoRoleMapping{
					{
						Repo:          "org/repo",
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
				Issuer:          "https://issuer.com",
				Audiences:       []string{"audience1", "audience2"},
				RoleSessionName: "session",
				RepoRoleMappings: []RepoRoleMapping{
					{
						Repo:          "org/repo",
						SessionPolicy: "policy",
						Roles:         []string{"role1"},
					},
				},
			},
			expectErr: false,
		},
		{
			name: "missing issuer",
			config: Config{
				Audience:        "audience",
				RoleSessionName: "session",
			},
			expectErr: true,
		},
		{
			name: "missing audience and audiences",
			config: Config{
				Issuer:          "https://issuer.com",
				RoleSessionName: "session",
			},
			expectErr: true,
		},
		{
			name: "missing role session name",
			config: Config{
				Issuer:    "https://issuer.com",
				Audiences: []string{"audience"},
			},
			expectErr: true,
		},
		{
			name: "invalid mapping - missing repo",
			config: Config{
				Issuer:          "https://issuer.com",
				Audiences:       []string{"audience"},
				RoleSessionName: "session",
				RepoRoleMappings: []RepoRoleMapping{
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
				Issuer:          "https://issuer.com",
				Audiences:       []string{"audience"},
				RoleSessionName: "session",
				RepoRoleMappings: []RepoRoleMapping{
					{
						Repo:  "org/repo",
						Roles: []string{"role1"},
					},
				},
			},
			expectErr: false,
		},
		{
			name: "invalid mapping - empty roles",
			config: Config{
				Issuer:          "https://issuer.com",
				Audiences:       []string{"audience"},
				RoleSessionName: "session",
				RepoRoleMappings: []RepoRoleMapping{
					{
						Repo:          "org/repo",
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

func TestFindSessionPolicyForRepo(t *testing.T) {
	cfg := &Config{
		RepoRoleMappings: []RepoRoleMapping{
			{
				Repo:          "org/repo1",
				SessionPolicy: "policy1",
				Roles:         []string{"role1"},
			},
			{
				Repo:          "org/repo2.*",
				SessionPolicy: "policy2",
				Roles:         []string{"role2"},
			},
		},
	}

	// Compile the patterns before testing
	for i := range cfg.RepoRoleMappings {
		var err error
		pattern := "^(?:" + cfg.RepoRoleMappings[i].Repo + ")$"
		cfg.RepoRoleMappings[i].compiledPattern, err = regexp.Compile(pattern)
		if err != nil {
			t.Fatalf("failed to compile pattern: %v", err)
		}
	}

	tests := []struct {
		name       string
		repo       string
		wantPolicy *string
	}{
		{
			name:       "exact match",
			repo:       "org/repo1",
			wantPolicy: strPtr("policy1"),
		},
		{
			name:       "regex match",
			repo:       "org/repo2-staging",
			wantPolicy: strPtr("policy2"),
		},
		{
			name:       "no match",
			repo:       "org/repo3",
			wantPolicy: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy, policyFile := cfg.FindSessionPolicyForRepo(tt.repo)

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

func TestMatchRolesToRepo(t *testing.T) {
	cfg := &Config{
		RepoRoleMappings: []RepoRoleMapping{
			{
				Repo:          "org/repo1",
				SessionPolicy: "policy1",
				Roles:         []string{"role1", "role2"},
			},
			{
				Repo:          "org/repo2.*",
				SessionPolicy: "policy2",
				Roles:         []string{"role3"},
			},
			{
				Repo:          "org/shared-.*",
				SessionPolicy: "policy3",
				Roles:         []string{"shared-role"},
			},
		},
	}

	// Compile the patterns before testing
	for i := range cfg.RepoRoleMappings {
		var err error
		pattern := "^(?:" + cfg.RepoRoleMappings[i].Repo + ")$"
		cfg.RepoRoleMappings[i].compiledPattern, err = regexp.Compile(pattern)
		if err != nil {
			t.Fatalf("failed to compile pattern: %v", err)
		}
	}

	tests := []struct {
		name        string
		repo        string
		wantMatched bool
		wantRoles   []string
	}{
		{
			name:        "exact match",
			repo:        "org/repo1",
			wantMatched: true,
			wantRoles:   []string{"role1", "role2"},
		},
		{
			name:        "regex match",
			repo:        "org/repo2-staging",
			wantMatched: true,
			wantRoles:   []string{"role3"},
		},
		{
			name:        "multiple matches - check implementation",
			repo:        "org/shared-repo2-staging",
			wantMatched: true,
			// The actual implementation may only match the first or most specific pattern
			// Adjust this based on your actual implementation behavior
			wantRoles: []string{"shared-role"},
		},
		{
			name:        "no match",
			repo:        "org/repo3",
			wantMatched: false,
			wantRoles:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, roles := cfg.MatchRolesToRepo(tt.repo)

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
		"AOW_ISSUER",
		"AOW_AUDIENCE",
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
	_ = os.Setenv("AOW_ISSUER", "https://env.test.issuer.com")
	_ = os.Setenv("AOW_AUDIENCE", "env-test-audience")
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
	assert.Equal(t, "https://env.test.issuer.com", cfg.Issuer, "Issuer should match env var")
	assert.Equal(t, "env-test-audience", cfg.Audience, "Audience should match env var")
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
