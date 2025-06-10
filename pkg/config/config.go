package config

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/boogy/aws-oidc-warden/pkg/utils"
	"github.com/spf13/viper"
)

var (
	once              sync.Once
	instance          *Config
	issuer            = "https://token.actions.githubusercontent.com" // Default issuer for GitHub Actions
	audience          = "sts.amazonaws.com"                           // Default audience for AWS STS
	role_session_name = "aws-oidc-warden"                             // Default role session name
	cacheType         = "memory"                                      // Default cache type
	cacheTTL          = "1h"                                          // Default cache TTL
	cacheMaxLocalSize = 10                                            // Default max local size for memory cache
)

// Constraint defines conditions that must be met for a role to be assumed
type Constraint struct {
	Branch       string   `mapstructure:"branch"`        // Branch name (e.g., "main", "dev")
	Ref          string   `mapstructure:"ref"`           // Git reference (e.g., "refs/heads/main", "refs/tags/v.*")
	RefType      string   `mapstructure:"ref_type"`      // Reference type (e.g., "branch", "tag")
	EventName    string   `mapstructure:"event_name"`    // GitHub event name (e.g., "push", "pull_request")
	WorkflowRef  string   `mapstructure:"workflow_ref"`  // Workflow reference (e.g., "owner/repo/.github/workflows/workflow.yml")
	Environment  string   `mapstructure:"environment"`   // GitHub environment (e.g., "production")
	ActorMatches []string `mapstructure:"actor_matches"` // GitHub actors allowed to assume the role

	// Cached compiled patterns (not serialized)
	branchPattern   *regexp.Regexp   `mapstructure:"-"`
	refPattern      *regexp.Regexp   `mapstructure:"-"`
	workflowPattern *regexp.Regexp   `mapstructure:"-"`
	actorPatterns   []*regexp.Regexp `mapstructure:"-"`
}

type RepoRoleMapping struct {
	Repo              string      `mapstructure:"repo"`                // Repository name (e.g., "owner/repo")
	SessionPolicy     string      `mapstructure:"session_policy"`      // Inline session policy (JSON string)
	SessionPolicyFile string      `mapstructure:"session_policy_file"` // S3 session policy file
	Roles             []string    `mapstructure:"roles"`               // List of IAM roles that can be assume
	Constraints       *Constraint `mapstructure:"constraints"`         // Constraints for role assumption

	// Cached compiled pattern (not serialized)
	compiledPattern *regexp.Regexp `mapstructure:"-"`
}

type Cache struct {
	Type          string        `mapstructure:"type"`           // Cache type (e.g., "memory", "dynamodb")
	TTL           time.Duration `mapstructure:"ttl"`            // Cache TTL duration (ex: "5m", "1h", "2h30", "24h", "1d", "1w")
	MaxLocalSize  int           `mapstructure:"max_local_size"` // Maximum size of local cache (if using memory cache)
	DynamoDBTable string        `mapstructure:"dynamodb_table"` // DynamoDB table name (if using DynamoDB cache)
	S3Bucket      string        `mapstructure:"s3_bucket"`      // S3 bucket name (if using S3 cache)
	S3Prefix      string        `mapstructure:"s3_prefix"`      // S3 prefix (if using S3 cache)
	S3Cleanup     bool          `mapstructure:"s3_cleanup"`     // S3 cleanup flag (if using S3 cache). Will delete old objects in the bucket.
}

type Config struct {
	Issuer                string            `mapstructure:"issuer"`                // Issuer is the expected issuer of the JWT token
	Audience              string            `mapstructure:"audience"`              // Audience is the expected audience of the JWT token (deprecated - use Audiences)
	Audiences             []string          `mapstructure:"audiences"`             // Audiences is the list of expected audiences of the JWT token
	S3ConfigBucket        string            `mapstructure:"s3_config_bucket"`      // S3ConfigBucket is the S3 bucket where the configuration file is stored
	S3ConfigPath          string            `mapstructure:"s3_config_path"`        // S3ConfigPath is the path to the configuration file in the S3 bucket
	S3SessionPolicyBucket string            `mapstructure:"session_policy_bucket"` // S3SessionPolicyBucket is the S3 bucket where the session policy file is stored
	RoleSessionName       string            `mapstructure:"role_session_name"`     // RoleSessionName is the name of the role session
	RepoRoleMappings      []RepoRoleMapping `mapstructure:"repo_role_mappings"`    // RepoRoleMappings is a list of repository to role mappings

	// Logging configuration directly to S3 (duplicates cloudwatch logs)
	LogToS3   bool   `mapstructure:"log_to_s3"`  // LogToS3 is a flag to enable logging to S3
	LogBucket string `mapstructure:"log_bucket"` // LogBucket is the S3 bucket to log to
	LogPrefix string `mapstructure:"log_prefix"` // LogKey is the S3 key to log to
	Cache     *Cache `mapstructure:"cache"`      // CacheConfig is the cache configuration

	// Performance optimization - not serialized
	estimatedRolesPerRepo int `mapstructure:"-"` // Calculated during Validate for efficient memory allocation
}

// NewConfig initializes and returns the configuration. It ensures that the config is loaded only once.
func NewConfig() (*Config, error) {
	var err error
	once.Do(func() {
		instance = &Config{}
		err = instance.LoadConfig()
	})
	return instance, err
}

// LoadConfig attempts to load configuration from a file or uses default values if not found.
func (c *Config) LoadConfig() error {
	// Set default config file name and path (yaml, json or toml or ...)
	configName := utils.GetEnv("CONFIG_NAME", "config") // Configuration file name without extension
	configPath := utils.GetEnv("CONFIG_PATH", ".")      // Configuration file path, default to current directory

	// Set environment variable handling first
	viper.SetEnvPrefix("aow") // Set the environment variable prefix ex: "AOW_"
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()

	viper.AddConfigPath("/etc/aws-oidc-warden/")
	viper.AddConfigPath(configPath)
	viper.SetConfigName(configName)

	// Set default values
	viper.SetDefault("issuer", issuer)
	viper.SetDefault("audience", audience)
	viper.SetDefault("audiences", []string{audience}) // Default to single audience for backwards compatibility
	viper.SetDefault("role_session_name", role_session_name)
	viper.SetDefault("cache.type", cacheType)
	viper.SetDefault("cache.ttl", cacheTTL)
	viper.SetDefault("cache.max_local_size", cacheMaxLocalSize)

	// Explicitly bind all config keys to environment variables
	// Core settings
	_ = viper.BindEnv("issuer")                // AOW_ISSUER
	_ = viper.BindEnv("audience")              // AOW_AUDIENCE
	_ = viper.BindEnv("audiences")             // AOW_AUDIENCES
	_ = viper.BindEnv("role_session_name")     // AOW_ROLE_SESSION_NAME
	_ = viper.BindEnv("s3_config_bucket")      // AOW_S3_CONFIG_BUCKET
	_ = viper.BindEnv("s3_config_path")        // AOW_S3_CONFIG_PATH
	_ = viper.BindEnv("session_policy_bucket") // AOW_SESSION_POLICY_BUCKET
	_ = viper.BindEnv("log_to_s3")             // AOW_LOG_TO_S3
	_ = viper.BindEnv("log_bucket")            // AOW_LOG_BUCKET
	_ = viper.BindEnv("log_prefix")            // AOW_LOG_PREFIX

	// Cache settings
	_ = viper.BindEnv("cache.type")             // AOW_CACHE_TYPE
	_ = viper.BindEnv("cache.ttl")              // AOW_CACHE_TTL
	_ = viper.BindEnv("cache.max_local_size")   // AOW_CACHE_MAX_LOCAL_SIZE
	_ = viper.BindEnv("cache.dynamodb_table")   // AOW_CACHE_DYNAMODB_TABLE
	_ = viper.BindEnv("cache.s3_bucket")        // AOW_CACHE_S3_BUCKET
	_ = viper.BindEnv("cache.s3_prefix")        // AOW_CACHE_S3_PREFIX
	_ = viper.BindEnv("cache.s3_cleanup")       // AOW_CACHE_S3_CLEANUP
	_ = viper.BindEnv("cache.s3_config_bucket") // AOW_CACHE_S3_CONFIG_BUCKET
	_ = viper.BindEnv("cache.s3_config_path")   // AOW_CACHE_S3_CONFIG_PATH

	// Logging settings
	_ = viper.BindEnv("log_to_s3")
	_ = viper.BindEnv("log_bucket")
	_ = viper.BindEnv("log_prefix")

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; rely on defaults
		} else {
			return fmt.Errorf("problem reading config file: %w", err)
		}
	}

	if err := viper.Unmarshal(c); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return c.Validate()
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.Issuer == "" {
		return errors.New("issuer is required")
	}

	// Handle backward compatibility between audience and audiences
	if len(c.Audiences) == 0 && c.Audience == "" {
		return errors.New("either audience or audiences is required")
	}

	// If audiences is empty but audience is set, use audience for backward compatibility
	if len(c.Audiences) == 0 && c.Audience != "" {
		c.Audiences = []string{c.Audience}
	}

	// If audience is empty but audiences is set, set audience to first audience for backward compatibility
	if c.Audience == "" && len(c.Audiences) > 0 {
		c.Audience = c.Audiences[0]
	}

	if c.RoleSessionName == "" {
		return errors.New("role session name is required")
	}

	for i := range c.RepoRoleMappings {
		mapping := &c.RepoRoleMappings[i]
		if mapping.Repo == "" || len(mapping.Roles) == 0 {
			return errors.New("repo and roles are required for each mapping")
		}

		// Precompile the regex pattern for this mapping
		var err error
		mapping.compiledPattern, err = regexp.Compile("^(?:" + mapping.Repo + ")$")
		if err != nil {
			return fmt.Errorf("invalid repository pattern '%s': %w", mapping.Repo, err)
		}

		// Precompile constraint patterns if they exist
		if mapping.Constraints != nil {
			if mapping.Constraints.Branch != "" {
				mapping.Constraints.branchPattern, err = regexp.Compile("^" + mapping.Constraints.Branch + "$")
				if err != nil {
					return fmt.Errorf("invalid branch pattern '%s': %w", mapping.Constraints.Branch, err)
				}
			}

			if mapping.Constraints.Ref != "" {
				mapping.Constraints.refPattern, err = regexp.Compile("^" + mapping.Constraints.Ref + "$")
				if err != nil {
					return fmt.Errorf("invalid ref pattern '%s': %w", mapping.Constraints.Ref, err)
				}
			}

			if mapping.Constraints.WorkflowRef != "" {
				mapping.Constraints.workflowPattern, err = regexp.Compile(mapping.Constraints.WorkflowRef)
				if err != nil {
					return fmt.Errorf("invalid workflow pattern '%s': %w", mapping.Constraints.WorkflowRef, err)
				}
			}

			// Precompile actor patterns
			if len(mapping.Constraints.ActorMatches) > 0 {
				mapping.Constraints.actorPatterns = make([]*regexp.Regexp, len(mapping.Constraints.ActorMatches))
				for i, pattern := range mapping.Constraints.ActorMatches {
					mapping.Constraints.actorPatterns[i], err = regexp.Compile("^" + pattern + "$")
					if err != nil {
						return fmt.Errorf("invalid actor match pattern '%s': %w", pattern, err)
					}
				}
			}
		}
	}

	// Calculate the average number of roles per mapping for more efficient memory allocation
	totalRoles := 0
	for _, mapping := range c.RepoRoleMappings {
		totalRoles += len(mapping.Roles)
	}

	if len(c.RepoRoleMappings) > 0 {
		c.estimatedRolesPerRepo = (totalRoles / len(c.RepoRoleMappings)) + 1 // Add 1 as safety margin
	} else {
		c.estimatedRolesPerRepo = 4 // Default if no mappings
	}

	return nil
}

// FindSessionPolicyForRepo finds the session policy for a given repository.
// Returns session policy or session policy file if defined in the config
func (c *Config) FindSessionPolicyForRepo(repository string) (*string, *string) {
	for _, mapping := range c.RepoRoleMappings {
		// Skip if the pattern wasn't compiled properly
		if mapping.compiledPattern == nil {
			continue
		}

		if mapping.compiledPattern.MatchString(repository) {
			if mapping.SessionPolicyFile != "" {
				return nil, &mapping.SessionPolicyFile
			}

			if mapping.SessionPolicy != "" {
				return &mapping.SessionPolicy, nil
			}
		}
	}
	return nil, nil
}

// MatchRolesToRepo matches roles to a repository.
func (c *Config) MatchRolesToRepo(repo string) (bool, []string) {
	// Pre-allocate capacity based on estimated roles per repo
	capacity := c.estimatedRolesPerRepo
	if capacity < 4 {
		capacity = 4 // Minimum capacity as fallback
	}
	roles := make([]string, 0, capacity)
	matched := false

	for _, mapping := range c.RepoRoleMappings {
		// Skip if the pattern wasn't compiled properly
		if mapping.compiledPattern == nil {
			continue
		}

		if mapping.compiledPattern.MatchString(repo) {
			matched = true
			roles = append(roles, mapping.Roles...)
		}
	}
	return matched, roles
}

// MatchRolesToRepoWithConstraints evaluates if a repository with specific token claims matches any role mappings.
// It returns a boolean indicating if any roles were matched and a slice of matched roles.
func (c *Config) MatchRolesToRepoWithConstraints(repo string, claims map[string]any) (bool, []string) {
	// Pre-allocate capacity based on estimated roles per repo
	capacity := c.estimatedRolesPerRepo
	if capacity < 4 {
		capacity = 4 // Minimum capacity as fallback
	}
	roles := make([]string, 0, capacity)
	matched := false

	for _, mapping := range c.RepoRoleMappings {
		// Skip if the pattern wasn't compiled properly
		if mapping.compiledPattern == nil {
			continue
		}

		// First check if the repo matches the basic pattern
		if !mapping.compiledPattern.MatchString(repo) {
			continue
		}

		// If there are no constraints, add the roles and continue
		if mapping.Constraints == nil {
			matched = true
			roles = append(roles, mapping.Roles...)
			continue
		}

		// Check if the claims satisfy all the specified constraints
		if !satisfiesConstraints(mapping.Constraints, claims) {
			continue
		}

		matched = true
		roles = append(roles, mapping.Roles...)
	}

	return matched, roles
}

// satisfiesConstraints checks if the provided claims satisfy all the specified constraints
func satisfiesConstraints(constraints *Constraint, claims map[string]any) bool {
	// Check branch constraint (using the 'ref' claim)
	if constraints.Branch != "" {
		ref, ok := claims["ref"].(string)
		if !ok {
			return false
		}

		// Use the pre-compiled branch pattern
		if !constraints.branchPattern.MatchString(ref) {
			return false
		}
	}

	// Check direct ref constraint
	if constraints.Ref != "" {
		ref, ok := claims["ref"].(string)
		if !ok {
			return false
		}

		// Use the pre-compiled ref pattern
		if !constraints.refPattern.MatchString(ref) {
			return false
		}
	}

	// Check ref type constraint
	if constraints.RefType != "" {
		refType, ok := claims["ref_type"].(string)
		if !ok || refType != constraints.RefType {
			return false
		}
	}

	// Check event name constraint
	if constraints.EventName != "" {
		eventName, ok := claims["event_name"].(string)
		if !ok || eventName != constraints.EventName {
			return false
		}
	}

	// Check workflow filename constraint
	if constraints.WorkflowRef != "" {
		workflow, ok := claims["workflow_ref"].(string)
		if !ok {
			return false
		}

		// Use the pre-compiled workflow pattern
		if !constraints.workflowPattern.MatchString(workflow) {
			return false
		}
	}

	// Check environment constraint
	if constraints.Environment != "" {
		environment, ok := claims["runner_environment"].(string)
		if !ok || environment != constraints.Environment {
			return false
		}
	}

	// Check actor matches
	if len(constraints.ActorMatches) > 0 {
		actor, ok := claims["actor"].(string)
		if !ok {
			return false
		}

		matched := false
		for _, pattern := range constraints.actorPatterns {
			if pattern.MatchString(actor) {
				matched = true
				break
			}
		}

		if !matched {
			return false
		}
	}

	// All constraints passed
	return true
}
