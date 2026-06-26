package config

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strconv"
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
	Branch       string   `mapstructure:"branch"        json:"branch,omitempty"`        // Branch name (e.g., "main", "dev")
	Ref          string   `mapstructure:"ref"           json:"ref,omitempty"`           // Git reference (e.g., "refs/heads/main", "refs/tags/v.*")
	RefType      string   `mapstructure:"ref_type"      json:"ref_type,omitempty"`      // Reference type (e.g., "branch", "tag")
	EventName    string   `mapstructure:"event_name"    json:"event_name,omitempty"`    // GitHub event name (e.g., "push", "pull_request")
	WorkflowRef  string   `mapstructure:"workflow_ref"  json:"workflow_ref,omitempty"`  // Workflow reference (e.g., "owner/repo/.github/workflows/workflow.yml")
	Environment  string   `mapstructure:"environment"   json:"environment,omitempty"`   // GitHub environment (e.g., "production")
	ActorMatches []string `mapstructure:"actor_matches" json:"actor_matches,omitempty"` // GitHub actors allowed to assume the role

	// Cached compiled patterns (not serialized)
	branchPattern   *regexp.Regexp   `mapstructure:"-" json:"-"`
	refPattern      *regexp.Regexp   `mapstructure:"-" json:"-"`
	workflowPattern *regexp.Regexp   `mapstructure:"-" json:"-"`
	actorPatterns   []*regexp.Regexp `mapstructure:"-" json:"-"`
}

type RepoRoleMapping struct {
	Repo              string      `mapstructure:"repo"                json:"repo"`                          // Repository name (e.g., "owner/repo")
	SessionPolicy     string      `mapstructure:"session_policy"      json:"session_policy,omitempty"`      // Inline session policy (JSON string)
	SessionPolicyFile string      `mapstructure:"session_policy_file" json:"session_policy_file,omitempty"` // S3 session policy file
	Roles             []string    `mapstructure:"roles"               json:"roles"`                         // List of IAM roles that can be assume
	Constraints       *Constraint `mapstructure:"constraints"         json:"constraints,omitempty"`         // Constraints for role assumption

	// Cached compiled pattern (not serialized)
	compiledPattern *regexp.Regexp `mapstructure:"-" json:"-"`
}

type Cache struct {
	Type          string        `mapstructure:"type"           json:"type"`                     // Cache type (e.g., "memory", "dynamodb")
	TTL           time.Duration `mapstructure:"ttl"            json:"ttl"`                      // Cache TTL duration (ex: "5m", "1h", "2h30", "24h", "1d", "1w")
	MaxLocalSize  int           `mapstructure:"max_local_size" json:"max_local_size,omitempty"` // Maximum size of local cache (if using memory cache)
	DynamoDBTable string        `mapstructure:"dynamodb_table" json:"dynamodb_table,omitempty"` // DynamoDB table name (if using DynamoDB cache)
	S3Bucket      string        `mapstructure:"s3_bucket"      json:"s3_bucket,omitempty"`      // S3 bucket name (if using S3 cache)
	S3Prefix      string        `mapstructure:"s3_prefix"      json:"s3_prefix,omitempty"`      // S3 prefix (if using S3 cache)
	S3Cleanup     bool          `mapstructure:"s3_cleanup"     json:"s3_cleanup,omitempty"`     // S3 cleanup flag (if using S3 cache). Will delete old objects in the bucket.
}

// TagAuth enables tag-based role authorization: a role may be assumed when its
// IAM tags authorize the request's OIDC claims, without an explicit
// repo_role_mappings entry. Also enables cross-account role assumption via a
// per-account spoke role (account ID is parsed from the requested role ARN).
type TagAuth struct {
	Enabled              bool          `mapstructure:"enabled"                json:"enabled,omitempty"`
	TagPrefix            string        `mapstructure:"tag_prefix"             json:"tag_prefix,omitempty"`              // default "aow/"
	SpokeRoleName        string        `mapstructure:"spoke_role_name"        json:"spoke_role_name,omitempty"`        // default "aow-spoke"
	ExternalID           string        `mapstructure:"external_id"            json:"external_id,omitempty"`            // optional hub->spoke external ID
	SpokeSessionDuration time.Duration `mapstructure:"spoke_session_duration" json:"spoke_session_duration,omitempty"` // hub->spoke session length, default 15m
}

type Config struct {
	Issuer                string            `mapstructure:"issuer"                json:"issuer"`                          // Issuer is the expected issuer of the JWT token
	Audience              string            `mapstructure:"audience"              json:"audience,omitempty"`              // Audience is the expected audience of the JWT token (deprecated - use Audiences)
	Audiences             []string          `mapstructure:"audiences"             json:"audiences,omitempty"`             // Audiences is the list of expected audiences of the JWT token
	S3ConfigBucket        string            `mapstructure:"s3_config_bucket"      json:"s3_config_bucket,omitempty"`      // S3ConfigBucket is the S3 bucket where the configuration file is stored
	S3ConfigPath          string            `mapstructure:"s3_config_path"        json:"s3_config_path,omitempty"`        // S3ConfigPath is the path to the configuration file in the S3 bucket
	S3SessionPolicyBucket string            `mapstructure:"session_policy_bucket" json:"session_policy_bucket,omitempty"` // S3SessionPolicyBucket is the S3 bucket where the session policy file is stored
	RoleSessionName       string            `mapstructure:"role_session_name"     json:"role_session_name"`               // RoleSessionName is the name of the role session
	RepoRoleMappings      []RepoRoleMapping `mapstructure:"repo_role_mappings"    json:"repo_role_mappings,omitempty"`    // RepoRoleMappings is a list of repository to role mappings

	// ConfigReloadInterval, when > 0, enables periodic hot-reload of the S3
	// configuration (S3ConfigBucket/S3ConfigPath) without redeploying. The
	// reload is lazy/per-request: the config is refetched at most once per
	// interval. 0 (default) disables reloading. Requires an S3 config source.
	ConfigReloadInterval time.Duration `mapstructure:"config_reload_interval" json:"config_reload_interval,omitempty"`

	// Logging configuration directly to S3 (duplicates cloudwatch logs)
	LogToS3   bool   `mapstructure:"log_to_s3"  json:"log_to_s3,omitempty"`  // LogToS3 is a flag to enable logging to S3
	LogBucket string `mapstructure:"log_bucket" json:"log_bucket,omitempty"` // LogBucket is the S3 bucket to log to
	LogPrefix string `mapstructure:"log_prefix" json:"log_prefix,omitempty"` // LogKey is the S3 key to log to
	Cache     *Cache `mapstructure:"cache"      json:"cache,omitempty"`      // CacheConfig is the cache configuration

	// TagAuth enables tag-based authorization and cross-account role assumption.
	TagAuth *TagAuth `mapstructure:"tag_auth" json:"tag_auth,omitempty"`

	// Performance optimization - not serialized
	estimatedRolesPerRepo int `mapstructure:"-" json:"-"` // Calculated during Validate for efficient memory allocation
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
	viper.SetDefault("tag_auth.enabled", false)
	viper.SetDefault("tag_auth.tag_prefix", "aow/")
	viper.SetDefault("tag_auth.spoke_role_name", "aow-spoke")
	viper.SetDefault("tag_auth.spoke_session_duration", "15m")

	// Explicitly bind all config keys to environment variables
	// Core settings
	_ = viper.BindEnv("issuer")                 // AOW_ISSUER
	_ = viper.BindEnv("audience")               // AOW_AUDIENCE
	_ = viper.BindEnv("audiences")              // AOW_AUDIENCES
	_ = viper.BindEnv("role_session_name")      // AOW_ROLE_SESSION_NAME
	_ = viper.BindEnv("s3_config_bucket")       // AOW_S3_CONFIG_BUCKET
	_ = viper.BindEnv("s3_config_path")         // AOW_S3_CONFIG_PATH
	_ = viper.BindEnv("config_reload_interval") // AOW_CONFIG_RELOAD_INTERVAL
	_ = viper.BindEnv("session_policy_bucket")  // AOW_SESSION_POLICY_BUCKET
	_ = viper.BindEnv("log_to_s3")              // AOW_LOG_TO_S3
	_ = viper.BindEnv("log_bucket")             // AOW_LOG_BUCKET
	_ = viper.BindEnv("log_prefix")             // AOW_LOG_PREFIX

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

	// Tag-based authorization settings
	_ = viper.BindEnv("tag_auth.enabled")                // AOW_TAG_AUTH_ENABLED
	_ = viper.BindEnv("tag_auth.tag_prefix")             // AOW_TAG_AUTH_TAG_PREFIX
	_ = viper.BindEnv("tag_auth.spoke_role_name")        // AOW_TAG_AUTH_SPOKE_ROLE_NAME
	_ = viper.BindEnv("tag_auth.external_id")            // AOW_TAG_AUTH_EXTERNAL_ID
	_ = viper.BindEnv("tag_auth.spoke_session_duration") // AOW_TAG_AUTH_SPOKE_SESSION_DURATION

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

// MergeBytes overlays serialized configuration onto c using the same snake_case
// schema as the config file (see example-config.yaml), then re-validates. Only
// keys present in data are overwritten. format is a viper config type
// ("json", "yaml", "toml"); empty defaults to "json".
//
// Use this for remote configuration (e.g. an S3 object) instead of
// encoding/json, which matches Go field names rather than the documented
// snake_case keys.
func (c *Config) MergeBytes(data []byte, format string) error {
	if format == "" {
		format = "json"
	}

	v := viper.New()
	v.SetConfigType(format)
	if err := v.ReadConfig(bytes.NewReader(data)); err != nil {
		return fmt.Errorf("failed to parse %s configuration: %w", format, err)
	}

	if err := v.Unmarshal(c); err != nil {
		return fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	reapplyEnvOverrides(c)

	return c.Validate()
}

// reapplyEnvOverrides re-applies AOW_* environment variables onto c after a
// remote-config merge, enforcing env > S3 config > file precedence. MergeBytes
// uses a fresh viper.Viper without the AOW_* bindings set up by LoadConfig, so
// env-var overrides are otherwise silently clobbered by S3 payload values.
func reapplyEnvOverrides(c *Config) {
	type strField struct {
		env string
		ptr *string
	}
	for _, f := range []strField{
		{"AOW_ISSUER", &c.Issuer},
		{"AOW_AUDIENCE", &c.Audience},
		{"AOW_ROLE_SESSION_NAME", &c.RoleSessionName},
		{"AOW_S3_CONFIG_BUCKET", &c.S3ConfigBucket},
		{"AOW_S3_CONFIG_PATH", &c.S3ConfigPath},
		{"AOW_SESSION_POLICY_BUCKET", &c.S3SessionPolicyBucket},
		{"AOW_LOG_BUCKET", &c.LogBucket},
		{"AOW_LOG_PREFIX", &c.LogPrefix},
	} {
		if v := os.Getenv(f.env); v != "" {
			*f.ptr = v
		}
	}

	// AOW_AUDIENCES — comma-separated list overrides the slice. Elements are
	// trimmed of whitespace so "a , b" and "a,b" are equivalent.
	if v := os.Getenv("AOW_AUDIENCES"); v != "" {
		parts := strings.Split(v, ",")
		audiences := parts[:0]
		for _, p := range parts {
			if s := strings.TrimSpace(p); s != "" {
				audiences = append(audiences, s)
			}
		}
		c.Audiences = audiences
	}

	if v := os.Getenv("AOW_LOG_TO_S3"); v != "" {
		c.LogToS3 = v == "true" || v == "1" || v == "True" || v == "TRUE"
	}

	if v := os.Getenv("AOW_CONFIG_RELOAD_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err != nil {
			slog.Warn("invalid env var, skipping", "key", "AOW_CONFIG_RELOAD_INTERVAL", "value", v, "error", err)
		} else {
			c.ConfigReloadInterval = d
		}
	}

	// Cache env overrides — ensure Cache is non-nil before writing.
	if c.Cache == nil {
		c.Cache = &Cache{}
	}

	for _, f := range []strField{
		{"AOW_CACHE_TYPE", &c.Cache.Type},
		{"AOW_CACHE_DYNAMODB_TABLE", &c.Cache.DynamoDBTable},
		{"AOW_CACHE_S3_BUCKET", &c.Cache.S3Bucket},
		{"AOW_CACHE_S3_PREFIX", &c.Cache.S3Prefix},
	} {
		if v := os.Getenv(f.env); v != "" {
			*f.ptr = v
		}
	}

	if v := os.Getenv("AOW_CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err != nil {
			slog.Warn("invalid env var, skipping", "key", "AOW_CACHE_TTL", "value", v, "error", err)
		} else {
			c.Cache.TTL = d
		}
	}

	if v := os.Getenv("AOW_CACHE_MAX_LOCAL_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err != nil {
			slog.Warn("invalid env var, skipping", "key", "AOW_CACHE_MAX_LOCAL_SIZE", "value", v, "error", err)
		} else {
			c.Cache.MaxLocalSize = n
		}
	}

	if v := os.Getenv("AOW_CACHE_S3_CLEANUP"); v != "" {
		if b, err := strconv.ParseBool(v); err != nil {
			slog.Warn("invalid env var, skipping", "key", "AOW_CACHE_S3_CLEANUP", "value", v, "error", err)
		} else {
			c.Cache.S3Cleanup = b
		}
	}

	// Tag-based authorization env overrides.
	if v := os.Getenv("AOW_TAG_AUTH_ENABLED"); v != "" {
		if c.TagAuth == nil {
			c.TagAuth = &TagAuth{}
		}
		c.TagAuth.Enabled = v == "true" || v == "1" || v == "True" || v == "TRUE"
	}
	if c.TagAuth != nil {
		for _, f := range []strField{
			{"AOW_TAG_AUTH_TAG_PREFIX", &c.TagAuth.TagPrefix},
			{"AOW_TAG_AUTH_SPOKE_ROLE_NAME", &c.TagAuth.SpokeRoleName},
			{"AOW_TAG_AUTH_EXTERNAL_ID", &c.TagAuth.ExternalID},
		} {
			if v := os.Getenv(f.env); v != "" {
				*f.ptr = v
			}
		}
		if v := os.Getenv("AOW_TAG_AUTH_SPOKE_SESSION_DURATION"); v != "" {
			if d, err := time.ParseDuration(v); err != nil {
				slog.Warn("invalid env var, skipping", "key", "AOW_TAG_AUTH_SPOKE_SESSION_DURATION", "value", v, "error", err)
			} else {
				c.TagAuth.SpokeSessionDuration = d
			}
		}
	}
}

// FormatFromPath returns the viper config type implied by a file path's
// extension, defaulting to "json".
func FormatFromPath(path string) string {
	switch {
	case strings.HasSuffix(path, ".yaml"), strings.HasSuffix(path, ".yml"):
		return "yaml"
	case strings.HasSuffix(path, ".toml"):
		return "toml"
	default:
		return "json"
	}
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

	// Normalize tag-auth defaults so the feature works even when Config is built
	// directly (e.g. in tests) without going through viper defaults.
	if c.TagAuth != nil && c.TagAuth.Enabled {
		if c.TagAuth.TagPrefix == "" {
			c.TagAuth.TagPrefix = "aow/"
		}
		if c.TagAuth.SpokeRoleName == "" {
			c.TagAuth.SpokeRoleName = "aow-spoke"
		}
		if c.TagAuth.SpokeSessionDuration == 0 {
			c.TagAuth.SpokeSessionDuration = 15 * time.Minute
		}
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
