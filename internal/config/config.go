package config

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/utils"
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

	defaultJWTLeeway           = 30 * time.Second  // Default clock-skew leeway for exp/iat/nbf checks
	maxJWTLeeway               = 120 * time.Second // Hard ceiling for jwt_leeway
	defaultMaxTokenBytes       = 8192              // Default token length cap (8 KB) before any parsing
	defaultMaxTokenLifetime    = time.Hour         // Default cap on exp-iat when max_token_lifetime is unset
	defaultMaxTokenAge         = time.Hour         // Default cap on now-iat when max_token_age is unset
	defaultJWKSRefetchCooldown = 60 * time.Second  // Default minimum interval between forced JWKS refetches per (issuer,kid)
	defaultLogLevel            = "info"            // Default slog level name

	validLogLevels = map[string]bool{"debug": true, "info": true, "warn": true, "error": true}

	accountIDPattern     = regexp.MustCompile(`^\d{12}$`)
	sessionTagKeyPattern = regexp.MustCompile(`^[A-Za-z0-9 _.:/=+@-]{1,128}$`)

	// reservedClaims are JWT-standard claim names that claim_mappings may never
	// target, since doing so could shadow a verified claim used for security
	// decisions (issuer, audience, timing, canonical sub).
	reservedClaims = map[string]bool{
		"iss": true, "aud": true, "exp": true, "nbf": true, "iat": true, "sub": true,
	}
)

// Condition defines claim predicates that must be met for a role to be
// assumed. The named fields below are provider-neutral sugar over the same
// generic mechanism: each compiles to an auto-anchored regex checked against
// one raw verified claim (see compileCondition/satisfiesConditions). Extra
// carries arbitrary claimName->regex entries not covered by a named field,
// so `conditions: {my_claim: "regex"}` works without a nested key.
type Condition struct {
	Branch       string   `mapstructure:"branch"        json:"branch,omitempty"`        // Regex against the 'ref' claim (e.g., "main", "dev")
	Ref          string   `mapstructure:"ref"           json:"ref,omitempty"`           // Regex against the 'ref' claim (e.g., "refs/heads/main", "refs/tags/v.*")
	RefType      string   `mapstructure:"ref_type"      json:"ref_type,omitempty"`      // Regex against 'ref_type' (e.g., "branch", "tag")
	EventName    string   `mapstructure:"event_name"    json:"event_name,omitempty"`    // Regex against 'event_name' (e.g., "push", "pull_request")
	WorkflowRef  string   `mapstructure:"workflow_ref"  json:"workflow_ref,omitempty"`  // Regex against 'workflow_ref' (e.g., "owner/repo/.github/workflows/workflow.yml")
	Environment  string   `mapstructure:"environment"   json:"environment,omitempty"`   // Regex against 'runner_environment' (e.g., "production")
	ActorMatches []string `mapstructure:"actor_matches" json:"actor_matches,omitempty"` // Regexes against 'actor'; OR within the list

	// Extra holds generic claimName->regex entries (raw verified claim names)
	// not covered by a named field above. Populated via mapstructure's
	// remain-fields so no nested key is required in config.
	Extra map[string]string `mapstructure:",remain" json:"extra,omitempty"`

	// Cached compiled patterns (not serialized)
	compiled      []compiledCondition `mapstructure:"-" json:"-"` // AND'd claimName/pattern pairs (named single-value fields + Extra)
	actorPatterns []*regexp.Regexp    `mapstructure:"-" json:"-"` // OR'd within this one dimension
}

// compiledCondition is one AND'd (claim name, anchored pattern) pair compiled
// from either a named Condition field or an Extra entry.
type compiledCondition struct {
	claim   string
	pattern *regexp.Regexp
}

// RoleMapping binds a subject (pattern) to a set of assumable roles, scoped
// to a single issuer, optionally gated by conditions on the raw claims.
type RoleMapping struct {
	Subject           string     `mapstructure:"subject"             json:"subject"`                       // Subject pattern (e.g., "owner/repo"); provider-defined shape
	Issuer            string     `mapstructure:"issuer"              json:"issuer,omitempty"`              // Trusted issuer this mapping applies to; resolved at Validate() (see resolveIssuer)
	SessionPolicy     string     `mapstructure:"session_policy"      json:"session_policy,omitempty"`      // Inline session policy (JSON string)
	SessionPolicyFile string     `mapstructure:"session_policy_file" json:"session_policy_file,omitempty"` // S3 session policy file
	Roles             []string   `mapstructure:"roles"               json:"roles"`                         // IAM roles (or "@role_set" aliases, resolved at Validate()) that can be assumed
	Conditions        *Condition `mapstructure:"conditions"          json:"conditions,omitempty"`          // Conditions for role assumption

	// Cached compiled pattern and declaration order (not serialized). order
	// preserves first-match-wins semantics for FindSessionPolicy once
	// mappings are bucketed into the index (see index.go).
	compiledPattern *regexp.Regexp `mapstructure:"-" json:"-"`
	order           int            `mapstructure:"-" json:"-"`
}

// RoleGroupDefaults are the fields a role_group applies uniformly to every
// subject it expands to.
type RoleGroupDefaults struct {
	Roles             []string   `mapstructure:"roles"               json:"roles,omitempty"`
	Conditions        *Condition `mapstructure:"conditions"          json:"conditions,omitempty"`
	SessionPolicy     string     `mapstructure:"session_policy"      json:"session_policy,omitempty"`
	SessionPolicyFile string     `mapstructure:"session_policy_file" json:"session_policy_file,omitempty"`
}

// RoleGroup is a DRY convenience: it expands to one RoleMapping per Subjects
// entry, all sharing Issuer and Defaults (Validate() does the expansion).
type RoleGroup struct {
	Issuer   string            `mapstructure:"issuer"   json:"issuer,omitempty"`
	Defaults RoleGroupDefaults `mapstructure:"defaults" json:"defaults,omitempty"`
	Subjects []string          `mapstructure:"subjects" json:"subjects"`
}

// IssuerConfig describes one trusted OIDC issuer: where its keys live, what
// audiences it may present, how its raw claims map to the canonical
// authorization surface (subject/conditions/session tags), and which claims
// must be present. The engine is provider-neutral; only `provider: github`
// gets native struct unmarshal, everything else is mapped-only.
type IssuerConfig struct {
	Issuer   string `mapstructure:"issuer"   json:"issuer"`             // Issuer is the exact `iss` claim value trusted for this entry
	Provider string `mapstructure:"provider" json:"provider,omitempty"` // "github" (native unmarshal) or "generic" (mapped-only, default)

	Audiences []string `mapstructure:"audiences" json:"audiences,omitempty"` // Audiences accepted for this issuer (ANY-match)
	JWKSURI   string   `mapstructure:"jwks_uri"  json:"jwks_uri,omitempty"`  // Optional explicit JWKS URI; skips OIDC discovery when set

	// ClaimMappings projects raw provider claims onto canonical fields.
	// Keys are canonical field names (e.g. "subject"); values are the raw
	// verified claim name to read. Non-github issuers must define "subject".
	ClaimMappings map[string]string `mapstructure:"claim_mappings" json:"claim_mappings,omitempty"`

	// RequiredClaims lists raw verified claim names that must be present and
	// non-empty for a token from this issuer to be accepted.
	RequiredClaims []string `mapstructure:"required_claims" json:"required_claims,omitempty"`

	// SessionTags maps an STS session tag key to the raw verified claim name
	// whose value populates it.
	SessionTags map[string]string `mapstructure:"session_tags" json:"session_tags,omitempty"`
}

// defaultGitHubIssuer returns the zero-config GitHub Actions issuer seeded
// when no configuration source is found at all (see Config.LoadConfig).
func defaultGitHubIssuer() IssuerConfig {
	return IssuerConfig{
		Issuer:         issuer,
		Provider:       "github",
		Audiences:      []string{audience},
		RequiredClaims: []string{"repository"},
		SessionTags: map[string]string{
			"repo":       "repository",
			"repo-owner": "repository_owner",
			"ref":        "ref",
			"ref-type":   "ref_type",
			"actor":      "actor",
			"event-name": "event_name",
		},
	}
}

type Cache struct {
	Type          string        `mapstructure:"type"           json:"type"`                     // Cache type (e.g., "memory", "dynamodb")
	TTL           time.Duration `mapstructure:"ttl"            json:"ttl"`                      // Cache TTL duration (ex: "5m", "1h", "2h30", "24h", "1d", "1w")
	MaxLocalSize  int           `mapstructure:"max_local_size" json:"max_local_size,omitempty"` // Maximum size of local cache (if using memory cache)
	DynamoDBTable string        `mapstructure:"dynamodb_table" json:"dynamodb_table,omitempty"` // DynamoDB table name (if using DynamoDB cache)
	S3Bucket      string        `mapstructure:"s3_bucket"      json:"s3_bucket,omitempty"`      // S3 bucket name (if using S3 cache)
	S3Prefix      string        `mapstructure:"s3_prefix"      json:"s3_prefix,omitempty"`      // S3 prefix (if using S3 cache)
	S3Cleanup     bool          `mapstructure:"s3_cleanup"     json:"s3_cleanup,omitempty"`     // S3 cleanup flag (if using S3 cache). Deletes expired objects discovered on read (not a bulk sweep).
}

// TagAuth enables tag-based role authorization: a role may be assumed when its
// IAM tags authorize the request's OIDC claims, without an explicit
// role_mappings entry. Cross-account transport (the per-account spoke role)
// is configured separately in CrossAccount.
type TagAuth struct {
	Enabled    bool   `mapstructure:"enabled"    json:"enabled,omitempty"`
	TagPrefix  string `mapstructure:"tag_prefix" json:"tag_prefix,omitempty"`   // default "aow/"
	DefaultOrg string `mapstructure:"default_org" json:"default_org,omitempty"` // prepended to bare aow/repo tag values: "api" -> "<default_org>/api"

	// TransitiveSessionTags, when true, marks every session tag attached to the
	// AssumeRole call transitive (see aws.selectTransitiveKeys) so they
	// propagate immutably through role chaining. Default off.
	TransitiveSessionTags bool `mapstructure:"transitive_session_tags" json:"transitive_session_tags,omitempty"`

	// multiIssuer is set by Config.Validate() (len(Issuers) > 1) and gates the
	// <prefix>issuer requirement in Authorize (no cross-issuer identity
	// collision via tag-auth). Not serialized; always recomputed.
	multiIssuer bool `mapstructure:"-" json:"-"`
}

// CrossAccount is a policy gate for member-account role assumption: Enabled
// false (the default, or this struct nil) hard-blocks every cross-account
// operation — both AssumeRole and, for tag_auth, the IAM tag read — failing
// closed rather than falling back to any other behavior. Role assumption is
// always direct: one hop, hub account to target account, using the warden's
// own credentials. SpokeRoleName/ExternalID/SpokeSessionDuration configure a
// separate hop — a convention-named role assumed only so tag_auth can read a
// target role's IAM tags cross-account (iam:GetRole); the spoke is never used
// to assume the target role itself, and ExternalID is never sent on that
// assume. Independent of tag_auth — explicit role_mappings can target
// member-account ARNs with tag_auth disabled. The account ID is parsed from
// the requested role ARN.
type CrossAccount struct {
	Enabled              bool          `mapstructure:"enabled"                json:"enabled,omitempty"`
	SpokeRoleName        string        `mapstructure:"spoke_role_name"        json:"spoke_role_name,omitempty"`        // default "aow-spoke"
	ExternalID           string        `mapstructure:"external_id"            json:"external_id,omitempty"`            // optional hub->spoke external ID
	SpokeSessionDuration time.Duration `mapstructure:"spoke_session_duration" json:"spoke_session_duration,omitempty"` // hub->spoke session length, default 15m, capped at 1h (chained-session limit)

	// AllowedAccounts restricts which member accounts the warden will assume into.
	// Empty/undefined = any account. The hub account is always allowed.
	AllowedAccounts []string `mapstructure:"allowed_accounts" json:"allowed_accounts,omitempty"`
}

// JWTValidation controls whether the service validates JWT signatures itself
// or trusts pre-validation by an upstream AWS service.
type JWTValidation struct {
	// Mode is one of "self" (default), "apigw", or "alb".
	// "self"  — full signature + claims verification by this service.
	// "apigw" — trust API Gateway HTTP API v2 JWT Authorizer; extract claims
	//            from event.requestContext.authorizer.jwt.claims.
	// "alb"   — trust ALB OIDC; verify ALB-signed x-amzn-oidc-data JWT (ES256).
	Mode string `mapstructure:"mode" json:"mode,omitempty"`

	// ALBExpectedSigner is the ARN of the ALB allowed to sign OIDC data.
	// Required in "alb" mode to prevent cross-ALB token injection.
	ALBExpectedSigner string `mapstructure:"alb_expected_signer" json:"alb_expected_signer,omitempty"`
}

type Config struct {
	// Issuers is the list of trusted OIDC issuers. At least one is required;
	// there is no single-issuer field anymore (v2.0.0 breaking change).
	Issuers []IssuerConfig `mapstructure:"issuers" json:"issuers"`

	S3ConfigBucket        string `mapstructure:"s3_config_bucket"      json:"s3_config_bucket,omitempty"`      // S3ConfigBucket is the S3 bucket where the configuration file is stored
	S3ConfigPath          string `mapstructure:"s3_config_path"        json:"s3_config_path,omitempty"`        // S3ConfigPath is the path to the configuration file in the S3 bucket
	S3SessionPolicyBucket string `mapstructure:"session_policy_bucket" json:"session_policy_bucket,omitempty"` // S3SessionPolicyBucket is the S3 bucket where the session policy file is stored
	RoleSessionName       string `mapstructure:"role_session_name"     json:"role_session_name"`               // RoleSessionName is the name of the role session

	// DefaultIssuer is the issuer inherited by a role_mapping/role_group that
	// doesn't set its own `issuer`. Only meaningful (and required to resolve
	// to a real issuer) when more than one issuer is configured; with a
	// single issuer, mappings implicitly bind to it regardless.
	DefaultIssuer string `mapstructure:"default_issuer" json:"default_issuer,omitempty"`

	// RoleSets are named ARN lists referenced from a mapping/group's `roles`
	// as "@name", resolved at Validate() before the requested-role gate.
	RoleSets map[string][]string `mapstructure:"role_sets" json:"role_sets,omitempty"`

	// RoleMappings is the literal, explicit set of subject-to-role bindings.
	// RoleGroups is a DRY convenience expanding to additional RoleMappings.
	// Neither is mutated by Validate(); the fully resolved/expanded set used
	// by AuthorizeRoles/FindSessionPolicy lives in the unexported `effective`.
	RoleMappings []RoleMapping `mapstructure:"role_mappings" json:"role_mappings,omitempty"`
	RoleGroups   []RoleGroup   `mapstructure:"role_groups"   json:"role_groups,omitempty"`

	// ConfigReloadInterval, when > 0, enables periodic hot-reload of the S3
	// configuration (S3ConfigBucket/S3ConfigPath) without redeploying. The
	// reload is lazy/per-request: the config is refetched at most once per
	// interval. 0 (default) disables reloading. Requires an S3 config source.
	ConfigReloadInterval time.Duration `mapstructure:"config_reload_interval" json:"config_reload_interval,omitempty"`

	// ConfigFragments lists additional sources — S3 URIs (e.g.
	// "s3://bucket/key") or local filesystem paths — merged into the combined
	// role_mappings/role_groups/role_sets/default_issuer set on top of the
	// base config (see fragments.go, provider.go). Base-only: a fragment can
	// never set this field itself; enforced by the fragment merge allowlist,
	// not by this field's type.
	ConfigFragments []string `mapstructure:"config_fragments" json:"config_fragments,omitempty"`

	// ConfigFragmentChecksums optionally pins an expected integrity value
	// (whatever a fragment's fetch reports as its etag — an S3 ETag, or the
	// sha256 content hash computed for local-path fragments) per
	// config_fragments entry. When set for an entry, a fetched value that
	// doesn't match exactly is rejected (S9); entries with no pinned value
	// are unauthenticated beyond transport — their etag is then used only
	// for reload change-detection (provider.go).
	ConfigFragmentChecksums map[string]string `mapstructure:"config_fragment_checksums" json:"config_fragment_checksums,omitempty"`

	// Logging configuration directly to S3 (duplicates cloudwatch logs)
	LogToS3   bool   `mapstructure:"log_to_s3"  json:"log_to_s3,omitempty"`  // LogToS3 is a flag to enable logging to S3
	LogBucket string `mapstructure:"log_bucket" json:"log_bucket,omitempty"` // LogBucket is the S3 bucket to log to
	LogPrefix string `mapstructure:"log_prefix" json:"log_prefix,omitempty"` // LogKey is the S3 key to log to
	Cache     *Cache `mapstructure:"cache"      json:"cache,omitempty"`      // CacheConfig is the cache configuration

	// LogLevel is the slog level name (debug/info/warn/error); default "info".
	// Validated (not merely parsed) in Validate() so an unknown value fails
	// config load rather than silently falling back at first use.
	LogLevel string `mapstructure:"log_level" json:"log_level,omitempty"`

	// LogClaimValues controls whether claim VALUES (canonical subject, raw
	// jwtSub, audience) appear in structured logs and audit records. Default
	// off: only claim NAMES plus the decision/reason are logged. Session tag
	// keys are always logged; tag values follow this flag too.
	LogClaimValues bool `mapstructure:"log_claim_values" json:"log_claim_values,omitempty"`

	// AuditRequired, when true, makes the audit trail a hard dependency of the
	// request: the audit record for an allow decision must be durably written
	// before credentials are returned, and a write failure (allow or deny)
	// denies the request instead of logging-and-continuing. Requires
	// log_to_s3 + log_bucket (enforced below) since those are what make the
	// audit sink capable of persisting anything.
	AuditRequired bool `mapstructure:"audit_required" json:"audit_required,omitempty"`

	// TagAuth enables tag-based authorization (IAM role tags authorize claims).
	TagAuth *TagAuth `mapstructure:"tag_auth" json:"tag_auth,omitempty"`

	// CrossAccount enables the hub-and-spoke transport for assuming roles in
	// other AWS accounts.
	CrossAccount *CrossAccount `mapstructure:"cross_account" json:"cross_account,omitempty"`

	// JWTValidation controls whether the service validates JWT signatures itself
	// or trusts pre-validation by an upstream AWS service.
	JWTValidation JWTValidation `mapstructure:"jwt_validation" json:"jwt_validation,omitempty"`

	// Hardening knobs (top-level, apply across all issuers and modes).
	JWTLeeway            *time.Duration `mapstructure:"jwt_leeway"             json:"jwt_leeway,omitempty"`             // Clock-skew leeway for exp/iat/nbf; nil = unset (defaults to 30s in Validate); hard max 120s
	MaxTokenLifetime     time.Duration  `mapstructure:"max_token_lifetime"     json:"max_token_lifetime,omitempty"`     // Reject if exp-iat exceeds this; 0/unset defaults to 1h in Validate (not "no cap")
	MaxTokenAge          time.Duration  `mapstructure:"max_token_age"          json:"max_token_age,omitempty"`          // Reject if now-iat exceeds this; 0/unset defaults to 1h in Validate (not "no cap")
	MaxTokenBytes        int            `mapstructure:"max_token_bytes"        json:"max_token_bytes,omitempty"`        // Token length cap before any parsing; default 8192 (8 KB)
	JWKSRefetchCooldown  time.Duration  `mapstructure:"jwks_refetch_cooldown"  json:"jwks_refetch_cooldown,omitempty"`  // Minimum interval between forced JWKS refetches per (issuer,kid); default 60s
	AllowInsecureIssuers bool           `mapstructure:"allow_insecure_issuers" json:"allow_insecure_issuers,omitempty"` // Dev-only: permit http:// issuer/jwks_uri

	// Performance optimization / resolved authorization state - not serialized.
	// Rebuilt fresh by Validate() every time (from RoleMappings/RoleGroups/
	// RoleSets), so Validate() stays idempotent and safe to call repeatedly
	// (e.g. after a hot-reload clone).
	estimatedRolesPerMapping int            `mapstructure:"-" json:"-"` // Calculated during Validate for efficient memory allocation
	effective                []*RoleMapping `mapstructure:"-" json:"-"` // fully resolved: issuer bound, role_sets expanded, patterns compiled
	index                    authzIndex     `mapstructure:"-" json:"-"` // per-issuer owner-bucketed index over effective (see index.go)
}

// envKeyReplacer mirrors the SetEnvKeyReplacer configured on viper in
// LoadConfig, so envVarName can derive the same AOW_ env var name viper would
// bind for a given config key.
var envKeyReplacer = strings.NewReplacer(".", "_", "-", "_")

// envVarName derives the AOW_ environment variable name for a config/viper
// key, matching viper's SetEnvPrefix("aow") + SetEnvKeyReplacer(".","_","-","_").
func envVarName(key string) string {
	return "AOW_" + strings.ToUpper(envKeyReplacer.Replace(key))
}

// envTrue implements the truthy check used by all boolean AOW_ env knobs.
func envTrue(v string) bool {
	return v == "true" || v == "1" || v == "True" || v == "TRUE"
}

// ensureTagAuth returns c.TagAuth, initializing it to a zero-value TagAuth
// first if it is nil.
func ensureTagAuth(c *Config) *TagAuth {
	if c.TagAuth == nil {
		c.TagAuth = &TagAuth{}
	}
	return c.TagAuth
}

// ensureCrossAccount returns c.CrossAccount, initializing it to a zero-value
// CrossAccount first if it is nil.
func ensureCrossAccount(c *Config) *CrossAccount {
	if c.CrossAccount == nil {
		c.CrossAccount = &CrossAccount{}
	}
	return c.CrossAccount
}

// splitCommaList splits v on "," trimming whitespace and dropping empty
// entries; used by every comma-separated list env knob.
func splitCommaList(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// warnInvalidEnv logs the standard "invalid env var, skipping" warning shared
// by every parse-then-assign env knob.
func warnInvalidEnv(key, value string, err error) {
	slog.Warn("invalid env var, skipping", "key", key, "value", value, "error", err)
}

// envBinding ties one AOW_ environment knob to both viper's file-load binding
// (LoadConfig) and the manual re-apply after a remote-config merge
// (reapplyEnvOverrides), so the two paths cannot drift.
type envBinding struct {
	key   string                    // config/viper key, e.g. "tag_auth.enabled"
	apply func(c *Config, v string) // parse v (a non-empty env value) and assign; encodes any parent-struct init
}

// envBindings is the single source of truth for every AOW_ environment-
// variable knob: LoadConfig binds each key to viper, and reapplyEnvOverrides
// re-applies each after a remote/S3 config merge (env > S3 > file precedence).
var envBindings = []envBinding{
	// Core settings (plain strings).
	{"role_session_name", func(c *Config, v string) { c.RoleSessionName = v }},
	{"s3_config_bucket", func(c *Config, v string) { c.S3ConfigBucket = v }},
	{"s3_config_path", func(c *Config, v string) { c.S3ConfigPath = v }},
	{"session_policy_bucket", func(c *Config, v string) { c.S3SessionPolicyBucket = v }},
	{"log_bucket", func(c *Config, v string) { c.LogBucket = v }},
	{"log_prefix", func(c *Config, v string) { c.LogPrefix = v }},
	{"log_level", func(c *Config, v string) { c.LogLevel = v }},

	// Booleans.
	{"log_to_s3", func(c *Config, v string) { c.LogToS3 = envTrue(v) }},
	{"log_claim_values", func(c *Config, v string) { c.LogClaimValues = envTrue(v) }},
	{"audit_required", func(c *Config, v string) { c.AuditRequired = envTrue(v) }},
	{"allow_insecure_issuers", func(c *Config, v string) { c.AllowInsecureIssuers = envTrue(v) }},

	// Durations (warn-and-skip on parse error).
	{"config_reload_interval", func(c *Config, v string) {
		if d, err := time.ParseDuration(v); err != nil {
			warnInvalidEnv(envVarName("config_reload_interval"), v, err)
		} else {
			c.ConfigReloadInterval = d
		}
	}},
	{"max_token_lifetime", func(c *Config, v string) {
		if d, err := time.ParseDuration(v); err != nil {
			warnInvalidEnv(envVarName("max_token_lifetime"), v, err)
		} else {
			c.MaxTokenLifetime = d
		}
	}},
	{"max_token_age", func(c *Config, v string) {
		if d, err := time.ParseDuration(v); err != nil {
			warnInvalidEnv(envVarName("max_token_age"), v, err)
		} else {
			c.MaxTokenAge = d
		}
	}},
	{"jwks_refetch_cooldown", func(c *Config, v string) {
		if d, err := time.ParseDuration(v); err != nil {
			warnInvalidEnv(envVarName("jwks_refetch_cooldown"), v, err)
		} else {
			c.JWKSRefetchCooldown = d
		}
	}},
	{"jwt_leeway", func(c *Config, v string) {
		if d, err := time.ParseDuration(v); err != nil {
			warnInvalidEnv(envVarName("jwt_leeway"), v, err)
		} else {
			c.JWTLeeway = &d
		}
	}},

	// Int (warn-and-skip on parse error).
	{"max_token_bytes", func(c *Config, v string) {
		if n, err := strconv.Atoi(v); err != nil {
			warnInvalidEnv(envVarName("max_token_bytes"), v, err)
		} else {
			c.MaxTokenBytes = n
		}
	}},

	// Comma-separated list.
	{"config_fragments", func(c *Config, v string) { c.ConfigFragments = splitCommaList(v) }},

	// Cache knobs (c.Cache is guaranteed non-nil before these run).
	{"cache.type", func(c *Config, v string) { c.Cache.Type = v }},
	{"cache.dynamodb_table", func(c *Config, v string) { c.Cache.DynamoDBTable = v }},
	{"cache.s3_bucket", func(c *Config, v string) { c.Cache.S3Bucket = v }},
	{"cache.s3_prefix", func(c *Config, v string) { c.Cache.S3Prefix = v }},
	{"cache.ttl", func(c *Config, v string) {
		if d, err := time.ParseDuration(v); err != nil {
			warnInvalidEnv(envVarName("cache.ttl"), v, err)
		} else {
			c.Cache.TTL = d
		}
	}},
	{"cache.max_local_size", func(c *Config, v string) {
		if n, err := strconv.Atoi(v); err != nil {
			warnInvalidEnv(envVarName("cache.max_local_size"), v, err)
		} else {
			c.Cache.MaxLocalSize = n
		}
	}},
	{"cache.s3_cleanup", func(c *Config, v string) {
		// NOTE: strconv.ParseBool, not envTrue — this field has always used
		// Go's canonical bool parsing rather than the looser truthy check.
		if b, err := strconv.ParseBool(v); err != nil {
			warnInvalidEnv(envVarName("cache.s3_cleanup"), v, err)
		} else {
			c.Cache.S3Cleanup = b
		}
	}},

	// Tag-based authorization knobs. enabled/transitive_session_tags create
	// TagAuth if nil; the rest only apply if it already exists (preserves the
	// pre-refactor init semantics exactly).
	{"tag_auth.enabled", func(c *Config, v string) { ensureTagAuth(c).Enabled = envTrue(v) }},
	{"tag_auth.transitive_session_tags", func(c *Config, v string) { ensureTagAuth(c).TransitiveSessionTags = envTrue(v) }},
	{"tag_auth.tag_prefix", func(c *Config, v string) {
		if c.TagAuth != nil {
			c.TagAuth.TagPrefix = v
		}
	}},
	{"tag_auth.default_org", func(c *Config, v string) {
		if c.TagAuth != nil {
			c.TagAuth.DefaultOrg = v
		}
	}},

	// Cross-account transport knobs.
	{"cross_account.enabled", func(c *Config, v string) { ensureCrossAccount(c).Enabled = envTrue(v) }},
	{"cross_account.spoke_role_name", func(c *Config, v string) { ensureCrossAccount(c).SpokeRoleName = v }},
	{"cross_account.external_id", func(c *Config, v string) { ensureCrossAccount(c).ExternalID = v }},
	{"cross_account.allowed_accounts", func(c *Config, v string) { ensureCrossAccount(c).AllowedAccounts = splitCommaList(v) }},
	{"cross_account.spoke_session_duration", func(c *Config, v string) {
		if d, err := time.ParseDuration(v); err != nil {
			warnInvalidEnv(envVarName("cross_account.spoke_session_duration"), v, err)
		} else {
			ensureCrossAccount(c).SpokeSessionDuration = d
		}
	}},

	// JWT validation settings (value struct, always present).
	{"jwt_validation.mode", func(c *Config, v string) { c.JWTValidation.Mode = v }},
	{"jwt_validation.alb_expected_signer", func(c *Config, v string) { c.JWTValidation.ALBExpectedSigner = v }},
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
	viper.SetDefault("role_session_name", role_session_name)
	viper.SetDefault("cache.type", cacheType)
	viper.SetDefault("cache.ttl", cacheTTL)
	viper.SetDefault("cache.max_local_size", cacheMaxLocalSize)
	viper.SetDefault("tag_auth.enabled", false)
	viper.SetDefault("tag_auth.tag_prefix", "aow/")
	viper.SetDefault("tag_auth.transitive_session_tags", false)
	viper.SetDefault("cross_account.enabled", false)
	viper.SetDefault("cross_account.spoke_role_name", "aow-spoke")
	viper.SetDefault("cross_account.spoke_session_duration", "15m")
	viper.SetDefault("jwt_validation.mode", "self")
	viper.SetDefault("max_token_bytes", defaultMaxTokenBytes)
	viper.SetDefault("jwks_refetch_cooldown", defaultJWKSRefetchCooldown)
	viper.SetDefault("allow_insecure_issuers", false)
	viper.SetDefault("log_level", defaultLogLevel)
	viper.SetDefault("log_claim_values", false)
	viper.SetDefault("audit_required", false)

	// Explicitly bind all config keys to environment variables. Driven by
	// envBindings (see below) so this list and reapplyEnvOverrides cannot
	// drift apart.
	for _, b := range envBindings {
		_ = viper.BindEnv(b.key)
	}

	configFileFound := true
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			configFileFound = false // No config file; rely on defaults/env
		} else {
			return fmt.Errorf("problem reading config file: %w", err)
		}
	}

	if err := viper.Unmarshal(c); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Zero-config GitHub seed: only when there is truly no configuration
	// source at all. If a config source IS present (file found) but declares
	// no issuers, that is a hard error below in Validate() — we never
	// silently fall back to trusting GitHub in that case.
	if !configFileFound && len(c.Issuers) == 0 {
		c.Issuers = []IssuerConfig{defaultGitHubIssuer()}
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
	// Ensure Cache is non-nil before applying cache knobs (matches prior
	// behavior: the old code unconditionally created c.Cache here).
	if c.Cache == nil {
		c.Cache = &Cache{}
	}
	for _, b := range envBindings {
		if v := os.Getenv(envVarName(b.key)); v != "" {
			b.apply(c, v)
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

// LeewayOrDefault returns the configured jwt_leeway, or the default when
// unset (nil). Safe on a config that never ran Validate() (e.g. hand-built
// test configs).
func (c *Config) LeewayOrDefault() time.Duration {
	if c.JWTLeeway == nil {
		return defaultJWTLeeway
	}
	return *c.JWTLeeway
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if len(c.Issuers) == 0 {
		return errors.New("at least one issuer is required (issuers)")
	}

	seenIssuers := make(map[string]bool, len(c.Issuers))
	for i := range c.Issuers {
		iss := &c.Issuers[i]

		if iss.Issuer == "" {
			return fmt.Errorf("issuers[%d]: issuer is required", i)
		}
		// Exact-match policy: no trailing-slash or case normalization, so a
		// duplicate check here must mirror what the validator does at runtime.
		if seenIssuers[iss.Issuer] {
			return fmt.Errorf("issuers[%d]: duplicate issuer %q", i, iss.Issuer)
		}
		seenIssuers[iss.Issuer] = true

		if len(iss.Audiences) == 0 {
			return fmt.Errorf("issuers[%d] (%s): at least one audience is required", i, iss.Issuer)
		}
		for j, aud := range iss.Audiences {
			if aud == "" {
				return fmt.Errorf("issuers[%d] (%s): audiences[%d] must not be empty", i, iss.Issuer, j)
			}
		}

		switch iss.Provider {
		case "":
			iss.Provider = "generic"
		case "github", "generic":
			// ok
		default:
			return fmt.Errorf("issuers[%d] (%s): provider must be 'github' or 'generic', got %q", i, iss.Issuer, iss.Provider)
		}

		// Non-github issuers cannot derive a canonical subject from a native
		// struct, so they must explicitly say which raw claim carries it.
		if iss.Provider != "github" && iss.ClaimMappings["subject"] == "" {
			return fmt.Errorf("issuers[%d] (%s): non-github issuers must define claim_mappings.subject", i, iss.Issuer)
		}

		// Reject claim_mappings that target a JWT-reserved claim name; doing
		// so could shadow a verified claim used for security decisions.
		for target := range iss.ClaimMappings {
			if reservedClaims[target] {
				return fmt.Errorf("issuers[%d] (%s): claim_mappings cannot target reserved claim %q", i, iss.Issuer, target)
			}
		}

		for tagKey := range iss.SessionTags {
			if !sessionTagKeyPattern.MatchString(tagKey) {
				return fmt.Errorf("issuers[%d] (%s): session_tags key %q is not a valid STS tag key (charset [A-Za-z0-9 _.:/=+@-], max 128 chars)", i, iss.Issuer, tagKey)
			}
		}
	}

	if c.RoleSessionName == "" {
		return errors.New("role session name is required")
	}

	for i, uri := range c.ConfigFragments {
		if strings.TrimSpace(uri) == "" {
			return fmt.Errorf("config_fragments[%d]: must not be empty", i)
		}
	}

	// Hardening knobs: apply defaults, then enforce bounds.
	if c.JWTLeeway == nil {
		d := defaultJWTLeeway
		c.JWTLeeway = &d
	}
	if *c.JWTLeeway > maxJWTLeeway {
		return fmt.Errorf("jwt_leeway must be <= %s, got %s", maxJWTLeeway, *c.JWTLeeway)
	}
	if *c.JWTLeeway < 0 {
		return fmt.Errorf("jwt_leeway must not be negative, got %s", *c.JWTLeeway)
	}
	if c.MaxTokenBytes == 0 {
		c.MaxTokenBytes = defaultMaxTokenBytes
	}
	if c.MaxTokenBytes < 0 {
		return fmt.Errorf("max_token_bytes must not be negative, got %d", c.MaxTokenBytes)
	}
	if c.JWKSRefetchCooldown == 0 {
		c.JWKSRefetchCooldown = defaultJWKSRefetchCooldown
	}
	if c.JWKSRefetchCooldown < 0 {
		return fmt.Errorf("jwks_refetch_cooldown must not be negative, got %s", c.JWKSRefetchCooldown)
	}
	if c.MaxTokenLifetime < 0 {
		return fmt.Errorf("max_token_lifetime must not be negative, got %s", c.MaxTokenLifetime)
	}
	if c.MaxTokenLifetime == 0 {
		c.MaxTokenLifetime = defaultMaxTokenLifetime
	}
	if c.MaxTokenAge < 0 {
		return fmt.Errorf("max_token_age must not be negative, got %s", c.MaxTokenAge)
	}
	if c.MaxTokenAge == 0 {
		c.MaxTokenAge = defaultMaxTokenAge
	}
	if c.LogLevel == "" {
		c.LogLevel = defaultLogLevel
	}
	if !validLogLevels[c.LogLevel] {
		return fmt.Errorf("log_level must be one of debug/info/warn/error, got %q", c.LogLevel)
	}
	if c.AuditRequired && (!c.LogToS3 || c.LogBucket == "") {
		return errors.New("audit_required requires log_to_s3=true and log_bucket to be configured")
	}

	if c.DefaultIssuer != "" && !seenIssuers[c.DefaultIssuer] {
		return fmt.Errorf("default_issuer %q is not a configured issuer", c.DefaultIssuer)
	}
	soleIssuer := ""
	if len(c.Issuers) == 1 {
		soleIssuer = c.Issuers[0].Issuer
	}
	// implicitlyBound counts mappings that got their issuer from default_issuer
	// rather than declaring one, while more than one issuer is configured — see
	// the warning emitted after the effective set is built.
	implicitlyBound := 0
	resolveIssuer := func(explicit string) (string, error) {
		switch {
		case explicit != "":
			if !seenIssuers[explicit] {
				return "", fmt.Errorf("issuer %q is not a configured issuer", explicit)
			}
			return explicit, nil
		case c.DefaultIssuer != "":
			if len(c.Issuers) > 1 {
				implicitlyBound++
			}
			return c.DefaultIssuer, nil
		case soleIssuer != "":
			return soleIssuer, nil
		default:
			return "", errors.New("issuer must be set explicitly (or via default_issuer) when multiple issuers are configured")
		}
	}

	// effective is rebuilt from scratch every Validate() call so repeated
	// validation (e.g. a hot-reload clone) is idempotent: role_groups always
	// re-expand from their source, never from a previously-expanded state.
	c.effective = make([]*RoleMapping, 0, len(c.RoleMappings))

	appendEffective := func(m RoleMapping, source string, i int) error {
		if m.Subject == "" || len(m.Roles) == 0 {
			return fmt.Errorf("%s[%d]: subject and roles are required", source, i)
		}
		resolvedIssuer, err := resolveIssuer(m.Issuer)
		if err != nil {
			return fmt.Errorf("%s[%d] (%s): %w", source, i, m.Subject, err)
		}
		m.Issuer = resolvedIssuer

		roles, err := c.resolveRoleSet(m.Roles)
		if err != nil {
			return fmt.Errorf("%s[%d] (%s): %w", source, i, m.Subject, err)
		}
		if len(roles) == 0 {
			return fmt.Errorf("%s[%d] (%s): subject and roles are required", source, i, m.Subject)
		}
		m.Roles = roles

		m.compiledPattern, err = compileAnchoredSubject(m.Subject)
		if err != nil {
			return fmt.Errorf("%s[%d]: invalid subject pattern %q: %w", source, i, m.Subject, err)
		}

		// Clone the condition into effective-private memory BEFORE compiling.
		// compileCondition mutates *Condition in place (it reslices
		// cond.compiled to [:0] and re-appends), and a single *Condition can be
		// shared across snapshots — a config_fragment reuses its parsed
		// FragmentConfig across hot reloads (provider.applyFragments), and a
		// role_group shares one Defaults.Conditions across every expanded
		// subject. Compiling a shared struct in place would race a concurrent
		// request reading the currently-served snapshot's compiled slice and
		// could momentarily blank it, silently passing all conditions. Cloning
		// here guarantees compileCondition only ever writes to a struct owned by
		// this effective mapping.
		m.Conditions = cloneCondition(m.Conditions)
		if err := compileCondition(m.Conditions); err != nil {
			return fmt.Errorf("%s[%d] (%s): %w", source, i, m.Subject, err)
		}

		m.order = len(c.effective)
		c.effective = append(c.effective, &m)
		return nil
	}

	for i := range c.RoleMappings {
		if err := appendEffective(c.RoleMappings[i], "role_mappings", i); err != nil {
			return err
		}
	}

	for gi := range c.RoleGroups {
		group := &c.RoleGroups[gi]
		if len(group.Subjects) == 0 {
			return fmt.Errorf("role_groups[%d]: subjects must not be empty", gi)
		}
		for si, subject := range group.Subjects {
			m := RoleMapping{
				Subject:           subject,
				Issuer:            group.Issuer,
				Roles:             group.Defaults.Roles,
				Conditions:        group.Defaults.Conditions,
				SessionPolicy:     group.Defaults.SessionPolicy,
				SessionPolicyFile: group.Defaults.SessionPolicyFile,
			}
			if err := appendEffective(m, fmt.Sprintf("role_groups[%d].subjects", gi), si); err != nil {
				return err
			}
		}
	}

	// A mapping that declares no issuer binds to default_issuer. With a single
	// configured issuer that is unambiguous, but once a second issuer exists
	// the same mappings silently move into whichever namespace default_issuer
	// names — so an overlay that adds an issuer AND sets default_issuer in one
	// merge re-homes every previously-implicit grant, with no redeploy. Fragments
	// are guarded against this (mergeFragment requires a base-defined,
	// non-conflicting default_issuer); the primary overlay is not, so surface it.
	if implicitlyBound > 0 {
		slog.Warn("mappings are bound to default_issuer while multiple issuers are configured; "+
			"set an explicit issuer on each mapping to pin it",
			slog.Int("mappingCount", implicitlyBound),
			slog.String("defaultIssuer", c.DefaultIssuer),
			slog.Int("issuerCount", len(c.Issuers)))
	}

	c.index = buildAuthzIndex(c.effective)
	warnUnscopedRoleGrants(c.effective)

	// Calculate the average number of roles per mapping for more efficient memory allocation
	totalRoles := 0
	for _, mapping := range c.effective {
		totalRoles += len(mapping.Roles)
	}

	if len(c.effective) > 0 {
		c.estimatedRolesPerMapping = (totalRoles / len(c.effective)) + 1 // Add 1 as safety margin
	} else {
		c.estimatedRolesPerMapping = 4 // Default if no mappings
	}

	// Normalize tag-auth defaults so the feature works even when Config is built
	// directly (e.g. in tests) without going through viper defaults.
	if c.TagAuth != nil {
		// multiIssuer gates the <prefix>issuer requirement in TagAuth.Authorize
		// (no cross-issuer identity collision via tag-auth).
		c.TagAuth.multiIssuer = len(c.Issuers) > 1

		if c.TagAuth.DefaultOrg != "" && strings.ContainsAny(c.TagAuth.DefaultOrg, "/ \t\n\r") {
			return fmt.Errorf("tag_auth.default_org %q must not contain '/' or whitespace", c.TagAuth.DefaultOrg)
		}
		if c.TagAuth.Enabled && c.TagAuth.TagPrefix == "" {
			c.TagAuth.TagPrefix = "aow/"
		}
	}

	// Normalize cross-account transport defaults, mirroring the tag-auth block
	// above for directly-built Configs.
	if c.CrossAccount != nil && c.CrossAccount.Enabled {
		if c.CrossAccount.SpokeRoleName == "" {
			c.CrossAccount.SpokeRoleName = "aow-spoke"
		}
		if c.CrossAccount.SpokeSessionDuration == 0 {
			c.CrossAccount.SpokeSessionDuration = 15 * time.Minute
		}
		for i, acct := range c.CrossAccount.AllowedAccounts {
			c.CrossAccount.AllowedAccounts[i] = strings.TrimSpace(acct)
			if !accountIDPattern.MatchString(c.CrossAccount.AllowedAccounts[i]) {
				return fmt.Errorf("cross_account.allowed_accounts entry %q is not a 12-digit AWS account ID", acct)
			}
		}
		if len(c.CrossAccount.AllowedAccounts) == 0 {
			slog.Warn("cross_account enabled with empty allowed_accounts; the warden may assume into ANY member account. Populate cross_account.allowed_accounts in production.")
		}
	}

	// Validate jwt_validation.mode, defaulting to "self" if not set.
	if c.JWTValidation.Mode == "" {
		c.JWTValidation.Mode = "self"
	}
	validModes := map[string]bool{"self": true, "apigw": true, "alb": true}
	if !validModes[c.JWTValidation.Mode] {
		return fmt.Errorf("jwt_validation.mode must be one of 'self', 'apigw', 'alb'; got %q", c.JWTValidation.Mode)
	}
	// alb_expected_signer is required in alb mode — without it any ALB can inject
	// a signed OIDC header and impersonate any GitHub repository (cross-ALB spoofing).
	if c.JWTValidation.Mode == "alb" && c.JWTValidation.ALBExpectedSigner == "" {
		return fmt.Errorf("jwt_validation.alb_expected_signer is required in alb mode to prevent cross-ALB token injection")
	}

	return nil
}

// resolveRoleSet expands any "@name" alias in roles to c.RoleSets[name],
// leaving literal role ARNs untouched. Resolution happens once, at Validate()
// time, before AuthorizeRoles' role∈roles security gate ever runs, so an
// alias can never widen a request beyond what's statically configured
// (the token never selects the role set, config does).
func (c *Config) resolveRoleSet(roles []string) ([]string, error) {
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		if !strings.HasPrefix(r, "@") {
			out = append(out, r)
			continue
		}
		name := strings.TrimPrefix(r, "@")
		set, ok := c.RoleSets[name]
		if !ok {
			return nil, fmt.Errorf("role_sets: %q is not defined", name)
		}
		if len(set) == 0 {
			return nil, fmt.Errorf("role_sets: %q must not be empty", name)
		}
		out = append(out, set...)
	}
	return out, nil
}

// compileCondition compiles every pattern on a Condition (nil is valid: no
// conditions means unconditional match) into the AND'd (claim, pattern) list
// checked by satisfiesConditions. Every named field compiles through the same
// anchored-regex mechanism as Extra, so "same mechanism" (D4) holds even for
// fields that used to be plain string equality (ref_type/event_name/
// environment) — an anchored regex over a literal string matches identically
// to `==`, so this is a pure widening, not a behavior change for existing
// literal configs.
func compileCondition(cond *Condition) error {
	if cond == nil {
		return nil
	}

	cond.compiled = cond.compiled[:0]
	add := func(claim, pattern string) error {
		if pattern == "" {
			return nil
		}
		re, err := compileAnchoredCondition(pattern)
		if err != nil {
			return fmt.Errorf("invalid pattern for %q: %w", claim, err)
		}
		cond.compiled = append(cond.compiled, compiledCondition{claim: claim, pattern: re})
		return nil
	}

	// NOTE: Branch and Ref intentionally both check the raw "ref" claim; this
	// mirrors pre-existing behavior.
	if err := add("ref", cond.Branch); err != nil {
		return err
	}
	if err := add("ref", cond.Ref); err != nil {
		return err
	}
	if err := add("ref_type", cond.RefType); err != nil {
		return err
	}
	if err := add("event_name", cond.EventName); err != nil {
		return err
	}
	if err := add("workflow_ref", cond.WorkflowRef); err != nil {
		return err
	}
	if err := add("runner_environment", cond.Environment); err != nil {
		return err
	}

	for claim, pattern := range cond.Extra {
		if err := add(claim, pattern); err != nil {
			return err
		}
	}

	if len(cond.ActorMatches) > 0 {
		cond.actorPatterns = make([]*regexp.Regexp, len(cond.ActorMatches))
		for i, pattern := range cond.ActorMatches {
			re, err := compileAnchoredCondition(pattern)
			if err != nil {
				return fmt.Errorf("invalid actor_matches pattern %q: %w", pattern, err)
			}
			cond.actorPatterns[i] = re
		}
	}

	return nil
}

// cloneCondition returns a deep copy of c with fresh, unshared compiled state.
// The input slices/maps (ActorMatches, Extra) are copied so the clone shares no
// backing storage with c, and the derived compiled/actorPatterns fields are
// reset to nil so compileCondition rebuilds them into freshly allocated memory
// rather than reslicing a backing array another snapshot may be reading.
// Returns nil for a nil input (a mapping with no conditions).
func cloneCondition(c *Condition) *Condition {
	if c == nil {
		return nil
	}
	nc := *c
	nc.compiled = nil
	nc.actorPatterns = nil
	if c.ActorMatches != nil {
		nc.ActorMatches = append([]string(nil), c.ActorMatches...)
	}
	if c.Extra != nil {
		nc.Extra = make(map[string]string, len(c.Extra))
		for k, v := range c.Extra {
			nc.Extra[k] = v
		}
	}
	return &nc
}

// bareWildcards are patterns that match every possible value. They must never
// gate an authorization decision — as a condition OR as a subject — because
// they reduce that gate to "always true".
//
// This is a literal check on the two shapes operators actually reach for, not
// a general "does this regex match everything" analysis: that is not something
// we can decide cheaply, and a determined operator can still write an
// equivalent pattern (`(.*)`, `.*.*`, `[\s\S]*`). It closes the documented
// footgun and makes the accident loud; it is not a proof of specificity.
var bareWildcards = map[string]bool{".*": true, ".+": true}

// compileAnchoredCondition compiles pattern as an auto-anchored regex,
// rejecting empty patterns and bare wildcards that would match anything
// (security conditions must be specific, never `.*`).
func compileAnchoredCondition(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, errors.New("pattern must not be empty")
	}
	if bareWildcards[pattern] {
		return nil, fmt.Errorf("pattern %q is too permissive; use a specific pattern", pattern)
	}
	return regexp.Compile("^(?:" + pattern + ")$")
}

// compileAnchoredSubject compiles a role_mapping/role_group subject pattern as
// an auto-anchored regex. It applies the same bare-wildcard rejection as
// compileAnchoredCondition: a subject is the primary identity gate, so
// `subject: ".*"` would grant its roles to every subject of the bound issuer —
// every repository in every org that can mint a token that issuer signs.
//
// The documentation has always said "keep patterns specific, never `.*`";
// until now nothing enforced it for subjects, only for conditions.
func compileAnchoredSubject(pattern string) (*regexp.Regexp, error) {
	if bareWildcards[pattern] {
		return nil, fmt.Errorf("subject pattern %q is too permissive; it matches every subject for this issuer — use a specific pattern", pattern)
	}
	return regexp.Compile("^(?:" + pattern + ")$")
}

// warnUnscopedRoleGrants logs a warning for every (issuer, role) that is
// granted by more than one effective mapping where the LOWEST-order grant
// carries no session policy but some higher-order grant does.
//
// FindSessionPolicy is lowest-order-wins among the mappings that grant a role,
// so in that shape the deliberately-scoped mapping's policy is silently
// dropped and the role is assumed unscoped. Within role_mappings the operator
// can fix this by reordering, but across the role_mappings/role_groups
// boundary they CANNOT: appendEffective assigns order by append sequence and
// every role_mapping is appended before every role_group, so a role_group's
// session policy can never outrank a policy-less role_mapping for the same
// role no matter how the file is written.
//
// The selection rule itself is deliberate and pinned by
// TestOrderWinsAmongMappingsGrantingTheSameRole, so this makes the footgun
// loud at config-load time rather than changing authorization semantics.
// Subject overlap is not computed (regex intersection is not decidable
// cheaply); sharing a role is a deliberate over-approximation, since a role
// granted twice with inconsistent scoping is worth surfacing regardless.
func warnUnscopedRoleGrants(effective []*RoleMapping) {
	type grant struct{ lowest, scoped *RoleMapping }
	grants := make(map[string]*grant)

	for _, m := range effective {
		hasPolicy := m.SessionPolicy != "" || m.SessionPolicyFile != ""
		for _, role := range m.Roles {
			key := m.Issuer + "\x00" + role
			g, ok := grants[key]
			if !ok {
				g = &grant{}
				grants[key] = g
			}
			if g.lowest == nil || m.order < g.lowest.order {
				g.lowest = m
			}
			if hasPolicy && (g.scoped == nil || m.order < g.scoped.order) {
				g.scoped = m
			}
		}
	}

	for key, g := range grants {
		if g.scoped == nil || g.lowest == nil || g.lowest == g.scoped {
			continue
		}
		issuer, role, _ := strings.Cut(key, "\x00")
		slog.Warn("role is granted by an unscoped mapping that outranks a scoped one; "+
			"the session policy will NOT be applied when both match",
			slog.String("issuer", issuer),
			slog.String("role", role),
			slog.String("winningSubject", g.lowest.Subject),
			slog.String("ignoredPolicySubject", g.scoped.Subject))
	}
}

// satisfiesConditions reports whether claims satisfy every AND'd condition
// (both the named-field conditions and any generic Extra entries), plus the
// OR'd actor_matches dimension. A nil Condition always satisfies (no gate).
func satisfiesConditions(cond *Condition, claims map[string]any) bool {
	if cond == nil {
		return true
	}

	for _, cc := range cond.compiled {
		val, ok := claims[cc.claim].(string)
		if !ok || !cc.pattern.MatchString(val) {
			return false
		}
	}

	if len(cond.actorPatterns) > 0 {
		actor, ok := claims["actor"].(string)
		if !ok {
			return false
		}
		matched := false
		for _, pattern := range cond.actorPatterns {
			if pattern.MatchString(actor) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// IssuerSessionTags returns the session_tags spec (STS tag key -> raw claim
// name) configured for issuer, or nil if issuer is not configured or has no
// session_tags. Used to drive aws.BuildSessionTags at role-assumption time.
func (c *Config) IssuerSessionTags(issuer string) map[string]string {
	for i := range c.Issuers {
		if c.Issuers[i].Issuer == issuer {
			return c.Issuers[i].SessionTags
		}
	}
	return nil
}

// FindSessionPolicy returns the session policy that scopes the assumption of
// role by (issuer, subject) under claims. The policy is taken from the specific
// mapping that AUTHORIZED this role — one that matches the subject, satisfies
// its conditions, AND grants role — never from an unrelated broader mapping
// that merely shares the subject. This mirrors AuthorizeRoles' match semantics
// exactly, so a role's scoping policy always travels with the grant.
//
// Selecting by subject alone (the pre-fix behavior) dropped the policy of a
// narrow, deliberately-scoped mapping whenever an earlier-declared broad
// mapping also matched the subject, causing a privileged role to be assumed
// unscoped. Among several qualifying mappings the first-declared (lowest order)
// wins, preserving first-match-wins semantics within the correct candidate set.
//
// Returns (nil, nil) when no mapping grants role — e.g. a role authorized via
// tag-auth, which carries no config-declared session policy. Bucketing into the
// index is purely a performance detail: every candidate is re-verified against
// its compiled pattern (index↔linear-scan parity).
func (c *Config) FindSessionPolicy(issuer, subject, role string, claims map[string]any) (*string, *string) {
	idx, ok := c.index[issuer]
	if !ok {
		return nil, nil
	}

	var best *RoleMapping
	for _, mapping := range candidatesFor(idx, subject) {
		if mapping.compiledPattern == nil || !mapping.compiledPattern.MatchString(subject) {
			continue
		}
		if !satisfiesConditions(mapping.Conditions, claims) {
			continue
		}
		if !slices.Contains(mapping.Roles, role) {
			continue
		}
		if best == nil || mapping.order < best.order {
			best = mapping
		}
	}

	if best == nil {
		return nil, nil
	}
	if best.SessionPolicyFile != "" {
		return nil, &best.SessionPolicyFile
	}
	if best.SessionPolicy != "" {
		return &best.SessionPolicy, nil
	}
	return nil, nil
}

// AuthorizeRoles evaluates every role_mapping/role_group entry bound to
// issuer whose subject pattern matches subject and whose conditions (if any)
// are satisfied by claims, and returns the union of their roles. The returned
// bool is true only when at least one mapping fully matched (subject pattern
// AND conditions); a subject that matches a pattern but fails that mapping's
// conditions does not count unless another mapping fully matches.
func (c *Config) AuthorizeRoles(issuer, subject string, claims map[string]any) (bool, []string) {
	capacity := c.estimatedRolesPerMapping
	if capacity < 4 {
		capacity = 4
	}
	roles := make([]string, 0, capacity)
	matched := false

	idx, ok := c.index[issuer]
	if !ok {
		return false, roles
	}

	for _, mapping := range candidatesFor(idx, subject) {
		if mapping.compiledPattern == nil || !mapping.compiledPattern.MatchString(subject) {
			continue
		}

		if !satisfiesConditions(mapping.Conditions, claims) {
			continue
		}

		matched = true
		roles = append(roles, mapping.Roles...)
	}

	return matched, roles
}
