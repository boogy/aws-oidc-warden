# Config Package - Configuration Management

**Technology**: Go, Viper, Regex
**Entry Point**: `config.go`
**Parent Context**: This extends [../../CLAUDE.md](../../CLAUDE.md)

---

## Development Commands

### From Package Directory

```bash
go test ./...              # Run config tests
go test -v ./...           # Verbose output
```

### From Root

```bash
go test -v ./pkg/config/   # Test this package
```

---

## Architecture

### Directory Structure

```
pkg/config/
├── config.go      # Configuration loading, validation, constraint matching
└── config_test.go # Unit tests
```

### Configuration Flow

```
Environment Variables → Viper → YAML/JSON/TOML File → Defaults → Validation → Regex Compilation
```

---

## Code Organization Patterns

### Singleton Pattern

Configuration is loaded once and reused:

```go
// ✅ DO: Use NewConfig() to get singleton instance
cfg, err := config.NewConfig()
if err != nil {
    slog.Error("Config error", "error", err)
    os.Exit(1)
}

// The same instance is returned on subsequent calls
cfg2, _ := config.NewConfig()  // Same instance as cfg
```

### Configuration Sources (Priority Order)

1. Environment variables (`AOW_` prefix)
2. Configuration file (YAML/JSON/TOML)
3. Default values

```go
// Environment variables always win
AOW_ISSUER=https://custom.issuer.com  // Overrides config file

// Config file values
issuer: "https://file.issuer.com"  // Overridden by env var

// Default values (lowest priority)
viper.SetDefault("issuer", "https://token.actions.githubusercontent.com")
```

### Constraint Pattern

Repository mappings with regex-based constraints:

```go
// ✅ DO: Define precise constraints
type Constraint struct {
    Branch       string   `mapstructure:"branch"`        // "refs/heads/main"
    Ref          string   `mapstructure:"ref"`           // "refs/tags/v.*"
    RefType      string   `mapstructure:"ref_type"`      // "branch", "tag"
    EventName    string   `mapstructure:"event_name"`    // "push", "pull_request"
    WorkflowRef  string   `mapstructure:"workflow_ref"`  // "deploy\\.ya?ml$"
    Environment  string   `mapstructure:"environment"`   // "production"
    ActorMatches []string `mapstructure:"actor_matches"` // ["admin-.*"]
}

// All constraints use AND logic - ALL must match
```

### Regex Pre-compilation Pattern

Patterns are compiled during validation for performance:

```go
// ✅ DO: Pre-compile patterns in Validate()
func (c *Config) Validate() error {
    for i := range c.RepoRoleMappings {
        mapping := &c.RepoRoleMappings[i]

        // Compile repository pattern with anchors
        mapping.compiledPattern, err = regexp.Compile("^(?:" + mapping.Repo + ")$")
        if err != nil {
            return fmt.Errorf("invalid repository pattern '%s': %w", mapping.Repo, err)
        }

        // Compile constraint patterns
        if mapping.Constraints != nil {
            if mapping.Constraints.Branch != "" {
                mapping.Constraints.branchPattern, err = regexp.Compile("^" + mapping.Constraints.Branch + "$")
            }
            // ... other patterns
        }
    }
    return nil
}
```

```go
// ❌ DON'T: Compile regex at runtime
func checkBranch(pattern, branch string) bool {
    re := regexp.MustCompile(pattern)  // Wrong: expensive, called per request
    return re.MatchString(branch)
}
```

---

## Key Structures

### Config (Main Structure)

```go
type Config struct {
    Issuer                string            `mapstructure:"issuer"`
    Audience              string            `mapstructure:"audience"`              // Deprecated
    Audiences             []string          `mapstructure:"audiences"`             // Preferred
    S3ConfigBucket        string            `mapstructure:"s3_config_bucket"`
    S3SessionPolicyBucket string            `mapstructure:"session_policy_bucket"`
    RoleSessionName       string            `mapstructure:"role_session_name"`
    RepoRoleMappings      []RepoRoleMapping `mapstructure:"repo_role_mappings"`
    LogToS3               bool              `mapstructure:"log_to_s3"`
    LogBucket             string            `mapstructure:"log_bucket"`
    LogPrefix             string            `mapstructure:"log_prefix"`
    Cache                 *Cache            `mapstructure:"cache"`
}
```

### RepoRoleMapping

```go
type RepoRoleMapping struct {
    Repo              string      `mapstructure:"repo"`                // "org/repo" or regex
    SessionPolicy     string      `mapstructure:"session_policy"`      // Inline JSON
    SessionPolicyFile string      `mapstructure:"session_policy_file"` // S3 key
    Roles             []string    `mapstructure:"roles"`               // Allowed role ARNs
    Constraints       *Constraint `mapstructure:"constraints"`         // Optional constraints
    compiledPattern   *regexp.Regexp                                   // Pre-compiled
}
```

### Cache Configuration

```go
type Cache struct {
    Type          string        `mapstructure:"type"`           // "memory", "dynamodb", "s3"
    TTL           time.Duration `mapstructure:"ttl"`            // "1h", "4h"
    MaxLocalSize  int           `mapstructure:"max_local_size"` // For memory cache
    DynamoDBTable string        `mapstructure:"dynamodb_table"`
    S3Bucket      string        `mapstructure:"s3_bucket"`
    S3Prefix      string        `mapstructure:"s3_prefix"`
    S3Cleanup     bool          `mapstructure:"s3_cleanup"`
}
```

---

## Environment Variables

All configuration can be set via environment variables with `AOW_` prefix:

| Variable                    | Config Key              | Default                                       |
| --------------------------- | ----------------------- | --------------------------------------------- |
| `AOW_ISSUER`                | `issuer`                | `https://token.actions.githubusercontent.com` |
| `AOW_AUDIENCE`              | `audience`              | `sts.amazonaws.com`                           |
| `AOW_AUDIENCES`             | `audiences`             | `["sts.amazonaws.com"]`                       |
| `AOW_ROLE_SESSION_NAME`     | `role_session_name`     | `aws-oidc-warden`                             |
| `AOW_CACHE_TYPE`            | `cache.type`            | `memory`                                      |
| `AOW_CACHE_TTL`             | `cache.ttl`             | `1h`                                          |
| `AOW_CACHE_MAX_LOCAL_SIZE`  | `cache.max_local_size`  | `10`                                          |
| `AOW_CACHE_DYNAMODB_TABLE`  | `cache.dynamodb_table`  | -                                             |
| `AOW_LOG_TO_S3`             | `log_to_s3`             | `false`                                       |
| `AOW_LOG_BUCKET`            | `log_bucket`            | -                                             |
| `AOW_SESSION_POLICY_BUCKET` | `session_policy_bucket` | -                                             |

---

## Quick Search Commands

### Find Configuration Options

```bash
# Find all mapstructure tags
rg -n 'mapstructure:"' pkg/config/

# Find environment variable bindings
rg -n "BindEnv\|SetEnvPrefix" pkg/config/

# Find default values
rg -n "SetDefault" pkg/config/
```

### Find Constraint Logic

```bash
# Find constraint checking
rg -n "satisfiesConstraints" pkg/config/

# Find role matching
rg -n "MatchRolesToRepo" pkg/config/
```

---

## Constraint Matching Logic

### satisfiesConstraints Function

All constraints must be satisfied (AND logic):

```go
// All specified constraints must pass
func satisfiesConstraints(constraints *Constraint, claims map[string]any) bool {
    // Branch constraint (matches 'ref' claim)
    if constraints.Branch != "" {
        ref, ok := claims["ref"].(string)
        if !ok || !constraints.branchPattern.MatchString(ref) {
            return false
        }
    }

    // Ref constraint (direct ref matching)
    if constraints.Ref != "" {
        ref, ok := claims["ref"].(string)
        if !ok || !constraints.refPattern.MatchString(ref) {
            return false
        }
    }

    // RefType constraint (exact match)
    if constraints.RefType != "" {
        refType, ok := claims["ref_type"].(string)
        if !ok || refType != constraints.RefType {
            return false
        }
    }

    // EventName constraint (exact match)
    if constraints.EventName != "" {
        eventName, ok := claims["event_name"].(string)
        if !ok || eventName != constraints.EventName {
            return false
        }
    }

    // WorkflowRef constraint (regex match)
    if constraints.WorkflowRef != "" {
        workflow, ok := claims["workflow_ref"].(string)
        if !ok || !constraints.workflowPattern.MatchString(workflow) {
            return false
        }
    }

    // ActorMatches constraint (any pattern matches)
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

    return true
}
```

---

## Common Gotchas

- **Regex Anchoring**: Repository patterns auto-wrapped with `^(?:pattern)$`
- **Backward Compatibility**: `audience` (string) and `audiences` ([]string) both supported
- **Case Sensitivity**: Environment variables are case-insensitive, config keys use snake_case
- **Nested Keys**: Use underscore for nested env vars: `AOW_CACHE_TTL` for `cache.ttl`
- **Constraint Logic**: ALL constraints must match (AND), not OR
- **Pattern Compilation**: Happens once during `Validate()`, not per request

---

## Testing Guidelines

### Unit Tests

```go
func TestConfig_MatchRolesToRepoWithConstraints(t *testing.T) {
    tests := []struct {
        name       string
        config     *Config
        repo       string
        claims     map[string]any
        wantMatch  bool
        wantRoles  []string
    }{
        {
            name: "branch constraint match",
            config: &Config{
                RepoRoleMappings: []RepoRoleMapping{{
                    Repo:  "myorg/myrepo",
                    Roles: []string{"arn:aws:iam::123:role/test"},
                    Constraints: &Constraint{Branch: "refs/heads/main"},
                }},
            },
            repo:      "myorg/myrepo",
            claims:    map[string]any{"ref": "refs/heads/main"},
            wantMatch: true,
            wantRoles: []string{"arn:aws:iam::123:role/test"},
        },
        // ... more test cases
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            _ = tt.config.Validate()  // Compile patterns
            gotMatch, gotRoles := tt.config.MatchRolesToRepoWithConstraints(tt.repo, tt.claims)
            assert.Equal(t, tt.wantMatch, gotMatch)
            assert.Equal(t, tt.wantRoles, gotRoles)
        })
    }
}
```

### Configuration File Examples

```yaml
# Minimal config
issuer: "https://token.actions.githubusercontent.com"
audiences: ["sts.amazonaws.com"]
role_session_name: "aws-oidc-warden"
repo_role_mappings:
  - repo: "myorg/myrepo"
    roles: ["arn:aws:iam::123456789012:role/my-role"]

# With constraints
repo_role_mappings:
  - repo: "myorg/.*"
    roles: ["arn:aws:iam::123456789012:role/my-role"]
    constraints:
      branch: "refs/heads/main"
      event_name: "push"
      actor_matches: ["admin-.*"]
```
