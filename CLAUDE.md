# AWS OIDC Warden

## Overview

- **Type**: Go service for OIDC token validation and AWS credential exchange
- **Stack**: Go +1.25, AWS Lambda, AWS SDK v2, JWT-go v5, Viper
- **Architecture**: Multi-deployment Lambda service with shared core logic
- **Deployments**: API Gateway, Lambda URLs, ALB, Local HTTP server

This CLAUDE.md is the authoritative source for development guidelines.
Subdirectory-specific CLAUDE.md files extend these rules.

---

## Universal Development Rules

### Code Quality (MUST)

- **MUST** follow Go idioms and conventions (effective Go)
- **MUST** use structured logging with `log/slog` (never `fmt.Print` for logs)
- **MUST** run `make check` (fmt + lint + test) before committing
- **MUST** handle all errors explicitly (no ignored returns)
- **MUST** close all readers/connections with deferred cleanup
- **MUST NOT** commit AWS credentials, tokens, or secrets
- **MUST NOT** use `panic` except in truly unrecoverable situations
- **MUST** sign all commits and tags
- **MUST NOT** include co-author for claude

### Best Practices (SHOULD)

- **SHOULD** use interfaces for testability (see `AwsConsumerInterface`, `TokenValidatorInterface`)
- **SHOULD** use table-driven tests for comprehensive coverage
- **SHOULD** pre-compile regex patterns during initialization (see `config.Validate()`)
- **SHOULD** limit external data reads (see `io.LimitReader` in `processor.go:158`)
- **SHOULD** validate JSON before processing external input
- **SHOULD** use `slog.Group` for structured log context

### Anti-Patterns (MUST NOT)

- **MUST NOT** use `any` type without explicit type assertions
- **MUST NOT** ignore error returns from `Close()` methods
- **MUST NOT** compile regex at runtime in hot paths
- **MUST NOT** use overly permissive regex patterns like `.*` for security constraints
- **MUST NOT** log full tokens or credentials (use `utils.RedactToken`)

---

## Core Commands

### Development

```bash
make build-local        # Build local development binary
make run                # Start local server on :8080 with example-config.yaml
make test               # Run all tests
make test-verbose       # Run tests with verbose output
make test-coverage      # Generate coverage report
make fmt                # Format code with go fmt
make lint               # Run golangci-lint
make check              # Run fmt + lint + test (pre-commit)
```

### Lambda Builds

```bash
make build-lambda       # Build all Lambda variants (ARM64)
make build-apigateway   # Build API Gateway handler → build/bootstrap-apigateway
make build-alb          # Build ALB handler → build/bootstrap-alb
make build-lambdaurl    # Build Lambda URL handler → build/bootstrap-lambdaurl
```

### Container & Release

```bash
make ko-build           # Build container images locally
make ko-publish         # Publish to ghcr.io
make release            # Create release with GoReleaser
make release-snapshot   # Create snapshot release
```

### Quality Gates (run before PR)

```bash
make check && make build-lambda
```

---

## Project Structure

### Entry Points (`cmd/`)

- **`cmd/apigateway/`** → API Gateway + Lambda (production with rate limiting)
- **`cmd/lambdaurl/`** → Lambda Function URLs (simple setup)
- **`cmd/alb/`** → Application Load Balancer (high traffic)
- **`cmd/local/`** → Local HTTP server (development)

All handlers share the same core logic via `pkg/handler/bootstrap.go`.

### Core Packages (`pkg/`)

- **`pkg/handler/`** → Request processing pipeline ([see pkg/handler/CLAUDE.md](pkg/handler/CLAUDE.md))
  - `bootstrap.go` - Dependency injection
  - `processor.go` - Core business logic
  - `types.go` - Request/response structures
  - `validation.go` - Input validation

- **`pkg/validator/`** → OIDC token validation ([see pkg/validator/CLAUDE.md](pkg/validator/CLAUDE.md))
  - `validator.go` - JWT parsing and verification

- **`pkg/config/`** → Configuration management
  - `config.go` - Viper-based configuration with `AOW_` env prefix

- **`pkg/cache/`** → Multi-tier caching system
  - `memory.go` - LRU in-memory cache
  - `dynamodb.go` - DynamoDB persistence
  - `s3.go` - S3 large object cache

- **`pkg/aws/`** → AWS service interactions
  - `consumer.go` - STS AssumeRole, S3, IAM operations
  - `service_wrapper.go` - AWS client initialization

### Documentation (`docs/`)

- `ARCHITECTURE.md` - System architecture and data flow
- `CONFIGURATION.md` - Complete configuration reference
- `SESSION_TAGGING.md` - AWS session tagging patterns

### Configuration

- `example-config.yaml` - Full configuration reference with all options
- Environment variables: `AOW_` prefix (e.g., `AOW_ISSUER`, `AOW_CACHE_TYPE`)

---

## Quick Find Commands

### Code Navigation

```bash
# Find handler implementations
rg -n "func.*Handle" pkg/handler/

# Find interface definitions
rg -n "type.*Interface" pkg/

# Find configuration options
rg -n "mapstructure:" pkg/config/config.go

# Find error definitions
rg -n "var Err" pkg/handler/

# Find AWS operations
rg -n "func.*\(.*AwsConsumer" pkg/aws/
```

### Test Discovery

```bash
# Find all tests
rg -n "func Test" --type go

# Find tests for specific package
rg -n "func Test" pkg/validator/

# Find test helpers
rg -n "func.*Helper\|Mock" --type go
```

### Configuration Search

```bash
# Find env variable bindings
rg -n "BindEnv" pkg/config/

# Find default values
rg -n "SetDefault" pkg/config/

# Find constraint fields
rg -n "type Constraint struct" -A 20 pkg/config/
```

---

## Architecture Patterns

### Bootstrap Pattern (Critical)

All Lambda handlers use dependency injection via `pkg/handler/bootstrap.go`:

```go
// Always use this pattern in cmd/* files
bootstrap, err := handler.NewBootstrap()
if err != nil {
    slog.Error("Failed to initialize", "error", err)
    os.Exit(1)
}
defer bootstrap.Cleanup() // Critical for S3 log flushing

handler := handler.NewAwsApiGatewayFromBootstrap(bootstrap)
lambda.Start(handler.Handle)
```

### Request Processing Pipeline

```
Token Validation → Repository Matching → Constraint Checking → Session Policy → Role Assumption
```

See `pkg/handler/processor.go:ProcessRequest()` for implementation.

### Error Handling Convention

Use wrapped errors with proper HTTP status mapping:

```go
// Define sentinel errors in pkg/handler/types.go
var ErrRoleNotPermitted = errors.New("role not permitted")
var ErrSessionPolicyAccess = errors.New("session policy access error")

// Map to HTTP status in handlers
switch {
case errors.Is(err, ErrRoleNotPermitted):
    statusCode = http.StatusForbidden
case errors.Is(err, ErrSessionPolicyAccess):
    statusCode = http.StatusInternalServerError
}
```

### Caching Strategy

Three-tier caching (`pkg/cache/`):

| Tier     | Use Case      | TTL           | Implementation         |
| -------- | ------------- | ------------- | ---------------------- |
| Memory   | Hot data      | Minutes-hours | LRU with max size      |
| DynamoDB | Persistence   | Hours         | TTL-based expiration   |
| S3       | Large objects | Days          | Metadata TTL + cleanup |

### Configuration Pattern

Viper with environment variable overrides (`AOW_` prefix):

```go
// Environment variables override YAML config
AOW_ISSUER=https://token.actions.githubusercontent.com
AOW_AUDIENCES=sts.amazonaws.com,custom.company.com  // Comma-separated
AOW_CACHE_TYPE=dynamodb
AOW_CACHE_DYNAMODB_TABLE=my-cache-table
```

---

## Security Guidelines

### Token Handling

- **NEVER** log full tokens (use `utils.RedactToken(token, 10, 10)`)
- **ALWAYS** validate JWT signature against JWKS
- **ALWAYS** check issuer, audience, and expiration claims
- **VALIDATE** repository patterns precisely (avoid overly permissive regex)

### Session Policy Security

```go
// Always validate JSON before processing
var jsonCheck any
if err := json.Unmarshal(policyBytes, &jsonCheck); err != nil {
    return fmt.Errorf("invalid JSON: %w", ErrSessionPolicyAccess)
}

// Always limit file reads
policyBytes, err := io.ReadAll(io.LimitReader(reader, 1024*1024)) // 1MB limit
```

### Constraint System Security

Use precise regex patterns in `repo_role_mappings`:

```yaml
# GOOD: Specific repository
repo: "^myorg/specific-repo$"

# GOOD: Namespaced pattern
repo: "^myorg/service-.*$"

# BAD: Overly permissive
repo: ".*"
```

### Safe Operations

- Review generated bash commands before execution
- Confirm before: git force push, `rm -rf`, database operations
- Use staging environment for testing role assumptions

---

## Git Workflow

- Branch from `main` for features: `feature/description`
- Use Conventional Commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`
- PRs require: passing CI (tests, lint, security scan)
- Squash commits on merge
- Delete branches after merge

### Commit Message Examples

```
feat: add support for multiple OIDC audiences
fix: prevent panic on nil JWKS response
docs: update configuration examples for DynamoDB cache
refactor: extract constraint validation to separate function
test: add integration tests for multi-audience validation
```

---

## Testing Requirements

### Unit Tests

- Location: Colocated with source (`*_test.go`)
- Framework: `testing` + `testify/assert`
- Pattern: Table-driven tests for comprehensive coverage
- Example: `pkg/validator/validator_test.go`

### Integration Tests

- Location: `pkg/validator/integration_test.go`
- Purpose: End-to-end flows with mock JWKS servers
- Pattern: Start test HTTP server, generate test JWTs

### Running Tests

```bash
make test               # Run all tests
make test-verbose       # Verbose output
make test-coverage      # Generate coverage report → coverage.html
```

### Test Patterns

```go
// Use interfaces for mocking (see pkg/aws/consumer.go)
type AwsConsumerInterface interface {
    AssumeRole(...) (*types.Credentials, error)
    GetS3Object(...) (io.ReadCloser, error)
}

// Table-driven tests
func TestConstraintValidation(t *testing.T) {
    tests := []struct {
        name        string
        constraint  *Constraint
        claims      map[string]any
        wantMatch   bool
    }{
        {"branch match", &Constraint{Branch: "refs/heads/main"}, ...},
        {"branch mismatch", &Constraint{Branch: "refs/heads/main"}, ...},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // test logic
        })
    }
}
```

---

## Available Tools

You have access to:

- Standard bash tools (rg, git, go, make)
- GitHub CLI (`gh`) for issues, PRs, releases
- Go tools (`go test`, `go fmt`, `golangci-lint`)

### Tool Permissions

- Read any file
- Write code files (`.go`, `.yaml`, `.md`)
- Run tests, linters, formatters
- Build binaries
- **ASK FIRST**: Editing `example-config.yaml` with real values
- **ASK FIRST**: Force push operations
- **ASK FIRST**: Modifying CI/CD workflows

---

## Key Files to Understand First

1. `pkg/handler/processor.go` - Core business logic
2. `pkg/validator/validator.go` - Token validation
3. `pkg/config/config.go` - Configuration and constraints
4. `pkg/aws/consumer.go` - AWS operations
5. `example-config.yaml` - Configuration reference
6. `docs/ARCHITECTURE.md` - System design

---

## Common Gotchas

- **Lambda Binary Name**: Must be named `bootstrap` for AWS Lambda runtime
- **Build Tags**: Use `-tags=lambda.norpc` for Lambda builds (performance)
- **Default Architecture**: ARM64 (`GOOS=linux GOARCH=arm64`) for cost efficiency
- **Config Priority**: Environment variables > config file > defaults
- **Audience Validation**: Supports both legacy single and new multi-audience
- **Regex Anchoring**: Repository patterns auto-anchored with `^(?:pattern)$`
- **Constraint Logic**: All constraints must match (AND logic, not OR)
