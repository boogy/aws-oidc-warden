# Handler Package - Request Processing Pipeline

**Technology**: Go, AWS Lambda Events, HTTP
**Entry Point**: `bootstrap.go` (dependency injection), `processor.go` (business logic)
**Parent Context**: This extends [../../CLAUDE.md](../../CLAUDE.md)

---

## Development Commands

### From Package Directory

```bash
go test ./...              # Run handler tests
go test -v ./...           # Verbose test output
go test -cover ./...       # Coverage report
```

### From Root

```bash
make test                  # Run all tests including handler
go test -v ./pkg/handler/  # Test this package only
```

---

## Architecture

### Directory Structure

```
pkg/handler/
├── bootstrap.go     # Dependency injection and initialization
├── processor.go     # Core business logic (ProcessRequest)
├── types.go         # Request/response structures, errors
├── validation.go    # Input validation helpers
├── apigateway.go    # API Gateway event handler
├── lambdaurl.go     # Lambda URL event handler
└── alb.go           # ALB event handler
```

### Request Processing Flow

```
HTTP Request → Event Handler → ProcessRequest() → Token Validation → Constraint Check → Role Assumption → Response
```

---

## Code Organization Patterns

### Bootstrap Pattern (CRITICAL)

All initialization happens in `bootstrap.go`. Entry points use this pattern:

```go
// ✅ DO: Use Bootstrap for dependency injection
bootstrap, err := handler.NewBootstrap()
if err != nil {
    slog.Error("Failed to initialize", "error", err)
    os.Exit(1)
}
defer bootstrap.Cleanup() // CRITICAL: Flushes S3 logs

handler := handler.NewAwsApiGatewayFromBootstrap(bootstrap)
lambda.Start(handler.Handle)
```

```go
// ❌ DON'T: Initialize dependencies directly in handlers
func Handle(ctx context.Context, event events.APIGatewayProxyRequest) {
    cfg, _ := config.NewConfig()  // Wrong: creates new config per request
    consumer := aws.NewAwsConsumer(cfg)  // Wrong: inefficient
}
```

### Processor Pattern

Core business logic is in `processor.go:ProcessRequest()`:

```go
// ✅ DO: Follow the established processing pipeline
func (r *RequestProcessor) ProcessRequest(ctx context.Context, requestData *RequestData, requestID string, log *slog.Logger) (*types.Credentials, error) {
    // 1. Validate token
    claims, err := r.validator.Validate(requestData.Token)

    // 2. Check repository constraints
    matched, roles := r.config.MatchRolesToRepoWithConstraints(claims.Repository, claimsMap)

    // 3. Get session policy (if configured)
    sessionPolicy, err := r.getSessionPolicy(claims.Repository)

    // 4. Assume role
    credentials, err := r.consumer.AssumeRole(...)

    return credentials, nil
}
```

### Error Handling Pattern

Define sentinel errors in `types.go`, map to HTTP status in handlers:

```go
// ✅ DO: Use sentinel errors for error classification
// types.go
var (
    ErrRoleNotPermitted    = errors.New("role not permitted")
    ErrSessionPolicyAccess = errors.New("session policy access error")
    ErrAssumeRoleFailed    = errors.New("assume role failed")
)

// In processor.go
return nil, fmt.Errorf("failed to assume role: %w", ErrAssumeRoleFailed)

// In apigateway.go - map to HTTP status
switch {
case errors.Is(err, ErrRoleNotPermitted):
    return createErrorResponse(http.StatusForbidden, "permission_denied", ...)
case errors.Is(err, ErrSessionPolicyAccess):
    return createErrorResponse(http.StatusInternalServerError, "session_policy_error", ...)
}
```

### Logging Pattern

Use structured logging with request context:

```go
// ✅ DO: Add context to logger, use groups
log = log.With(
    slog.Group("request",
        slog.String("repository", claims.Repository),
        slog.String("ref", claims.Ref),
        slog.String("role", requestedRole),
        slog.String("actor", claims.Actor),
    ),
)

log.Info("Token validation successful",
    slog.Duration("validationTime", time.Since(startTime)),
)
```

```go
// ❌ DON'T: Use unstructured logging
log.Info(fmt.Sprintf("Validated token for %s in %v", repo, duration))
```

---

## Key Files

### Core Files (understand these first)

- `processor.go` - The main business logic; understand `ProcessRequest()` and `getSessionPolicy()`
- `bootstrap.go` - Dependency injection; `NewBootstrap()` initializes everything
- `types.go` - All data structures: `RequestData`, `ResponseData`, error definitions

### Event Handlers

- `apigateway.go` - `events.APIGatewayProxyRequest` → `events.APIGatewayProxyResponse`
- `lambdaurl.go` - `events.LambdaFunctionURLRequest` → `events.LambdaFunctionURLResponse`
- `alb.go` - `events.ALBTargetGroupRequest` → `events.ALBTargetGroupResponse`

All handlers have identical business logic, only event parsing differs.

---

## Quick Search Commands

### Find Handler Logic

```bash
# Find ProcessRequest implementation
rg -n "func.*ProcessRequest" pkg/handler/

# Find error handling
rg -n "errors.Is\|errors.As" pkg/handler/

# Find response creation
rg -n "createErrorResponse\|createSuccessResponse" pkg/handler/
```

### Find Types

```bash
# Find request/response types
rg -n "type.*struct" pkg/handler/types.go

# Find error definitions
rg -n "var Err" pkg/handler/types.go
```

---

## Common Gotchas

- **Cleanup is Critical**: Always `defer bootstrap.Cleanup()` to flush S3 logs
- **Context Values**: Start time is stored in context (`StartTimeContextKey`)
- **Token Redaction**: Always use `utils.RedactToken()` before logging tokens
- **Session Policy Priority**: Inline policy overrides S3 file if both exist
- **Size Limits**: S3 policy files limited to 1MB (`io.LimitReader`)

---

## Testing Guidelines

### Unit Tests

- Use mock interfaces (`AwsConsumerInterface`, `TokenValidatorInterface`)
- Test error paths explicitly
- Verify logging output for security-sensitive operations

### Integration Points

- Session policy loading from S3
- Constraint evaluation with claims
- AWS STS role assumption

### Test Pattern Example

```go
func TestProcessRequest_InvalidToken(t *testing.T) {
    mockValidator := &MockValidator{
        ValidateError: errors.New("invalid signature"),
    }

    processor := NewRequestProcessor(cfg, mockConsumer, mockValidator)

    _, err := processor.ProcessRequest(ctx, &RequestData{Token: "invalid"}, "req-1", log)

    assert.Error(t, err)
    assert.Contains(t, err.Error(), "token validation failed")
}
```
