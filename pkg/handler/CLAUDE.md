# Handler — Request Processing Pipeline

Extends [../../CLAUDE.md](../../CLAUDE.md). Core request logic shared by all deployments.

## Files

- `bootstrap.go` — `NewBootstrap()` wires dependencies (config, validator, cache, AWS consumer).
- `processor.go` — `ProcessRequest()` is the pipeline; `getSessionPolicy()` resolves inline-or-S3 policy.
- `types.go` — `RequestData`/response structs and sentinel errors (`ErrRoleNotPermitted`, `ErrSessionPolicyAccess`, …).
- `validation.go` — input validation helpers.
- `apigateway.go` / `lambdaurl.go` / `alb.go` — frontend adapters. Identical business logic; only event parse/serialize differs.

Pipeline: `MaybeRefresh()` config snapshot → token validation → account allow-list guard (if `tag_auth.enabled`) → `MatchRolesToRepoWithConstraints` (explicit) → tag-auth fallback (`GetRoleTags` + `TagAuth.Authorize`, if enabled and explicit match failed) → session policy resolution → role assumption.

## Conventions

- Entry points construct via `NewBootstrap()` then the matching `New…FromBootstrap`; always `defer bootstrap.Cleanup()` — it flushes S3 logs.
- Classify failures with sentinel errors in `types.go`; adapters map them to HTTP status via `errors.Is`.
- Structured logging with request context (`slog.With` + `slog.Group`); redact tokens with `utils.RedactToken` before logging.
- Test with `TokenValidatorInterface` / `AwsConsumerInterface` mocks; cover error paths.

## Gotchas

- Inline session policy overrides the S3 file when both are set.
- S3 policy reads are bounded (`io.LimitReader`, 1MB).
- Start time is carried in context (`StartTimeContextKey`).
