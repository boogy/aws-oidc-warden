# Handler — Request Processing Pipeline

Extends [../../CLAUDE.md](../../CLAUDE.md). Core request logic shared by all deployments.

## Files

- `bootstrap.go` — `NewBootstrap()` wires dependencies; constructs the correct `ClaimsExtractorInterface` from `cfg.JWTValidation.Mode`. Holds both `Validator` (kept for external use) and `Extractor` (used by processor).
- `processor.go` — `ProcessRequest(ctx, requestData, input, requestID, log)`. Takes `ExtractionInput` and calls `extractor.Extract()` instead of `validator.Validate()` directly.
- `types.go` — `RequestData`/response structs and sentinel errors. In delegated modes, `RequestData.Token` may be empty.
- `validation.go` — `ValidateRequestData` (self mode), `ParseRoleOnlyRequestBody` (delegated modes — only `role` required), shared `validateRole()` helper.
- `apigateway.go` — REST API v1 adapter (`events.APIGatewayProxyRequest`). Passes `ExtractionInput{Token: requestData.Token}`; always self mode.
- `apigatewayv2.go` — HTTP API v2 adapter (`events.APIGatewayV2HTTPRequest`). Reads authorizer claims from `event.RequestContext.Authorizer.JWT.Claims`; use with `jwt_validation.mode: "apigw"`.
- `alb.go` — ALB adapter. Reads `x-amzn-oidc-data` header when present (delegated ALB mode); falls back to token-in-body (self mode).
- `lambdaurl.go` — Lambda URL adapter. Always self mode.

## Pipeline

`MaybeRefresh()` → `extractor.Extract(ctx, input)` → account allow-list guard (if `TagAuth.Enabled`) → `cfg.AuthorizeRoles(issuer, subject, claims)` → tag-auth fallback (`cfg.TagAuth.Authorize`) → `cfg.FindSessionPolicy` → `cfg.IssuerSessionTags` → role assumption → audit record.

## Conventions

- Entry points construct via `NewBootstrap()` then the matching `New…FromBootstrap`; always `defer bootstrap.Cleanup()`.
- `ClaimsExtractorInterface` is the only way claims enter `ProcessRequest` — never call `validator.Validate()` directly from adapters.
- In delegated mode, if the upstream injects no claims, `Extract()` returns an error that wraps `ErrTokenValidationFailed` — the bypass-prevention guard.
- `ParseRoleOnlyRequestBody` must be used by delegated adapters; `ParseRequestBody` requires a non-empty token.
- Classify failures with sentinel errors in `types.go`; adapters map them to HTTP status via `errors.Is`.
- Structured logging with request context (`slog.With`); redact tokens with `utils.RedactToken` before logging.
- Test processor with `ClaimsExtractorInterface` mocks (not `TokenValidatorInterface`); the latter is for `SelfExtractor` unit tests only.

## Gotchas

- `apigatewayv2.go` is the only adapter compatible with API Gateway JWT Authorizer — v1 REST API does not receive authorizer claims.
- The extractor is created once at bootstrap; changing `jwt_validation.mode` at runtime requires a Lambda cold start.
- Inline session policy overrides the S3 file when both are set.
- S3 policy reads are bounded (`io.LimitReader`, 1 MB).
- Start time is carried in context (`StartTimeContextKey`).
