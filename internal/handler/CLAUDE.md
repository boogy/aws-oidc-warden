# Handler — Request Processing Pipeline

Extends [../../CLAUDE.md](../../CLAUDE.md). Core request logic shared by all deployments.

## Files

- `bootstrap.go` — `NewBootstrap()` wires dependencies; constructs the correct `ClaimsExtractorInterface` from `cfg.JWTValidation.Mode`. Holds both `Validator` (kept for external use) and `Extractor` (used by processor). Ends with `warmJWKSCache(mode, validator)`: a best-effort JWKS prefetch during cold start (Lambda INIT), **self mode only** (delegated modes never consult JWKS) and bounded by `jwksWarmPrefetchTimeout` (3s) so an unreachable issuer can't stall INIT — on timeout the first request just pays the fetch as before. It reuses the same fetch/cache/validation path, so it changes only _when_ a key is fetched, never whether it is trusted.
- `processor.go` — `ProcessRequest(ctx, requestData, input, requestID, log)`. Takes `ExtractionInput` and calls `extractor.Extract()` instead of `validator.Validate()` directly.
- `types.go` — `RequestData`/response structs and sentinel errors. In delegated modes, `RequestData.Token` may be empty.
- `validation.go` — `ValidateRequestData` (self mode), `ParseRoleOnlyRequestBody` (delegated modes — only `role` required), shared `validateRole()` helper.
- `apigateway.go` — REST API v1 adapter (`events.APIGatewayProxyRequest`). Passes `ExtractionInput{Token: requestData.Token}`; always self mode.
- `apigatewayv2.go` — HTTP API v2 adapter (`events.APIGatewayV2HTTPRequest`). Reads authorizer claims from `event.RequestContext.Authorizer.JWT.Claims`; use with `jwt_validation.mode: "apigw"`.
- `alb.go` — ALB adapter. Reads `x-amzn-oidc-data` header when present (delegated ALB mode); falls back to token-in-body (self mode).
- `lambdaurl.go` — Lambda URL adapter. Always self mode.

## Pipeline

`MaybeRefresh()` → `extractor.Extract(ctx, input)` → account allow-list guard (if `CrossAccount.Enabled`) → `cfg.AuthorizeRoles(issuer, subject, claims)` → tag-auth fallback (`cfg.TagAuth.Authorize`) → `cfg.FindSessionPolicy` → `cfg.IssuerSessionTags` → role assumption → audit record.

## Conventions

- Entry points construct via `NewBootstrap()` then the matching `New…FromBootstrap`; always `defer bootstrap.Cleanup()`.
- `ClaimsExtractorInterface` is the only way claims enter `ProcessRequest` — never call `validator.Validate()` directly from adapters.
- In delegated mode, if the upstream injects no claims, `Extract()` returns an error that wraps `ErrTokenValidationFailed` — the bypass-prevention guard.
- `ParseRoleOnlyRequestBody` must be used by delegated adapters; `ParseRequestBody` requires a non-empty token.
- Classify failures with sentinel errors in `types.go`; adapters map them to HTTP status via `errors.Is`.
- Structured logging with the request-scoped logger (`slog.With`), never the package-level `slog` — a package-level call writes past the request logger, losing `requestId` correlation and escaping any handler a test installed. Never log token material; if a site ever must, redact it with `utils.RedactToken` first.
- Claim VALUES in the log stream (canonical subject included) go through `subjectAttr(cfg, …)` / the `cfg.LogClaimValues` gate, so `log_claim_values=false` holds across the whole log stream and not just the audit record.
- Test processor with `ClaimsExtractorInterface` mocks (not `TokenValidatorInterface`); the latter is for `SelfExtractor` unit tests only.
- Adapters must derive request identity through `reqcontext.go` (`resolveRequestID`/`clientIP`) rather than rolling their own — `requestId` is the Lambda invocation UUID (stable across frontends), `frontendRequestId` is the per-frontend ID kept as the join key back to API Gateway / ALB access logs, and `sourceIp` is always either a parsed IP or empty, never a non-IP value like an ARN.

## Gotchas

- `apigatewayv2.go` is the only adapter compatible with API Gateway JWT Authorizer — v1 REST API does not receive authorizer claims.
- The extractor is created once at bootstrap; changing `jwt_validation.mode` at runtime requires a Lambda cold start.
- Inline session policy overrides the S3 file when both are set.
- S3 policy reads are bounded (`io.LimitReader`, 1 MB).
- Start time is carried in context (`StartTimeContextKey`).
