# Handler — Request Processing Pipeline

Extends [../../CLAUDE.md](../../CLAUDE.md). Core request logic shared by all deployments.

## Files

- `bootstrap.go` — `NewBootstrap(adapter)` wires dependencies (`adapter` is stamped into every log line); constructs the correct `ClaimsExtractorInterface` from `cfg.JWTValidation.Mode`. Holds both `Validator` (kept for external use) and `Extractor` (used by processor). Ends with `warmJWKSCache(mode, validator)`: a best-effort JWKS prefetch during cold start (Lambda INIT), **self mode only** (delegated modes never consult JWKS) and bounded by `jwksWarmPrefetchTimeout` (3s) so an unreachable issuer can't stall INIT — on timeout the first request just pays the fetch as before. It reuses the same fetch/cache/validation path, so it changes only _when_ a key is fetched, never whether it is trusted.
- `processor.go` — `ProcessRequest(ctx, requestData, input, requestID, log)`. Takes `ExtractionInput` and calls `extractor.Extract()` instead of `validator.Validate()` directly. It captures one `cfg := provider.Get()` after `MaybeRefresh` and sets `input.Config = cfg`, so claim extraction and authorization are decided by the same config generation — the extractors would otherwise read the provider again and a reload landing between the two reads would split one request across two generations.
- `types.go` — `RequestData`/response structs and sentinel errors. In delegated modes, `RequestData.Token` may be empty.
- `validation.go` — `ValidateRequestData` (self mode), `ParseRoleOnlyRequestBody` (delegated modes — only `role` required), shared `validateRole()` helper.
- `errors.go` — `classifyError`: the single sentinel-error → HTTP status + error-code map every adapter serializes through.
- `response.go` — shared success/error response construction.
- `reqcontext.go` — `resolveRequestID` / `clientIP`; the only supported way for an adapter to derive `requestId`, `frontendRequestId`, and `sourceIp`.
- `audit.go` — `AuditSink` and the allow/deny audit record, including `auditClaims` (claim values formatted through `utils.FormatClaimValue`).
- `route.go` — classifies the IdP discovery/JWKS paths before the normal pipeline; near misses and wrong methods map to `idp_path_not_found` / `method_not_allowed`; the exact paths refresh config and answer `idp_path_not_found` while `idp.enabled` is false. Credentials always go through `/verify`.
- `idp.go` — `selectIdP` routes an `idp_token` role (in `idp.allowed_roles`) to `issueIdP` while `idp.enabled`; over 1h without it is refused. `issueIdP` mints and runs an in-process `AssumeRoleWithWebIdentity`; `ProcessRequest` (`processor.go`) is the single entry for both. `idp_helpers.go` — duration, session-name and source-identity resolution. `idp_document.go` — serves discovery/JWKS.
- `bootstrap.go` `NewIdPService` — builds the `idp.Service` whenever an `idp` block exists (keys warm only when `idp.enabled`); the KMS client comes from `DefaultIdPKMS`, its own wrapper, not the consumer's, so `RefreshClients` does not reach it.
- `apigateway.go` — REST API v1 adapter (`events.APIGatewayProxyRequest`). Passes `ExtractionInput{Token: requestData.Token}`; always self mode. IdP routes match `requestContext.path` (stage-qualified), not `event.Path`.
- `apigatewayv2.go` — HTTP API v2 adapter (`events.APIGatewayV2HTTPRequest`). Reads authorizer claims from `event.RequestContext.Authorizer.JWT.Claims`; use with `jwt_validation.mode: "apigw"`.
- `alb.go` — ALB adapter. Reads `x-amzn-oidc-data` header when present (delegated ALB mode); falls back to token-in-body (self mode).
- `lambdaurl.go` — Lambda URL adapter. Always self mode.

## Pipeline

`MaybeRefresh()` → `extractor.Extract(ctx, input)` → account allow-list guard (every request — `IsTargetAccountAllowed` itself encodes disabled-means-hub-only, so it fails closed rather than being skipped) → `cfg.AuthorizeRoles(issuer, subject, claims)` → tag-auth fallback (`cfg.TagAuth.Authorize`) → `cfg.FindSessionPolicy` → `cfg.EffectiveSessionTags` → role assumption → audit record.

## Conventions

- Entry points construct via `NewBootstrap(adapter)` then the matching `New…FromBootstrap`; Lambda mains start with `lambda.StartWithOptions(h.Handler, lambda.WithEnableSIGTERM(bootstrap.Cleanup))` — `lambda.Start` never returns, so a deferred `Cleanup()` never runs.
- `ClaimsExtractorInterface` is the only way claims enter `ProcessRequest` — never call `validator.Validate()` directly from adapters.
- In delegated mode, if the upstream injects no claims, `Extract()` returns an error that wraps `ErrTokenValidationFailed` — the bypass-prevention guard.
- `ParseRoleOnlyRequestBody` must be used by delegated adapters; `ParseRequestBody` requires a non-empty token.
- Classify failures with sentinel errors in `types.go`; `classifyError` (`errors.go`) maps them to HTTP status.
- Log via `logevent.{Debug,Info,Warn,Error}(ctx, log, event, msg, attrs...)` with the request-scoped logger and a catalog event, never a package-level `slog` call — `ctx` carries `requestId`/`frontendRequestId`/`sourceIp` correlation, which a bare `slog` call would lose. Never log token material; if a site ever must, redact it with `utils.RedactToken` first.
- Claim VALUES in the log stream (canonical subject included) go through `subjectAttr(cfg, …)` / the `cfg.LogClaimValues` gate, so `log_claim_values=false` holds across the whole log stream and not just the audit record.
- Test processor with `ClaimsExtractorInterface` mocks (not `TokenValidatorInterface`); the latter is for `SelfExtractor` unit tests only.
- Adapters must derive request identity through `reqcontext.go` (`resolveRequestID`/`clientIP`) rather than rolling their own — `requestId` is the Lambda invocation UUID (stable across frontends), `frontendRequestId` is the per-frontend ID kept as the join key back to API Gateway / ALB access logs, and `sourceIp` is always either a parsed IP or empty, never a non-IP value like an ARN.

## Gotchas

- `apigatewayv2.go` is the only adapter compatible with API Gateway JWT Authorizer — v1 REST API does not receive authorizer claims.
- The extractor is created once at bootstrap; changing `jwt_validation.mode` at runtime requires a Lambda cold start.
- A mapping sets `session_policy` or `session_policy_file`, never both; `Validate()` rejects both.
- S3 policy reads are bounded (`io.LimitReader`, 1 MB).
- Start time is carried in context (`StartTimeContextKey`).
- IdP kill switch: `idp.enabled` is live; when off, mint answers `503 idp_signing_unavailable` and discovery/JWKS answer 404 (after the 405 method check). Those routes call `RefreshIfDue`, never `MaybeRefresh`, so they never wait on a refresh. Env overrides S3 config. Past max-stale, `/verify` and mint answer `503 config_stale`; discovery/JWKS keep serving.
