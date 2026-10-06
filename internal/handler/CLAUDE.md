# Handler — Request Processing Pipeline

Extends [../../CLAUDE.md](../../CLAUDE.md). Core request logic shared by all deployments.

## Files

- `bootstrap.go` — `NewBootstrap(adapter)` wires dependencies (`adapter` is stamped into every log line); constructs the correct `ClaimsExtractorInterface` from `cfg.JWTValidation.Mode`. Holds the `Extractor` the processor uses. Ends with `warmJWKSCache(mode, validator)`: a best-effort JWKS prefetch during cold start (Lambda INIT), **self mode only** (delegated modes never consult JWKS) and bounded by `jwksWarmPrefetchTimeout` (3s) so an unreachable issuer can't stall INIT — on timeout the first request just pays the fetch as before. It reuses the same fetch/cache/validation path, so it changes only _when_ a key is fetched, never whether it is trusted. `warmCallerIdentity` then primes the consumer's cached STS caller identity (via `IsTargetAccountAllowed` on a placeholder ARN, `callerWarmTimeout` 3s) so the first AssumeRole skips `GetCallerIdentity`; a failure only logs `app.warm.failure` (Warn) and never fails bootstrap.
- `processor.go` — `ProcessRequest(ctx, requestData, input, requestID, log)`. Takes `ExtractionInput` and calls `extractor.Extract()` instead of `validator.Validate()` directly. It captures one `cfg := provider.Get()` after `RefreshIfDue` and sets `input.Config = cfg`, so claim extraction and authorization are decided by the same config generation — the extractors would otherwise read the provider again and a reload landing between the two reads would split one request across two generations.
- `types.go` — `RequestData`/response structs and sentinel errors. In delegated modes, `RequestData.Token` may be empty.
- `validation.go` — `ValidateRequestData` (self mode), `ParseRoleOnlyRequestBody` (delegated modes — only `role` required), shared `validateRole()` helper. Bodies are capped at `maxBodyBytes` (twice the token+role limits plus 4 KiB, under 40 KiB); an over-cap body is `ErrInvalidJSON`, while a token or role over its own limit still gets its specific error.
- `errors.go` — `classifyError`: the single sentinel-error → HTTP status + error-code map every adapter serializes through.
- `response.go` — shared success/error response construction.
- `reqcontext.go` — `resolveRequestID` / `clientIP`; the only supported way for an adapter to derive `requestId`, `frontendRequestId`, and `sourceIp`.
- `audit.go` — `AuditSink` and the allow/deny audit record, including `auditClaims` (claim values formatted through `utils.FormatClaimValue`). Under `audit_required`, every decision is a synchronous `WriteRecord` except extract-stage (pre-auth) denies, flagged `preAuth`, which are batched via `BufferRecord` so unauthenticated floods cannot throttle the S3 prefix.
- `route.go` — classifies the IdP discovery/JWKS paths before the normal pipeline; near misses and wrong methods map to `idp_path_not_found` / `method_not_allowed`; the exact paths refresh config and answer `idp_path_not_found` while `idp.enabled` is false. Credentials always go through `/verify`. `WithIdP` precomputes the frozen paths (lowercased), the source-identity template and the IdP issuer once, so per-request routing and minting do no template parsing.
- `idp.go` — `selectIdP` routes a mapping with `idp_token` or `max_session_duration` over 1h (`Decision.IDPTokenAllowed`) to `issueIdP` while `idp.enabled`; over 1h without it is refused. `issueIdP` mints and runs an in-process `AssumeRoleWithWebIdentity`; `ProcessRequest` (`processor.go`) is the single entry for both. `idp_helpers.go` — duration, session-name and source-identity resolution. `idp_document.go` — serves discovery/JWKS.
- `bootstrap.go` `NewIdPService` — builds the `idp.Service` whenever an `idp` block exists (keys warm only when `idp.enabled`); the KMS client comes from `DefaultIdPKMS`, the shared `AwsServiceWrapper` singleton the consumer also uses.
- `apigateway.go` — REST API v1 adapter (`events.APIGatewayProxyRequest`). Passes `ExtractionInput{Token: requestData.Token}`; always self mode. IdP routes match `requestContext.path` (stage-qualified), not `event.Path`.
- `apigatewayv2.go` — HTTP API v2 adapter (`events.APIGatewayV2HTTPRequest`). Reads authorizer claims from `event.RequestContext.Authorizer.JWT.Claims`; use with `jwt_validation.mode: "apigw"`.
- `alb.go` — ALB adapter. The path follows `jwt_validation.mode` captured at construction, never header presence: `alb` mode reads `x-amzn-oidc-data` with a role-only body (a missing header still reaches `ALBExtractor` and is denied); `self` mode reads the token from the body and ignores the header (an ALB authenticate action always sets it).
- `lambdaurl.go` — Lambda URL adapter. Always self mode.

## Pipeline

`RefreshIfDue()` → `extractor.Extract(ctx, input)` → stale gate (authenticated callers only: waits on `MaybeRefresh`, re-extracts against the refreshed config, else `503 config_stale`) → account allow-list guard (every request — `IsTargetAccountAllowed` itself encodes disabled-means-hub-only, so it fails closed rather than being skipped) → `cfg.AuthorizeRoles(issuer, subject, claims)` → tag-auth fallback (`cfg.TagAuth.Authorize`) → `cfg.FindSessionPolicy` → `cfg.EffectiveSessionTags` → role assumption → audit record.

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
- S3 policy reads are bounded (`io.LimitReader`, 1 MB). With `session_policy_bucket_owner` set they go through `GetS3ObjectIfChanged(…, "", owner)` (ExpectedBucketOwner); unset, `BuildConfigProvider` logs `policy.s3_owner_unpinned` once.
- Start time is carried in context (`StartTimeContextKey`).
- IdP kill switch: `idp.enabled` is live; when off, mint answers `503 idp_signing_unavailable` and discovery/JWKS answer 404 (after the 405 method check). Those routes call `RefreshIfDue`, never `MaybeRefresh`, so they never wait on a refresh. Env overrides S3 config. Past max-stale, `/verify` and mint answer `503 config_stale`; discovery/JWKS keep serving.
