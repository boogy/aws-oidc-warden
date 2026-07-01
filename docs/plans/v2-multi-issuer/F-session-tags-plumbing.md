# Group F — Session tags & role-assumption plumbing

Prereqs: B, D. Files: `internal/aws/` (session-tag fn), `internal/handler/processor.go` + adapters.
**Read `SHARED.md` first** — invariants 1, 8, 11.

## Tasks

- **F1** `BuildSessionTags(rawClaims map[string]any, tagSpec map[string]string)` (was `CreateSessionTags`) → one STS tag per `tagKey: claimName` where value non-empty. Enforce STS limits **and charset**: ≤50 tags; key ≤128 / value ≤256; chars `[A-Za-z0-9 _.:/=+@-]`. **Skip + `log()`** invalid tags — never coerce/mangle a value an ABAC condition might trust.
- **F2** Plumb the matched issuer's `session_tags` from the validated request through `processor.go` → `AssumeRole`. **Preserve invariant #1** (requested role ∈ matched mapping's resolved roles — the token never picks an arbitrary role). `TransitiveSessionTags` applies over the configured tag set.
- **F3 (S10)** No internal-detail leakage: STS/IAM/role/account errors → generic client denial via sentinel-error mapping; full detail only in logs/audit. Validate requested session duration within STS bounds (and `SpokeSessionDuration` for TagAuth cross-account).
- **F4 (cleanup)** Dedupe adapter boilerplate: extract the repeated `requestID` (ctx → uuid fallback) + `processingMS` (`time.Since(startTime).Milliseconds()`) + response-field set + structured-log block into one shared helper in `internal/handler` (e.g. `requestMeta`/`finalizeResponse`), called by `alb.go`, `apigatewayv2.go`, `lambdaurl.go` (+ v1 if present). Preserve the uuid fallback and redaction-on-log **exactly**.

## Security review F

tag injection / ABAC trust (invalid value skipped not mangled); requested-role gate intact (token can't escalate); transitive-tag scope; TagAuth × multi-issuer interaction; **and** the shared helper didn't drop the requestID fallback or change what's logged (no token/credential leakage).

## Verification slice

- `BuildSessionTags`: illegal-charset value → tag skipped (not mangled) + logged; >50 tags bounded; empty value skipped.
- Requested-role not in matched roles → deny. STS error → generic client denial, detail only in logs.
- Adapter helper parity: requestID fallback + redaction preserved across all frontends.
- `make check` + `go test -race ./internal/aws/... ./internal/handler/...` green.

## Commit

`feat(aws,handler): config-driven session tags + role-assumption plumbing` → update `PROGRESS.md`.
