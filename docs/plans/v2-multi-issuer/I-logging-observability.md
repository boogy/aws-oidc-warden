# Group I — Logging, audit & observability (cross-cutting)

Built incrementally alongside A–G; reviewed as a unit after G. Files: `internal/s3logger/`, `internal/utils/` (redaction), `internal/handler/processor.go` + adapters, `internal/config` (`log_level`, `log_claim_values`, `audit_required` knobs).
**Read `SHARED.md` first** — invariant 11.

## Tasks

- **I1 Structured logging contract.** Standardize `slog` fields everywhere: `requestId`, `frontend`, `jwtMode`, `issuer`, `provider`, `jwtSub` (the `sub` claim), canonical `subject` (authz identity), `audience`, `kid`, `cacheResult`, `decision`, `reason`, `matchedRole`, `accountId`, `processingMs`, `stage`. One helper attaches base fields (composes with F4's request-meta helper).
- **I2 Audit log via `internal/s3logger`.** A structured record for **every decision** — issuance (verified identity, matched issuer, matched mapping or TagAuth path, requested+granted role, account, session tags applied, session policy ref, expiry) **and every denial** (reason + failing stage).
  - **Durability (V8, high):** `Flush()` is `defer`'d in `main()` → in Lambda it runs only at container reclaim and the batch timer is frozen between invocations, so buffered records can be lost. When `audit_required=true`, **flush the record synchronously before returning** (always flush an issuance before responding with credentials). Treat `Cleanup()` / the Lambda `SHUTDOWN` hook as best-effort backstop only.
- **I3 Security-signal logging (warn/error for SIEM).** Anomalies with context (no secrets): unknown/unconfigured issuer, signature failure, alg/key-type mismatch, expired/`nbf`/max-age rejection, JWKS refetch (+ cooldown-suppressed storms), audience mismatch, condition failures (log the failing **condition name + match result**, not raw sensitive values), oversized token, fragment-rejected keys.
- **I4 Secret-safety & log-injection.** Never log raw JWT/credentials — reference tokens by `kid`/`sub`/`jti`; route through `internal/utils` `RedactToken`. Log claim **values** as structured fields only (no string concat → no log-forging). Add `log_level` + `log_claim_values` (default off): suppress values while keeping claim names + decisions.
- **I5 Observability.** Per-stage timings (validate/JWKS/match/assume) + counters (cache hit ratio, deny-reason tally, JWKS fetch count) as structured fields; optional CloudWatch EMF — **low-cardinality dims only** (issuer/decision/reason/frontend/mode); high-cardinality (subject/sub/requestId) in logs (O2).
- **I6 `audit_required` knob (O1):** off = log-and-continue on audit-write failure (availability); on = fail-closed (deny) when the trail can't be persisted.

## Security review I (ADVERSARIAL)

grep the whole diff for any path logging a raw token/credential or full claim set; redaction on **every** error branch; no log-injection via claim values; audit captures **both** allow and deny with sufficient-but-not-excessive detail; `log_claim_values=off` actually suppresses values everywhere; `audit_required=true` truly flushes before returning credentials.

## Verification slice

- Audit record emitted on **both** allow and deny (required fields; deny includes failing stage). With `audit_required=true`, the record is durably written before the credential response (not buffer-only).
- Negative: error at each stage → no raw token/credential in logs (`RedactToken` applied); `log_claim_values=off` → values absent, names+decision present.
- Log-injection: claim value with newlines/control chars doesn't break log structure.
- `make check` + `go test -race ./...` green.

## Commit

`feat(logging): structured contract, durable audit trail, SIEM signals, observability` → update `PROGRESS.md`.
