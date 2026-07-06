# Logging, audit & observability

The service emits structured `slog` JSON to stdout (CloudWatch) and, when
enabled, a durable per-decision audit trail to S3. Secrets are never logged:
no path logs a raw JWT or credential.

**Every authorization decision — allow _and_ deny — is always logged** as one
standardized `slog` line, emitted before (and independently of) any S3 write.
In Lambda that stream lands in CloudWatch Logs, which is itself durable, so the
decision trail is never off. `audit_required` and `log_to_s3` add a _second_,
S3-based structured trail on top of that baseline; they do not enable or
disable decision logging itself.

## Knobs

| key                         | env                                 | default | meaning                                                                                                                                                                                |
| --------------------------- | ----------------------------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `log_level`                 | `AOW_LOG_LEVEL`                     | `info`  | `debug` / `info` / `warn` / `error`; **validated but not wired to the running handler** — see note below                                                                               |
| `LOG_LEVEL` (no `AOW_`)     | `LOG_LEVEL`                         | `info`  | the env var that actually sets `slog` verbosity at bootstrap (Lambda), or `-log-level` in `cmd/local`                                                                                  |
| `log_claim_values`          | `AOW_LOG_CLAIM_VALUES`              | `false` | when false, claim **values** are suppressed in both logs and audit records (names/decision/reason kept)                                                                                |
| `audit_required`            | `AOW_AUDIT_REQUIRED`                | `false` | when true, an allow decision's audit record is written **before** credentials are returned; a write failure denies the request (fail-closed). Requires `log_to_s3=true` + `log_bucket` |
| `log_to_s3`                 | `AOW_LOG_TO_S3`                     | `false` | persist logs/audit records to S3                                                                                                                                                       |
| `log_bucket` / `log_prefix` | `AOW_LOG_BUCKET` / `AOW_LOG_PREFIX` | —       | S3 destination                                                                                                                                                                         |

## Decision log / audit record fields

One record is produced per authorization decision (allow **and** deny). The
same redacted record backs both the standardized log line and the durable
audit record, so they never disagree.

Always present: `requestId`, `frontend`, `jwtMode`, `decision` (`allow`/`deny`),
`processingMs`. Deny adds `stage` (`extract` / `account_check` /
`claims_processing` / `authorize` / `session_policy` / `assume_role`) and
`reason`. Allow adds `issuer`, `provider`, `matchedVia` (`explicit`/`tag-auth`),
`requestedRole`, `grantedRole`, `accountId`, `sessionTagKeys`,
`sessionPolicyRef`, `expiry`.

Claim **values** — `jwtSub` (raw `sub`), `subject` (canonical identity),
`audience`, and resolved `sessionTags` — appear only when
`log_claim_values=true`. `sessionTagKeys` (names only) are always present.

Records are built with `encoding/json`, which escapes control characters, so a
claim value containing newlines cannot forge a log line or break the record.

> **`log_level` note:** `log_level` / `AOW_LOG_LEVEL` is validated (an unknown
> level name is rejected at config load) but is **not** applied to the running
> `slog` handler, whose level is fixed at bootstrap from the bare `LOG_LEVEL`
> env var (Lambda) or the `-log-level` flag (`cmd/local`). To change verbosity,
> set `LOG_LEVEL` / `-log-level`, not `AOW_LOG_LEVEL`.

## Security signals (for SIEM)

Warn/error lines carry context (never secrets) for: unknown/unconfigured
issuer, signature failure, algorithm/key-type mismatch, expired / `nbf` /
max-age rejection, audience mismatch, condition failure (by claim name +
match result), oversized token, forced JWKS refetch (and cooldown-suppressed
storms), fragment-rejected keys, account-not-allowed, and assume-role failure.

## Durability note (Lambda)

With `audit_required=false` (the default, best-effort), every decision record
is appended to the amortized batch buffer — the same one `WriteLogToS3` feeds
— and flushed by size (`BatchSize`), age (`MaxBatchAge`), or `Cleanup()`.
Batched flushing runs on a timer that is frozen between Lambda invocations, so
buffered records can be lost at container reclaim. When you need a guaranteed
trail, set `audit_required=true`: each decision record is written
synchronously (bypassing the batch buffer) before the credential response, and
a write failure fails the request closed. Treat container-shutdown flushing as
a best-effort backstop only.

## Production hardening recommendation

For any security-sensitive deployment, enable the durable, fail-closed trail:

```yaml
log_to_s3: true
log_bucket: "your-audit-bucket" # object-lock / WORM + restrictive bucket policy
audit_required: true # deny rather than issue credentials with no audit record
```

The default (`audit_required: false`) favors availability and zero-dependency
startup: it never blocks credential issuance on S3, and it lets the service run
with no S3 bucket configured. It is the right default for local/dev and for
deployments that treat CloudWatch Logs as the system of record. It is **not**
the recommended posture when the audit trail is a compliance or security
control — there, a lost or unwritten record must fail the request, which is
exactly what `audit_required: true` guarantees. Point CloudWatch alerts at
`errorCode=audit_write_failed` so a failing sink is paged, not silently
tolerated.

## Suggested CloudWatch alerts

- Spike in `decision=deny` with `stage=authorize` (misconfigured mappings or an
  attack).
- Any `errorCode=audit_write_failed` (audit sink unavailable under
  `audit_required`).
- Forced-JWKS-refetch rate climbing (possible bogus-`kid` flooding).
