# Logging, audit & observability

The service emits structured `slog` JSON to stdout (CloudWatch) and, when
enabled, a durable per-decision audit trail to S3. Secrets are never logged:
no path logs a raw JWT or credential.

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

Batched log flushing runs on a timer that is frozen between Lambda invocations,
so buffered records can be lost at container reclaim. When you need a guaranteed
trail, set `audit_required=true`: each issuance record is written synchronously
(bypassing the batch buffer) before the credential response, and a write
failure fails the request closed. Treat container-shutdown flushing as a
best-effort backstop only.

## Suggested CloudWatch alerts

- Spike in `decision=deny` with `stage=authorize` (misconfigured mappings or an
  attack).
- Any `errorCode=audit_write_failed` (audit sink unavailable under
  `audit_required`).
- Forced-JWKS-refetch rate climbing (possible bogus-`kid` flooding).
