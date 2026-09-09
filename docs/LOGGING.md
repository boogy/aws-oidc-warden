# Logging, audit & observability

The service emits structured `slog` JSON to stdout (CloudWatch) and, when enabled, a durable per-decision audit trail to S3. **No path logs a raw JWT or credential.**

**Every authorization decision — allow *and* deny — is always logged** as one standardized `slog` line, emitted before and independently of any S3 write. In Lambda that stream lands in CloudWatch Logs, which is itself durable, so the decision trail is never off. `log_to_s3` and `audit_required` add a *second*, S3-based trail on top of that baseline; they do not switch decision logging on or off.

All output is JSON (`slog.NewJSONHandler` is the only handler constructed anywhere in the service, enforced by `TestLogOutputIsJSON` / `TestBootstrapLoggerIsJSONHandler`), so a downstream parser can rely on every line being valid JSON. Records are built with `encoding/json`, which escapes control characters — a claim value containing newlines cannot forge a log line or break the record.

**On this page**

| Section | Contents |
| --- | --- |
| [Knobs](#knobs) | The config keys, and the `log_level` trap |
| [Decision log & audit record fields](#decision-log--audit-record-fields) | Exhaustive field reference for both surfaces |
| [What `claims` contains](#what-claims-contains) | Why `github` gets a full dump and others don't |
| [Source IP trust model](#source-ip-trust-model) | Per-frontend attestation; the ALB rules |
| [The durable trail & `audit_required`](#the-durable-trail--audit_required) | Batched vs. fail-closed, and how enforcement engages |
| [Production hardening recommendation](#production-hardening-recommendation) | What to set for a security-sensitive deployment |
| [SIEM signals & alerts](#security-signals-for-siem) | What to watch |

## Knobs

| Key | Env | Default | Meaning |
| --- | --- | --- | --- |
| `log_claim_values` | `AOW_LOG_CLAIM_VALUES` | `true` | When false, claim **values** are suppressed in both logs and audit records. Names, decision and reason are kept |
| `log_to_s3` | `AOW_LOG_TO_S3` | `false` | Persist logs/audit records to S3 |
| `log_bucket` / `log_prefix` | `AOW_LOG_BUCKET` / `AOW_LOG_PREFIX` | — | S3 destination |
| `audit_required` | `AOW_AUDIT_REQUIRED` | `true` | Fail-closed audit. See [below](#the-durable-trail--audit_required) — it is a **no-op until `log_to_s3` + `log_bucket` are also set** |
| `log_level` | `AOW_LOG_LEVEL` | `info` | `debug`/`info`/`warn`/`error`. **Validated but not wired to the running handler** — see the trap below |
| — | `LOG_LEVEL` (no `AOW_` prefix) | `info` | The env var that *actually* sets `slog` verbosity, read at bootstrap. In `cmd/local`, the `-log-level` flag |

<!-- prettier-ignore -->
> [!WARNING]
> **The `log_level` trap.** `log_level` / `AOW_LOG_LEVEL` is validated — an unknown level name is rejected at config load — but is **not** applied to the running `slog` handler, whose level is fixed at bootstrap from the bare `LOG_LEVEL` env var (Lambda) or `-log-level` (`cmd/local`). Setting `AOW_LOG_LEVEL=debug` will load cleanly and change nothing. **Set `LOG_LEVEL` instead.**

## Decision log & audit record fields

One record per authorization decision, allow **and** deny. The same redacted record backs both surfaces, so the *values* can never disagree — but the *field sets* differ:

- The **CloudWatch decision line** is a queryable subset, plus one synthesized field (`matchedRole`).
- The **durable S3 record** is the complete record.

Both lists below are exhaustive.

### CloudWatch decision line

Bound by the frontend adapter to the request-scoped logger, so these appear on **every** log line for the request, not only the decision line:

| Field | When present | Notes |
| --- | --- | --- |
| `requestId` | Always | The Lambda invocation UUID, stable across every frontend mode, so a cross-frontend query has one shape to match on |
| `frontendRequestId` | When the frontend issues its own ID | API Gateway v1/v2 and Lambda Function URLs do; **ALB does not**. The join key back to that frontend's access logs |
| `sourceIp` / `sourceIpFrom` | Each only when known | See [Source IP trust model](#source-ip-trust-model) |

Added by `auditLogAttrs` for the decision itself:

| Field | When present | Notes |
| --- | --- | --- |
| `frontend`, `jwtMode`, `decision`, `matchedRole`, `processingMs` | Always | `decision` is `allow`/`deny` |
| `issuer`, `provider` | Once claims are extracted | So they appear on **every deny past the `extract` stage** — `account_check`, `authorize`, `session_policy` and `assume_role` denies all carry them |
| `accountId`, `sessionName` | Allow only | Genuinely allow-only: both are set only once a role has actually been assumed |
| `stage` | Deny only | One of `extract` / `account_check` / `authorize` / `session_policy` / `assume_role` |
| `reason` | Deny only | |
| `jwtSub`, `subject`, `audience`, `claims` | When `log_claim_values=true` **and** non-empty | Suppressed entirely, not blanked, when the gate is off |

Two fields are worth calling out:

- **`matchedRole` is synthesized, not stored** — the granted role once one was assumed, otherwise the requested role. It is the **only** role field on the decision line: key queries on it, never on `requestedRole`/`grantedRole`, which are record-only.
- **`sessionName` is not claim-derived.** It is the STS session name actually used — the global `role_session_name`, or the per-mapping override that authorized the role ([CONFIGURATION.md](CONFIGURATION.md#per-mapping-role_session_name)). It is recorded because that override exists purely for CloudTrail attribution, so the trail must say which name the CloudTrail entry will carry. Being operator-declared static config, it is **not** suppressed by `log_claim_values=false`.

Empty attributes are omitted rather than emitted blank. `sourceIpFrom` is present only when the IP was **not** platform-attested — absent for the common `frontend` case, so a reader sees provenance called out only when the value is client-supplied and spoofable.

### Durable S3 record

Everything above (the values, not the synthesized `matchedRole`), plus seven fields that **never reach CloudWatch**:

| Field | When present | Notes |
| --- | --- | --- |
| `requestedRole` | **Allow and deny** | Set at record construction, before any stage runs, so even an `extract`-stage deny carries it |
| `grantedRole` | Allow only | Equal to `requestedRole` once granted |
| `matchedVia` | Always | `explicit` or `tag-auth`. **The field to check for "credential issued via tag-auth fallback"** — a question CloudWatch cannot answer, only S3 |
| `sessionTagKeys` | Once a role is granted | Session-tag *names*; present regardless of `log_claim_values` |
| `sessionTags` | When `log_claim_values=true` | Resolved session-tag *values* |
| `sessionPolicyRef` | If a policy was applied | Reference to the session policy |
| `expiry` | Allow only | The issued credential's expiration, RFC3339 |

The record keeps its own shape regardless of the line-level omission above: these optional fields are all `json:",omitempty"`, so absence already means "empty". Note the record does keep `sourceIpFrom` even for the attested `frontend` case, where it is a real value rather than line noise.

Timing fields (`validationMs`, `totalMs`, `durationMs`) are millisecond integers, matching `processingMs` — not raw nanosecond counts.

## What `claims` contains

`claims` answers "who did this", on **both** allow and deny records. How much it carries depends on the issuer's `provider`:

| `provider` | `claims` carries |
| --- | --- |
| `github` | The **full verified claim set** — every GitHub Actions OIDC claim, not a curated subset |
| anything else | **Only** the claims that issuer's own config references (see below) |

**Why `github` is a full dump.** Every claim GitHub puts in that token is non-secret workflow metadata, and a complete dump beats a curated list that silently omits whatever an investigation actually needs — and that someone must revise every time GitHub adds a claim.

**Why every other issuer is opt-in.** An arbitrary OIDC issuer can put email addresses, group memberships or entitlements in a token. Writing a claim into the config is the operator's statement that it is both meaningful and safe to record; a claim nothing references is never copied out. What counts as "referenced":

- the issuer's `claim_mappings` targets
- its `required_claims`
- its `session_tags` targets — the issuer's own, **and** those added by any `role_mappings` entry bound to it
- every claim named by a condition on a `role_mappings` entry bound to it

Conditions count because a record that omits the claim which *decided* the request cannot explain its own decision — the `groups` value a `none_of` vetoed on is exactly what a reader needs to see.

Values are formatted exactly as session-tag values are, so **a claim reported here and the same claim attached as a session tag can never disagree.**

Two normalizations apply to any issuer or provider:

- `repository` → `repo` and `repository_id` → `repo_id`, so the audit vocabulary stays stable and queryable whichever name a token uses. The rename is **suppressed** in the one case where it would destroy information: if the token also carries a claim already named `repo` (or `repo_id`) *and* that claim itself reaches the record, the original name is kept so the two cannot overwrite each other.
- A claim with an empty value is skipped (e.g. `base_ref`/`head_ref` outside a pull request) — no information, and it costs bytes in a per-request S3 object.

<!-- prettier-ignore -->
> [!NOTE]
> **Registered claims are duplicated in the `github` dump, and the formats differ.** Because it is the full claim set, it repeats claims the record already carries under dedicated names: `iss`→`issuer`, `sub`→`jwtSub`, `aud`→`audience`, `exp`→`expiry`. (`iat`, `nbf` and `jti` have no dedicated field and exist only inside `claims`.)
>
> **Key consumers on the dedicated fields, not their `claims` copies** — the same value can be formatted differently: `expiry` is RFC3339 (`2026-08-19T09:00:00Z`) while `claims.exp` is the raw epoch as a string (`1755594000`), so comparing the two textually will not match.
>
> On a realistic 30-claim token this duplication grows the record from 647 to 1526 bytes (+879, +136%). That cost is accepted deliberately.

## Source IP trust model

`sourceIp` is **audit metadata only.** Authorization never consults it: access is decided entirely by the verified OIDC token, so a forged IP grants nothing. What a forged IP *can* do is misattribute an entry in the audit trail — which matters, because that trail is the compliance artifact. `sourceIpFrom` records which source produced the value, so provenance is never inferred.

| Frontend | `sourceIpFrom` | Trust |
| --- | --- | --- |
| API Gateway HTTP (v2) | `frontend` | **Attested by AWS.** `requestContext.http.sourceIp` is observed by the platform and cannot be set by the caller |
| API Gateway REST (v1) | `frontend` | **Attested by AWS** (`requestContext.identity.sourceIp`) |
| Lambda Function URL | `frontend` | **Attested by AWS** |
| ALB | `x-forwarded-for` or `""` | **Client-supplied.** ALB provides no source-IP field, so the value comes from the `X-Forwarded-For` header |

Verifying the JWT does not make that header trustworthy: token verification authenticates the workflow identity carried *inside* the token, while `X-Forwarded-For` is a network-layer header the caller sets independently, and nothing in the token attests to it.

### The ALB rules

**The rightmost hop is used, not the leftmost.** ALB appends the TCP peer it actually observed to whatever `X-Forwarded-For` the client already sent. In `1.2.3.4, 203.0.113.7` the client supplied `1.2.3.4` and the load balancer appended `203.0.113.7`. Every entry left of the last is caller-controlled — taking the leftmost would log precisely the value an attacker chose.

**There is no fallback to an earlier field.** Only the last comma-separated field is ever examined; if it is missing, empty, or does not parse as an IP, both `sourceIp` and `sourceIpFrom` are `""`. An earlier implementation fell back to the rightmost *parseable* field, which let a caller append a trailing empty or malformed entry and get their own earlier entry logged as the source IP. **An absent source IP is strictly better than one fabricated by the caller.**

<!-- prettier-ignore -->
> [!IMPORTANT]
> **Deployment requirement (ALB only).** The ALB must be configured to **append** to `X-Forwarded-For` — the default — rather than preserve or remove it. A preserved header is entirely caller-supplied, and no parsing strategy on the receiving end can make it trustworthy; the rightmost rule depends on the load balancer adding the final entry.
>
> **Topology caveat (ALB only).** The rightmost hop is the client's IP only when the ALB is the internet-facing edge. Put CloudFront or a second load balancer in front and the rightmost hop becomes *that proxy's* address, with the client's real IP one or more entries to its left. The service does not guess at a trusted-hop count, so in that topology `sourceIp` identifies the proxy, not the caller. If you need per-client IPs there, terminate the trust decision in the proxy layer.

**Recommended posture.** Use API Gateway HTTP (v2) with `jwt_validation.mode: "apigw"` (the OpenTofu variable for the same setting is `jwt_validation_mode`). It is the most secure supported frontend on two independent axes: the source IP is platform-attested, so no client-supplied header is ever trusted and the caveat above cannot apply; and a JWT Authorizer rejects invalid tokens at the gateway before the Lambda is invoked. The OpenTofu stack does not provision an ALB at all.

## The durable trail & `audit_required`

Two modes, and the switch between them is **not** `audit_required` alone:

| | `audit_required=false` | `audit_required=true` *and* `log_to_s3` + `log_bucket` set |
| --- | --- | --- |
| Write path | Appended to the amortized batch buffer (the one `WriteLogToS3` feeds) | Written **synchronously**, bypassing the buffer, **before** the credential response |
| Flush trigger | Size (`BatchSize`), age (`MaxBatchAge`), or `Cleanup()` | n/a |
| On write failure | Logged; request proceeds | **Request is denied** (fail-closed) |
| Durability | **Records can be lost at container reclaim** — the flush timer is frozen between Lambda invocations | Guaranteed before credentials are issued |

Treat container-shutdown flushing as a best-effort backstop only.

<!-- prettier-ignore -->
> [!IMPORTANT]
> **`audit_required` defaults to `true`, but is a no-op until `log_to_s3` + `log_bucket` are configured.** A warning is logged at boot, decisions still reach CloudWatch, and the S3 path falls back to the batched behaviour above. This is what lets local/dev and no-bucket deployments start with zero dependencies.

Enforcement is **re-derived from the active config snapshot on every call** via `AuditEnforced()`, never resolved once at boot and never written back over the declared intent. Two consequences:

- Supplying `log_to_s3` + `log_bucket` through a **hot reload engages the fail-closed guarantee immediately** — no restart, and no need to restate `audit_required`.
- To opt out of fail-closed behaviour even with S3 logging configured, set `audit_required: false` explicitly.

## Production hardening recommendation

For any security-sensitive deployment, enable the durable, fail-closed trail:

```yaml
log_to_s3: true
log_bucket: "your-audit-bucket" # object-lock / WORM + restrictive bucket policy
audit_required: true # deny rather than issue credentials with no audit record
```

A lost or unwritten record must fail the request — that is exactly what `audit_required: true` (the default) guarantees, **once a bucket is configured**. Point a CloudWatch alert at `errorCode=audit_write_failed` so a failing sink is paged rather than silently tolerated.

## Security signals (for SIEM)

Warn/error lines carry context (never secrets) for: unknown/unconfigured issuer, signature failure, algorithm/key-type mismatch, expired / `nbf` / max-age rejection, audience mismatch, condition failure (by claim name + match result), oversized token, forced JWKS refetch (and cooldown-suppressed storms), fragment-rejected keys, account-not-allowed, and assume-role failure.

## Suggested CloudWatch alerts

| Alert on | Why |
| --- | --- |
| Spike in `decision=deny` with `stage=authorize` | Misconfigured mappings, or an attack |
| Any `errorCode=audit_write_failed` | Audit sink unavailable under `audit_required` |
| Any `errorCode=assume_role_denied` | A target role's trust policy is refusing, or the execution role is missing `sts:AssumeRole`/`sts:TagSession`. The log line carries `stsErrorCode` |
| Rising forced-JWKS-refetch rate | Possible bogus-`kid` flooding |
| `matchedVia=tag-auth` where you expect none | Credentials issued through the tag-auth fallback (S3 record only) |
