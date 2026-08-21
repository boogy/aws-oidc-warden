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
| `log_claim_values`          | `AOW_LOG_CLAIM_VALUES`              | `true`  | when false, claim **values** are suppressed in both logs and audit records (names/decision/reason kept)                                                                                |
| `audit_required`            | `AOW_AUDIT_REQUIRED`                | `true`  | when true, an allow decision's audit record is written **before** credentials are returned; a write failure denies the request (fail-closed). Requires `log_to_s3=true` + `log_bucket` — until both are set this is a no-op (warning logged at boot), so it does not force S3 to be configured |
| `log_to_s3`                 | `AOW_LOG_TO_S3`                     | `false` | persist logs/audit records to S3                                                                                                                                                       |
| `log_bucket` / `log_prefix` | `AOW_LOG_BUCKET` / `AOW_LOG_PREFIX` | —       | S3 destination                                                                                                                                                                         |

## Decision log / audit record fields

One record is produced per authorization decision (allow **and** deny). The
same redacted record backs both surfaces, so the *values* they carry can
never disagree — but the two surfaces do not carry the same *field set*: the
CloudWatch decision line is a queryable subset of the record plus one
synthesized field (`matchedRole`); the durable S3 record is the complete
record. The two lists below are exhaustive for each surface.

### CloudWatch decision line

Bound by the frontend adapter to the request-scoped logger, so these are
present on every log line for the request, not only the decision line:

- `requestId` — always present. The Lambda invocation UUID, stable across
  every frontend mode, so a query spanning frontends has one shape to match
  on.
- `frontendRequestId` — present whenever the frontend issues an ID of its own
  (API Gateway v1/v2, Lambda Function URLs); absent for ALB, which issues
  none. The join key back to that frontend's own access logs.
- `sourceIp` / `sourceIpFrom` — each present only when known (see
  [Source IP trust model](#source-ip-trust-model) below).

Added by `auditLogAttrs` for the decision itself:

- Always: `frontend`, `jwtMode`, `decision` (`allow`/`deny`), `matchedRole`,
  `processingMs`.
- Present when non-empty: `issuer`, `provider`, `accountId`, `sessionName`,
  `stage` (deny only — one of `extract` / `account_check` / `authorize` /
  `session_policy` / `assume_role`), `reason` (deny only).
- Present when `log_claim_values=true` **and** non-empty: `jwtSub`,
  `subject`, `audience`, `claims`.

`matchedRole` is synthesized, not a stored field: the granted role once one
was assumed, otherwise the requested role. It is the **only** role field on
the decision line — key a query on it, not on `requestedRole`/`grantedRole`,
which are record-only (below).

`issuer` and `provider` are set as soon as claims are extracted, so they
appear on every deny past the `extract` stage, not only on an allow —
`account_check`, `authorize`, `session_policy`, and `assume_role` denies all
carry them. The fields that genuinely are allow-only are `accountId` and
`sessionName`: both are set only once a role has actually been assumed.

`sessionName` is the STS session name actually used — the global
`role_session_name` or the per-mapping override that authorized the role (see
[CONFIGURATION.md](CONFIGURATION.md)). It is recorded because that override
exists purely for CloudTrail attribution, so the audit trail has to say which
name the CloudTrail entry will carry. It is operator-declared static config,
never claim-derived, so it is **not** suppressed by `log_claim_values=false`.

### Durable S3 audit record

Everything on the decision line above (the values, not the synthesized
`matchedRole`), plus seven fields that never reach CloudWatch:

- `requestedRole` — the role the request asked for. Present on **allow and
  deny** alike: it is set at record construction, before any stage runs, so
  even an `extract`-stage deny still carries it.
- `grantedRole` — the role actually granted; **allow only**, and equal to
  `requestedRole` once granted.
- `matchedVia` (`explicit`/`tag-auth`) — which authorization path allowed the
  request. This is the field to check for "credential issued via tag-auth
  fallback" — that question has no answer from CloudWatch, only from S3.
- `sessionTagKeys` — session-tag names; always present once a role is
  granted, regardless of `log_claim_values`.
- `sessionTags` — resolved session-tag values; present only when
  `log_claim_values=true`.
- `sessionPolicyRef` — reference to the session policy applied, if any.
- `expiry` — the issued credential's expiration, RFC3339.

`claims` answers "who did this", on **both** allow and deny records. Two raw
claim names are always renamed on the way in, regardless of issuer or
provider: `repository` becomes `repo` and `repository_id` becomes `repo_id`,
so the audit vocabulary stays stable and queryable whenever a token happens
to carry a claim under either name. A claim with an empty value is still
skipped (e.g. `base_ref`/`head_ref` outside a pull request), since it carries
no information and costs bytes in a per-request S3 object.

For `provider: github` issuers, `claims` carries the **full verified claim
set** — every GitHub Actions OIDC claim, not a curated subset. A full dump is
deliberate for `github` specifically: every claim GitHub puts in that token
is non-secret workflow metadata, and a complete dump beats a curated list
that silently omits whatever an investigation actually needs. For every
other issuer, `claims` carries only the claims that issuer's own
`claim_mappings` reference — an arbitrary OIDC issuer can put email
addresses, group memberships, or entitlements in a token, and naming a claim
in `claim_mappings` is the operator's statement that it is both meaningful
and safe to record. Values are formatted exactly as session tag values are,
so a claim reported here and the same claim attached as a session tag can
never disagree.

Because the `github` dump is the full verified claim set, it necessarily
repeats registered claims the record already carries under dedicated field
names: `iss`→`issuer`, `sub`→`jwtSub`, `aud`→`audience`, `exp`→`expiry` (4 of
4 dedicated fields). `iat`, `nbf`, and `jti` have no dedicated field, so they
exist only inside `claims`. The dedicated fields are the stable, queryable
ones a consumer should key on, not their `claims` copies — and the format can
differ for the same value: `expiry` is RFC3339 (e.g.
`2026-08-19T09:00:00Z`) while `claims.exp` is the raw epoch as a string (e.g.
`1755594000`), so comparing the two textually will not match. On a realistic
30-claim token this duplication grows the record from 647 to 1526 bytes (+879
bytes, +136%); that cost is accepted deliberately, not overlooked, because a
curated list is one a future GitHub claim can silently fall through, and any
curated list is one someone must revise every time GitHub adds a claim —
`claims` stays the full verified claim set on purpose.

Records are built with `encoding/json`, which escapes control characters, so a
claim value containing newlines cannot forge a log line or break the record.

The CloudWatch decision line omits empty attributes rather than emitting them
blank: `stage`/`reason` are absent on an allow decision (they're deny-only),
and with `log_claim_values=false` the claim values (`jwtSub`, `subject`,
`audience`, `claims`) are absent, not blanked. `sourceIp` is present whenever
known; `sourceIpFrom` is present only when the IP was **not**
platform-attested (i.e. it's absent for the common `frontend` case, so a
reader only sees provenance called out when it's a client-supplied,
spoofable value). The durable audit record keeps its own shape regardless: the
optional fields above are all `json:"...,omitempty"` there, so absence already
means "empty" independent of this log-line-only omission — but note the record
does keep `sourceIpFrom` even for the attested `frontend` case, because there
it is a real value rather than line noise. `frontend`, `jwtMode`, and
`decision` are unconditional in both.

Timing fields (`validationMs`, `totalMs`, `durationMs`) are millisecond
integers, matching `processingMs` — not raw nanosecond counts.

All log output is JSON (`slog.NewJSONHandler`, the only handler constructed
anywhere in the service); this is enforced by
`TestLogOutputIsJSON`/`TestBootstrapLoggerIsJSONHandler`, so a downstream
parser can rely on every line being valid JSON.

> **`log_level` note:** `log_level` / `AOW_LOG_LEVEL` is validated (an unknown
> level name is rejected at config load) but is **not** applied to the running
> `slog` handler, whose level is fixed at bootstrap from the bare `LOG_LEVEL`
> env var (Lambda) or the `-log-level` flag (`cmd/local`). To change verbosity,
> set `LOG_LEVEL` / `-log-level`, not `AOW_LOG_LEVEL`.

## Source IP trust model

`sourceIp` is audit metadata. Authorization never consults it: access is decided
entirely by the verified OIDC token, so a forged IP grants nothing. What a forged
IP can do is misattribute an entry in the audit trail, which matters because that
trail is the compliance artifact. `sourceIpFrom` records which of the two
sources below produced the value, so provenance is never inferred.

| Frontend | `sourceIpFrom` | Trust |
|---|---|---|
| API Gateway HTTP (v2) | `frontend` | Attested by AWS. `requestContext.http.sourceIp` is observed by the platform and cannot be set by the caller. |
| API Gateway REST (v1) | `frontend` | Attested by AWS (`requestContext.identity.sourceIp`). |
| Lambda Function URL | `frontend` | Attested by AWS. |
| ALB | `x-forwarded-for` or `""` | **Client-supplied.** ALB provides no source-IP field, so the value comes from the `X-Forwarded-For` header; `sourceIpFrom` is `""` when no usable value is present (see below). |

For ALB the **rightmost** hop is used, not the leftmost. ALB appends the TCP peer
it actually observed to whatever `X-Forwarded-For` the client already sent, so in
`1.2.3.4, 203.0.113.7` the client supplied `1.2.3.4` and the load balancer
appended `203.0.113.7`. Every entry left of the last one is caller-controlled;
taking the leftmost would log precisely the value an attacker chose.

Only the last comma-separated field is ever examined, and there is no fallback
to an earlier one: if that field is missing, empty, or does not parse as an IP,
`sourceIp` and `sourceIpFrom` are both `""`. An earlier implementation fell back
to the rightmost *parseable* field, which meant a caller who appended a trailing
empty or malformed entry to the header could still get their own, earlier entry
logged as the source IP. That fallback has been removed deliberately: an absent
source IP is strictly better than one fabricated by the caller.

Verifying the JWT does not make this header trustworthy. Token verification
authenticates the workflow identity carried *inside* the token; `X-Forwarded-For`
is a network-layer header the caller sets independently, and nothing in the token
attests to it.

**Deployment requirement (ALB only).** The ALB in front of this service must be
configured to **append** to `X-Forwarded-For` — the default behavior — rather
than preserve or remove it. A preserved header is entirely caller-supplied, and
no parsing strategy on the receiving end can make it trustworthy; the rightmost
rule above depends on the load balancer being the one adding the final entry.

**Topology caveat (ALB only).** The rightmost hop is the client's IP only when
the ALB is the internet-facing edge. Put a CloudFront distribution or a second
load balancer in front and the rightmost hop becomes that proxy's address, with
the client's real IP one or more entries to its left. The service does not guess
at a trusted-hop count, so in that topology `sourceIp` identifies the proxy, not
the caller. If you need per-client IPs there, terminate the trust decision in the
proxy layer.

**Recommended posture.** Use API Gateway HTTP (v2) with
`jwt_validation_mode: "apigw"`. This is the most secure of the supported
frontends on two independent axes: the source IP is platform-attested, so no
client-supplied header is ever trusted and the caveat above cannot apply; and a
JWT Authorizer rejects invalid tokens at the gateway before the Lambda is
invoked. The OpenTofu stack does not provision an ALB at all.

## Security signals (for SIEM)

Warn/error lines carry context (never secrets) for: unknown/unconfigured
issuer, signature failure, algorithm/key-type mismatch, expired / `nbf` /
max-age rejection, audience mismatch, condition failure (by claim name +
match result), oversized token, forced JWKS refetch (and cooldown-suppressed
storms), fragment-rejected keys, account-not-allowed, and assume-role failure.

## Durability note (Lambda)

With `audit_required=false`, every decision record is appended to the
amortized batch buffer — the same one `WriteLogToS3` feeds — and flushed by
size (`BatchSize`), age (`MaxBatchAge`), or `Cleanup()`. Batched flushing runs
on a timer that is frozen between Lambda invocations, so buffered records can
be lost at container reclaim. `audit_required` defaults to `true`, so once
`log_to_s3`+`log_bucket` are configured you get the guaranteed trail by
default: each decision record is written synchronously (bypassing the batch
buffer) before the credential response, and a write failure fails the request
closed. Until `log_to_s3`+`log_bucket` are configured, `audit_required=true`
is a no-op (a warning is logged at boot) and decisions fall back to the
batched path above. Treat container-shutdown flushing as a best-effort
backstop only.

## Production hardening recommendation

For any security-sensitive deployment, enable the durable, fail-closed trail:

```yaml
log_to_s3: true
log_bucket: "your-audit-bucket" # object-lock / WORM + restrictive bucket policy
audit_required: true # deny rather than issue credentials with no audit record
```

`audit_required` defaults to `true`, but the declared intent is never mutated
— enforcement is derived fresh from the active config snapshot on every call
via `AuditEnforced()`, so it stays a no-op (decisions still log to CloudWatch,
a warning is logged at boot) until `log_to_s3`+`log_bucket` are also
configured, which lets local/dev and deployments with no S3 bucket configured
still get zero-dependency startup for free. Because enforcement is re-derived
rather than resolved once at boot, supplying `log_to_s3`+`log_bucket` via a hot
reload engages the fail-closed guarantee immediately, with no restart and no
need to restate `audit_required`: a lost or unwritten record must fail the
request, which is exactly what `audit_required: true` (the default)
guarantees. Set `audit_required: false` explicitly to opt out of the
fail-closed behavior even with S3 logging configured. Point CloudWatch alerts at
`errorCode=audit_write_failed` so a failing sink is paged, not silently
tolerated.

## Suggested CloudWatch alerts

- Spike in `decision=deny` with `stage=authorize` (misconfigured mappings or an
  attack).
- Any `errorCode=audit_write_failed` (audit sink unavailable under
  `audit_required`).
- Forced-JWKS-refetch rate climbing (possible bogus-`kid` flooding).
