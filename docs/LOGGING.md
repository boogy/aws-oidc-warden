# Logging, audit & observability

The service emits structured JSON log events (`internal/logevent`, backed by `slog.NewJSONHandler`) to stdout (CloudWatch) and, when enabled, a durable per-decision audit trail to S3. **No path logs a raw JWT or credential.**

**Every authorization decision — allow _and_ deny — is always logged** as one standardized `authz.decision` line, emitted before and independently of any S3 write. In Lambda that stream lands in CloudWatch Logs, which is itself durable, so the decision trail is never off. `log_to_s3` and `audit_required` add a _second_, S3-based trail on top of that baseline; they do not switch decision logging on or off.

All output is JSON (`slog.NewJSONHandler` is the only handler constructed anywhere in the service, enforced by `TestLogOutputIsJSON` / `TestBootstrapLoggerIsJSONHandler`), so a downstream parser can rely on every line being valid JSON. Records are built with `encoding/json`, which escapes control characters — a claim value containing newlines cannot forge a log line or break the record.

**On this page**

| Section                                                                     | Contents                                             |
| --------------------------------------------------------------------------- | ---------------------------------------------------- |
| [Log schema](#log-schema)                                                   | Base keys, `outcome` rules, level policy             |
| [Event catalog](#event-catalog)                                             | Every registered event: type, level, key attrs       |
| [Knobs](#knobs)                                                             | The config keys, and the `log_level` trap            |
| [Decision log & audit record fields](#decision-log--audit-record-fields)    | Exhaustive field reference for both surfaces         |
| [What `claims` contains](#what-claims-contains)                             | Why `github` gets a full dump and others don't       |
| [Source IP trust model](#source-ip-trust-model)                             | Per-frontend attestation; the ALB rules              |
| [The durable trail & `audit_required`](#the-durable-trail--audit_required)  | Batched vs. fail-closed, and how enforcement engages |
| [Production hardening recommendation](#production-hardening-recommendation) | What to set for a security-sensitive deployment      |
| [SIEM signals & alerts](#security-signals-for-siem)                         | What to watch, as Logs Insights queries              |

## Log schema

Every log line carries a base set of keys (from `internal/logevent.Setup` and the request context) plus the event's own attrs.

| Key                                                        | Source                            | Notes                                                                                 |
| ----------------------------------------------------------- | ---------------------------------- | -------------------------------------------------------------------------------------- |
| `time`, `level`, `msg`                                     | `slog`                             | `msg` is a static string, never interpolated — look up detail in the event's attrs     |
| `eventType`                                                | catalog event                      | dot-separated, e.g. `sts.assume_role.failure` — the stable field to query and alert on |
| `eventCategory`                                             | catalog event                      | `eventType`'s first segment, e.g. `sts`                                               |
| `outcome`                                                  | catalog event                      | `success`/`failure` when the event type ends in one of those; `allow`/`deny` on `authz.decision` only; absent otherwise |
| `service`, `version`, `adapter`, `schemaVersion`           | `internal/logevent.Setup`          | `service="aws-oidc-warden"`; `adapter` is `apigateway`\|`apigatewayv2`\|`alb`\|`lambdaurl`\|`local`; `schemaVersion=1` |
| `requestId`, `frontendRequestId`, `sourceIp`, `sourceIpFrom` | request context (`logevent.WithRequest`) | Present once a request context exists; see [Decision log & audit record fields](#decision-log--audit-record-fields) |

**Level policy:**

- **Error** — server-side fault needing operator action: STS/S3/IAM failures, JWKS fetch/discovery failure, invalid cache item, audit write/marshal/buffer failure, config reload failure, startup failure.
- **Warn** — security-relevant or degraded-but-serving: `authz.decision` deny, `request.rejected`, JWKS refetch rate-limited/prefetch failure, config warnings, STS name/duration clamps and dropped session tags, oversized S3/cache objects.
- **Info** — lifecycle and successful state changes: `authz.decision` allow, `app.start`, successful config reload/AssumeRole/client refresh.
- **Debug** — per-step pipeline detail, cache traffic, `request.response`.

**One terminal line per request.** Each request emits exactly one of `authz.decision` (the pipeline ran to a decision) or `request.rejected` (rejected before the pipeline, e.g. malformed body). `request.response` is a separate Debug line logged on every response in addition to the terminal line, never a substitute for it.

## Event catalog

Every registered event (`internal/logevent/events_*.go`), grouped by `eventCategory`. Attrs listed are in addition to the base keys above; `authz.decision`'s full attr set is detailed in [Decision log & audit record fields](#decision-log--audit-record-fields). Pipeline lines logged after the role is parsed carry a `request` group: `roleArn`, plus `subject`, `repository`, `ref`, `branch`, `actor` when `log_claim_values` is on.

| eventType | Level | Key attrs |
| --- | --- | --- |
| `app.start` | Info | binName, commit, date |
| `app.stop` | Info | — |
| `app.init.failure` | Error | component, error |
| `app.resource_close.failure` | Warn | resource, error |
| `audit.buffer.failure` | Error | error |
| `audit.client.init` | Info | bucket |
| `audit.client.init.failure` | Error | error |
| `audit.client.unavailable` | Debug | error |
| `audit.flush.failure` | Error | error |
| `audit.flush.success` | Debug | bucket, key, bytes |
| `audit.marshal.failure` | Error | error |
| `audit.write.failure` | Error | error (s3logger: bucket, key) |
| `audit.write.success` | Debug | bucket, key, bytes |
| `authz.decision` | Info (allow) / Warn (deny) | frontend, jwtMode, decision, matchedRole, processingMs, issuer, provider, accountId, sessionName, stage, reason, jwtSub, subject, audience, claims |
| `authz.stage.deny` | Debug | stage-specific |
| `authz.tag_auth.lookup_failure` | Warn | error |
| `authz.tag_auth.success` | Info | — |
| `aws.clients.refresh.failure` | Error | error |
| `aws.clients.refresh.start` | Debug | — |
| `aws.clients.refresh.success` | Info | — |
| `aws.iam.get_role.failure` | Error | roleName, error |
| `aws.iam.get_role.success` | Debug | roleName |
| `aws.s3.get.failure` | Error | bucket, key, error |
| `aws.s3.get.success` | Debug | bucket, key, sizeBytes |
| `aws.s3.object.oversize` | Warn | size, maxAllowed, bucket, key |
| `cache.cleanup.failure` | Warn | backend, key, error |
| `cache.evict` | Debug | backend, key, lastAccess |
| `cache.expired` | Debug | backend, key |
| `cache.hit` | Debug | backend, key |
| `cache.item.invalid` | Error | backend, key, error |
| `cache.item.oversize` | Warn | backend, key, maxAllowed, size (write path) |
| `cache.miss` | Debug | backend, key |
| `cache.read.failure` | Error | backend, key, error |
| `cache.set` | Debug | backend, key, ttlMs, size (dynamodb, s3) |
| `cache.write.failure` | Error | backend, key, error |
| `config.env.invalid` | Warn | key, value, error |
| `config.fragments.merged` | Info | fragmentCount, totalMappings |
| `config.fragments.soft_cap` | Warn | totalMappings, softCap, fragmentCount |
| `config.hot_reload.enabled` | Info | intervalMs, bucket, key |
| `config.jwt_validation.delegated` | Warn | mode |
| `config.reload.failure` | Error | error |
| `config.reload.success` | Info | roleMappings, fragments |
| `config.warning` | Warn | warning (stable code) + context, e.g. mappingCount/defaultIssuer/issuerCount, issuer/roleArn/winningSubject/ignoredPolicySubject, roleArn/scopedBy/subject |
| `http.response.failure` | Error | error |
| `http.response.write_failure` | Warn | error |
| `http.server.failure` | Error | error |
| `http.server.start` | Info | port, verifyEndpoint, healthEndpoint |
| `jwks.alb_key.failure` | Error | kid, region, error |
| `jwks.discovery.failure` | Error | issuer, error |
| `jwks.fetch.failure` | Error | issuer, error |
| `jwks.prefetch.failure` | Warn | issuer, error |
| `jwks.refetch.forced` | Info | issuer, kid |
| `jwks.refetch.rate_limited` | Warn | issuer, kid |
| `policy.session.load.failure` | Error | bucket, key, error |
| `policy.session.loaded` | Debug | subject, source, bucket, key, policySize, durationMs |
| `request.rejected` | Warn | reason |
| `request.response` | Debug (outcome=failure) | errorCode, status, processingMs |
| `request.response` | Debug (outcome=success) | processingMs |
| `sts.assume_role.failure` | Error | roleArn, stsErrorCode, error, durationMs |
| `sts.assume_role.success` | Info | roleArn, durationMs, assumedRoleId |
| `sts.caller_identity.failure` | Error | error |
| `sts.duration.clamped` | Warn | requestedSeconds, clampReason |
| `sts.external_id.suspicious` | Warn | externalIdLength, roleArn |
| `sts.session_name.truncated` | Warn | original, originalLength |
| `sts.session_tag.dropped` | Warn | tagKey, claim, dropReason |
| `sts.spoke.assumed` | Info | roleArn, sessionName, expires |
| `token.claims` | Debug | claims (gated by `log_claim_values`) |
| `token.extract` | Debug | jwtMode |
| `token.validated` | Debug | validationMs |

## Knobs

| Key                         | Env                                 | Default | Meaning                                                                                                                              |
| --------------------------- | ----------------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `log_claim_values`          | `AOW_LOG_CLAIM_VALUES`              | `true`  | When false, claim **values** are suppressed in both logs and audit records. Names, decision and reason are kept                      |
| `log_to_s3`                 | `AOW_LOG_TO_S3`                     | `false` | Persist logs/audit records to S3                                                                                                     |
| `log_bucket` / `log_prefix` | `AOW_LOG_BUCKET` / `AOW_LOG_PREFIX` | —       | S3 destination                                                                                                                       |
| `audit_required`            | `AOW_AUDIT_REQUIRED`                | `true`  | Fail-closed audit. See [below](#the-durable-trail--audit_required) — it is a **no-op until `log_to_s3` + `log_bucket` are also set** |
| `log_level`                 | `AOW_LOG_LEVEL`                     | `info`  | `debug`/`info`/`warn`/`error`. **Validated but not wired to the running handler** — see the trap below                               |
| —                           | `LOG_LEVEL` (no `AOW_` prefix)      | `info`  | The env var that _actually_ sets `slog` verbosity, read at bootstrap. In `cmd/local`, the `-log-level` flag                          |

<!-- prettier-ignore -->
> [!WARNING]
> **The `log_level` trap.** `log_level` / `AOW_LOG_LEVEL` is validated — an unknown level name is rejected at config load — but is **not** applied to the running `slog` handler, whose level is fixed at bootstrap from the bare `LOG_LEVEL` env var (Lambda) or `-log-level` (`cmd/local`). Setting `AOW_LOG_LEVEL=debug` will load cleanly and change nothing. **Set `LOG_LEVEL` instead.**

## Decision log & audit record fields

One record per authorization decision, allow **and** deny, logged as `eventType = "authz.decision"` (`outcome` is `allow`/`deny`, redundant with the record's own `decision` field). The same redacted record backs both surfaces, so the _values_ can never disagree — but the _field sets_ differ:

- The **CloudWatch decision line** is a queryable subset, plus one synthesized field (`matchedRole`).
- The **durable S3 record** is the complete record.

Both lists below are exhaustive.

### CloudWatch decision line

Bound by the frontend adapter to the request-scoped logger, so these appear on **every** log line for the request, not only the decision line:

| Field                       | When present                        | Notes                                                                                                              |
| --------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `requestId`                 | Always                              | The Lambda invocation UUID, stable across every frontend mode, so a cross-frontend query has one shape to match on |
| `frontendRequestId`         | When the frontend issues its own ID | API Gateway v1/v2 and Lambda Function URLs do; **ALB does not**. The join key back to that frontend's access logs  |
| `sourceIp` / `sourceIpFrom` | Each only when known                | See [Source IP trust model](#source-ip-trust-model)                                                                |

Added by `auditLogAttrs` for the decision itself:

| Field                                                            | When present                                   | Notes                                                                                                                                              |
| ---------------------------------------------------------------- | ---------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `frontend`, `jwtMode`, `decision`, `matchedRole`, `processingMs` | Always                                         | `decision` is `allow`/`deny`                                                                                                                       |
| `issuer`, `provider`                                             | Once claims are extracted                      | So they appear on **every deny past the `extract` stage** — `account_check`, `authorize`, `session_policy` and `assume_role` denies all carry them |
| `accountId`, `sessionName`                                       | Allow only                                     | Genuinely allow-only: both are set only once a role has actually been assumed                                                                      |
| `stage`                                                          | Deny only                                      | One of `extract` / `account_check` / `authorize` / `session_policy` / `assume_role`                                                                |
| `reason`                                                         | Deny only                                      |                                                                                                                                                    |
| `jwtSub`, `subject`, `audience`, `claims`                        | When `log_claim_values=true` **and** non-empty | Suppressed entirely, not blanked, when the gate is off                                                                                             |

Two fields are worth calling out:

- **`matchedRole` is synthesized, not stored** — the granted role once one was assumed, otherwise the requested role. It is the **only** role field on the decision line: key queries on it, never on `requestedRole`/`grantedRole`, which are record-only.
- **`sessionName` is not claim-derived.** It is the STS session name actually used — the global `role_session_name`, or the per-mapping override that authorized the role ([CONFIGURATION.md](CONFIGURATION.md#per-mapping-role_session_name)). It is recorded because that override exists purely for CloudTrail attribution, so the trail must say which name the CloudTrail entry will carry. Being operator-declared static config, it is **not** suppressed by `log_claim_values=false`.

Empty attributes are omitted rather than emitted blank. `sourceIpFrom` is present only when the IP was **not** platform-attested — absent for the common `frontend` case, so a reader sees provenance called out only when the value is client-supplied and spoofable.

### Durable S3 record

Everything above (the values, not the synthesized `matchedRole`), plus seven fields that **never reach CloudWatch**:

| Field              | When present                 | Notes                                                                                                                                         |
| ------------------ | ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `requestedRole`    | **Allow and deny**           | Set at record construction, before any stage runs, so even an `extract`-stage deny carries it                                                 |
| `grantedRole`      | Allow only                   | Equal to `requestedRole` once granted                                                                                                         |
| `matchedVia`       | Always                       | `explicit` or `tag-auth`. **The field to check for "credential issued via tag-auth fallback"** — a question CloudWatch cannot answer, only S3 |
| `sessionTagKeys`   | Once a role is granted       | Session-tag _names_; present regardless of `log_claim_values`                                                                                 |
| `sessionTags`      | When `log_claim_values=true` | Resolved session-tag _values_                                                                                                                 |
| `sessionPolicyRef` | If a policy was applied      | Reference to the session policy                                                                                                               |
| `expiry`           | Allow only                   | The issued credential's expiration, RFC3339                                                                                                   |

The record keeps its own shape regardless of the line-level omission above: these optional fields are all `json:",omitempty"`, so absence already means "empty". Note the record does keep `sourceIpFrom` even for the attested `frontend` case, where it is a real value rather than line noise.

Timing fields (`validationMs`, `totalMs`, `durationMs`) are millisecond integers, matching `processingMs` — not raw nanosecond counts.

## What `claims` contains

`claims` answers "who did this", on **both** allow and deny records. How much it carries depends on the issuer's `provider`:

| `provider`    | `claims` carries                                                                        |
| ------------- | --------------------------------------------------------------------------------------- |
| `github`      | The **full verified claim set** — every GitHub Actions OIDC claim, not a curated subset |
| anything else | **Only** the claims that issuer's own config references (see below)                     |

**Why `github` is a full dump.** Every claim GitHub puts in that token is non-secret workflow metadata, and a complete dump beats a curated list that silently omits whatever an investigation actually needs — and that someone must revise every time GitHub adds a claim.

**Why every other issuer is opt-in.** An arbitrary OIDC issuer can put email addresses, group memberships or entitlements in a token. Writing a claim into the config is the operator's statement that it is both meaningful and safe to record; a claim nothing references is never copied out. What counts as "referenced":

- the issuer's `claim_mappings` targets
- its `required_claims`
- its `session_tags` targets — the issuer's own, **and** those added by any `role_mappings` entry bound to it
- every claim named by a condition on a `role_mappings` entry bound to it

Conditions count because a record that omits the claim which _decided_ the request cannot explain its own decision — the `groups` value a `none_of` vetoed on is exactly what a reader needs to see.

Values are formatted exactly as session-tag values are, so **a claim reported here and the same claim attached as a session tag can never disagree.**

Two normalizations apply to any issuer or provider:

- `repository` → `repo` and `repository_id` → `repo_id`, so the audit vocabulary stays stable and queryable whichever name a token uses. The rename is **suppressed** in the one case where it would destroy information: if the token also carries a claim already named `repo` (or `repo_id`) _and_ that claim itself reaches the record, the original name is kept so the two cannot overwrite each other.
- A claim with an empty value is skipped (e.g. `base_ref`/`head_ref` outside a pull request) — no information, and it costs bytes in a per-request S3 object.

<!-- prettier-ignore -->
> [!NOTE]
> **Registered claims are duplicated in the `github` dump, and the formats differ.** Because it is the full claim set, it repeats claims the record already carries under dedicated names: `iss`→`issuer`, `sub`→`jwtSub`, `aud`→`audience`, `exp`→`expiry`. (`iat`, `nbf` and `jti` have no dedicated field and exist only inside `claims`.)
>
> **Key consumers on the dedicated fields, not their `claims` copies** — the same value can be formatted differently: `expiry` is RFC3339 (`2026-08-19T09:00:00Z`) while `claims.exp` is the raw epoch as a string (`1755594000`), so comparing the two textually will not match.
>
> On a realistic 30-claim token this duplication grows the record from 647 to 1526 bytes (+879, +136%). That cost is accepted deliberately.

## Source IP trust model

`sourceIp` is **audit metadata only.** Authorization never consults it: access is decided entirely by the verified OIDC token, so a forged IP grants nothing. What a forged IP _can_ do is misattribute an entry in the audit trail — which matters, because that trail is the compliance artifact. `sourceIpFrom` records which source produced the value, so provenance is never inferred.

| Frontend              | `sourceIpFrom`            | Trust                                                                                                           |
| --------------------- | ------------------------- | --------------------------------------------------------------------------------------------------------------- |
| API Gateway HTTP (v2) | `frontend`                | **Attested by AWS.** `requestContext.http.sourceIp` is observed by the platform and cannot be set by the caller |
| API Gateway REST (v1) | `frontend`                | **Attested by AWS** (`requestContext.identity.sourceIp`)                                                        |
| Lambda Function URL   | `frontend`                | **Attested by AWS**                                                                                             |
| ALB                   | `x-forwarded-for` or `""` | **Client-supplied.** ALB provides no source-IP field, so the value comes from the `X-Forwarded-For` header      |

Verifying the JWT does not make that header trustworthy: token verification authenticates the workflow identity carried _inside_ the token, while `X-Forwarded-For` is a network-layer header the caller sets independently, and nothing in the token attests to it.

### The ALB rules

**The rightmost hop is used, not the leftmost.** ALB appends the TCP peer it actually observed to whatever `X-Forwarded-For` the client already sent. In `1.2.3.4, 203.0.113.7` the client supplied `1.2.3.4` and the load balancer appended `203.0.113.7`. Every entry left of the last is caller-controlled — taking the leftmost would log precisely the value an attacker chose.

**There is no fallback to an earlier field.** Only the last comma-separated field is ever examined; if it is missing, empty, or does not parse as an IP, both `sourceIp` and `sourceIpFrom` are `""`. An earlier implementation fell back to the rightmost _parseable_ field, which let a caller append a trailing empty or malformed entry and get their own earlier entry logged as the source IP. **An absent source IP is strictly better than one fabricated by the caller.**

<!-- prettier-ignore -->
> [!IMPORTANT]
> **Deployment requirement (ALB only).** The ALB must be configured to **append** to `X-Forwarded-For` — the default — rather than preserve or remove it. A preserved header is entirely caller-supplied, and no parsing strategy on the receiving end can make it trustworthy; the rightmost rule depends on the load balancer adding the final entry.
>
> **Topology caveat (ALB only).** The rightmost hop is the client's IP only when the ALB is the internet-facing edge. Put CloudFront or a second load balancer in front and the rightmost hop becomes *that proxy's* address, with the client's real IP one or more entries to its left. The service does not guess at a trusted-hop count, so in that topology `sourceIp` identifies the proxy, not the caller. If you need per-client IPs there, terminate the trust decision in the proxy layer.

**Recommended posture.** Use API Gateway HTTP (v2) with `jwt_validation.mode: "apigw"`. It is the most secure supported frontend on two independent axes: the source IP is platform-attested, so no client-supplied header is ever trusted and the caveat above cannot apply; and a JWT Authorizer rejects invalid tokens at the gateway before the Lambda is invoked.

## The durable trail & `audit_required`

Two modes, and the switch between them is **not** `audit_required` alone:

|                  | `audit_required=false`                                                                                          | `audit_required=true` _and_ `log_to_s3` + `log_bucket` set                          |
| ---------------- | --------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Write path       | Appended to the amortized batch buffer (the one `BufferRecord` feeds)                                           | Written **synchronously**, bypassing the buffer, **before** the credential response |
| Flush trigger    | Size (`BatchSize`), age (`MaxBatchAge`), or container shutdown (SIGTERM → `Cleanup()`)                          | n/a                                                                                 |
| On write failure | Logged; request proceeds                                                                                        | **Request is denied** (fail-closed)                                                 |
| Durability       | **Best-effort** — flushed on SIGTERM within Lambda's ~500 ms shutdown window; a crash or slow S3 PUT loses them | Guaranteed before credentials are issued                                            |

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

A lost or unwritten record must fail the request — that is exactly what `audit_required: true` (the default) guarantees, **once a bucket is configured**. Alert on `eventType = "audit.write.failure"` or `"audit.buffer.failure"` so a failing sink is paged rather than silently tolerated.

## Security signals (for SIEM)

Warn/Error lines carry context (never secrets). Query these by `eventType` (see the [Event catalog](#event-catalog)):

- Unknown/unconfigured issuer, signature failure, algorithm/key-type mismatch, expired/`nbf`/max-age rejection, audience mismatch, condition failure, account-not-allowed → `authz.decision` with `outcome = "deny"` (inspect `stage`/`reason`)
- Oversized token or cache/JWKS object → `cache.item.oversize`, `aws.s3.object.oversize`
- Forced JWKS refetch, and cooldown-suppressed storms → `jwks.refetch.forced`, `jwks.refetch.rate_limited`
- Assume-role failure → `sts.assume_role.failure` (carries `stsErrorCode`)

## Suggested CloudWatch alerts

CloudWatch Logs Insights queries, filtered on `eventType` (and `outcome` where relevant). **Lambda must set `LoggingConfig.LogFormat = "JSON"`** so these become structured fields — the app already emits JSON either way, but without that setting Lambda re-wraps each line as a string field and the query below won't see `eventType` directly.

| Query | Why |
| --- | --- |
| `filter eventType = "authz.decision" and outcome = "deny" and stage = "authorize"` | Misconfigured mappings, or an attack |
| `filter eventType = "audit.write.failure" or eventType = "audit.buffer.failure"` | Audit sink unavailable under `audit_required` |
| `filter eventType = "sts.assume_role.failure"` | A target role's trust policy is refusing, or the execution role is missing `sts:AssumeRole`/`sts:TagSession`. Carries `stsErrorCode` |
| `filter eventType = "jwks.refetch.forced"` (rate of occurrence, rising) | Possible bogus-`kid` flooding |

`matchedVia = "tag-auth"` (credentials issued through the tag-auth fallback) is S3-record-only — it is not on the CloudWatch decision line — so alert on it against the durable trail (e.g. Athena over the S3 objects), not Logs Insights.
