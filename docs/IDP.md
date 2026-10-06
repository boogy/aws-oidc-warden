# Warden as an identity provider (IdP mode)

Optional. The warden validates the inbound OIDC token as usual, then mints its **own** short-lived OIDC token and exchanges it in-process with an unsigned `sts:AssumeRoleWithWebIdentity`. The caller gets ordinary STS credentials.

- [Why](#why)
- [When the IdP is used](#when-the-idp-is-used)
- [Flow](#flow)
- [Hosting discovery and JWKS](#hosting-discovery-and-jwks)
- [KMS signing key](#kms-signing-key)
- [Multi-region deployment](#multi-region-deployment)
- [IAM OIDC provider](#iam-oidc-provider)
- [Trust policy](#trust-policy)
- [Configuration](#configuration)
- [Session duration](#session-duration)
- [Session name](#session-name)
- [Source identity](#source-identity)
- [Calling the endpoint](#calling-the-endpoint)
- [Key rotation](#key-rotation)
- [Hot reload and the kill switch](#hot-reload-and-the-kill-switch)
- [Security notes](#security-notes)
- [Incident response](#incident-response)
- [Error codes and audit fields](#error-codes-and-audit-fields)

## Why

`sts:AssumeRole` called with a role session (always the case on Lambda) is role chaining: STS caps the session at **1 hour**. `AssumeRoleWithWebIdentity` is not chained, so the session can last up to the target role's `MaxSessionDuration` (15 minutes to 12 hours). IdP mode exists for long jobs that outlive one hour.

## When the IdP is used

Every caller uses `/verify`. The mapping that authorizes the role picks the path, never the request:

| Authorizing mapping sets               | Path (while `idp.enabled`) | Session length                            |
| -------------------------------------- | -------------------------- | ----------------------------------------- |
| `max_session_duration` over 1h         | IdP                        | up to that ceiling                        |
| `idp_token: true`                      | IdP                        | up to `max_session_duration` (default 1h) |
| neither                                | `AssumeRole`               | up to 1h, or the mapping's lower ceiling  |

- No role list to maintain: the mappings are the list.
- An IdP mapping uses the IdP for every request, short ones included, so its roles must trust the warden's IAM OIDC provider ([Trust policy](#trust-policy)).
- `idp_token: true` is for a mapping capped at 1h whose role should still be IdP-issued, e.g. one that trusts only the warden's OIDC provider.
- A `max_session_duration` over 1h with no `idp` block is a load error.

A request for more than 1h that cannot use the IdP is refused, never shortened:

| Over 1h requested, and…                | Answer                        |
| -------------------------------------- | ----------------------------- |
| no `idp` block configured              | 400 `duration_exceeds_cap`    |
| the mapping is not an IdP mapping      | 403 `idp_not_permitted`       |
| `idp.enabled: false` (kill switch)     | 503 `idp_signing_unavailable` |

## Flow

```mermaid
sequenceDiagram
    autonumber
    participant C as Caller (CI job)
    participant W as Warden
    participant K as KMS
    participant S as STS
    participant H as Discovery/JWKS host

    C->>W: POST /verify {token, role, durationSeconds?, sessionName?}
    W->>W: Validate inbound token, authorize; the authorizing mapping selects the IdP
    W->>K: kms:Sign (minted token, self-verified before use)
    W->>S: AssumeRoleWithWebIdentity (unsigned, minted token)
    S->>H: GET discovery + JWKS
    S-->>W: Credentials
    W-->>C: Credentials + issuer, roleArn, sessionName, sourceIdentity, durationSeconds, tokenId
```

The minted token never leaves the warden and is never logged or returned. Its claims come only from warden config and the verified inbound identity; inbound claims are never copied.

## Hosting discovery and JWKS

STS fetches `idp.issuer` + `/.well-known/openid-configuration` (here `https://idp.example.com/.well-known/openid-configuration`) and the JWKS when it validates the minted token. Both must be reachable from the public internet at the `idp.issuer` URL.

**Production default: static documents.** Generate them with `idp-export` and upload them to S3/CloudFront (or any static host) at the `idp.issuer` origin:

```sh
idp-export -config config.yaml -out ./site
```

The documents are written under `-out` at `idp.paths.discovery` and `idp.paths.jwks`. `idp-export` applies the `s3_config_bucket` overlay, `mappings_file` and `config_fragments` like the running service, so it needs the same S3 read access. It exports whether or not `idp.enabled` is set, so the documents can be published before the warden starts minting. A warden-served JWKS couples STS availability to the Lambda: every exchange triggers a JWKS fetch, and the warden can DoS itself under load.

With an MRK config, run `idp-export` with `AWS_REGION` set to an allowed region.

**Dev and low volume: warden-served.** The warden answers `GET`/`HEAD` on `idp.paths.discovery` and `idp.paths.jwks` with `Cache-Control: public, max-age=<jwks_cache_max_age>`. If you use this:

- Throttle the discovery/JWKS routes separately from `/verify`.
- The routes must carry **no authorizer** (required in `apigw` delegated mode; STS cannot present a token).
- `idp.paths.*` must match the path the caller requests. An HTTP API v2 with a named stage includes it (`/prod/.well-known/jwks.json`) and returns 404 unless configured that way. A REST API (v1) routes on `requestContext.path`, which keeps the stage on the `execute-api` domain and the base-path mapping on a custom domain.
- Only the two `idp.paths.*` are exposed. Any other near miss of them (other case, trailing slash, one extra leading segment) returns 404 `idp_path_not_found`. A method other than `GET`/`HEAD` returns 405 `method_not_allowed` with an `Allow` header.

One issuer URL per deployment, never shared between stages. A deployment may span regions with one multi-region key (see [Multi-region deployment](#multi-region-deployment)).

## KMS signing key

| Requirement  | Value                                                                   |
| ------------ | ----------------------------------------------------------------------- |
| Key spec     | `ECC_NIST_P256` (`ES256`) or `RSA_2048`/`RSA_3072`/`RSA_4096` (`RS256`) |
| Key usage    | `SIGN_VERIFY`                                                           |
| Multi-region | `false`, or an MRK whose primary and replicas are all in `idp.kms_allowed_regions` |
| State        | `Enabled`                                                               |

`NewKMSSigner` calls `DescribeKey` and `GetPublicKey` and refuses a key that is disabled, multi-region with a primary or replica outside `idp.kms_allowed_regions`, not `SIGN_VERIFY`, of another spec, or whose `SigningAlgorithms` lacks the configured algorithm.

`idp.signing_keys[].kms_key_id` must be the **full key ARN**. Aliases and bare key IDs are rejected: anyone who can `UpdateAlias` could re-point an alias at another key. `GetPublicKey.KeyId` must equal the configured ARN. For an MRK (`key/mrk-…`) the region in the configured ARN is rewritten to the KMS client's region, which must be in `idp.kms_allowed_regions` (required for any MRK). `DescribeKey` must then report the effective ARN. When `kms_allowed_regions` is set, every key ARN's region must be listed, single-region keys included.

Key policy: grant the warden role only `kms:Sign`, `kms:GetPublicKey`, `kms:DescribeKey`, and deny signing to everyone else and key tampering to everyone except a break-glass role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AdminNoSign",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:root" },
      "Action": ["kms:Describe*", "kms:List*", "kms:GetKeyPolicy", "kms:GetPublicKey", "kms:TagResource"],
      "Resource": "*"
    },
    {
      "Sid": "WardenSign",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:role/aws-oidc-warden" },
      "Action": ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"],
      "Resource": "*"
    },
    {
      "Sid": "DenySignToOthers",
      "Effect": "Deny",
      "NotPrincipal": { "AWS": "arn:aws:iam::123456789012:role/aws-oidc-warden" },
      "Action": "kms:Sign",
      "Resource": "*"
    },
    {
      "Sid": "DenyTamper",
      "Effect": "Deny",
      "NotPrincipal": { "AWS": "arn:aws:iam::123456789012:role/break-glass" },
      "Action": ["kms:PutKeyPolicy", "kms:ScheduleKeyDeletion", "kms:DisableKey", "kms:CreateGrant", "kms:ReplicateKey", "kms:UpdateAlias", "kms:UpdatePrimaryRegion"],
      "Resource": "*"
    }
  ]
}
```

Also:

- Apply the key policy on every replica; each replica has its own.
- A break-glass `kms:ReplicateKey` must pass the hardened `Policy`. Without it, KMS attaches the default policy, which grants the account root `kms:*`.
- SCP: deny the tamper actions on the key (including `kms:ReplicateKey` and `kms:UpdatePrimaryRegion`) for everyone but the break-glass role.
- SCP or `DenyTamper` condition: deny `kms:ReplicateKey` when `kms:ReplicaRegion` is `StringNotEquals` the allowed regions.
- Alarms (CloudTrail/EventBridge): any `kms:Sign` by another principal, and every action in the tamper list (including `kms:ReplicateKey` and `kms:UpdatePrimaryRegion`).
- Alarms must cover every region. `ReplicateKey` logs `CreateKey` in the replica's region. Also alarm on `PutKeyPolicy` in every region.
- Warden role IAM: `kms:DescribeKey`, `kms:GetPublicKey` and `kms:Sign` on each region's replica ARN. A role shared across regions needs all of them; a per-region role needs only its local one.
- Quota: KMS `Sign` request quotas are per account and shared with every other signer. Use a dedicated account or a sized quota. Throttling surfaces as 503 `idp_signing_unavailable`.

## Multi-region deployment

One `idp.issuer` can be served from several regions of the same deployment:

- Create one MRK and one replica per region. Every region runs the same config.
- Set `idp.kms_allowed_regions` to the primary and every replica region. Required for an MRK.
- Each region signs with its local replica. Same key material gives the same `kid` and one JWKS.
- Host the JWKS statically and globally (S3 + CloudFront from `idp-export`), not from a regional Lambda.
- Create a single global IAM OIDC provider for `idp.issuer`.
- The replica-region allowlist is a detective control. A rogue replica is detected at the next cold start, which fails the IdP closed in every region. It does not revoke the replica: until someone acts, it can sign tokens STS trusts.
- The preventive controls are `DenyTamper` on `kms:ReplicateKey` in the primary key policy, and the SCP.
- Adding a region: add it to `kms_allowed_regions` in every region's config, deploy, then `ReplicateKey`.
- Removing a region: delete the replica and wait until it is fully deleted (past its waiting period), then drop the region from the allowlist.
- A single-region key cannot serve a multi-region deployment; KMS keys are regional, and the signer rejects a client region that differs from the key's. Finish rotating onto the MRK in the home region before adding regions.

The rest of a multi-region deployment (per-region buckets, cache, environment): [ARCHITECTURE.md § Multi-region](ARCHITECTURE.md#multi-region) and [examples/multi-region/](examples/multi-region/README.md).

## IAM OIDC provider

Create one IAM OIDC provider per deployment for the warden itself. The inbound issuers (GitHub, GitLab, …) need no IAM provider for IdP mode:

- URL: `idp.issuer` (`https://idp.example.com`)
- Client ID: `idp.audience` (`idp-audience-example`)

IAM ignores thumbprints for providers served by a CA-trusted certificate.

## Trust policy

Every target role trusts the warden's IAM OIDC provider (not GitHub's or any other inbound issuer's) and needs these actions: `sts:AssumeRoleWithWebIdentity`, `sts:TagSession`, `sts:SetSourceIdentity`. The examples use `idp.issuer: https://idp.example.com`, so the provider is `oidc-provider/idp.example.com` and the condition keys are `idp.example.com:aud` / `idp.example.com:sub`. With a path in the issuer (`https://example.com/idp`), both carry it: `oidc-provider/example.com/idp` and `example.com/idp:aud` / `example.com/idp:sub`.

`aud` is always pinned with `StringEquals`. The minted `sub` is `idp.subject_template` with its placeholders filled, and always ends with the role ARN:

| Placeholder                           | Value                                                |
| ------------------------------------- | ---------------------------------------------------- |
| `{role_arn}`                          | target role ARN (required, exactly once, at the end) |
| `{account_id}`, `{role_name}`         | parts of the role ARN                                |
| `{source_issuer}`, `{source_subject}` | inbound issuer and canonical subject                 |

**Recommended: keep the default `{role_arn}`.** The `sub` is then the role's own ARN: short, one fixed value per role. Which callers may assume the role is decided by the warden's mappings; which roles the IdP can reach is decided by which roles trust the warden's IAM OIDC provider.

Worked example for `role/LongDeploy` with the default template:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Federated": "arn:aws:iam::123456789012:oidc-provider/idp.example.com" },
      "Action": ["sts:AssumeRoleWithWebIdentity", "sts:TagSession", "sts:SetSourceIdentity"],
      "Condition": {
        "StringEquals": {
          "idp.example.com:aud": "idp-audience-example",
          "idp.example.com:sub": "arn:aws:iam::123456789012:role/LongDeploy"
        }
      }
    }
  ]
}
```

**Optional: `{source_issuer}#{source_subject}#{role_arn}`** puts the caller into `sub`, so the role's trust policy can also pin the caller. Use it only when whoever writes the mappings is trusted less than the role owner (for example a split `mappings_file`). Costs: the full issuer URL makes each value long, and the trust policy size limit (2,048 characters by default) caps how many callers one role can list. `{source_subject}` needs `{source_issuer}#` before it.

The warden still issues the token; the inbound issuer and subject are only text inside the minted `sub`. A GitHub Actions caller from `octo-org/api` (canonical subject = `repository` claim) minting for `LongDeploy` gets this `sub`, pinned whole with `StringEquals`:

```json
"StringEquals": {
  "idp.example.com:aud": "idp-audience-example",
  "idp.example.com:sub": "https://token.actions.githubusercontent.com#octo-org/api#arn:aws:iam::123456789012:role/LongDeploy"
}
```

Pitfalls with the caller-bearing template:

- `StringLike` `*` is greedy across `#`. Keep the source issuer as a fixed prefix and the role ARN as a fixed suffix so the wildcard covers only the source subject. Never wildcard the role-ARN part, and never put a leading or trailing wildcard around the issuer.
- Matching is case-sensitive.
- Pin `sub` with `StringEquals` wherever the whole value is known; avoid `StringLike` with `*`.
- Without the fixed suffix, a subject containing `#` could forge another role's `sub`.

Optional hardening:

- Pin session tags, for example `"aws:RequestTag/repository": "octo-org/api"` under `StringEquals`; pair it with `Null` (`"aws:RequestTag/repository": "false"`) so the tag must be present.
- Pin the source-identity prefix with `StringLike` on `sts:SourceIdentity`. With the default template it starts with the inbound issuer host the warden writes there (for example `token.actions.githubusercontent.com=*`); never pin the full value.
- Use `ForAllValues:StringEquals` on `aws:TagKeys` with a `Null` check to restrict which tag keys may be sent.

### `audience_mode: role_arn`

`aud` becomes the target role ARN instead of `idp.audience`. Register each role ARN as a client ID on the IAM OIDC provider (IAM limits client IDs per provider; check the current quota) and pin `idp.example.com:aud` with `StringEquals` to the role's own ARN. A token minted for role A then fails `aud` on role B even if a `sub` pin is wrong. The default `static` keeps `idp.audience`.

## Configuration

```yaml
idp:
  enabled: true
  issuer: "https://idp.example.com"
  audience: "idp-audience-example"
  signing_keys:
    - kms_key_id: "arn:aws:kms:eu-west-1:123456789012:key/00000000-0000-0000-0000-000000000000"
      algorithm: ES256
      status: active

role_mappings:
  - issuer: "https://token.actions.githubusercontent.com" # inbound issuer, not idp.issuer
    subject: "octo-org/long-job"
    roles: ["arn:aws:iam::123456789012:role/LongDeploy"]
    max_session_duration: 4h # over 1h: issued through the IdP
```

Full key reference: [CONFIGURATION.md](CONFIGURATION.md#idp-optional-identity-provider).

- `max_session_duration` is set per mapping (or in `role_groups[].defaults`) and applies to every role that mapping grants: 15m to 12h, default `1h`. There is no service-wide ceiling; each role's trust policy and IAM `MaxSessionDuration` are the hard limits.
- `idp` is base-only: config fragments and the mappings file cannot carry it.
- A role in another account needs `cross_account.enabled: true` and, when `allowed_accounts` is non-empty, that account listed in it, as for `AssumeRole`; otherwise the request is refused with 403 `permission_denied`. The exchange never uses the spoke role.

## Session duration

| Request `durationSeconds`             | Result                                     |
| ------------------------------------- | ------------------------------------------ |
| omitted                               | `min(3600, ceiling)`                       |
| outside 900..43200                    | 400 `invalid_duration`                     |
| above the ceiling                     | 400 `duration_exceeds_cap` (never clamped) |
| above the role's `MaxSessionDuration` | 400 `duration_exceeds_role_max`            |

Ceiling = the authorizing mapping's `max_session_duration` (1h when unset). When several mappings grant the role, the lowest-order one wins. Set the role's `MaxSessionDuration` at least as high as the longest session you intend to allow.

A role served by `AssumeRole` accepts `durationSeconds` from 900 to 3600 (omitted = 3600). Above that see [Why](#why).

## Session name

The same rule applies to every request, IdP or `AssumeRole`:

1. The mapping's `role_session_name`, if set. It overrides a request `sessionName`.
2. The request `sessionName`, only if the mapping sets `allow_session_name: true`; otherwise it is ignored. When used it must match `^[\w+=,.@-]{2,64}$`, else 400 `invalid_session_name`. An ignored or overridden name is not validated; it logs `authz.session_name.ignored` (Warn).
3. The global `role_session_name`.

## Source identity

`idp.source_identity` is a template rendered per request and set as the STS `SourceIdentity` (carried in the minted token, immutable for the session). Placeholders:

| Placeholder      | Value                                                                                                  |
| ---------------- | ------------------------------------------------------------------------------------------------------ |
| `{request_id}`   | the warden request ID                                                                                  |
| `{subject}`      | the canonical subject                                                                                  |
| `{issuer}`       | the inbound issuer's host and path (not `idp.issuer`), so two issuers sharing a subject cannot collide |
| `{claim:<name>}` | a verified inbound claim; a missing claim fails with 403 `idp_source_identity_invalid`                 |

The default is `{issuer}:{subject}`. STS allows only `[\w=,.@-]`, so every other character becomes `=`, including the literal `:`. A substituted value that needed sanitizing also gets `+` and 16 hex characters of its SHA-256, so distinct inputs stay distinct. Example: inbound issuer `https://token.actions.githubusercontent.com`, subject `octo-org/api` renders `token.actions.githubusercontent.com=octo-org=api+<16 hex>`.

Over 64 characters, `idp.source_identity_overflow` decides: `truncate` (default; 47 characters, `+`, 16 hex of the SHA-256) or `reject` (403 `idp_source_identity_invalid`). The audit field `sourceIdentityTruncated` flags truncation. Truncation is attribution, not an access boundary.

`{issuer}` renders the issuer URL host plus its path (trailing `/` dropped). A path issuer such as `https://kc.example.com/realms/a` contains `/`, so it is sanitized and hashed; issuers sharing a host still render distinctly.

`aws:SourceIdentity` is the key for downstream ABAC and CloudTrail attribution. `idp.include_source_identity: false` omits it from the minted token. The template is then not rendered, so a bad template cannot fail the mint.

## Calling the endpoint

`POST` to `/verify` on the warden's own front end (API Gateway, ALB or Lambda URL), here `https://warden.example.com`, with the optional `durationSeconds` and `sessionName`. It is not the static discovery host. The inbound token's audience must match that issuer's `audiences` in the warden config, not `idp.audience`. GitHub Actions example:

```yaml
name: long-job
on: push
permissions:
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Get credentials
        run: |
          TOKEN=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -r .value)
          RESP=$(curl -sSf -X POST "https://warden.example.com/verify" \
            -d "$(jq -n --arg t "$TOKEN" '{token:$t, role:"arn:aws:iam::123456789012:role/LongDeploy", durationSeconds:14400}')")
          echo "::add-mask::$(jq -r .data.SecretAccessKey <<<"$RESP")"
          echo "::add-mask::$(jq -r .data.SessionToken <<<"$RESP")"
          {
            echo "AWS_ACCESS_KEY_ID=$(jq -r .data.AccessKeyId <<<"$RESP")"
            echo "AWS_SECRET_ACCESS_KEY=$(jq -r .data.SecretAccessKey <<<"$RESP")"
            echo "AWS_SESSION_TOKEN=$(jq -r .data.SessionToken <<<"$RESP")"
          } >> "$GITHUB_ENV"
```

The success body carries `AccessKeyId`, `SecretAccessKey`, `SessionToken`, `Expiration`, `issuer`, `roleArn`, `sessionName`, `sourceIdentity`, `durationSeconds`, `tokenId` under `data`. It never contains a token.

## Key rotation

The loader is all-or-nothing: if any configured key fails to load, none are served. Rotate in this order:

1. Add the new key as `verify_only`; deploy, or re-run `idp-export` and upload.
2. Wait at least `jwks_cache_max_age` plus STS's own cache time.
3. Make the new key `active` and the old one `verify_only`.
4. **Remove the old key from config and deploy.**
5. Wait for the JWKS max-age to pass.
6. **Only then** disable or schedule deletion of the old KMS key.

For an MRK, replicate the new key to every allowed region before step 1.

Disabling a KMS key that is still configured makes the load fail and takes the IdP down. At most 5 keys, exactly one `active`.

## Hot reload and the kill switch

| Frozen at cold start (restart to change)                                                                                                                                                         | Live (read per request)                                                          |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------- |
| `issuer`, `audience`, `audience_mode`, `jwks_uri`, `paths`, `signing_keys`, `subject_template`, `source_identity*`, `include_source_identity`, `token_ttl`, `sign_timeout`, `jwks_cache_max_age` | `enabled`, plus per-mapping `idp_token`, `max_session_duration`                 |

A reload that changes a frozen field, or adds an `idp` block absent at startup, logs `config.idp.reload_ignored` once and keeps the running values. A reload that makes an inbound issuer equal the frozen IdP issuer, or adds a second issuer while the frozen `source_identity` lacks `{issuer}`, is rejected (`config.idp.issuer_collision`).

**Kill switch:** set `idp.enabled: false` in the layer that set it. Environment beats S3: `AOW_IDP_ENABLED` is re-applied after every S3 merge, so never set `AOW_IDP_ENABLED` on Lambda if the S3 overlay is your switch. Order of operations:

1. Disable.
2. Confirm a request for more than 1h answers 503 `idp_signing_unavailable`. Requests of 1h or less fall back to `AssumeRole`, which only works where the role also trusts the warden's own role.
3. Then revoke (remove the client ID from the warden's IAM OIDC provider; add a Deny on `aws:TokenIssueTime`).

While disabled, the warden answers 404 `idp_path_not_found` on GET/HEAD of its discovery and JWKS paths (other methods stay 405) (logged at Debug as `idp.path.disabled`, not as a near miss), so STS stops trusting the key once its JWKS cache expires. Statically hosted documents (`idp-export`) keep serving: remove them yourself.

## Security notes

- The token is self-verified before use, signed only by the configured KMS key, and never logged.
- Only `ES256` and `RS256`.
- Transitive session tags: with `session_tags_transitive`, the minted token carries the tag keys as transitive; STS packed-policy limits apply (500 `idp_token_too_large`).
- Token size: STS accepts at most 20,000 bytes; long claim values and many tags can exceed it.
- The IdP reaches only roles whose trust policy trusts the warden's IAM OIDC provider with the `sub` pin: a role opts in on the AWS side.
- PEM key files are dev-only; they are refused on Lambda unless `allow_insecure_issuers` is set.

| Risk                                                          | Control                                                                                  |
| ------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Key policy tampering, alias re-pointing, multi-region replica | Full-ARN pinning, tamper Deny and SCP (preventive), replica-region allowlist (detective), alarms |
| A mapping writer widening sessions                            | The role's trust policy (`sub` pin) and IAM `MaxSessionDuration`                         |
| Self-DoS through JWKS fetches                                 | Static hosting from `idp-export` by default                                              |
| Half-rotated keys                                             | All-or-nothing loader; rotation order above                                              |
| Cross-role token reuse                                        | `sub` ends with the role ARN; optional `audience_mode: role_arn`                         |
| Session-name spoofing                                         | Caller names need `allow_session_name`; validated charset; `SourceIdentity` is immutable |

## Incident response

In order:

1. Stop minting: `idp.enabled: false` (see the kill switch above).
2. Stop STS accepting: remove the client ID from the warden's IAM OIDC provider, or disable the KMS key.
3. Revoke live sessions: add a Deny on `aws:TokenIssueTime` to the affected roles.
4. Scope the damage in CloudTrail by `accessKeyId` and `sourceIdentity` (both are in the audit record).
5. Rotate the signing key.
6. Restrict `iam:UpdateRole` and trust-policy edits to a break-glass role.

## Error codes and audit fields

Every response uses the standard error envelope. "Retry" means the same request may succeed later.

| Code                          | Status | Retry | Cause                                                                           |
| ----------------------------- | ------ | ----- | ------------------------------------------------------------------------------- |
| `idp_not_permitted`           | 403    | No    | Over 1h for a mapping that is not an IdP mapping                                |
| `idp_source_identity_invalid` | 403    | No    | Source identity could not be derived or overflowed with `reject`                |
| `idp_subject_invalid`         | 403    | No    | `subject_template` rendered a `sub` over 255 bytes or outside ASCII `!`–`~`     |
| `idp_exchange_denied`         | 403    | No    | STS refused: fix the trust policy or the warden's IAM OIDC provider             |
| `invalid_duration`            | 400    | No    | `durationSeconds` outside 900..43200                                            |
| `duration_exceeds_cap`        | 400    | No    | Above the mapping's `max_session_duration`, or over 1h with no `idp` block      |
| `duration_exceeds_role_max`   | 400    | No    | Above the role's `MaxSessionDuration`                                           |
| `invalid_session_name`        | 400    | No    | `sessionName` fails the pattern                                                 |
| `idp_path_not_found`          | 404    | No    | Near miss of a discovery/JWKS path, or either path while `idp.enabled` is false |
| `method_not_allowed`          | 405    | No    | Not `GET`/`HEAD` on a discovery/JWKS path                                       |
| `idp_token_too_large`         | 500    | No    | Minted token or packed policy over the STS limit; reduce session tags           |
| `idp_signing_unavailable`     | 503    | Yes   | KMS unavailable or throttled; also the kill-switch answer over 1h               |
| `idp_exchange_unavailable`    | 503    | Yes   | STS could not reach discovery or JWKS                                           |

The audit record gains, for `action: mint_token`: `tokenId`, `idpSessionCapSeconds`, `sourceIdentity`, `sourceIdentityTruncated`, `accessKeyId`. Both actions record `durationSeconds`, `requestedDurationSeconds` when the caller sent one, `sessionNameSource` (`mapping`, `request` or `default`) and, when the caller sent one and `log_claim_values` is true, `requestedSessionName`, even if it was ignored. Log events are catalogued in [LOGGING.md](LOGGING.md#event-catalog).
