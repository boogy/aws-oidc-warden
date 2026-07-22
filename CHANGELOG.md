# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.0] - 2026-07-22

Findings from a whole-codebase security review that covered the packages the
2.1.0/2.1.1 sweeps had not reached (`internal/cache`, `internal/s3logger`, the
SSRF/JWKS fetch path, fragment integrity, and the AWS spoke/tag caches). Every
fix is mutation-tested — each was confirmed to fail its regression test when the
fix is removed. Three behavior changes; see Upgrade notes.

No authorization bypass was found. The two most consequential properties were
re-confirmed rather than changed: the SSRF block is enforced at **dial** time
against the already-resolved IP (so DNS rebinding is structurally prevented, not
merely time-windowed) and on every redirect hop; and the JWKS refetch limiter
cannot be used to pin a stale key set after a rotation, because a forced refetch
that the limiter *allows* write-through repairs the cache — spending the slot is
the act that installs the new keys.

### Upgrade notes

- **Enable `audit_required` by redeploy, not by hot reload.** With the fail-open
  closed, a reload that turns on `audit_required` from a boot config with
  `log_to_s3: false` leaves the sink with no S3 client, and every request now
  fails closed until a cold start. Previously it silently returned credentials
  with no audit record.
- **The SSRF guard blocks more ranges.** If a JWKS or issuer host resolves into
  `100.64.0.0/10` or `0.0.0.0/8`, or is reached through the NAT64 well-known
  prefix, it will now be refused. Public issuers are unaffected; `allow_insecure_issuers`
  still relaxes loopback only.
- **`iam:GetRole` rejects a role whose name exceeds 64 characters** instead of
  truncating it. Such a name never denoted a real role, so a request that
  previously "worked" was already reading the wrong role's tags.

### Security

- **`audit_required` no longer fails open after a hot reload** — `S3Logger`
  captures the `*config.Config` handed to it at bootstrap, but the hot-reload
  provider swaps in a **new** `Config` on every refresh, so that snapshot could
  disagree with the live config the processor reads. `WriteRecord` gated on the
  stale snapshot's `LogToS3`, so a reload that turned on `audit_required` +
  `log_to_s3` left it a silent no-op that **returned success** — credentials
  were released with no audit record, the exact inverse of `audit_required`'s
  fail-closed contract. Durability now rests on whether an S3 client actually
  exists, and `WriteRecord` never no-ops. Static deployments were unaffected:
  `Validate()` gates the `audit_required` → `log_to_s3` pairing within a single
  config.

- **Durable audit records follow a hot-reloaded `log_bucket`** — the bucket was
  captured at construction, so rotating `log_bucket` by reload (e.g. to a
  locked-down bucket during an incident) kept writing to the previous bucket
  while `WriteRecord` reported success: a write that "succeeded" somewhere the
  operator no longer intended. `S3Logger` now takes a live-config source
  (`SetConfigSource`, the same seam `AwsConsumer` already uses) and resolves the
  bucket per write.

  **Known residuals.** (a) A reload that enables `audit_required` from a boot
  config with `log_to_s3: false` now correctly refuses every request
  (fail-closed) until a cold start rather than silently leaking — enable it by
  redeploy, not reload. (b) The best-effort `BufferRecord` path still consults
  the boot snapshot, so records are dropped when `log_to_s3` is enabled only by
  reload; that path is explicitly best-effort and never gates credentials.

- **`config_fragments` checksum pins are enforced on every refresh** — the pin
  was compared only on the "changed" path, so a cache hit (`etag == prevETag`)
  skipped it entirely and a pin newly added or rotated to quarantine
  already-applied fragment content was silently inert — precisely the
  incident-response case pinning exists for. Cold starts always enforced it,
  which bounded the exposure.

- **`iam:GetRole` no longer truncates an over-long role name** — a name longer
  than IAM's 64-character maximum was silently truncated and the lookup ran
  against the truncated name, reading the tags of a *different* role than the
  ARN named. Since those tags drive tag-based authorization, silently rewriting
  the identifier is the wrong reflex; it is now rejected. Not exploitable (an
  over-long name never denotes a real role, and the subsequent `AssumeRole` uses
  the full ARN), but it matches the "skip/reject, never coerce" rule
  `BuildSessionTags` already follows. The cap is measured on the role **name**
  — the segment after the last `/` — because a role identifier may carry a path
  (`/team/sub/Name`); measuring the whole string would reject a valid role with
  a deep path and a short name.

- **`ExternalId` is no longer logged** — the too-short-external-ID rejection
  path logged the value. Only reachable for a one-character secret, so nothing
  meaningful leaked, but it printed a configured shared secret.

- **`Cache-Control: no-store` on all API responses** — a 200 carries live AWS
  credentials. The handlers do not inspect the HTTP method (a GET is processed
  identically to a POST), so the usual "caches don't store POST responses"
  reasoning could not be relied on; the requirement is now stated explicitly
  rather than inherited from the method.

- **SSRF guard covers IPv6 carrier forms and the remaining reserved IPv4
  ranges** — `isBlockedIP` saw through only the IPv4-mapped `::ffff:x.x.x.x`
  form. It now also resolves the deprecated IPv4-compatible `::x.x.x.x` form and
  the NAT64 well-known prefix `64:ff9b::/96` (which a NAT64 gateway rewrites to
  the embedded IPv4, loopback and link-local included), and blocks
  `100.64.0.0/10` (RFC 6598 shared address space, used by AWS for ECS `awsvpc`
  and EKS pod networking) and `0.0.0.0/8`. None was exploitable — reaching any
  required controlling DNS for an already-trusted issuer, and the
  IPv4-compatible forms are unroutable — but the guard already blocked RFC1918,
  so leaving these open was an inconsistency rather than a considered exception.
  A companion test pins that public addresses and the `100.64.0.0/10` boundaries
  are **not** over-blocked.

- **`GetRoleTags` authorizes the target account before consulting its cache** —
  the role-tag cache was read first, so for up to `roleTagCacheTTL` (60s) after
  an operator revoked an account, a warm entry kept handing back that account's
  IAM tags for tag-based authorization to act on. Revocation now takes effect on
  the next request. `spokeCredsFor` already validated before *its* cache, so the
  two caches in that file now follow one rule; more importantly, this layer no
  longer depends on `ProcessRequest` happening to call `IsTargetAccountAllowed`
  earlier in the pipeline — a cross-package ordering nothing enforces, and the
  only reason the stale window was previously unreachable. The check applies the
  same policy the post-cache path already enforced, so it changes *when* the
  decision is made, not what it decides.

- **`GetRoleAs` rejects a nil credentials provider** — it would otherwise leave
  the hub credentials in place and read a same-named role in the **hub** account
  while the caller believed it read a member account's. Unreachable via its one
  caller; the guarantee no longer depends on that caller.

- **`GetRoleTags` returns a copy of its cached tag map** — it handed out the
  cached map itself, so any caller that mutated it would poison every later
  authorization decision for that role. The sole caller only reads, so this is
  defensive, but the failure mode would be silent and cross-request.

### Added

- **Config-load warning for implicit issuer binding** — a mapping that declares
  no `issuer` binds to `default_issuer`. With one configured issuer that is
  unambiguous; once a second exists, those mappings silently move into whichever
  namespace `default_issuer` names — so a remote overlay that adds an issuer
  **and** sets `default_issuer` in one merge re-homes every previously-implicit
  grant with no redeploy, moving a GitHub-bound grant to another IdP. Fragments
  are already guarded (`mergeFragment` requires a base-defined, non-conflicting
  `default_issuer`); the primary overlay was not, so `Validate()` now warns.

- **Config-load warning for unscoped role grants** — when the lowest-`order`
  mapping granting a role carries no `session_policy` but a higher-order one
  does, `Validate()` now warns, because `FindSessionPolicy` is lowest-order-wins
  and the scoped policy is silently dropped. This is most acute across the
  `role_mappings`/`role_groups` boundary: `Validate()` appends every
  `role_mapping` before every `role_group`, so a `role_group`'s session policy
  can **never** outrank a policy-less `role_mapping` for the same role, and —
  unlike the intra-`role_mappings` case — no file ordering can fix it. The
  selection rule itself is unchanged and remains pinned by
  `TestOrderWinsAmongMappingsGrantingTheSameRole`; this makes the footgun loud
  rather than changing authorization semantics.

- **Regression tests for the reviewed areas** — JWKS cache issuer isolation and
  concurrency (`internal/cache`), SSRF guard depth proving the block is enforced
  at **dial** time and on every redirect hop (`internal/validator`), role-tag /
  spoke-credential cache keying and expiry (`internal/aws`), fragment integrity
  and merge scoping (`internal/config`), and the `audit_required` contract
  (`internal/handler`, `internal/s3logger`).

## [2.1.1] - 2026-07-21

Hardening release closing the last unenforced authorization footgun found by an
independent verification sweep of the 2.1.0 authorization layer, plus the
adversarial test suite that sweep produced. One behavior change: a config that
uses a bare wildcard as a `subject` now fails to load instead of silently
authorizing everything — see Upgrade notes.

### Security

- **Bare wildcard `subject` patterns are now rejected** — `Validate()` refused a
  bare `.*`/`.+` in `conditions`, but never applied the same rule to a
  `role_mapping.subject` or a `role_groups.subjects` entry, even though the
  subject is the primary identity gate. `subject: ".*"` therefore compiled
  happily and granted that mapping's roles to **every** subject of the bound
  issuer — for the default GitHub issuer, every repository in every organization
  that can mint a token GitHub signs. The documentation has said "keep patterns
  specific, never `.*`" since 1.x; nothing enforced it. Both paths into the
  effective mapping set now share one guard (`bareWildcards`), so subjects and
  conditions can no longer drift apart.

  The check is deliberately literal — it matches the two shapes operators
  actually type. An equivalent pattern written another way (`(.*)`, `[\s\S]*`)
  still compiles; this stops the accident, not a determined operator.

### Added

- **Adversarial authorization test suite** — 36 tests across the four security
  layers, written independently of the existing tests and verified to have teeth
  by mutation testing (each was confirmed to fail when the fix it covers is
  removed):
  - `internal/config/authz_adversarial_test.go` — includes a differential fuzz
    (400 random configs × 21 adversarial subject patterns × 18 subjects) that
    diffs the owner-bucketed index against a reference linear scan for both
    `AuthorizeRoles` and `FindSessionPolicy`. An index false *negative* is
    fail-open — a policy-bearing mapping dropped from the scan while a broader
    policy-less one still authorizes yields an unscoped assumption — so this is
    fuzzed rather than example-tested. Reverting the 2.1.0 `classifySubject` fix
    makes it re-derive that bug unaided.
  - `internal/validator/trust_boundary_test.go` — cross-issuer key confusion,
    `alg:none`, HS256/RSA algorithm confusion, payload splicing, time bounds, and
    proof that an unconfigured `iss` triggers zero network requests (no SSRF
    primitive via the `iss` claim).
  - `internal/aws/assume_adversarial_test.go` — cross-account fail-closed paths,
    malformed-ARN guard bypass attempts, session-tag charset/limit handling
    (skipped, never truncated or sanitized), transitive-tag opt-in, duration
    clamping.
  - `internal/handler/pipeline_e2e_test.go` — the scoping policy actually reaching
    STS, every deny path stopping before STS, and a failed or invalid-JSON
    session-policy file denying rather than assuming unscoped.

### Upgrade notes

- **A config with `subject: ".*"` (or `.+`) will now fail to load.** This is
  intentional and fail-closed: the service refuses to start rather than run an
  authorization rule that matches every repository. If you hit this, replace the
  wildcard with a pattern scoped to the organizations you actually trust (e.g.
  `myorg/.*`), which continues to work unchanged. Patterns that merely *contain*
  a wildcard — `org/service-.*`, `myorg/.*`, `.*/shared-lib` — are unaffected;
  only a subject that is *entirely* `.*` or `.+` is rejected. No mapping in
  `example-config.yaml` or the shipped documentation used one.

## [2.1.0] - 2026-07-21

Security-hardening release: three authorization-layer defects found in an audit
of the token→AssumeRole path, each fixed with a regression test that fails
before the change. No config-schema or deployment changes — existing configs
keep working — but authorization behavior is now stricter where the old code was
wrong (a role that was silently assumed unscoped now carries its intended
session policy, and conditions can no longer be transiently bypassed), so review
the Security notes before upgrading.

### Security

- **Session policy scoping bound to the granting role** — `FindSessionPolicy`
  resolved by `(issuer, subject)` only and returned the first-declared mapping
  matching the subject, ignoring which mapping granted the requested role. A
  broad, policy-less `role_mapping` declared before a narrow mapping that
  deliberately scopes a privileged role with a `session_policy` caused that role
  to be assumed **unscoped**. The lookup is now role- and condition-aware: the
  scoping policy always comes from the mapping that authorized the role
  (subject match + conditions satisfied + grants the role). Signature changed to
  `FindSessionPolicy(issuer, subject, role, claims)`.

- **Hot-reload condition race fixed (authorization bypass)** — a
  `config_fragment`'s `*Condition` was shared across config snapshots, and each
  hot reload recompiled it in place (`Validate` → `compileCondition`) while
  concurrent requests read the served snapshot with no lock. A reader observing
  the transiently-empty compiled list had all conditions silently pass. Fragment
  and role-group conditions are now cloned into per-snapshot private memory
  before compilation, so a reload can never mutate a condition another request
  is evaluating. Affected configs using `config_reload_interval` +
  `config_fragments` with `conditions`; base-config conditions were unaffected.

- **Correct index bucketing for quantified-slash subject patterns** — the
  authorization index inferred a mapping's owner bucket from the raw text before
  the first `/`. A subject pattern whose first slash is quantified (e.g.
  `owner/?repo-.*`, `owner/*repo`) also matches slash-less subjects, so the
  index could drop a mapping a full scan would find — diverging from the
  authorize decision and mis-scoping the session policy. Bucketing now uses the
  compiled pattern's guaranteed literal prefix (`regexp.LiteralPrefix`), so a
  mapping is owner-scoped only when every match provably starts with `owner/`.
  Operator-config-only and fail-closed for authorization; no attacker vector.

### Upgrade notes

Two consequences of the session-policy fix above. Neither is a new code change;
both describe behavior as shipped in 2.1.0, called out because they can be
observed as a difference in production.

- **Tag-authorized roles now correctly receive no session policy.** Session
  policies have always been documented as coming only from `role_mappings`, with
  a tag-authorized role "scoped solely by its own IAM permissions" (see
  `docs/TAG_BASED_AUTHORIZATION.md` → Security model & foot-guns #3). Because the
  pre-fix lookup keyed on `(issuer, subject)` alone, a role authorized via
  `tag_auth` could nevertheless pick up the session policy of an unrelated
  mapping that merely matched the same subject. The role-aware lookup removes
  that accident, so the code now matches the documented contract. If you run
  `tag_auth` alongside `role_mappings` carrying `session_policy`, tag-authorized
  sessions that were incidentally being scoped no longer are — confirm those
  roles are least-privilege at the IAM level, which is the documented
  expectation. `tag_auth.enabled` defaults to `false`, so this affects opt-in
  configurations only.

- **`session_policy` selection remains order-sensitive among mappings that grant
  the same role.** First-declared still wins, but the candidate set is now
  correctly narrowed to mappings that actually grant the requested role and
  satisfy their conditions. One consequence survives and is worth auditing: if a
  broad mapping grants a role with **no** `session_policy` and a later, narrower
  mapping grants that *same* role *with* one, the broad mapping wins on order and
  the role is assumed **unscoped**. This is consistent with the union semantics of
  `AuthorizeRoles` — the broad entry did explicitly grant the role — and is
  unchanged from previous releases, but it is rarely intended. Declare the scoped
  mapping first, or avoid granting a policy-scoped role from a broader,
  policy-less entry. See `docs/CONFIGURATION.md`.

### Performance

- **JWKS warm prefetch on cold start** — `NewBootstrap()` now prefetches every
  issuer's JWKS during Lambda INIT (self mode only, 3s bounded), so the first
  request no longer pays an inline OIDC discovery + JWKS fetch. Best-effort:
  a slow/unreachable issuer is abandoned at the timeout and fetched on demand.

## [2.0.1] - 2026-07-08

### Security

- **Go 1.26.5** — toolchain bump fixing GO-2026-5856 (Encrypted Client Hello
  privacy leak in `crypto/tls`), reachable via the HTTPS paths the warden
  uses (JWKS fetch, S3 reads, local server).

### Fixed

- **OpenTofu `api_endpoint` output** — the `$default` stage `invoke_url` ends
  with a trailing slash, so the output rendered `…amazonaws.com//verify`;
  HTTP APIs do not normalize double slashes, making the documented smoke-test
  URL a 404. The slash is now trimmed before appending `/verify`.

### Changed

- **OpenTofu quick-setup guardrails** — a missing `dist/function.zip` now
  fails `plan` with a clear "run deploy/opentofu/build.sh first" precondition
  instead of a raw `filebase64sha256` error, and the API Gateway JWT
  Authorizer (`apigw` mode) now defaults to `var.issuer` / `var.audiences`
  so the authorizer and the rendered `config.yaml` cannot drift apart
  (`jwt_authorizer_issuer` / `jwt_authorizer_audiences` remain as explicit
  overrides).

## [2.0.0] - 2026-07-02

Multi-issuer, any-provider release. v2 validates OIDC tokens from any number of
issuers/providers, keys authorization on a provider-neutral canonical
**subject**, and scales to thousands of mappings. This is a breaking release —
see `docs/MIGRATION_V2.md` for the upgrade path.

### Breaking Changes

- **Multi-issuer config model** — the top-level `issuer` / `audience` /
  `audiences` keys are **removed**. Trusted issuers are now declared under
  `issuers[]` (each with `issuer`, `provider`, `audiences`, optional
  `jwks_uri` / `claim_mappings` / `required_claims` / `session_tags`). The
  `AOW_ISSUER` / `AOW_AUDIENCE` / `AOW_AUDIENCES` env vars are removed.
- **Provider-neutral authorization renames** — `repo_role_mappings` →
  `role_mappings` (mapping key `repo:` → `subject:`, `constraints:` →
  `conditions:`), `repo_role_groups` → `role_groups`. The old keys are no
  longer accepted.
- **Authorization keys on a canonical `subject`** — derived per issuer
  (GitHub default = the `repository` claim). Non-`github` providers **must**
  set `claim_mappings.subject`. A token can never self-assert an unmapped
  subject.
- **Session tags are per-issuer and spec-driven** — configured via each
  issuer's `session_tags` (STS tag key ← raw claim name). The default GitHub
  `repo` tag now carries the **full `owner/repo`** (the raw `repository`
  claim); v1 stripped the owner to a bare name. Update any ABAC policies that
  matched a bare repo name. Invalid tag values are **skipped and logged, never
  sanitized/truncated** (a mangled value must not silently reach an ABAC
  condition).
- **Delegated modes (`apigw` / `alb`) require exactly one configured issuer**
  and fail closed otherwise; they re-validate the same claim bounds as `self`.
- **Tag-based authorization is issuer-bound** — set `aow/issuer` on the role;
  the canonical identity tag is `aow/subject`. `aow/repo` / `aow/repo-owner`
  remain accepted as aliases through the v2 migration window.
- **Go API** — `types.GithubClaims` → `types.Claims`; `CreateSessionTags` →
  `BuildSessionTags(rawClaims, tagSpec)`; `MatchRolesToRepoWithConstraints` →
  `AuthorizeRoles(issuer, subject, claims)`; `FindSessionPolicyForRepo` →
  `FindSessionPolicy(issuer, subject)`; `AwsConsumer.AssumeRole` gained a
  `sessionTags` parameter. `MatchRolesToRepo` and the exported `GithubClaims`
  are removed.
- **S3/JSON config files must use `snake_case` keys** — `PascalCase` keys (`RepoRoleMappings`, `RoleSessionName`, etc.) are no longer accepted. Migrate any S3-hosted JSON configs to `snake_case` before upgrading (#230)
- **`workflow_ref` constraint regex is now auto-anchored** — previously matched as a substring; now compiled as `^(?:...)$` like all other constraints. Patterns relying on partial matching must be updated (#237)

### Added

- **Multi-issuer registry routing** — an incoming token's unverified `iss` is
  used only to route to that issuer's spec (exact match); identity/role
  decisions use only post-signature-verified, re-asserted claims. Per-issuer
  audiences, `claim_mappings`, and `required_claims`.
- **Any-provider support** — `provider: generic` validates tokens from any
  OIDC IdP by mapping raw claims to the canonical `subject` (GitHub keeps its
  native claim struct via `provider: github`). Adding a provider needs no core
  code changes (open/closed `providerAdapter` seam).
- **Generic `conditions`** — gate a mapping on any raw verified claim by name
  (named fields `branch`/`ref`/`ref_type`/`event_name`/`workflow_ref`/
  `environment`/`actor_matches` plus arbitrary `claim: regex` entries).
- **Config scaling** — `default_issuer`, `role_sets` (named ARN lists
  referenced as `@name`), `role_groups`, and `config_fragments` (additional
  sources merged onto the base config; local filesystem paths today, remote
  fetchers pluggable via `config.WithFragmentFetcher` but not yet wired into
  the shipped binaries; sha256-gated safe reload; optional
  `config_fragment_checksums` integrity pins). An owner-bucketed authorization
  index keeps matching fast at thousands of mappings, proven byte-identical to
  a linear scan.
- **Token hardening knobs** — `jwt_leeway` (≤120s), `max_token_lifetime`,
  `max_token_age`, `max_token_bytes`, `jwks_refetch_cooldown`,
  `allow_insecure_issuers`.
- **Structured audit trail** — one JSON record per allow/deny decision via
  `internal/s3logger`; `audit_required` makes the issuance record durable
  before credentials are returned (fail-closed); `log_level` and
  `log_claim_values` knobs; a standardized structured-logging field contract.
- **Cross-account role assumption** — a top-level `cross_account` block
  (`enabled`, `spoke_role_name`, `external_id`, `spoke_session_duration`,
  `allowed_accounts`; env prefix `AOW_CROSS_ACCOUNT_*`). The warden assumes
  member-account target roles **directly** (one hop, its own hub credentials);
  target roles trust the hub execution role for `sts:AssumeRole` +
  `sts:TagSession` with **no `sts:ExternalId` condition** (none is sent on the
  direct assume). `enabled` is a fail-closed **policy gate**: `false` (or the
  block omitted) hard-denies every cross-account operation. `allowed_accounts`
  restricts member accounts (empty = any once enabled; hub always allowed).
  Independent of tag-auth — explicit `role_mappings` can target member-account
  ARNs. For cross-account **tag-based authorization**, a convention-named
  spoke role (default `aow-spoke`, permissions policy `iam:GetRole` only) acts
  solely as a tag-read broker — IAM has no resource-based policies, so a
  target-account identity is needed for that one read; `external_id` applies
  only to that hub→spoke hop, and `spoke_session_duration` is capped at 1 h
  (the spoke hop is itself a chained session). Full worked example (hub config + member-account
  roles + StackSets template) under `docs/examples/cross-account/` (#236)
- Transitive session tags — `tag_auth.transitive_session_tags` marks the
  attached session tags transitive so they flow immutably across further role
  chaining by the target role (#233)
- Short `aow`/`repo` session tags via `tag_auth.default_org` — when a default org is set, the org prefix is stripped from session tag values to stay within the 256-char STS limit (#234)
- EC key support restored (ES256/384/512) — EC tokens were incorrectly rejected in prior versions (#230)
- Hot-reload now propagates to the AWS consumer — `allowed_accounts`, tag-auth enable/disable, spoke role, and external-id changes take effect without a Lambda cold start (#237)
- Validator reads issuer/audiences from the live config on every call — revoked audiences are enforced immediately after an S3 config reload (#230)
- `jwt_validation.mode` config option (`"self"` / `"apigw"` / `"alb"`) to delegate JWT verification to API Gateway HTTP API v2 JWT Authorizer or ALB OIDC.
- `ClaimsExtractorInterface` in `internal/validator/` with `SelfExtractor`, `APIGWExtractor`, and `ALBExtractor` implementations.
- `AwsApiGatewayV2` Lambda adapter (`internal/handler/apigatewayv2.go`) and `cmd/apigatewayv2/` entry point for HTTP API v2 deployments.
- `ParseRoleOnlyRequestBody` for delegated-mode requests (only `role` ARN required in body).
- `AOW_JWT_VALIDATION_MODE` and `AOW_JWT_VALIDATION_ALB_EXPECTED_SIGNER` environment variables.
- In-memory ALB public key cache (5-minute TTL) in `ALBExtractor` to avoid per-request HTTP latency.
- OpenTofu deployment (`deploy/opentofu/`) — modular root wiring reusable `s3`, `dynamodb` (JWKS cache), `iam` (least-privilege Lambda role), `lambda` (zip packaging + log group), and `apigateway` (HTTP API verify route) modules, with config rendered from `terraform.tfvars` (#243)
- CloudFormation quick-start template (`deploy/cloudformation/quickstart.yaml`) and deployment guide (`deploy/README.md`) (#243)

### Security

- **Algorithm/key pinning** — RS/ES 256–512 only (never `none`/HS\*); a JWKS
  key is pinned by `kid` + `alg` + `use=sig` + key-type↔alg-family, so a
  duplicate-`kid` JWKS cannot cause wrong-key selection. RSA ≥2048; EC verified
  on its declared curve.
- **RSA public exponent validated** — `parseRSAKey` now rejects a JWKS `e`
  that decodes to more than 4 bytes or to a value `< 3` or even, closing a
  path where an oversized exponent could silently truncate/overflow through
  `big.Int.Int64()`→`int` and produce an unintended `rsa.PublicKey`.
- **`max_token_lifetime` / `max_token_age` now default to 1h, not "no cap"**
  — previously an unset (zero) value meant unbounded; `Validate()` now
  applies a 1h default (same pattern as `max_token_bytes`) so a
  stolen/leaked long-lived token isn't usable indefinitely by default.
  Still fully overridable per-deployment; negative values remain rejected.
- **Bounded time and size in `self` AND delegated modes** — `exp`/`iat`
  required, leeway ≤120s, optional lifetime/age caps, pre-parse token-length
  cap; a single shared claim-check path guarantees delegated modes are not a
  weaker path.
- **SSRF-hardened JWKS/discovery fetch** — outbound fetches can never reach
  private/loopback/link-local/metadata IPs (enforced at dial time, including
  on redirects); OIDC discovery `issuer` is validated; forced JWKS refetches
  are rate-limited per `(issuer, kid)`.
- **ALB public-key cache bounded** — the in-process ALB signer-key success
  cache (`albKeyCache`) now caps at 128 distinct `kid` entries, clearing
  itself before growing past the cap (mirrors the existing JWKS key-memo
  overflow pattern), so a flood of distinct/rotating kids can only cost
  re-fetches, never unbounded memory.
- **`TokenValidatorInterface` narrowed to `Validate` only** — `FetchJWKS`
  and `GenKeyFunc` remain on the concrete `*TokenValidator` (used by tests
  and `WarmPrefetch`) but are no longer part of the interface contract,
  since neither is a standalone, audience-checked validation entry point.
- **Fragments cannot weaken security** — a fragment may only set
  `role_mappings` / `role_groups` / `role_sets` / `default_issuer`; `issuers`,
  hardening knobs, `allow_insecure_issuers`, and `tag_auth` are base-only.
- **Reload fails safe** — a failed/invalid/tampered reload retains the
  last-good config and never reverts to the zero-config seed.
- **Secret-safe logging** — no path logs a raw JWT or credential; with
  `log_claim_values=false` (default), claim values are suppressed in both the
  log stream and the audit records while names/decision/reason are retained.
- **`apigw` mode trust boundary documented** — `lambda:InvokeFunction` on
  this function is equivalent to full identity impersonation in `apigw`
  mode (no signature check on upstream-injected claims; the bypass guard
  only rejects empty claims, not forged ones). See
  `docs/TOKEN_VALIDATION.md` §2.2 and `docs/ARCHITECTURE.md` for the
  required invoke-policy mitigation.

### Removed

- Top-level `issuer` / `audience` / `audiences` config keys and the
  `AOW_ISSUER` / `AOW_AUDIENCE` / `AOW_AUDIENCES` env vars (use `issuers[]`).
- `repo_role_mappings` / `repo_role_groups` config keys (use `role_mappings` /
  `role_groups`).
- Exported `types.GithubClaims`, `CreateSessionTags`, and `MatchRolesToRepo`.

### Fixed

- `config_fragments` are now merged when no S3 config source is configured — previously a file-based deployment (or `cmd/local`) listing local-path fragments got a static provider that silently ignored every fragment. Bootstrap now builds a fragment-merging provider (initial merge at startup, re-resolved per `config_reload_interval` when > 0) whenever fragments are listed; an invalid fragment fails startup instead of silently serving the base config.
- Error responses no longer include the raw internal error string (`errorDetails` removed): JWT-library parse internals, JWKS/discovery/S3 failure detail, and config mismatch text stay in the server-side logs, correlatable via `requestId`. The per-adapter marshal-failure fallback body is a static JSON constant instead of interpolating `err.Error()` unescaped.
- API Gateway delegated mode (`apigw`) now decodes a bracketed multi-value `aud` (`"[aud1 aud2]"`, the JWT Authorizer's stringified array form) into individual audiences before ANY-match, instead of never matching.
- The standardized decision log line no longer emits a duplicate `requestId` JSON key (it comes from the request-scoped logger only; the durable audit record keeps its own `requestId` field).
- Request-body parse failures no longer log a 100-char body preview (a malformed body can contain a partial bearer token); only the parse error and body size are logged.
- Adapter binaries now fail fast at startup when `jwt_validation.mode` is incompatible with the deployed adapter (panic with a clear message) instead of failing silently per request.
- ALB public-key cache no longer has a read/write data race and now evicts expired entries on read, preventing unbounded growth of stale keys.
- ALB and API Gateway delegated modes now enforce token expiration (`exp` required) and reject future-`iat` tokens, matching self-mode strictness.
- RSA JWKS keys shorter than 2048 bits are now rejected, and EC JWKS keys are validated to lie on their declared curve (defense-in-depth against a compromised JWKS source).
- Malformed role ARNs now return the dedicated `ErrInvalidRoleFormat` sentinel (still HTTP 400) instead of being misreported as an empty role.
- Frontend adapters (`alb`, `apigateway`, `lambdaurl`) now share the `classifyError` helper, removing duplicated/dead error-classification switches.
- Invalid `LOG_LEVEL` now logs a well-formed structured warning instead of a malformed printf-style line; full claims log at Debug rather than Info.
- JWT validation failures now return HTTP 401 instead of HTTP 500 (#230)
- S3 config hot-reload no longer triggers N concurrent fetches at the interval boundary — exactly one fetch per interval (#230)
- `AOW_*` env-var overrides are preserved across S3 hot-reloads (#230)
- S3Logger now initialises after the config provider so `log_bucket`/`log_prefix` from remote config are respected (#230)
- Authorization now builds its claim set from the verified raw claims (`claims.Raw`) instead of a JSON round-trip of the typed struct, which dropped non-GitHub claims and wrongly denied legitimate `generic`-issuer / custom-claim requests.
- `transitive_session_tags` now marks **every** operator-configured session tag transitive; a hardcoded `repo`/`ref`/`actor` set previously dropped custom-named tags from `TransitiveTagKeys`, breaking ABAC across assumed roles. `TAG_BASED_AUTHORIZATION.md`, `CONFIGURATION.md`, `ARCHITECTURE.md`, and the `config.go` field comment were corrected to match.
- **deploy: OpenTofu stack rendered a v1 config that v2 rejects at startup.** `main.tf` emitted top-level `issuer`/`audiences` and `repo_role_mappings` (with `repo:`/`constraints:`) — keys removed in 2.0.0 — so the deployed Lambda failed config load with "at least one issuer is required". It now renders the v2 schema: a single GitHub `issuers[]` entry (with `required_claims` and the standard `session_tags` spec) plus `role_mappings` (`subject:`/`conditions:`); the tf variable was renamed `repo_role_mappings` → `role_mappings` accordingly. The unusable `jwt_validation_mode = "alb"` option was removed from the OpenTofu and CloudFormation stacks (it requires the `alb` binary behind an ALB, which neither provisions — the `apigateway` binary refuses to start in `alb` mode), along with the now-orphaned `alb_expected_signer` variable.
- deploy: CloudFormation quickstart set the `AOW_ISSUER`/`AOW_AUDIENCES` env vars removed in 2.0.0; dropped them (and the `Issuer`/`Audiences` parameters) and documented that `ConfigBucket`/`ConfigKey` are effectively required for a working v2 deployment.
- docs: refreshed `TAG_BASED_AUTHORIZATION.md` to the v2 model — `role_mappings`/`conditions` naming, the canonical `aow/subject` identity tag and the multi-issuer `aow/issuer` gate in the tag reference and corner cases, and the session-tag `repo` value (full `owner/repo` since 2.0.0, not the bare name shown in the ABAC examples).
- docs: `SESSION_TAGGING.md` workflow example could never work — it sent `github.token` (not an OIDC ID token) to a nonexistent `/assume-role` endpoint and parsed a `.credentials` response field. Replaced with the `core.getIDToken()` → `POST /verify` → `.data` flow, and updated the CloudTrail/ABAC examples to the full `owner/repo` tag value.
- docs: `ARCHITECTURE.md` drift — corrected the config-precedence order (env > S3 > file > defaults), replaced the fictitious memory→DynamoDB→S3 cache-cascade diagram (backends are alternatives selected by `cache.type`) and invented cache-hit-rate/latency figures, removed the nonexistent "automatic credential rotation" and iat-based cache invalidation claims, updated the stale `RequestProcessor`/`AwsConsumerInterface`/`Cache` interface listings, and marked `alb_expected_signer` as required in `alb` mode.
- docs: added the `MULTI_ISSUER.md` "Delegated modes are single-issuer only" section that `CONFIGURATION.md` linked to (broken anchor) plus a cross-issuer tag-auth section; README now lists all four Lambda variants including the `apigatewayv2-latest` image; root/package `CLAUDE.md` files updated (consumer interface methods, `alb_expected_signer` required, `newClaimsExtractor` signature, Go 1.26, `make check` includes vuln).
- docs: documented the per-mode request contract (`self`/`apigw`/`alb`). The only prior request example showed the self-mode body (`{token, role}`) with no note that it is mode-specific — an `apigw` user would wrongly put the token in the body and omit the `Authorization: Bearer` header API Gateway requires. Added a contract table + `apigw` GitHub Actions example to `README.md`, and a new "§2.1 Request contract per mode" section to `docs/TOKEN_VALIDATION.md`.
- docs: JWKS label in the token-validation sequence diagram used semicolons — mermaid statement separators that broke rendering; switched to commas.
- Audit records buffer into the amortized batch by default; a per-request synchronous S3 `PutObject` fires only when `audit_required=true` (which stays synchronous and fail-closed), not on every decision.
- A required-audit write failure is classified before the wrapped deny sentinel, so it surfaces as `audit_write_failed`/500 instead of being masked as a plain deny.
- An explicit `jwt_leeway: 0` is honored instead of being coerced back to the 30s default.
- `FindSessionPolicy` runs once per allow decision instead of twice.
- CI: `build.yml` image-pull retry loop now fails loudly after the last attempt (previously the failure branch checked `attempt -eq 5` inside a 3-iteration loop and never fired).
- CI: `apigatewayv2` container image is now vulnerability-scanned and listed in the release summary — it was built, signed, and attested but skipped by both.
- **cache: DynamoDB/S3 writes are now synchronous** — persistent-tier writes (and expired-object deletes) ran in fire-and-forget goroutines that Lambda freezes on handler return, silently losing them; every new container then refetched JWKS from the IdP.
- cache: unified the S3 item size limit to 512KB on both read and write — the write path previously accepted up to 1MB while the read path rejected anything over 512KB, so items between the two limits were stored but never readable.
- cache: the memory backend now honors `cache.ttl` and `cache.max_local_size`; both were silently ignored (hardcoded 10m / 100 entries).
- cache: `cache.s3_cleanup` is now functional — it gates deletion of expired objects discovered on read; previously the flag was parsed but never used (deletion was unconditional).
- cache: local-tier race fixes — a `Get` racing a `Set` could resurrect a stale value or delete a freshly stored one; local tiers now do the full lookup-and-update under one lock.
- cache: DynamoDB items with a missing or malformed `Expiration` attribute are treated as expired (fail closed) instead of never expiring.
- cache: local tiers keep the item's real expiration when repopulated from DynamoDB/S3, instead of extending it by the default TTL.
- cache: no spurious LRU eviction when overwriting an existing key at capacity.

### Changed

- **Session durations are clamped to 1 hour whenever the warden's own
  credentials are a role session** (always true on Lambda, same-account
  assumes included): AWS role chaining _fails_ a `DurationSeconds` above 3600
  on a chained `AssumeRole` rather than clamping it, so the warden clamps
  first and logs a warning instead of surfacing an STS error. Only `local`
  server mode running with IAM user credentials can issue sessions beyond
  1 hour (single hop, up to the target role's configured max, cross-account
  targets included).
- CI: consolidated `build.yml` into `release.yml` — a single tag-triggered workflow with one concurrency group and a combined summary. The GoReleaser (archives) and ko (image) jobs stay independent so neither blocks the other. Replaced the duplicated tag-extraction steps with the built-in `github.ref_name`.
- CI: `release.yml` and `make ko-publish` pass `--tags` explicitly per module (`<module>-<tag>` / `<module>-latest`, plus bare `<tag>` / `latest` for the `apigateway` default module) — ko has no config-file tag scheme, so a prior attempt to drive this from a `.ko.yaml` per-build `tags:` key was silently a no-op (every module published only `:latest`, caught by a `v2.0.0-rc.1` dry-run release before the real tag went out).
- CI: lint is now a blocking check (removed `continue-on-error`) and `golangci-lint` is pinned to `v2.12.2`; a shared `.golangci.yml` makes `make lint` and CI use the same linter set.
- CI: added a blocking `govulncheck` job (and a `make vuln` target) for Go-native vulnerability scanning; Trivy/gosec remain advisory.
- CI: added `concurrency` groups to all workflows — PR/branch runs auto-cancel superseded runs; tag-triggered publish/release runs do not.

- Moved `pkg/` to `internal/` — all shared packages are now under `internal/` in line with Go conventions
- `ProcessRequest` signature now accepts `validator.ExtractionInput` to carry per-request extraction data.
- `RequestProcessor` holds `ClaimsExtractorInterface` instead of `TokenValidatorInterface` directly.
- `jwt_leeway` / `max_token_lifetime` / `max_token_age` / `max_token_bytes` are read live from the config provider on every `Validate()` call, so a hot-reloaded change takes effect without a Lambda restart; delegated `apigw`/`alb` extractors likewise resolve the issuer spec, time bounds, and `alb_expected_signer` live on each `Extract()`.
- `normalizeClaims` populates the raw `sub` for every provider, so the audit record's `jwtSub` is present for generic (non-GitHub) issuers too.
- cache internals: removed unused `RefreshClient`/`Cleanup`/`GetStats` methods; AWS clients sit behind `dynamoDBAPI`/`s3API` interfaces for testability; the package now has a test suite.

### Dependencies

- actions/checkout 6.0.3 → 7.0.0
- securego/gosec 2.26.1 → 2.27.1
- codecov/codecov-action 6.0.1 → 7.0.0
- github/codeql-action 4.36.0 → 4.36.2
- docker/login-action 4.1.0 → 4.2.0
- golangci/golangci-lint-action 9.2.0 → 9.2.1
- goreleaser/goreleaser-action 7.2.1 → 7.2.2
- aquasecurity/trivy-action 0.35.0 → 0.36.0
- securego/gosec 2.25.0 → 2.26.1

---

## [1.3.6] - 2026-01-25

### Changed

- Updated dependencies and documentation (#125)

### Dependencies

- actions/setup-go 6.1.0 → 6.2.0
- golangci/golangci-lint-action 9.1.0 → 9.2.0
- github/codeql-action 4.31.4 → 4.31.11
- actions/checkout 6.0.0 → 6.0.1
- codecov/codecov-action 5.5.1 → 5.5.2
- securego/gosec 2.22.10 → 2.22.11

---

## [1.3.5] - 2025-11-30

### Dependencies

- Updated Go dependencies (#109)
- actions/setup-go 6.0.0 → 6.1.0
- golangci/golangci-lint-action 8.0.0 → 9.1.0
- github/codeql-action 4.31.2 → 4.31.4
- actions/checkout 5.0.0 → 6.0.0

---

## [1.3.4] - 2025-11-06

### Dependencies

- Updated Go dependencies (#98)
- github/codeql-action 3.30.5 → 4.31.2
- docker/login-action 3.5.0 → 3.6.0

---

## [1.3.3] - 2025-09-19

### Dependencies

- Updated Go version and dependencies (#71)
- actions/setup-go 5.5.0 → 6.0.0
- aquasecurity/trivy-action 0.32.0 → 0.33.1
- github/codeql-action 3.29.11 → 3.30.3

---

## [1.3.2] - 2025-08-29

### Dependencies

- Bumped golang module (#60)
- github.com/aws/aws-sdk-go-v2/service/sts
- actions/checkout 4.2.2 → 5.0.0
- goreleaser/goreleaser-action 6.3.0 → 6.4.0

---

## [1.3.1] - 2025-08-18

### Fixed

- Replaced deprecated `builds` with `ids` in goreleaser archives (#25)
- Fixed goreleaser configuration issues (#53)

### Dependencies

- Bumped golang modules (#53)
- docker/login-action 3.4.0 → 3.5.0
- aquasecurity/trivy-action 0.31.0 → 0.32.0
- github/codeql-action 3.29.0 → 3.29.8

---

## [1.3.0] - 2025-07-14

### Performance

- Optimized Lambda bootstrap initialization — moved AWS client construction out of the hot path; Lambda cold starts reduced (#24)

### Dependencies

- github/codeql-action 3.28.19 → 3.29.0

---

## [1.2.0] - 2025-06-10

### Added

- Multi-audience support for OIDC token validation — `audience` config field now accepts a list; all values are checked against the token's `aud` claim (#6)
- CodeQL security analysis workflow and badge

### Changed

- Improved example configuration with better security patterns
- Updated GoReleaser archive format to modern syntax

---

## [1.1.0] - 2025-06-07

### Added

- `make build` command and improved CI workflow (#5)

---

## [1.0.0] - 2025-06-07

### Added

- Initial release — modular architecture with Lambda (API Gateway, ALB, Lambda URL) and local HTTP server deployment targets
- OIDC JWT validation with JWKS signature verification
- AWS STS AssumeRole with ABAC session tagging from token claims
- Repository + constraint matching with anchored regex
- Multi-tier JWKS cache (memory / DynamoDB / S3)
- Container image published to GHCR and Docker Hub
- CodeQL, Trivy, and gosec security scanning in CI

[2.2.0]: https://github.com/boogy/aws-oidc-warden/compare/v2.1.1...v2.2.0
[2.1.1]: https://github.com/boogy/aws-oidc-warden/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/boogy/aws-oidc-warden/compare/v2.0.1...v2.1.0
[2.0.1]: https://github.com/boogy/aws-oidc-warden/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/boogy/aws-oidc-warden/compare/v1.3.6...v2.0.0
[1.3.6]: https://github.com/boogy/aws-oidc-warden/compare/v1.3.5...v1.3.6
[1.3.5]: https://github.com/boogy/aws-oidc-warden/compare/v1.3.4...v1.3.5
[1.3.4]: https://github.com/boogy/aws-oidc-warden/compare/v1.3.3...v1.3.4
[1.3.3]: https://github.com/boogy/aws-oidc-warden/compare/v1.3.2...v1.3.3
[1.3.2]: https://github.com/boogy/aws-oidc-warden/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/boogy/aws-oidc-warden/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/boogy/aws-oidc-warden/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/boogy/aws-oidc-warden/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/boogy/aws-oidc-warden/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/boogy/aws-oidc-warden/releases/tag/v1.0.0
