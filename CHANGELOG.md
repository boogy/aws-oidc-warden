# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- CI: moved the container image tag scheme into `.ko.yaml` per-build `tags:` as the single source of truth (`<module>-<tag>` / `<module>-latest`, plus bare `<tag>` / `latest` for the `apigateway` default module). `release.yml` and `make ko-publish` no longer pass `--tags`, which removes the special-cased apigateway publish step and makes `make ko-publish` emit the same tags as CI; only the local `make ko-build` (to `ko.local`) still overrides with `--tags`.
- CI: lint is now a blocking check (removed `continue-on-error`) and `golangci-lint` is pinned to `v2.12.2`; a shared `.golangci.yml` makes `make lint` and CI use the same linter set.
- CI: added a blocking `govulncheck` job (and a `make vuln` target) for Go-native vulnerability scanning; Trivy/gosec remain advisory.
- CI: added `concurrency` groups to all workflows — PR/branch runs auto-cancel superseded runs; tag-triggered publish/release runs do not.

- Moved `pkg/` to `internal/` — all shared packages are now under `internal/` in line with Go conventions
- `ProcessRequest` signature now accepts `validator.ExtractionInput` to carry per-request extraction data.
- `RequestProcessor` holds `ClaimsExtractorInterface` instead of `TokenValidatorInterface` directly.
- `jwt_leeway` / `max_token_lifetime` / `max_token_age` / `max_token_bytes` are read live from the config provider on every `Validate()` call, so a hot-reloaded change takes effect without a Lambda restart; delegated `apigw`/`alb` extractors likewise resolve the issuer spec, time bounds, and `alb_expected_signer` live on each `Extract()`.
- `normalizeClaims` populates the raw `sub` for every provider, so the audit record's `jwtSub` is present for generic (non-GitHub) issuers too.

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

[Unreleased]: https://github.com/boogy/aws-oidc-warden/compare/v2.0.0...HEAD
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
