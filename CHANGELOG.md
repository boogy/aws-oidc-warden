# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **IdP mode (`idp`, optional)**: the warden mints a KMS-signed OIDC token and exchanges it via unsigned `AssumeRoleWithWebIdentity`, lifting the 1h role-chaining cap. `/verify` routes a mapping through it when its `max_session_duration` is over 1h or it sets `idp_token`; no role list; over-1h requests it cannot serve get 503 `idp_signing_unavailable`, 403 `idp_not_permitted` or 400 `duration_exceeds_cap`. See `docs/IDP.md`.
- **Multi-region KMS keys** for `idp.signing_keys`: one issuer across regions, each signing with its local replica; replicas are confined to `idp.kms_allowed_regions`.
- **IdP discovery and JWKS paths** answer 404 while `idp.enabled` is false, refresh config without waiting, and match `requestContext.path` on REST API (v1).
- **`idp-export` command** writes the discovery and JWKS documents for S3/CloudFront hosting, with overlay and fragments applied.
- **`max_session_duration`** on a mapping bounds `durationSeconds` (15m–12h, default 1h); over 1h, like `idp_token`, needs an `idp` block.
- **Audit fields**: `action`, `tokenId`, `durationSeconds`, `requestedDurationSeconds`, `sessionNameSource`, `requestedSessionName`; new deny stages `duration`, `session_name`, `idp_mint`, `idp_exchange`.
- **13 IdP error codes**, documented in the README and `GITHUB_ACTIONS.md` retry tables.
- **`mappings_file`** loads hot-reloaded role mappings from a separate local or `s3://` file. See `docs/CONFIGURATION.md` § Split configuration.
- **`mappings_max_stale`** answers 503 `config_stale` once mappings are older than this (default 3x `config_reload_interval` for `s3://`).
- **`allow_session_name`** on a mapping lets callers name their STS session; otherwise a requested `sessionName` is ignored.
- **`s3_config_bucket_owner`** pins the expected owner on S3 config reads; required for `s3://` mappings and fragments.

### Changed

- **Failed config refreshes back off exponentially** (up to 8x the interval), and requests no longer wait on an in-flight refresh unless mappings are past `mappings_max_stale` (max 5s). Stale mappings retry every 10s.
- **`/verify` accepts `durationSeconds` (900–3600) and `sessionName`**, like `aws-actions/configure-aws-credentials`.
- **The `s3_config_bucket` overlay uses a conditional GET** when `s3_config_bucket_owner` is set.
- **A mapping setting both `session_policy` and `session_policy_file`, or `allow_session_name` with `role_session_name`, fails to load** instead of silently ignoring one.

### Fixed

- **`s3://` entries in `config_fragments` are fetched** instead of failing every refresh.
- **The local dev server caps request bodies, sets read timeouts** and serves only its known paths.
- **Remote `mappings_file` and fragment URIs must use lowercase `s3://`**; `S3://` skipped the owner and staleness checks.
- **Config objects and S3 session policies over 1 MiB are rejected** instead of silently truncated.
- **A `cross_account` refusal during role exchange** returns 403 `permission_denied`, audited at stage `account_check`.
- **ALB responses set `multiValueHeaders`**, so credential and error responses keep `Content-Type` and security headers on multi-value target groups.

### Dependencies

- **AWS SDK for Go v2**
  - `github.com/aws/aws-sdk-go-v2/service/kms` v1.61.1 (new)

### Documentation

- `docs/IDP.md` setup guide, plus IdP references in `CONFIGURATION.md`, `ARCHITECTURE.md` and `example-config.yaml`.
- `docs/examples/split-config/`: annotated service and mappings files with per-caller outcomes.
- `GITHUB_ACTIONS.md`: the composite action gains `duration-seconds` and `session-name` inputs.
- `example-config.yaml` moved to `docs/examples/`; the split-config and cross-account examples are production-shaped.
- `docs/examples/multi-region/` and `ARCHITECTURE.md` § Multi-region: shared config, per-region resources via `AOW_*` env.

## [3.5.2] - 2026-09-26

### Fixed

- **A role ARN that is not an IAM role returns `400 invalid_request`**, not a retryable `500 assume_role_failed`.
- **ALB: an oversized `x-amzn-oidc-data` header returns `400 invalid_request`**, not `400 internal_error`.
- **`audit_required` with no audit sink (`make run` with `log_to_s3` set) logs `audit.write.failure`** alongside the existing `500 audit_write_failed`.

### Documentation

- **`ARCHITECTURE.md` Required IAM Permissions** covers every bucket: the audit bucket needs `s3:PutObject` and `s3:PutObjectTagging`; adds the config bucket (`s3:GetObject`) and S3 cache bucket; drops unused `s3:PutObject` on session policies.
- **`500 policy_error` and `500 audit_write_failed` are deterministic, not retryable.** `GITHUB_ACTIONS.md` failover examples (JS, `curl`, composite action) stop on these `errorCode`s; a persistent `assume_role_failed` with `stsErrorCode = MalformedPolicyDocument` is non-transient.
- README quick-start and `SESSION_TAGGING.md` example check `res.ok` and show status and `errorCode` on refusal.
- `README.md` troubleshooting names `s3:PutObjectTagging` and the no-sink case; `GITHUB_ACTIONS.md` `400 invalid_request` lists the same causes; `github-script@v9` needs Actions Runner v2.327.1+.

## [3.5.1] - 2026-09-26

### Dependencies

- **Go toolchain** 1.26.7 → 1.27.1 (`go` directive in `go.mod`).
- golangci-lint (CI) 2.12.2 → 2.14.0.
- **AWS SDK for Go v2 patch bumps.** No API changes.
  - `github.com/aws/aws-lambda-go` 1.55.0 → 1.55.1
  - `github.com/aws/aws-sdk-go-v2` 1.47.0 → 1.47.1
  - `github.com/aws/aws-sdk-go-v2/config` 1.33.5 → 1.33.6
  - `github.com/aws/aws-sdk-go-v2/credentials` 1.20.5 → 1.20.6
  - `github.com/aws/aws-sdk-go-v2/service/dynamodb` 1.69.0 → 1.69.1
  - `github.com/aws/aws-sdk-go-v2/service/iam` 1.64.0 → 1.64.1
  - `github.com/aws/aws-sdk-go-v2/service/s3` 1.113.1 → 1.113.4
  - `github.com/aws/aws-sdk-go-v2/service/sts` 1.51.0 → 1.51.1
  - `github.com/aws/smithy-go` 1.28.1 → 1.28.2
  - transitive `feature/ec2/imds`, `internal/*`, `service/internal/*`, `signin`, `sso`, `ssooidc` patch bumps

### Documentation

- **Fixed every `github-script` example** (README, `GITHUB_ACTIONS.md`, `SESSION_TAGGING.md`): removed the `require('@actions/core')` line that caused `SyntaxError`; moved to `actions/github-script@v9`.
- Status-code tables in README and `GITHUB_ACTIONS.md` list `400 invalid_request`, `500 policy_error`, `500 audit_write_failed`.
- `MULTI_ISSUER.md`: `claim_mappings.subject` may target `sub`; `ARCHITECTURE.md`: `TokenValidatorInterface.Validate` takes a `context.Context`.

## [3.5.0] - 2026-09-25

### Added

- **Structured, typed log events (`internal/logevent`) replace ad hoc `slog` calls.** Every line carries `eventType`, `eventCategory` and `outcome`; see [docs/LOGGING.md](docs/LOGGING.md#event-catalog).

  - `service`, `version`, `adapter`, `schemaVersion` appear on every line.
  - `requestId`, `frontendRequestId`, `sourceIp`, `sourceIpFrom` reach every line of a request, including `internal/validator`, `internal/cache`, `internal/aws`.
  - New `sts.assume_role.success` (Info) logs `roleArn`, `durationMs`, `assumedRoleId`.
  - `docs_sync_test.go` in `internal/logevent` fails CI if a registered event lacks a `docs/LOGGING.md` catalog row.
  - `forbidigo` bans direct `slog` calls outside `internal/logevent` and tests.

### Changed

- **Client-caused denials log at Warn, never Error.** `authz.decision` with `outcome = "deny"` and `request.rejected` are Warn; Error is for server-side faults.
- **Exactly one terminal log line per request:** `authz.decision` or `request.rejected`; `request.response` is a separate Debug line.
- **`msg` text changed on every migrated line; query on `eventType` instead.**
- **Role ARNs are logged as `roleArn`, never `role`** (pipeline `request` group, `unscoped_mapping_outranks_scoped` / `tag_auth_bypasses_mapping_scoping` warnings).
- **`handler.NewBootstrap(adapter string)`** takes the frontend adapter name.
- **`aws.BuildSessionTags(ctx, rawClaims, tagSpec)`** takes a `context.Context` first.
- `internal/cache`, `internal/validator`, `internal/aws` and `internal/s3logger` I/O paths are context-aware.

### Fixed

- **Unbounded log buffer in warm Lambda containers.** Logs now go to stdout (CloudWatch) only; S3 keeps the audit record.
- **Buffered audit records lost at container shutdown.** Lambda mains use `lambda.WithEnableSIGTERM(bootstrap.Cleanup)` to flush the batch; best-effort (~500 ms), `audit_required` remains the durable path.

## [3.4.1] - 2026-09-18

Maintenance release: dependency updates only. Nothing to do on upgrade.

### Changed

- **Dependency updates.**

  - `github.com/aws/aws-sdk-go-v2/config` 1.33.4 → 1.33.5
  - `github.com/aws/aws-sdk-go-v2/credentials` 1.20.4 → 1.20.5
  - `github.com/aws/aws-sdk-go-v2/service/dynamodb` 1.66.0 → 1.69.0
  - `github.com/aws/aws-sdk-go-v2/service/iam` 1.62.0 → 1.64.0
  - `github.com/aws/aws-sdk-go-v2/service/s3` 1.110.0 → 1.113.1
  - `github.com/aws/aws-sdk-go-v2/service/sts` 1.50.0 → 1.51.0
  - `golang.org/x/sync` 0.22.0 → 0.23.0
  - `golang.org/x/sys` 0.47.0 → 0.48.0 (indirect)
  - `golang.org/x/text` 0.41.0 → 0.42.0 (indirect)
  - Transitive AWS SDK modules: `service/internal/checksum` 1.11.1 → 1.11.3, `service/internal/endpoint-discovery` 1.13.1 → 1.13.3, `service/internal/s3shared` 1.20.1 → 1.20.3

## [3.4.0] - 2026-09-11

### Added

- **`issuers[].tag_prefix` sets a per-issuer tag-auth tag namespace**, overriding global `tag_auth.tag_prefix` (default `aow/`; `AOW_TAG_AUTH_TAG_PREFIX`). A prefix outside `[A-Za-z0-9_.:/=+@-]{1,64}` is a boot-time error. See [docs/TAG_BASED_AUTHORIZATION.md § Per-issuer tag prefixes](docs/TAG_BASED_AUTHORIZATION.md#per-issuer-tag-prefixes).

### Removed

- **All infrastructure-as-code left this repo:** `deploy/` (OpenTofu module, CloudFormation quick-start, `build.sh`, deployment guide) and `docs/examples/cross-account/member-account-roles.yaml`.

  **Migrating:** the application is unchanged. Deployment requirements are in [docs/ARCHITECTURE.md § Infrastructure as code](docs/ARCHITECTURE.md#infrastructure-as-code). Keep your own copy of the OpenTofu module (see git history). [docs/examples/cross-account/README.md](docs/examples/cross-account/README.md) now carries every trust policy, permissions policy, role path and `aow/*` tag inline.

## [3.3.0] - 2026-09-09

### Added

- **`role_mappings[].session_tags` (and `role_groups[].defaults.session_tags`) attach extra STS session tags to the roles that mapping grants.** Additive only: a key the issuer already defines is rejected by `Validate()` at boot.

### Changed

- **STS `AccessDenied` returns `403 assume_role_denied`, not `500 assume_role_failed`.** Throttling, expired credentials and policy-document faults stay retryable 500. Clients branching on status must update: a trust-policy refusal is not retryable.
- The `Error assuming role` log line carries `stsErrorCode`.
- **CI integration moved to [docs/GITHUB_ACTIONS.md](docs/GITHUB_ACTIONS.md); the README is now an overview** with one minimal snippet. The new document has the request/response contract, retry column per status, `github-script` and `curl` variants, failover, composite action, and a GitLab example. Security material stays in the README; no document renamed.
- **Documented a resilient two-region deployment** in `deploy/README.md` (**Multi-region deployment (resilience)**). It uses two independent stacks with caller failover and one shared region-free `aws-oidc-warden-exec` role. Per-region `name_prefix`, audit-bucket layout, revocation and IAM quotas are covered there.
- **Multi-region failover for callers, in shell and JavaScript** ([docs/GITHUB_ACTIONS.md](docs/GITHUB_ACTIONS.md#multi-region-failover)): one token reused, `400`/`401`/`403` final, only unreachable or transient failures fail over. `curl` abandons a blackholed region in about two seconds; `fetch` with `AbortSignal.timeout` spends the full budget.
- **`docs/GITHUB_ACTIONS.md` gained "Ship it as a composite action"**: a complete `action.yml` owning endpoints, failover, retry predicate and timeouts. The action sees the OIDC token, so protect its repository.
- **The `apigw` invoke restriction is a prominent warning** in `deploy/README.md`: `lambda:InvokeFunction` is equivalent to credential minting, since the application rejects only empty claims. It lists what never to grant and a `get-policy` audit command.
- **Documentation restructured for readability and accuracy** across `README.md`, `docs/ARCHITECTURE.md` (removed the nonexistent Dockerfile and duplicate Terraform), `docs/LOGGING.md` (incl. `log_level` callout: `AOW_LOG_LEVEL` is never wired to the running handler), `docs/CONFIGURATION.md`, `docs/TOKEN_VALIDATION.md`, `docs/TAG_BASED_AUTHORIZATION.md` and `docs/SESSION_TAGGING.md`; no file renamed. `deploy/README.md` lists the `config.yaml`-only features: `role_groups`, list-valued `subject`, boolean condition groups, `role_mappings[].session_tags`.
- **Dependencies: `smithy-go` promoted to a direct requirement, `testify` 1.11.1 → 1.12.1.** `github.com/aws/smithy-go` is imported directly by `internal/aws/stserr.go`.

## [3.2.0] - 2026-09-03

### Added

- **`role_mappings[].subject` accepts a list of patterns.** Elements are OR'd and validated alone; empty, bare `.*`/`.+` or repeated elements fail to load.

### Fixed

- **`compileAnchoredSubject` lacked an empty-pattern guard**, so `subject: ["", "org/repo"]` compiled `""` to `^(?:)$`. The guard now lives in the compile helper.

## [3.1.0] - 2026-08-31

### Fixed

- **A remote config overlay that failed validation left `role_mappings` half-merged while the old authorization index kept serving.** `MergeBytes` now merges into a copy and swaps it in only after `Validate()` succeeds.

### Changed

- One authorization traversal per request instead of three: `Config.Authorize` returns a `Decision` (2000 mappings: 1556 ns to 514 ns).
- `Validate()` compiles each distinct anchored pattern once (5000 mappings: 76.6 ms to 20.7 ms).
- `parseECKey` uses `ecdsa.ParseUncompressedPublicKey`; keys with stripped leading zeros are still accepted.
- Go directive raised to 1.26.7.
- `MergeBytes` slice clears are driven by a `clearOnDeclare` table, guarded by a reflection test.
- A merge that drops a `config_fragment_checksums` pin for a still-listed fragment logs `WARN`.
- Behavior-preserving deduplication across `internal/handler`, `internal/cache`, `internal/config` and `internal/aws`; no exported or config change.
- DynamoDB and S3 cache backends emit the `Evicting LRU cache item` debug line on local-tier eviction.
- S3 cache AWS-config load failure logs `Failed to load AWS config for S3 cache`.

### Removed

- Unused `AwsConsumer.RoleHasTag` and its test.

### Documentation

- `docs/PERFORMANCE.md` records measured scale behaviour and Lambda memory sizing.
- **`docs/CONFIGURATION.md` wrongly called `role_mappings: null` in an overlay deny-all.** Revoking all grants needs both `role_mappings: null` and `role_groups: null`.
- Documented that `role_sets` merge by name and an overlay cannot narrow or delete one.
- Documented that restating `config_fragment_checksums` unpins omitted fragments and a rejected overlay is never partially applied.

### Tests

- Fixed four misnamed or non-failing cases in `TestMergeBytesDeclaredSlicesReplaceRatherThanIndexMerge`.
- Added `internal/config/scale_bench_test.go` benchmarks.
- Tests needing transitive tags use top-level `session_tags_transitive`.
- Added `TestMergeBytesFragmentChecksumsReplaceWholesale`, `TestLostFragmentPins` and `TestMergeBytesRoleSetsMergeByKey`.
- Added tag-auth fallback tests `TestProcessRequest_TagAuthReadFailureDenies` and `TestProcessRequest_TagAuthAuditRecordsMatchedVia`.

## [3.0.2] - 2026-08-28

### Security

- **A remote config overlay merged `role_mappings` by slice index, so an entry omitting `roles` inherited the displaced mapping's roles (and `conditions`).** A declared slice now replaces wholesale, so an overlay relying on the old merge fails to load. See [docs/CONFIGURATION.md](docs/CONFIGURATION.md#overlay-merge-semantics).

## [3.0.1] - 2026-08-28

### Security

- **`apigw` mode: a `none_of` deny-list never fired on list- or object-valued claims, authorizing the caller it should refuse.** Such claims are now undecidable under negation, so the veto fires; a scalar claim shaped like `[x]` also vetoes.
- **Known limitation: positive conditions on list-valued claims still diverge.** `conditions: {groups: "deployers"}` grants in `self` but denies in `apigw` (fail-closed). Use `self`/`alb` mode or a scalar claim behind an API Gateway JWT Authorizer.

### Fixed

- **An integral claim above 2^53 rendered in scientific notation, so conditions written in decimal could not match.** `utils.FormatClaimValue` now renders every finite integral `float64` with `strconv.FormatFloat(f, 'f', -1, 64)`. Distinct integers above 2^53 can still collide in `float64`.

### Changed

- Internal comment cleanup; no behavior change.

## [3.0.0] - 2026-08-26

Conditions become claim-native: every `conditions:` key names the claim it checks, for any issuer, takes one pattern or a list, and `all_of`/`any_of`/`none_of` compose them. The top level stays an implicit AND.

**Breaking:** `branch` is removed in favor of `ref`, `actor_matches` of `actor`, and `environment` of `runner_environment`. Rename the keys; an unrenamed `branch:`/`actor_matches:` stops authorizing (fail-open inside `none_of`) and logs a startup warning. An unrenamed `environment:` silently checks the deployment-environment claim. The `aow/environment` role tag follows the rename. See [docs/MIGRATION_V3.md](docs/MIGRATION_V3.md).

### Added

- **Condition keys are claim names, for every issuer.** Named fields (`ref`, `ref_type`, `event_name`, `workflow_ref`) are sugar over the same generic path.
- **Every condition value accepts a list of alternatives.** Patterns for one claim are OR-ed, separate claims AND-ed; a list-valued claim matches when any element matches.
- **`all_of`, `any_of` and `none_of` in `conditions`.** Groups nest, evaluate without per-request allocation, and `none_of` is exact negation; existing configs keep their meaning.
- **Load-time guards on condition complexity.** `Validate()` rejects empty groups, members gating nothing, and blocks compiling to no predicate; nesting is capped at 5 levels and 64 nodes, and errors name the node path.
- **Tag-based authorization can constrain any claim: `aow/claim.<name>`.** It narrows but never grants, compares the claim value (case-sensitive name, list claims match any element), and leaves existing roles unaffected.

### Fixed

- **A condition on a list-valued claim could never match.** A list claim now matches when any string element matches.
- **A `none_of` veto on a mixed-case claim never fired.** Claim lookup is now collision-first, then exact, then case-folded; ambiguous case collisions deny the whole mapping.
- **A hot reload could split one request across two config generations.** `ExtractionInput.Config` now carries the request's pinned config to every extractor.
- **A hot reload could hand a request another config's issuer registry.** Registry and provenance are now published as one atomic snapshot.
- **A condition on a bool or numeric claim is decided on its value in both directions.** `none_of: [{email_verified: "false"}]` now vetoes the JSON bool `false`; objects and object-bearing lists veto, absent claims stay excluded. Behavior change: a positive condition on a bool or numeric claim that never matched now matches, so review non-GitHub `conditions:` on such claims.
- **`claim_mappings` was validated on the wrong side.** `claim_mappings.subject` may no longer target `iss`, `aud`, `exp`, `nbf` or `iat`; `sub` stays allowed.
- **Log lines for non-GitHub issuers showed four empty GitHub fields.** Logs always carry `subject` and add GitHub fields only when populated; the deny reason is now provider-neutral.
- **A non-GitHub audit record omitted deciding claims.** It now carries every claim the issuer's `claim_mappings`, `required_claims`, `session_tags` and conditions reference; `provider: github` is unchanged.
- **BREAKING: `config_fragment_checksums` is a list of `{uri, checksum}` entries**, because as a map no real fragment path could be pinned. `Validate()` rejects a pin whose `uri` matches no `config_fragments` entry.
- **A `role_sets` name containing an upper-case letter could not be referenced.** References now resolve exact-first, then case-folded.
- **Documented `session_tags` keys as lower-case-only**, matching loader behavior; no code change.
- **Documentation corrected against v3 behaviour.** `TestDocumentedYAMLLoadsAndValidates` now also covers `docs/examples/` and no longer skips blocks with unknown keys.
- **A second line-by-line documentation pass.** Fixed `docs/MIGRATION_V2.md`, `README.md`, `docs/MIGRATION_V3.md`, `docs/CONFIGURATION.md`, `docs/LOGGING.md`, `docs/ARCHITECTURE.md`, the `CLAUDE.md` files, `example-config.yaml` and a `internal/cache/dynamodb.go` comment.
- **`utils.RedactToken` panicked on negative or overflowing counts.** Counts are now clamped, and `internal/utils` coverage is 100%.
- **`example-config.yaml` no longer emits an unscoped-grant warning at boot.**
- **The `internal/config` suite passed only in declaration order.** Leaked `CONFIG_NAME` and viper state made two `none_of` guards pass vacuously; the suite now passes under `-shuffle`.

### Changed

- **BREAKING: `branch`, `actor_matches` and `environment` are removed; `environment` now checks the deployment-environment claim.** Rename `branch:` → `ref:`, `actor_matches:` → `actor:`, `environment:` → `runner_environment:`; stale keys deny. See [docs/MIGRATION_V3.md](docs/MIGRATION_V3.md).
- **A condition key naming a claim GitHub does not issue warns at load** (`provider: github` only; advisory).
- **An empty condition pattern (`ref: ""`, `ref: []`) is rejected at load.**
- **A condition key naming no claim is rejected, and compile errors are deterministic** (sorted order).
- **`all_of`, `any_of`, `none_of` and `claims` are reserved keys under `conditions:`.** `claims:` keys are always raw claim names.
- **BREAKING: the `aow/environment` role tag checks the deployment-environment claim and `aow/runner-environment` the runner type.** Retag roles still using `aow/environment: github-hosted` as `aow/runner-environment`; list them with `aws resourcegroupstaggingapi get-resources --tag-filters Key=aow/environment`.
- **A condition key with no value is rejected**, as is `conditions:` with nothing under it; omit the key for an unconditional mapping.
- **A typo inside a `none_of` warns in stronger terms**; `docs/CONFIGURATION.md` documents that a two-key `none_of` member is a negated AND.
- **The condition engine moved to `internal/config/condition.go`.** No behavior change.
- **Code cleanup and multi-issuer tests.** Fixed stale doc comments and `TODO`s, replaced `context.TODO()` with `context.Background()`, added `IssuerSessionTags` and provider-rule tests, and consolidated `internal/` tests into fewer files.
- **Dependencies updated, and `mapstructure` promoted to a direct requirement.**
  - `aws-sdk-go-v2` 1.43.5 → 1.43.7
  - `config` 1.32.36 → 1.32.38
  - `credentials` 1.19.35 → 1.19.37
  - `dynamodb` 1.63.2 → 1.63.4
  - `iam` 1.59.0 → 1.59.2
  - `s3` 1.107.1 → 1.107.3
  - `sts` 1.45.5 → 1.45.7
  - `smithy-go` 1.27.7 → 1.28.0
  - `github.com/go-viper/mapstructure/v2` moved from indirect to direct

## [2.4.1] - 2026-08-22

Follow-up to the 2.4.0 audit hardening, fixing defects in the audit path.

### Added

- **A boot warning when `tag_auth` can bypass a mapping's scoping.** `Validate()` warns per role whose mapping `session_policy` or `role_session_name` does not apply to tag-authorized sessions.

### Fixed

- **A hot reload enabling `log_to_s3` + `log_bucket` bricked credential issuance until cold start.** `WriteRecord` now builds the S3 client on demand.
- **Boolean `AOW_` environment variables parsed differently at boot and on reload.** Both paths use `strconv.ParseBool`; an unparseable value warns and keeps the current value. Covers `log_to_s3`, `log_claim_values`, `audit_required`, `allow_insecure_issuers`, `session_tags_transitive`, `cache.s3_cleanup`, `tag_auth.enabled`, `tag_auth.transitive_session_tags` and `cross_account.enabled`.
- **The ALB adapter read no request header on a multi-value target group.** It now reads `multiValueHeaders` too, folding repeated values on `", "`.
- **Header lookups picked a random value when the same header arrived in different cases.** The exact canonical key now wins, else the lexicographically smallest variant.
- **The deny `reason` ignored `log_claim_values`.** Error-derived reasons are replaced with a claim-free summary when the gate is off.
- **A claim alias could overwrite a different claim in the audit record.** The alias applies only when the target name is not already emitted.
- **The batch-flush timer never started when S3 logging was enabled by hot reload.**
- **Best-effort S3 write paths gated on the boot config.** `WriteLogToS3` and `WriteSingleLog` now read the live config.
- **The enforced audit write ran on the logger's background context.** It now uses the request's context.
- **S3 object tags were not URL-encoded.** The tagging string is now `url.Values`-encoded.
- **`FormatClaimValue` rendered 2^53 in scientific notation.** The exact-integer guard now includes 2^53.

## [2.4.0] - 2026-08-21

Audit and observability hardening: durable S3 audit trail on by default, requester and source IP in every record, machine-queryable decision log line.

### Added

- **`claims` in the durable audit record.** Identifying claims on allow and deny, gated by `log_claim_values`; GitHub reports `repository`/`repository_id` as `repo`/`repo_id`. See [docs/LOGGING.md](docs/LOGGING.md).
- **Top-level `session_tags_transitive`** (env `AOW_SESSION_TAGS_TRANSITIVE`). Replaces the deprecated `tag_auth.transitive_session_tags`; recommended, since tags otherwise drop on role chaining. See [docs/TAG_BASED_AUTHORIZATION.md](docs/TAG_BASED_AUTHORIZATION.md#role-chaining--transitive-session-tags).
- **`sourceIp` and `sourceIpFrom` on the audit record.** `sourceIpFrom` is `frontend` or `x-forwarded-for` (ALB); authorization never uses the IP. See [Source IP trust model](docs/LOGGING.md#source-ip-trust-model).
- **`frontendRequestId` on the decision log line and audit record.** Join key to API Gateway access logs; absent on ALB.
- **`Config.AuditEnforced()`.** Audit enforcement is derived per config snapshot, so enabling `log_to_s3` + `log_bucket` by hot reload engages fail-closed without restart.
- **Per-mapping `role_session_name`.** `role_mappings[].role_session_name` and `role_groups[].defaults.role_session_name` override the global value. See [docs/CONFIGURATION.md](docs/CONFIGURATION.md).
- **`sessionName` on the audit record and decision log line.** Not suppressed by `log_claim_values=false`.

### Changed

- **`audit_required` now defaults to `true`.** Takes effect only with `log_to_s3=true` + `log_bucket`; otherwise a boot warning. Set `audit_required: false` to opt out.

  **Behavior change on upgrade.** Deployments with `log_to_s3` + `log_bucket` move to fail-closed: a failed audit write returns `ErrAuditWriteFailed` (HTTP 500). Before upgrading, confirm the Lambda role has `s3:PutObject` and `s3:PutObjectTagging` on `log_bucket` and alert on `errorCode=audit_write_failed`.

  **OpenTofu.** The module provisions the audit-log bucket when `enable_s3_logs || audit_required`, so `tofu apply` creates it unless `audit_required = false`. See [deploy/README.md](deploy/README.md).

- **`log_claim_values` now defaults to `true`.** Logs and audit records carry canonical subject, `jwtSub`, audience, session-tag values and `claims`.

  **Privacy note.** YAML/env deployments that never set it will record identifying values (GitHub `actor` plus `sourceIp`). Review retention and access, or set `log_claim_values: false`. OpenTofu deployments are unaffected.

- **`requestId` is now the Lambda invocation UUID in every frontend mode.** The frontend's own ID moves to `frontendRequestId`.
- **Decision log line no longer duplicates `sourceIp`, `sourceIpFrom`, `frontendRequestId`.**
- **Decision log line omits empty attributes.** Timings are millisecond integers `validationMs`/`totalMs`/`durationMs`.
- **`role_session_name` is validated at boot.** `Validate()` rejects values outside STS's 2-64 characters of `[\w+=,.@-]`.

  **Behavior change on upgrade.** A global name with a space or `/` previously booted with the character stripped and now refuses to boot; fix it first. Hot reload keeps the last-good config. The runtime sanitizer now substitutes `-` instead of deleting, and warns on truncation.

### Fixed

- **`audit_required` disabled itself permanently.** `Validate()` no longer mutates it; enforcement comes from `AuditEnforced()`.
- **Audit-log writes failed with `AccessDenied` in both deployment templates.** Both now grant `s3:PutObject` and `s3:PutObjectTagging`.
- **ALB logged the target-group ARN as `sourceIp`.** Every frontend now logs a validated IP or nothing; ALB uses the rightmost `X-Forwarded-For` hop.
- **Durable S3 audit record carried no source IP.**
- **Lambda URL logged `rawPath` instead of `path`.**
- **`requestMeta` minted its own request ID** when the context value was empty.
- **Claim-extraction debug line logged `mode` instead of `jwtMode`.**
- **`"Assuming role"` and `"Successfully assumed role"` were logged twice per request.** Uncorrelated duplicates removed; the processor line is now `Info`.
- **Requested role ARN was repeated three times in one log line.**
- **Numeric claims were recorded in scientific notation.** Integral values now render as integers in audit records and session tags (`utils.FormatClaimValue`).
- **A claim rename could silently drop a verified claim.** A rename is skipped when the token already has the alias target.
- **Unused or over-broad IAM permissions in both deployment templates.** Removed `iam:ListRoleTags`/`iam:ListRole*`; enumerated S3 actions instead of `s3:PutObject*`, `s3:DeleteObject*`, `s3:GetObject*`.

## [2.3.0] - 2026-08-12

Multi-issuer support in `apigw` validation mode, end to end, with one OpenTofu authorizer and route per issuer. `alb` mode still requires exactly one issuer. Single-issuer configs boot unchanged; existing `apigw` OpenTofu deployments need a state migration (see Breaking Changes).

### Added

- **Multi-issuer `apigw` mode.** Each `issuers[]` entry gets its own JWT Authorizer and route, resolved by the authorizer-verified `iss`.
- **`issuers` Terraform variable** (`deploy/opentofu/variables.tf`). Map of issuer name to `issuer`/`provider`/`audiences`/`session_tags`/`route_key` (plus optional `claim_mappings`/`required_claims`/`jwks_uri`); drives `config.yaml` and per-issuer authorizers/routes.
- **`config.yaml` rendered from `templates/config.yaml.tftpl`** with unquoted keys; a plan-time precondition catches template drift.

### Fixed

- **`aws_iam_role_policy` count** (`874ea91`) is known at plan time, so `tofu plan` works on a fresh account.
- **Multi-issuer + `role_mappings` rendered a config that failed cold start.** Added `issuer` to `var.role_mappings` and `var.default_issuer`, plus a plan-time precondition.
- **Zero-config GitHub seed leaked `required_claims`/`session_tags` into other issuers.** `MergeBytes` now replaces `Issuers` when the payload declares `issuers`; `config_fragments` are unaffected.
- **A backslash in a rendered config value broke `tofu plan`.** Interpolated scalars go through `jsonencode`; `claim_mappings`/`session_tags` keys are now quoted.
- **Mismatched Lambda binary variant panicked on every invocation.** `build.sh` writes `dist/variant`; `modules/lambda` checks it at plan time; a missing marker passes.
- **`jwt_authorizer_issuer` could diverge and deny every request.** Plan-time precondition rejects issuer divergence; `jwt_authorizer_audiences` may still narrow.
- **`var.route_key` accepted `null` and any string.** Now `nullable = false` with `"<METHOD> <path>"` validation.
- **`var.role_mappings` accepted an empty `roles` list.** Validation requires at least one role.
- **Lambda-variant guard broke `tofu test` after `build.sh`.** Added `var.check_lambda_variant` (default `true`); `hardening.tftest.hcl` sets it `false`.
- **`roles = null` / `audiences = null` gave an opaque `length()` error.** Added `!= null` guards on `var.role_mappings[*].roles` and `var.issuers[*].audiences`.
- **Precondition did not check `issuer`/`default_issuer` membership.** New preconditions on `aws_s3_object.config` check `var.default_issuer` and every `role_mappings[*].issuer` against the configured issuers; the hardcoded mapping `issuer` in `terraform.tfvars.example` is commented out.

### Breaking Changes

- **Existing `apigw`-mode deploys need a manual state migration.** Run `tofu state mv` for the authorizer and route (`aws_apigatewayv2_authorizer.jwt[0]`, `aws_apigatewayv2_route.this`) before the first `tofu apply`, or they are recreated. Self-mode needs no action.
- **CloudFormation `apigw` deploys with `JWTAuthorizerIssuer` differing from `config.yaml`'s issuer now return 401 on every request** (`ErrUnknownIssuer`). Verify the two match before upgrading. See [deploy/README.md](deploy/README.md).
- **A remote config with `issuers: null` now fails to boot** instead of silently trusting the GitHub Actions issuer (fail-open). Affects hand-written S3 configs only.

### Changed

- **Dependencies.** AWS SDK for Go v2 patch bumps (`aws-sdk-go-v2` 1.43.4 → 1.43.5, `config` 1.32.35 → 1.32.36, `credentials` 1.19.34 → 1.19.35, `dynamodb` 1.63.1 → 1.63.2, `iam` 1.58.1 → 1.58.2, `s3` 1.106.5 → 1.107.1, `sts` 1.45.4 → 1.45.5, `smithy-go` 1.27.6 → 1.27.7, plus transitive `internal/*` modules) and `golang.org/x/text` 0.40.0 → 0.41.0.
- **Go toolchain** 1.26.5 → 1.26.6, fixing 6 stdlib vulnerabilities; `govulncheck ./...` is clean.

## [2.2.2] - 2026-08-06

Follow-up review of 2.2.0 areas. No authorization bypass; reachable only from the local dev server or with `log_level: debug`.

### Security

- **`audit_required` no longer fails open when no audit sink is wired.** A missing sink now returns `ErrAuditWriteFailed`. Reachable only via `cmd/local`.
- **`log_claim_values: false` now holds in `getSessionPolicy` debug logs.** Subject goes through the request-scoped logger and a shared `subjectAttr` gate.

### Added

- Regression test `TestHotReload_AuthorizationDecisionFollowsRemoteConfig`: a reload changes the `ProcessRequest` authorization outcome, and an invalid config keeps the last-good grants.

### Removed

- Dead code: `AwsConsumer.GetSessionPolicyFromS3` and the four unused `(*S3Logger).With…` builders. `utils.RedactToken` and `config.WithFragmentFetcher` were audited and kept.

### Changed

- AWS SDK v2 dependency bumps (`aws-sdk-go-v2` 1.43.2 → 1.43.4, `config` 1.32.33 → 1.32.35, `credentials` 1.19.32 → 1.19.34, `dynamodb` 1.62.2 → 1.63.1, `iam` 1.57.0 → 1.58.1, `s3` 1.106.2 → 1.106.5, `sts` 1.45.2 → 1.45.4, `smithy-go` 1.27.5 → 1.27.6, plus transitive `// indirect` updates).

## [2.2.1] - 2026-07-30

Maintenance release: dependency and CI-action updates only; nothing to do on upgrade.

### Changed

- AWS SDK v2 and transitive dependency bumps (`go.mod`/`go.sum`).
- CI action bumps: `actions/checkout` 7.0.0 → 7.0.1, `docker/login-action` 4.4.0 → 4.5.1, and `github/codeql-action` (`init`/`autobuild`/`analyze`) 4.37.1 → 4.37.3.

## [2.2.0] - 2026-07-22

Fixes from a security review of `internal/cache`, `internal/s3logger`, the SSRF/JWKS fetch path, fragment integrity and the AWS spoke/tag caches. No authorization bypass found; three behavior changes (see Upgrade notes).

### Upgrade notes

- **Enable `audit_required` by redeploy, not hot reload.** A reload enabling it from a boot config with `log_to_s3: false` now fails every request closed until a cold start.
- **SSRF guard blocks more ranges.** Hosts resolving into `100.64.0.0/10`, `0.0.0.0/8` or the NAT64 well-known prefix are refused; `allow_insecure_issuers` still relaxes loopback only.
- **`iam:GetRole` rejects role names over 64 characters** instead of truncating.

### Security

- **`audit_required` no longer fails open after a hot reload.** `WriteRecord` never no-ops; durability depends on an S3 client existing.
- **S3 writes follow a hot-reloaded `log_bucket`.** `S3Logger.SetConfigSource` resolves the bucket per write on every path.

  **Known residuals.** Enabling `audit_required` by reload from `log_to_s3: false` refuses requests until a cold start. Best-effort `BufferRecord` still reads the boot snapshot and never gates credentials.

- **`config_fragments` checksum pins are enforced on every refresh**, including cache hits.
- **`iam:GetRole` no longer truncates over-long role names.** The 64-character cap applies to the name after the last `/`.
- **`ExternalId` is no longer logged.**
- **`Cache-Control: no-store` on all API responses.**
- **SSRF guard covers IPv6 carrier forms and more reserved IPv4 ranges.** Adds IPv4-compatible `::x.x.x.x`, NAT64 `64:ff9b::/96`, `100.64.0.0/10` and `0.0.0.0/8`.
- **`GetRoleTags` authorizes the target account before consulting its cache.** Revocation applies on the next request.
- **`GetRoleAs` rejects a nil credentials provider.**
- **`GetRoleTags` returns a copy of its cached tag map.**

### Added

- **Config-load warning for implicit issuer binding.** `Validate()` warns when mappings without `issuer` bind to `default_issuer` and a second issuer exists.
- **Config-load warning for unscoped role grants.** `Validate()` warns when the lowest-`order` mapping granting a role has no `session_policy` but a higher-order one does; selection rule unchanged.
- **Regression tests** for JWKS cache isolation, SSRF dial-time and redirect blocking, role-tag/spoke-credential caches, fragment integrity, and the `audit_required` contract.

## [2.1.1] - 2026-07-21

Hardening release from an independent verification sweep of the 2.1.0 authorization layer. One behavior change: a bare-wildcard `subject` now fails to load.

### Security

- **Bare wildcard `subject` patterns are now rejected.** `Validate()` refuses `.*`/`.+` in `role_mapping.subject` and `role_groups.subjects`, sharing the `bareWildcards` guard with conditions. The check is literal; equivalent patterns such as `(.*)` still compile.

### Added

- **Adversarial authorization test suite.** 36 mutation-verified tests:
  - `internal/config/authz_adversarial_test.go` — differential fuzz of the owner-bucketed index against a linear scan.
  - `internal/validator/trust_boundary_test.go` — key confusion, `alg:none`, algorithm confusion, payload splicing, time bounds, no network request for an unconfigured `iss`.
  - `internal/aws/assume_adversarial_test.go` — cross-account fail-closed, malformed ARNs, session-tag limits, transitive tags, duration clamping.
  - `internal/handler/pipeline_e2e_test.go` — session policy reaches STS, deny paths stop before STS, failed session-policy file denies.

### Upgrade notes

- **A config with `subject: ".*"` (or `.+`) now fails to load.** Replace it with a scoped pattern such as `myorg/.*`; patterns merely containing a wildcard are unaffected.

## [2.1.0] - 2026-07-21

Security-hardening release: three authorization-layer fixes. No config-schema or deployment changes, but authorization is stricter; review before upgrading.

### Security

- **Session policy scoping bound to the granting role.** `FindSessionPolicy(issuer, subject, role, claims)` now takes the policy from the mapping that authorized the role; previously a broad policy-less mapping could cause an unscoped assumption.
- **Hot-reload condition race fixed (authorization bypass).** Fragment and role-group conditions are cloned per snapshot. Affected `config_reload_interval` + `config_fragments` with `conditions`.
- **Correct index bucketing for quantified-slash subject patterns.** Bucketing uses `regexp.LiteralPrefix`, so patterns like `owner/?repo-.*` are no longer dropped from the index.

### Upgrade notes

- **Tag-authorized roles now receive no session policy.** If `tag_auth` runs alongside `role_mappings` with `session_policy`, confirm those roles are least-privilege in IAM. `tag_auth.enabled` defaults to `false`.
- **`session_policy` selection stays order-sensitive among mappings granting the same role.** A broad policy-less mapping declared first wins and the role is assumed unscoped; declare the scoped mapping first. See `docs/CONFIGURATION.md`.

### Performance

- **JWKS warm prefetch on cold start.** `NewBootstrap()` prefetches every issuer's JWKS during INIT (self mode, 3s bound).

## [2.0.1] - 2026-07-08

### Security

- **Go 1.26.5.** Fixes GO-2026-5856 (`crypto/tls` Encrypted Client Hello privacy leak).

### Fixed

- **OpenTofu `api_endpoint` output.** Trailing slash trimmed, fixing the `//verify` 404.

### Changed

- **OpenTofu quick-setup guardrails.** A missing `dist/function.zip` fails `plan` with a clear precondition; the `apigw` authorizer defaults to `var.issuer`/`var.audiences` (`jwt_authorizer_issuer`/`jwt_authorizer_audiences` remain as overrides).

## [2.0.0] - 2026-07-02

Multi-issuer, any-provider release with provider-neutral canonical **subject** authorization. Breaking: see `docs/MIGRATION_V2.md`.

### Breaking Changes

- **Multi-issuer config model**: top-level `issuer` / `audience` / `audiences` keys and `AOW_ISSUER` / `AOW_AUDIENCE` / `AOW_AUDIENCES` env vars removed. Declare issuers under `issuers[]`.
- **Authorization renames**: `repo_role_mappings` → `role_mappings` (`repo:` → `subject:`, `constraints:` → `conditions:`), `repo_role_groups` → `role_groups`. Old keys rejected.
- **Canonical `subject`**: derived per issuer (GitHub default = `repository` claim). Non-`github` providers must set `claim_mappings.subject`.
- **Session tags are per-issuer**: set via each issuer's `session_tags`. The GitHub `repo` tag is now the full `owner/repo`; update ABAC policies matching a bare name. Invalid tag values are skipped and logged, never sanitized.
- **Delegated modes (`apigw` / `alb`)**: require exactly one configured issuer; fail closed otherwise.
- **Tag-based authorization is issuer-bound**: set `aow/issuer` on the role; identity tag is `aow/subject`. `aow/repo` / `aow/repo-owner` remain aliases during the migration window.
- **Go API**: `types.GithubClaims` → `types.Claims`; `CreateSessionTags` → `BuildSessionTags(rawClaims, tagSpec)`; `MatchRolesToRepoWithConstraints` → `AuthorizeRoles(issuer, subject, claims)`; `FindSessionPolicyForRepo` → `FindSessionPolicy(issuer, subject)`; `AwsConsumer.AssumeRole` gains `sessionTags`. `MatchRolesToRepo` removed.
- **S3/JSON config files must use `snake_case` keys**; migrate `PascalCase` configs before upgrading (#230).
- **`workflow_ref` condition regex is auto-anchored** (`^(?:...)$`); update partial-match patterns (#237).

### Added

- **Multi-issuer registry routing**: per-issuer audiences, `claim_mappings`, `required_claims`.
- **Any-provider support**: `provider: generic` maps raw claims to the canonical `subject`.
- **Generic `conditions`**: gate a mapping on any verified claim (named fields plus arbitrary `claim: regex`).
- **Config scaling**: `default_issuer`, `role_sets` (`@name`), `role_groups`, `config_fragments` (local paths, optional `config_fragment_checksums`), owner-bucketed authorization index.
- **Token hardening knobs**: `jwt_leeway` (≤120s), `max_token_lifetime`, `max_token_age`, `max_token_bytes`, `jwks_refetch_cooldown`, `allow_insecure_issuers`.
- **Structured audit trail**: one JSON record per decision via `internal/s3logger`; `audit_required` makes it durable and fail-closed; `log_level` and `log_claim_values` knobs.
- **Cross-account role assumption**: `cross_account` block (`enabled`, `spoke_role_name`, `external_id`, `spoke_session_duration`, `allowed_accounts`; `AOW_CROSS_ACCOUNT_*`); the warden assumes member-account roles directly and `enabled: false` hard-denies. Tag-based authorization uses a spoke role (default `aow-spoke`, `iam:GetRole` only) with `spoke_session_duration` capped at 1h. Example under `docs/examples/cross-account/` (#236).
- `tag_auth.transitive_session_tags` marks session tags transitive (#233).
- `tag_auth.default_org` strips the org prefix from `aow`/`repo` tag values (#234).
- EC key support restored (ES256/384/512) (#230).
- Hot-reload reaches the AWS consumer: `allowed_accounts`, tag-auth, spoke role, and external-id changes apply without a cold start (#237).
- Validator reads issuer/audiences live; revoked audiences apply after S3 reload (#230).
- `jwt_validation.mode` (`self` / `apigw` / `alb`) delegates JWT verification to API Gateway v2 JWT Authorizer or ALB OIDC.
- `ClaimsExtractorInterface` with `SelfExtractor`, `APIGWExtractor`, `ALBExtractor`.
- `AwsApiGatewayV2` adapter and `cmd/apigatewayv2/` entry point.
- `ParseRoleOnlyRequestBody` for delegated modes.
- `AOW_JWT_VALIDATION_MODE` and `AOW_JWT_VALIDATION_ALB_EXPECTED_SIGNER` env vars.
- In-memory ALB public key cache (5-minute TTL).
- OpenTofu deployment (`deploy/opentofu/`) (#243).
- CloudFormation quick-start (`deploy/cloudformation/quickstart.yaml`) and `deploy/README.md` (#243).

### Security

- **Algorithm/key pinning**: RS/ES 256–512 only (never `none`/HS\*); keys pinned by `kid` + `alg` + `use=sig`; RSA ≥2048; EC verified on its curve.
- **RSA public exponent validated**: `parseRSAKey` rejects oversized, `< 3`, or even `e`.
- **`max_token_lifetime` / `max_token_age` default to 1h** instead of unbounded; negative values rejected.
- **Bounded time and size in all modes**: `exp`/`iat` required, leeway ≤120s, optional lifetime/age caps, token-length cap, shared claim-check path.
- **SSRF-hardened JWKS/discovery fetch**: private/loopback/link-local/metadata IPs blocked at dial time; discovery `issuer` validated; refetches rate-limited per `(issuer, kid)`.
- **ALB key cache bounded** at 128 `kid` entries.
- **`TokenValidatorInterface` narrowed to `Validate`**.
- **Fragments cannot weaken security**: only `role_mappings` / `role_groups` / `role_sets` / `default_issuer` allowed; the rest is base-only.
- **Reload fails safe**: invalid reload keeps last-good config.
- **Secret-safe logging**: no raw JWT or credential logged; `log_claim_values=false` (default) suppresses claim values.
- **`apigw` trust boundary documented**: `lambda:InvokeFunction` equals identity impersonation; see `docs/TOKEN_VALIDATION.md` §2.2 and `docs/ARCHITECTURE.md`.

### Removed

- Top-level `issuer` / `audience` / `audiences` keys and `AOW_ISSUER` / `AOW_AUDIENCE` / `AOW_AUDIENCES` env vars (use `issuers[]`).
- `repo_role_mappings` / `repo_role_groups` keys (use `role_mappings` / `role_groups`).
- Exported `types.GithubClaims`, `CreateSessionTags`, `MatchRolesToRepo`.

### Fixed

- `config_fragments` are merged when no S3 config source is set; an invalid fragment fails startup.
- Error responses no longer include raw internal errors (`errorDetails` removed); use `requestId` to find them in logs.
- `apigw` mode decodes bracketed multi-value `aud` (`"[aud1 aud2]"`).
- Decision log line no longer duplicates `requestId`.
- Request-body parse failures no longer log a body preview.
- Adapters fail fast at startup when `jwt_validation.mode` is incompatible.
- ALB key cache data race fixed; expired entries evicted on read.
- ALB and API Gateway modes enforce `exp` and reject future `iat`.
- RSA JWKS keys <2048 bits rejected; EC keys validated on curve.
- Malformed role ARNs return `ErrInvalidRoleFormat` (HTTP 400).
- Adapters share `classifyError`.
- Invalid `LOG_LEVEL` logs a structured warning; full claims log at Debug.
- JWT validation failures return HTTP 401, not 500 (#230).
- S3 hot-reload does one fetch per interval (#230).
- `AOW_*` env overrides preserved across S3 hot-reloads (#230).
- S3Logger initialises after the config provider so remote `log_bucket`/`log_prefix` apply (#230).
- Authorization uses verified raw claims (`claims.Raw`); `generic`/custom-claim requests no longer wrongly denied.
- `transitive_session_tags` marks every configured session tag transitive.
- **deploy: OpenTofu stack rendered a v1 config.** Now renders the v2 schema; variable renamed `repo_role_mappings` → `role_mappings`. Removed the unusable `jwt_validation_mode = "alb"` option and `alb_expected_signer` variable from OpenTofu and CloudFormation.
- deploy: CloudFormation quickstart dropped removed `AOW_ISSUER`/`AOW_AUDIENCES` and the `Issuer`/`Audiences` parameters; `ConfigBucket`/`ConfigKey` effectively required.
- docs: `TAG_BASED_AUTHORIZATION.md` updated to the v2 model.
- docs: `SESSION_TAGGING.md` workflow example fixed (`core.getIDToken()` → `POST /verify` → `.data`).
- docs: `ARCHITECTURE.md` drift corrected (precedence order, cache diagram, interfaces, `alb_expected_signer`).
- docs: added `MULTI_ISSUER.md` "Delegated modes are single-issuer only" and cross-issuer tag-auth sections; README lists all four Lambda variants; `CLAUDE.md` files updated.
- docs: per-mode request contract added to `README.md` and `docs/TOKEN_VALIDATION.md` §2.1.
- docs: fixed mermaid JWKS label in the token-validation diagram.
- Audit records batch by default; synchronous S3 write only when `audit_required=true`.
- Required-audit write failure surfaces as `audit_write_failed`/500.
- Explicit `jwt_leeway: 0` is honored.
- `FindSessionPolicy` runs once per allow decision.
- CI: `build.yml` image-pull retry now fails after the last attempt.
- CI: `apigatewayv2` image is scanned and listed in the release summary.
- **cache: DynamoDB/S3 writes are synchronous**, no longer lost on Lambda freeze.
- cache: S3 item size limit unified to 512KB on read and write.
- cache: memory backend honors `cache.ttl` and `cache.max_local_size`.
- cache: `cache.s3_cleanup` now gates deletion of expired objects.
- cache: fixed local-tier `Get`/`Set` races.
- cache: DynamoDB items with missing or malformed `Expiration` are treated as expired.
- cache: local tiers keep the real expiration when repopulated.
- cache: no spurious LRU eviction when overwriting a key at capacity.

### Changed

- **Session durations are clamped to 1 hour** whenever the warden's credentials are a role session (always on Lambda); only `local` mode with IAM user credentials can exceed 1 hour.
- CI: `build.yml` merged into `release.yml` (single tag-triggered workflow).
- CI: `release.yml` and `make ko-publish` pass `--tags` per module (`<module>-<tag>` / `<module>-latest`, bare `<tag>` / `latest` for `apigateway`).
- CI: lint is blocking, `golangci-lint` pinned to `v2.12.2`, shared `.golangci.yml`.
- CI: blocking `govulncheck` job and `make vuln`; Trivy/gosec stay advisory.
- CI: `concurrency` groups on all workflows.
- Moved `pkg/` to `internal/`.
- `ProcessRequest` accepts `validator.ExtractionInput`.
- `RequestProcessor` holds `ClaimsExtractorInterface` instead of `TokenValidatorInterface`.
- `jwt_leeway` / `max_token_lifetime` / `max_token_age` / `max_token_bytes` and delegated extractor settings are read live; hot-reload applies without restart.
- `normalizeClaims` populates raw `sub` for every provider, so `jwtSub` is present for generic issuers.
- cache internals: removed unused `RefreshClient`/`Cleanup`/`GetStats`; AWS clients behind `dynamoDBAPI`/`s3API`; added tests.

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

- Faster Lambda cold starts: AWS client construction moved out of the hot path (#24)

### Dependencies

- github/codeql-action 3.28.19 → 3.29.0

---

## [1.2.0] - 2025-06-10

### Added

- Multi-audience support: `audience` accepts a list, all checked against `aud` (#6)
- CodeQL security analysis workflow and badge

### Changed

- Improved example configuration
- Updated GoReleaser archive format

---

## [1.1.0] - 2025-06-07

### Added

- `make build` command and improved CI workflow (#5)

---

## [1.0.0] - 2025-06-07

### Added

- Initial release: Lambda (API Gateway, ALB, Lambda URL) and local HTTP server targets
- OIDC JWT validation with JWKS signature verification
- AWS STS AssumeRole with ABAC session tagging from token claims
- Repository + constraint matching with anchored regex
- Multi-tier JWKS cache (memory / DynamoDB / S3)
- Container image published to GHCR and Docker Hub
- CodeQL, Trivy, and gosec security scanning in CI

[Unreleased]: https://github.com/boogy/aws-oidc-warden/compare/v3.5.2...HEAD
[3.5.2]: https://github.com/boogy/aws-oidc-warden/compare/v3.5.1...v3.5.2
[3.5.1]: https://github.com/boogy/aws-oidc-warden/compare/v3.5.0...v3.5.1
[3.5.0]: https://github.com/boogy/aws-oidc-warden/compare/v3.4.1...v3.5.0
[3.4.1]: https://github.com/boogy/aws-oidc-warden/compare/v3.4.0...v3.4.1
[3.4.0]: https://github.com/boogy/aws-oidc-warden/compare/v3.3.0...v3.4.0
[3.3.0]: https://github.com/boogy/aws-oidc-warden/compare/v3.2.0...v3.3.0
[3.2.0]: https://github.com/boogy/aws-oidc-warden/compare/v3.1.0...v3.2.0
[3.1.0]: https://github.com/boogy/aws-oidc-warden/compare/v3.0.2...v3.1.0
[3.0.2]: https://github.com/boogy/aws-oidc-warden/compare/v3.0.1...v3.0.2
[3.0.1]: https://github.com/boogy/aws-oidc-warden/compare/v3.0.0...v3.0.1
[3.0.0]: https://github.com/boogy/aws-oidc-warden/compare/v2.4.1...v3.0.0
[2.4.1]: https://github.com/boogy/aws-oidc-warden/compare/v2.4.0...v2.4.1
[2.4.0]: https://github.com/boogy/aws-oidc-warden/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/boogy/aws-oidc-warden/compare/v2.2.2...v2.3.0
[2.2.2]: https://github.com/boogy/aws-oidc-warden/compare/v2.2.1...v2.2.2
[2.2.1]: https://github.com/boogy/aws-oidc-warden/compare/v2.2.0...v2.2.1
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
