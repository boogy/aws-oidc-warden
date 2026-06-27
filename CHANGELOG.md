# Changelog

AWS OIDC Warden — validates OIDC tokens (e.g. GitHub Actions) and exchanges them for short-lived AWS credentials via STS AssumeRole.

All notable changes are documented here. Format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/); versioning follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] - 2026-06-27

### ⚠️ Breaking Changes

**S3 JSON remote config keys must now be snake_case.**

`cloneConfig` previously serialized the config struct via `json.Marshal` without explicit `json` struct tags, producing PascalCase JSON keys (`RepoRoleMappings`, `RoleSessionName`, etc.). These keys were inconsistent with the snake_case schema used by Viper/mapstructure everywhere else. Matching `json` tags (`snake_case`, `omitempty`) have been added to `Config`, `RepoRoleMapping`, `Constraint`, and `Cache`, so `cloneConfig` now round-trips through the same snake_case schema as the rest of the system.

**Who is affected:** operators who store their remote config as a **JSON file in S3** and whose JSON uses PascalCase keys (e.g. `RepoRoleMappings`). YAML config files, environment variables (`AOW_*`), and JSON files already using snake_case keys are **unaffected**.

**Migration:** rename all top-level and nested JSON keys to snake_case. For example:

| Old (PascalCase) | New (snake_case) |
|---|---|
| `RepoRoleMappings` | `repo_role_mappings` |
| `RoleSessionName` | `role_session_name` |
| `Issuer` | `issuer` |
| `CacheType` | `type` (under `cache:`) |

See `docs/CONFIGURATION.md` for the full schema reference.

---

### Added

- **Tag-based authorization (hub/spoke ABAC model).** A new `tag_auth` config block enables authorizing role assumption by reading IAM role tags from the target role rather than relying solely on `repo_role_mappings`. The hub Lambda reads tags from the spoke account via cross-account credentials and matches them against OIDC claims. Covers the full pipeline: `GetRoleTags` with cross-account read + caching; `ParseRoleARN`; account-aware `AssumeRoleAs` / `GetRoleAs` wrappers; spoke credential resolution with caching; cross-account `AssumeRole` routed through spoke credentials; handler-level `tag_auth` authorization gate.

- **Multi-dimensional tag matching.** Tag conditions support nine claim dimensions: `aow/repo`, `aow/repo-owner`, `aow/branch`, `aow/ref`, `aow/ref-type`, `aow/event-name`, `aow/workflow-ref`, `aow/environment`, and `aow/actor`. All set tags on a role must match (AND semantics) before the role assumption is authorized.

- **Transitive session tags (`tag_auth.transitive_session_tags`).** When enabled, `aow/repo`, `aow/ref`, and `aow/actor` session tags are marked transitive so they propagate through chained role assumptions, enabling ABAC policies on downstream spoke roles without re-asserting identity.

- **Target-account allow-list (`tag_auth.allowed_accounts`).** An explicit list of AWS account IDs that the hub is permitted to assume roles into. The hub account is implicitly included. Requests targeting an unlisted account are rejected with HTTP 403. An empty list triggers a `slog.Warn` (fail-open guard) to alert operators of a potentially misconfigured defense-in-depth layer.

- **Short repo tags via `tag_auth.default_org`.** When set to a GitHub org/user prefix, bare `aow/repo` tag values (e.g. `my-repo`) are expanded to the full `org/repo` form before matching, removing the need to repeat the org name on every role tag. Format validated at startup; newlines/CR stripped.

- **New documentation and diagrams.** `docs/TAG_BASED_AUTHORIZATION.md` covers configuration, conditions, precedence interaction matrix, corner cases, and ABAC. Five SVG diagrams added: decision flow, tag matching, precedence, cross-account topology, and ABAC policy evaluation.

### Changed

- **Go toolchain bumped to 1.26.4.** `go.mod` / `go.sum` updated accordingly.

- **Token validation failures now return HTTP 401.** Previously, all JWT failures (expired, bad signature, wrong audience, etc.) returned HTTP 500. A new `ErrTokenValidationFailed` sentinel is wrapped with `%w` and all three frontend adapters (`apigateway`, `alb`, `lambdaurl`) check via `errors.Is` to map it to 401 Unauthorized.

- **Cross-account (chained) sessions clamped to 1 hour.** When the hub assumes a spoke role and then chains another `AssumeRole` using those credentials, the requested session duration is clamped to 3600 s (the AWS maximum for chained sessions), preventing STS errors at runtime.

- **S3 JSON remote config now uses snake_case keys** (see Breaking Changes above). This change also improves consistency between the in-memory config, YAML files, and JSON remote configs.

### Fixed

- **EC key support restored (ES256/384/512).** `GenKeyFunc` now handles both RSA and EC keys via a type-switch. EC signatures were rejected with "signing method not in valid methods". Empty or missing `kty` fields now return a descriptive error instead of constructing a zero-value RSA key that bypassed the rotation-retry path.

- **S3 hot-reload preserves `AOW_*` env-var overrides.** `MergeBytes` previously used a fresh `viper.Viper` without `AOW_*` env bindings, causing each S3 reload to silently overwrite env-var-derived fields and break the documented `AOW_* > file > defaults` precedence. A `reapplyEnvOverrides()` call at the end of `MergeBytes` restores the correct precedence.

- **Missing `AOW_*` env overrides for audiences and cache settings.** `reapplyEnvOverrides` now covers `AOW_AUDIENCES` (comma-split), `AOW_AUDIENCE`, and all seven `AOW_CACHE_*` keys (`TYPE`, `TTL`, `MAX_LOCAL_SIZE`, `DYNAMODB_TABLE`, `S3_BUCKET`, `S3_PREFIX`, `S3_CLEANUP`). Parse errors for duration/int/bool fields are logged via `slog.Warn` instead of silently skipped.

- **Concurrent S3 reload-burst prevention.** `MaybeRefresh` previously triggered N concurrent S3 fetches when N requests arrived simultaneously at a reload boundary. Replaced with double-checked locking (fast-path atomic read, re-check inside mutex) so exactly one fetch fires per interval. The `config_reload_interval` is now stored in an `atomic.Int64` and can be updated live from the reloaded config without holding the mutex.

- **S3Logger initialized after config provider.** `NewBootstrap` previously called `s3logger.NewS3Logger(cfg)` before `buildConfigProvider` applied the S3 config overlay, silently ignoring any `log_bucket` or `log_prefix` set in the remote config for the Lambda container lifetime. Ordering is now correct.

- **Issuer and audiences re-read from provider on every `Validate` call.** `TokenValidator` previously captured issuer and audiences at construction time. Hot-reloaded config changes (e.g. a revoked audience removed from S3 config) were not reflected until cold start, breaking a security invariant. `TokenValidator` now holds a `*config.Provider` and calls `provider.Get()` on each `Validate` / `ParseToken` invocation.

- **`AOW_AUDIENCES` whitespace trimmed.** Comma-separated audience values from the env var are now trimmed of leading/trailing whitespace before use.

- **`token_invalid` error code and clearer JWT parse errors.** The JSON error body now includes `"code": "token_invalid"` for JWT failures, making programmatic error handling more reliable. JWT parse error messages are clearer about the failure reason.

### Security

- **Transitive session tags are identity-asserting and immutable.** The `aow/repo`, `aow/ref`, and `aow/actor` tags, when marked transitive, propagate the verified OIDC identity through chained role assumptions. Downstream IAM policies can enforce ABAC conditions on these tags without trusting intermediate callers to re-assert identity.

- **Account allow-list is a fail-closed guardrail.** `tag_auth.allowed_accounts` prevents the hub from being used as a pivot to arbitrary AWS accounts. Requests to unlisted accounts are rejected before any STS call is made. An empty list is flagged with a warning rather than silently permitted, ensuring operators make a conscious decision about the allow-list scope.

- **Live audience and issuer validation.** The fix to re-read issuer/audiences from the provider on every `Validate` call closes a window where a revoked audience removed from the S3 remote config would remain accepted until the next cold start. Audience and issuer checks now always reflect the current active config.

- **Documented `ParseToken` audience-bypass caveat.** `ParseToken` (used for claim extraction before full validation) intentionally skips audience verification. This behaviour is now explicitly documented in code and configuration docs so implementors are aware and do not rely on `ParseToken` for access control decisions.

---

[2.0.0]: https://github.com/boogy/aws-oidc-warden/compare/v1.3.6...v2.0.0
