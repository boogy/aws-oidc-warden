# Config — Configuration Management

Extends [../../CLAUDE.md](../../CLAUDE.md). Viper-based loading, validation, and constraint matching (`config.go`).

## Loading

- `NewConfig()` loads once (`sync.Once`) and returns the shared instance.
- Precedence: `AOW_`-prefixed env vars > config file (YAML/JSON/TOML) > defaults.
- Nested keys map to underscores: `AOW_CACHE_TTL` → `cache.ttl`. See `example-config.yaml` for the full reference.

## Key structures & methods

- `Config` — `issuers` (`[]IssuerConfig`, v2 multi-issuer model; no legacy single `issuer`/`audience`/`audiences` fields), S3 config/policy buckets, `repo_role_mappings`, logging, `cache`, `JWTValidation`, plus top-level hardening knobs.
- `IssuerConfig` — one trusted issuer: `issuer` (exact `iss` match, no normalization), `provider` (`"github"` = native claim struct unmarshal, `"generic"` = mapped-only via `claim_mappings`; default `"generic"`), `audiences` (ANY-match, ≥1 required), `jwks_uri` (optional override, skips OIDC discovery), `claim_mappings` (canonical field ← raw claim; may never target a JWT-reserved claim: `iss/aud/exp/nbf/iat/sub`), `required_claims`, `session_tags` (STS tag key ← raw claim; keys must match `[A-Za-z0-9 _.:/=+@-]{1,128}`). Non-`github` issuers must set `claim_mappings.subject`.
- Zero-config seed: if no config file/source is found (`viper.ReadInConfig()` returns `ConfigFileNotFoundError`) and `issuers` is still empty after unmarshal, `LoadConfig()` seeds a single default GitHub Actions issuer (`defaultGitHubIssuer()`). If a config source *is* present but defines no issuers, `Validate()` hard-fails — the seed never masks a misconfigured file.
- Hardening knobs (top-level, all optional): `jwt_leeway` (default 30s, hard max 120s — `Validate()` rejects anything higher), `max_token_lifetime` / `max_token_age` (0 = no cap), `max_token_bytes` (default 8192), `jwks_refetch_cooldown` (default 60s), `allow_insecure_issuers` (default false, dev-only escape hatch for `http://` issuer/jwks_uri). Env: `AOW_JWT_LEEWAY`, `AOW_MAX_TOKEN_LIFETIME`, `AOW_MAX_TOKEN_AGE`, `AOW_MAX_TOKEN_BYTES`, `AOW_JWKS_REFETCH_COOLDOWN`, `AOW_ALLOW_INSECURE_ISSUERS`.
- Logging/audit knobs: `log_level` (`debug`/`info`/`warn`/`error`, default `"info"`; `Validate()` rejects anything else), `log_claim_values` (default `false` — suppresses claim VALUES in structured logs/audit records, keeping names/decision/reason), `audit_required` (default `false` — when `true`, requires `log_to_s3=true` + `log_bucket` set, and makes the audit-record write durable/fail-closed before an allow decision returns credentials). Env: `AOW_LOG_LEVEL`, `AOW_LOG_CLAIM_VALUES`, `AOW_AUDIT_REQUIRED`.
- `Validate()` on `issuers`: at least one required; exact-match duplicate issuer URLs rejected; each needs ≥1 audience; `provider` restricted to `github`/`generic`; `claim_mappings` reserved-claim and `session_tags` charset checks run per issuer.
- `JWTValidation` — `Mode` (`"self"` default, `"apigw"`, `"alb"`) and `ALBExpectedSigner` (ARN of the trusted ALB; optional but strongly recommended in `alb` mode). Env: `AOW_JWT_VALIDATION_MODE`, `AOW_JWT_VALIDATION_ALB_EXPECTED_SIGNER`. `Validate()` rejects unknown modes.
- `RepoRoleMapping` — `repo` pattern, `roles`, optional `session_policy`/`session_policy_file`, optional `constraints`.
- `Constraint` — `branch`, `ref`, `ref_type`, `event_name`, `workflow_ref`, `environment`, `actor_matches`. All present constraints must match (AND).
- `Validate()` — compiles all regex patterns once; repo patterns auto-anchored `^(?:pattern)$`.
- `MatchRolesToRepoWithConstraints(repo, claims)`, `MatchRolesToRepo(repo)`, `FindSessionPolicyForRepo(repo)`.
- `TagAuth` (opt-in, default off) + `Authorize(roleTags, claims)` in `tagauth.go` — tag-based authorization fallback; exact matching only (AWS tag charset, no regex), space-list = OR, cross-tag = AND, `repo`-OR-`repo-owner` identity gate. Full field set: `TagPrefix string` (default `"aow/"`), `SpokeRoleName string` (default `"aow-spoke"`), `ExternalID string` (optional hub→spoke external ID), `DefaultOrg string` (expands bare `aow/repo` tokens to `<org>/name`; must not contain `/` or whitespace), `SpokeSessionDuration time.Duration` (default 15m), `TransitiveSessionTags bool` (marks `repo`/`ref`/`actor` immutable through role chaining, default false), `AllowedAccounts []string` (allow-list of member account IDs; hub implicit; empty = any; non-12-digit rejected by `Validate()`). See `docs/TAG_BASED_AUTHORIZATION.md`.
- `Provider` — hot-reload wrapper around `Config`: `NewProvider(base, interval, format, fetch)` / `NewStaticProvider(cfg)`; `MaybeRefresh(ctx)` does a lazy per-request reload (atomic swap from clone of pristine base); `Get()` returns the current active config. The token validator calls `Get()` on every `Validate()` so issuer/audience changes apply immediately.

## Gotchas

- Never compile regex per request — only in `Validate()`.
- Keep patterns specific; reject `.*` for security constraints.
- Env keys are case-insensitive; config keys are snake_case.
