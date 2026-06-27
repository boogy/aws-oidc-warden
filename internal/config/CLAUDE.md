# Config — Configuration Management

Extends [../../CLAUDE.md](../../CLAUDE.md). Viper-based loading, validation, and constraint matching (`config.go`).

## Loading

- `NewConfig()` loads once (`sync.Once`) and returns the shared instance.
- Precedence: `AOW_`-prefixed env vars > config file (YAML/JSON/TOML) > defaults.
- Nested keys map to underscores: `AOW_CACHE_TTL` → `cache.ttl`. See `example-config.yaml` for the full reference.

## Key structures & methods

- `Config` — issuer, `audiences` (plus deprecated `audience`), S3 config/policy buckets, `repo_role_mappings`, logging, `cache`.
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
