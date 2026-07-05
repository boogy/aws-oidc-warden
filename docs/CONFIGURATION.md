# AWS OIDC Warden Configuration

This document explains how to configure AWS OIDC Warden using environment variables and configuration files.

## Configuration Methods

AWS OIDC Warden can be configured using:

1. Environment variables (prefixed with `AOW_`)
2. Configuration file (YAML, JSON, or TOML)
3. A combination of both (environment variables override config file values)

See [example-config.yaml](../example-config.yaml) for a complete, annotated reference configuration.

## The v2 issuer model

> **Breaking change from v1**: the single top-level `issuer` / `audience` / `audiences` scalars are gone. Every trusted OIDC issuer — GitHub Actions, GitLab CI/CD, a custom IdP, or several of each — is declared as an entry in `issuers`. See [MIGRATION_V2.md](MIGRATION_V2.md) for the exact rename table and upgrade steps, and [MULTI_ISSUER.md](MULTI_ISSUER.md) for a walkthrough of onboarding a new provider.

```yaml
issuers:
  - issuer: "https://token.actions.githubusercontent.com"
    provider: "github" # native claim struct; canonical subject = "repository" claim
    audiences:
      - "sts.amazonaws.com"
    required_claims:
      - "repository"
    session_tags:
      repo: "repository"
      repo-owner: "repository_owner"

  - issuer: "https://gitlab.com"
    provider: "generic" # mapped-only; must declare claim_mappings.subject
    audiences:
      - "sts.amazonaws.com"
    claim_mappings:
      subject: "project_path"
    required_claims:
      - "project_path"
    session_tags:
      project: "project_path"
```

### `issuers[]` fields

| Config File Key   | Description                                                                                                                       | Default      |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| `issuer`          | Exact `iss` claim value trusted for this entry. No trailing-slash or case normalization — must match byte-for-byte.               | (required)   |
| `provider`        | `"github"` (native `types.Claims` struct unmarshal) or `"generic"` (mapped-only via `claim_mappings`).                            | `"generic"`  |
| `audiences`       | Accepted `aud` values for this issuer; ANY-match. At least one required.                                                          | (required)   |
| `jwks_uri`        | Explicit JWKS URI; when set, skips OIDC discovery (`<issuer>/.well-known/openid-configuration`).                                  | (discovered) |
| `claim_mappings`  | Canonical field name → raw verified claim name (e.g. `subject: project_path`). May never target a JWT-reserved claim (see below). | (empty)      |
| `required_claims` | Raw verified claim names that must be present and non-empty for a token from this issuer.                                         | (empty)      |
| `session_tags`    | STS session tag key → raw verified claim name, applied at `AssumeRole` time.                                                      | (empty)      |

Reserved claim names that `claim_mappings` may **never** target (shadowing them could let a claim override a security-relevant field): `iss`, `aud`, `exp`, `nbf`, `iat`, `sub`.

`session_tags` keys must match the STS tag-key charset `^[A-Za-z0-9 _.:/=+@-]{1,128}$`; a key that doesn't is a config validation error.

**Provider-specific behavior**: `provider: "github"` unmarshals the token into the native `types.Claims` struct (all of GitHub's OIDC claims — `repository`, `ref`, `actor`, `workflow_ref`, etc. — are available for `conditions` without any `claim_mappings`), and its canonical `subject` defaults to the `repository` claim (`owner/repo`) unless overridden. Every other `provider` value is `"generic"`: only the claims listed in `claim_mappings` are given canonical names, and `claim_mappings.subject` **must** be set — `Validate()` rejects a non-`github` issuer that omits it.

### Zero-config seed

If no config file/S3 source is found at all, `LoadConfig()` seeds a single default GitHub Actions issuer equivalent to:

```yaml
issuers:
  - issuer: "https://token.actions.githubusercontent.com"
    provider: "github"
    audiences: ["sts.amazonaws.com"]
    required_claims: ["repository"]
    session_tags:
      repo: "repository"
      repo-owner: "repository_owner"
      ref: "ref"
      ref-type: "ref_type"
      actor: "actor"
      event-name: "event_name"
```

This only happens when there is **no** configuration source whatsoever. If a config file (or S3 object) _is_ present but declares an empty `issuers` list, `Validate()` hard-fails — the seed never masks a misconfigured file.

> **Breaking change**: the seeded `repo` session tag now carries the **full `owner/repo`** string (the raw `repository` claim, unmodified), not the bare repo name v1 produced by stripping the owner. See [SESSION_TAGGING.md](SESSION_TAGGING.md) and [MIGRATION_V2.md](MIGRATION_V2.md).

## Authorization: role_mappings, role_groups, role_sets

v2 renames the repo-centric `repo_role_mappings` to the provider-neutral `role_mappings`, matched on `(issuer, subject)` instead of `(repo)`. Two DRY conveniences sit on top: `role_groups` (expand one set of role/condition defaults across many subjects) and `role_sets` (named, reusable ARN lists).

```yaml
default_issuer: "https://token.actions.githubusercontent.com" # only needed with >1 issuer

role_sets:
  readonly:
    - "arn:aws:iam::123456789012:role/github-actions-readonly"
  deployers:
    - "arn:aws:iam::123456789012:role/github-actions-deploy"
    - "arn:aws:iam::123456789012:role/github-actions-deploy-secondary"

role_mappings:
  - subject: "octo-org/api"
    issuer: "https://token.actions.githubusercontent.com" # explicit; overrides default_issuer
    roles: ["@deployers"]
    conditions:
      branch: "main"
      event_name: "push"

  - subject: "group/project" # GitLab project_path
    issuer: "https://gitlab.com"
    roles: ["@readonly"]

role_groups:
  - issuer: "https://token.actions.githubusercontent.com"
    subjects:
      - "octo-org/service-a"
      - "octo-org/service-b"
      - "octo-org/service-c"
    defaults:
      roles: ["@readonly"]
      conditions:
        event_name: "push"
```

| Concept         | Replaces (v1)        | Notes                                                                                                                                                             |
| --------------- | -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `role_mappings` | `repo_role_mappings` | `subject` replaces `repo`; each entry binds to one `issuer` (explicit, `default_issuer`, or the sole configured issuer).                                          |
| `conditions`    | `constraints`        | Same fields (`branch`, `ref`, `ref_type`, `event_name`, `workflow_ref`, `environment`, `actor_matches`), plus an open-ended map of `claim_name: pattern` entries. |
| `role_sets`     | (new)                | Named `[]string` ARN lists; reference as `"@name"` inside any `roles` list. Resolved once at `Validate()`, before the requested-role gate.                        |
| `role_groups`   | (new)                | Expands to one `role_mappings` entry per `subjects[]` entry, sharing `issuer` + `defaults` (roles/conditions/session_policy). Re-expanded on every `Validate()`.  |

`subject` is matched with the same auto-anchored-regex semantics `repo` used (`^(?:pattern)$`) — keep patterns specific; a bare `.*`/`.+` is rejected wherever it's used as a security condition (`conditions` fields), though `subject` itself has no such restriction beyond anchoring.

`conditions.branch` and `conditions.ref` both check the raw `ref` claim (`refs/heads/main`, `refs/tags/v1.2.3`, ...) — this is intentional, not a bug; use whichever name reads better for your pattern.

Authorization is evaluated by `Config.AuthorizeRoles(issuer, subject, claims)`, which unions the roles of every `(issuer, subject)`-matching, condition-satisfying mapping; `Config.FindSessionPolicy(issuer, subject)` separately picks the first-declared match (config order) for the session policy, ignoring conditions — this mirrors the pre-v2 first-match-wins session-policy behavior.

### Owner-bucketed index

Internally, `Validate()` builds a per-issuer index (`exact` subject / `byOwner` prefix / `any` fallback bucket) so a request only re-checks the mappings that could plausibly match its subject, instead of scanning the whole list. This is a pure performance optimization: every candidate is still re-verified against its compiled pattern, so behavior is identical to a linear scan. One subtlety worth knowing if you write subject patterns with top-level `|` alternation (e.g. `"octo-org/(api|web)"` vs. `"octo-org/api|other-org/web"`): a pattern whose top-level alternation could span more than one literal owner always falls into the `any` bucket (never misclassified into `exact`/`byOwner`), so it is still checked against every subject — just not via the fast path.

## Environment Variable Reference

### Core Settings

| Environment Variable         | Config File Key          | Description                                                                                                             | Default           |
| ---------------------------- | ------------------------ | ----------------------------------------------------------------------------------------------------------------------- | ----------------- |
| `AOW_ROLE_SESSION_NAME`      | `role_session_name`      | AWS STS role session name                                                                                               | `aws-oidc-warden` |
| `AOW_S3_CONFIG_BUCKET`       | `s3_config_bucket`       | S3 bucket holding the remote config object                                                                              | (empty)           |
| `AOW_S3_CONFIG_PATH`         | `s3_config_path`         | Key/path of the remote config object in that bucket                                                                     | (empty)           |
| `AOW_CONFIG_RELOAD_INTERVAL` | `config_reload_interval` | Hot-reload the S3 config at most this often (e.g. `5m`); `0` disables                                                   | `0` (disabled)    |
| `AOW_CONFIG_FRAGMENTS`       | `config_fragments`       | Comma-separated fragment sources merged onto base config (local paths only — see [Config fragments](#config-fragments)) | (empty)           |
| `AOW_SESSION_POLICY_BUCKET`  | `session_policy_bucket`  | S3 bucket for `session_policy_file` lookups                                                                             | (empty)           |

`issuers`, `default_issuer`, `role_sets`, `role_mappings`, `role_groups`, and `config_fragment_checksums` are structured values with no flat env-var equivalent — set them in the config file (or a fragment).

### Cache Settings

| Environment Variable       | Config File Key        | Description                       | Default  |
| -------------------------- | ---------------------- | --------------------------------- | -------- |
| `AOW_CACHE_TYPE`           | `cache.type`           | Cache type (memory, dynamodb, s3) | `memory` |
| `AOW_CACHE_TTL`            | `cache.ttl`            | Cache TTL                         | `1h`     |
| `AOW_CACHE_MAX_LOCAL_SIZE` | `cache.max_local_size` | Max size for memory cache         | `10`     |
| `AOW_CACHE_DYNAMODB_TABLE` | `cache.dynamodb_table` | DynamoDB table name               |          |
| `AOW_CACHE_S3_BUCKET`      | `cache.s3_bucket`      | S3 bucket name                    |          |
| `AOW_CACHE_S3_PREFIX`      | `cache.s3_prefix`      | S3 key prefix                     |          |
| `AOW_CACHE_S3_CLEANUP`     | `cache.s3_cleanup`     | Clean up old cache objects        | `false`  |

### Hardening Knobs

Top-level, apply across every configured issuer and every `jwt_validation.mode`.

| Environment Variable         | Config File Key          | Description                                                                                                          | Default            |
| ---------------------------- | ------------------------ | -------------------------------------------------------------------------------------------------------------------- | ------------------ |
| `AOW_JWT_LEEWAY`             | `jwt_leeway`             | Clock-skew leeway applied to `exp`/`iat`/`nbf` checks                                                                | `30s` (max `120s`) |
| `AOW_MAX_TOKEN_LIFETIME`     | `max_token_lifetime`     | Reject if `exp - iat` exceeds this; `0` = no cap                                                                     | `0` (no cap)       |
| `AOW_MAX_TOKEN_AGE`          | `max_token_age`          | Reject if `now - iat` exceeds this; `0` = no cap                                                                     | `0` (no cap)       |
| `AOW_MAX_TOKEN_BYTES`        | `max_token_bytes`        | Raw token length cap enforced before any parsing                                                                     | `8192` (8 KB)      |
| `AOW_JWKS_REFETCH_COOLDOWN`  | `jwks_refetch_cooldown`  | Minimum interval between forced JWKS refetches per `(issuer, kid)` — bounds the cost of an unknown-`kid` DoS attempt | `60s`              |
| `AOW_ALLOW_INSECURE_ISSUERS` | `allow_insecure_issuers` | Dev-only escape hatch: permit `http://` issuer/`jwks_uri` (otherwise rejected)                                       | `false`            |

`jwt_leeway: 0` and `max_token_bytes: 0` mean "use the default", not "disable" — `Validate()` applies the default whenever the field is its zero value. A negative value for any of these knobs is a config validation error; `jwt_leeway` above `120s` is also rejected.

### Logging & Audit Settings

| Environment Variable           | Config File Key    | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Default |
| ------------------------------ | ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `AOW_LOG_TO_S3`                | `log_to_s3`        | Enable logging to S3 (in addition to CloudWatch)                                                                                                                                                                                                                                                                                                                                                                                                                | `false` |
| `AOW_LOG_BUCKET`               | `log_bucket`       | S3 bucket for logs                                                                                                                                                                                                                                                                                                                                                                                                                                              | (empty) |
| `AOW_LOG_PREFIX`               | `log_prefix`       | S3 key prefix for logs                                                                                                                                                                                                                                                                                                                                                                                                                                          | (empty) |
| `AOW_LOG_LEVEL`                | `log_level`        | Must be one of `debug`/`info`/`warn`/`error` — validated at config load. **Not currently wired to the slog handler's verbosity**; see the gotcha below.                                                                                                                                                                                                                                                                                                         | `info`  |
| `AOW_LOG_CLAIM_VALUES`         | `log_claim_values` | Include claim VALUES (canonical subject, raw `sub`, audience, session tag values) in structured logs and the audit record. Off by default: only claim NAMES, decision, and reason are logged.                                                                                                                                                                                                                                                                   | `false` |
| `AOW_AUDIT_REQUIRED`           | `audit_required`   | Make the audit-record write a hard, fail-closed dependency: an allow decision only returns credentials after the audit record is durably written; requires `log_to_s3=true` + `log_bucket` set. Default `false` favors availability + zero-dependency startup (decisions are still logged to CloudWatch); **set `true` in production** when the audit trail is a security/compliance control. See [LOGGING.md](LOGGING.md#production-hardening-recommendation). | `false` |
| `LOG_LEVEL` (no `AOW_` prefix) | N/A                | Sets the initial `slog` handler level at process bootstrap, **before** config is loaded (`internal/handler/bootstrap.go`). This is the env var that actually controls verbosity in the Lambda deployments.                                                                                                                                                                                                                                                      | `info`  |

> **Gotcha**: `log_level`/`AOW_LOG_LEVEL` is validated (rejects an unknown level name) but is **not** currently applied to the running `slog` handler — the handler's level is set once, at bootstrap, from the bare `LOG_LEVEL` env var (Lambda) or the `-log-level` CLI flag (`cmd/local`). If you need to change verbosity, set `LOG_LEVEL` (Lambda) or `-log-level` (local), not `AOW_LOG_LEVEL`. See [LOGGING.md](LOGGING.md).

See [LOGGING.md](LOGGING.md) for the full audit-record schema and the standardized decision log line.

### Tag-Based Authorization Settings

Optional, disabled by default. When enabled, a role may be assumed via its IAM tags even if it's not listed in `role_mappings`/`role_groups`. See [TAG_BASED_AUTHORIZATION.md](TAG_BASED_AUTHORIZATION.md) for the tag reference and IAM setup, and [MULTI_ISSUER.md](MULTI_ISSUER.md) for the v2 canonical `subject`/`issuer` tags.

| Environment Variable                   | Config File Key                    | Description                                                                                                     | Default |
| -------------------------------------- | ---------------------------------- | --------------------------------------------------------------------------------------------------------------- | ------- |
| `AOW_TAG_AUTH_ENABLED`                 | `tag_auth.enabled`                 | Enable tag-based authorization                                                                                  | `false` |
| `AOW_TAG_AUTH_TAG_PREFIX`              | `tag_auth.tag_prefix`              | Namespace prefix for authorization tag keys                                                                     | `aow/`  |
| `AOW_TAG_AUTH_DEFAULT_ORG`             | `tag_auth.default_org`             | Org prefix for bare `aow/repo` tokens (e.g. `"api"` → `"<org>/api"`); must not contain `/` or whitespace        | (empty) |
| `AOW_TAG_AUTH_TRANSITIVE_SESSION_TAGS` | `tag_auth.transitive_session_tags` | Mark every attached session tag (the issuer's `session_tags` spec) transitive — immutable through role chaining | `false` |

`tag_auth`'s identity gate now accepts the canonical `<prefix>subject` tag (any issuer's subject) in addition to the legacy `<prefix>repo`/`<prefix>repo-owner` tags (GitHub-shaped subjects only). With more than one issuer configured, `Authorize()` also requires a matching `<prefix>issuer` tag on the role — a role with no `<prefix>issuer` tag cannot be reached via tag-auth once a second issuer is added, preventing a role scoped to one issuer's subjects from being reachable by another issuer's identically-shaped subject. See [MULTI_ISSUER.md](MULTI_ISSUER.md).

### Cross-Account Settings

Optional, disabled by default, and a **policy gate**: `false` (the default) hard-blocks every cross-account operation — both role assumption and, for `tag_auth`, IAM tag reads — regardless of `role_mappings` or `tag_auth` settings. Role assumption is always **direct**, hub → target, one hop, using the warden's own credentials; the per-account spoke role is used only so `tag_auth` can read a target role's IAM tags cross-account (`iam:GetRole`) — it never assumes the target role itself. Cross-account sessions are capped at 1h whenever the warden's own credentials are a role session (always true on Lambda, same-account assumes included) — see [Session Security](ARCHITECTURE.md#3-aws-integration-security). See [TAG_BASED_AUTHORIZATION.md](TAG_BASED_AUTHORIZATION.md#cross-account) and the worked example in [examples/cross-account/](examples/cross-account/).

| Environment Variable                       | Config File Key                        | Description                                                                                                                                                  | Default     |
| ------------------------------------------ | -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------- |
| `AOW_CROSS_ACCOUNT_ENABLED`                | `cross_account.enabled`                | Policy gate: required `true` for any cross-account operation (assumes and tag reads); `false` fails closed                                                   | `false`     |
| `AOW_CROSS_ACCOUNT_SPOKE_ROLE_NAME`        | `cross_account.spoke_role_name`        | Role assumed in each member account, used only for cross-account tag reads (`tag_auth`)                                                                      | `aow-spoke` |
| `AOW_CROSS_ACCOUNT_EXTERNAL_ID`            | `cross_account.external_id`            | Optional external ID for the hub→spoke trust; never sent on the hub→target assume                                                                            |             |
| `AOW_CROSS_ACCOUNT_SPOKE_SESSION_DURATION` | `cross_account.spoke_session_duration` | Hub→spoke session length; capped at `1h` (the spoke hop is a chained session, which AWS limits to 1 h)                                                       | `15m`       |
| `AOW_CROSS_ACCOUNT_ALLOWED_ACCOUNTS`       | `cross_account.allowed_accounts`       | Comma-separated member account IDs allowed as assume targets (must be 12 digits; hub always allowed; empty = any once enabled — a startup warning is logged) | (empty)     |

### JWT Validation Mode Settings

| Environment Variable                     | Config File Key                      | Description                                                                           | Default                                     |
| ---------------------------------------- | ------------------------------------ | ------------------------------------------------------------------------------------- | ------------------------------------------- |
| `AOW_JWT_VALIDATION_MODE`                | `jwt_validation.mode`                | JWT validation mode (`"self"`, `"apigw"`, or `"alb"`)                                 | `"self"`                                    |
| `AOW_JWT_VALIDATION_ALB_EXPECTED_SIGNER` | `jwt_validation.alb_expected_signer` | ARN of the trusted ALB; **required** in ALB mode to prevent cross-ALB token injection | (empty, startup fails if unset in alb mode) |

> **Multi-issuer restriction**: `apigw` and `alb` modes trust an upstream that has already verified the token against a single issuer, so both modes require **exactly one** entry in `issuers` — `NewBootstrap()` fails at cold start otherwise (`jwt_validation.mode %q supports exactly one configured issuer, got %d`). Multi-issuer configs are `self`-mode only. See [MULTI_ISSUER.md](MULTI_ISSUER.md#delegated-modes-are-single-issuer-only).

### Other Settings

| Environment Variable | Description                          | Default  |
| -------------------- | ------------------------------------ | -------- |
| `CONFIG_NAME`        | Config file name (without extension) | `config` |
| `CONFIG_PATH`        | Config file directory                | `.`      |

`CONFIG_PATH` is also always checked at `/etc/aws-oidc-warden/` in addition to the configured path.

## Config fragments

`config_fragments` lists additional sources merged on top of the base config's `default_issuer`, `role_sets`, `role_mappings`, and `role_groups` (and _only_ those four keys; anything else in a fragment is a hard error). This lets teams own their own role-mapping fragment without touching the base config that defines `issuers`/hardening knobs/`tag_auth`.

> **Local paths only, for now.** `config.Provider` supports remote (`"scheme://"`, e.g. `s3://`) fragment URIs through an injected `FragmentFetchFunc` (`config.WithFragmentFetcher`), but the shipped binaries (Lambda and `cmd/local`) never install one — `bootstrap.go` calls `config.NewProvider(...)` with no `ProviderOption`s. A `config_fragments` entry with a `scheme://` prefix will hard-fail to fetch in every current deployment. Use local filesystem paths only until a fetcher is wired in.

```yaml
config_fragments:
  - "/etc/aws-oidc-warden/fragments/team-platform.yaml"
  - "/etc/aws-oidc-warden/fragments/team-data.yaml"

# Optional: pin an expected content hash per fragment. A fetched value that
# doesn't match exactly is rejected.
config_fragment_checksums:
  "/etc/aws-oidc-warden/fragments/team-platform.yaml": "sha256:a1b2c3d4e5f6..."
```

Rules enforced on every merge:

- **Allowlist**: a fragment may only set `default_issuer`, `role_sets`, `role_mappings`, `role_groups`. Any other top-level key is rejected.
- **`default_issuer`**: a fragment's `default_issuer` must already be a base-defined issuer, and cannot conflict with the base's own `default_issuer` if both set one.
- **`role_sets`**: merged by name; a fragment defining a `role_sets` name the base (or another already-merged fragment) already defined is rejected.
- **`role_mappings`/`role_groups`**: appended.
- Each fragment is capped at 1 MiB; fetch failures (and re-validation failures after merge) fall back to the last-known-good config rather than serving a partial/invalid merge.
- Local-path fragments are content-hashed (sha256) for change detection; a remote fetcher (once wired) would use its own scheme's native change-detection token (e.g. an S3 ETag). Either can be pinned via `config_fragment_checksums`.

## Hot-reloading

When `s3_config_bucket`/`s3_config_path` are set, the process fetches and overlays that object at startup (failing fast if it's unreachable or invalid). If `config_reload_interval` is also > 0, the running service re-fetches the object at most once per that interval — checked lazily, once per request, via `Provider.MaybeRefresh` — and atomically swaps in a re-validated config; an invalid or unreachable reload is logged and the previous config is kept. `config_fragments` are re-resolved on the same cadence. Everything read per-request off the live `*config.Config` (issuers, `role_mappings`/`role_groups`/`role_sets`, `tag_auth`, session tags, ...) picks up a reload immediately with no restart; the `jwt_validation.mode`-selected extractor is fixed at cold start (see above).

## Configuration File Format

AWS OIDC Warden supports YAML, JSON, and TOML configuration files (format auto-detected from the file extension via `FormatFromPath`; anything other than `.yaml`/`.yml`/`.toml` is treated as JSON). See [example-config.yaml](../example-config.yaml) for a complete annotated example covering a two-issuer (GitHub + GitLab) setup, `role_sets`/`role_groups`/`default_issuer`, `tag_auth`, `jwt_validation`, and hardening/logging knobs.
