# AWS OIDC Warden

Go service that validates OIDC tokens (e.g. GitHub Actions) and exchanges them for short-lived AWS credentials via STS AssumeRole. Runs as a Lambda behind multiple front-ends, or as a local HTTP server.

Request flow: multi-issuer token validation → canonical-subject authorization (issuer-bound) → condition checking → session policy → role assumption (`internal/handler/processor.go`).

This file is the map. Each package below has its own `CLAUDE.md` with the detail — open the one for the area you're touching. The conventions, security, and git rules at the bottom are shared by all packages (each subdir file `Extends` this one).

## Package guide

- **`internal/handler/`** → [CLAUDE.md](internal/handler/CLAUDE.md) — core request pipeline shared by every deployment. `NewBootstrap()` wires DI (config, validator, cache, AWS consumer); `ProcessRequest()` runs the pipeline; `RequestData` + sentinel errors live in `types.go`; the per-frontend adapters (`apigateway.go` / `alb.go` / `lambdaurl.go`) differ only in event parse/serialize.
  _Go here when_ changing request flow, adding a frontend, or touching error→HTTP mapping.

- **`internal/validator/`** → [CLAUDE.md](internal/validator/CLAUDE.md) — multi-issuer JWT parse + JWKS signature/claims verification (`TokenValidatorInterface`). Routes on the unverified `iss` to a per-issuer registry spec, then verifies signature → re-asserted issuer → audience (ANY-match) → time bounds → required*claims → canonical-subject normalization. Allowed algorithms only (ES/RS 256–512, never `none`). Delegated `apigw`/`alb` share the same claim-check path.
  \_Go here when* touching token verification, JWKS fetching, or audience handling.

- **`internal/config/`** → [CLAUDE.md](internal/config/CLAUDE.md) — Viper config (`AOW_` env prefix > file > defaults), the `issuers[]` model, issuer-bound subject/condition matching over an owner-bucketed index, config fragments, and the remote `Provider` (lazy refresh via injected `FetchFunc`, atomic swap from a pristine base). Key methods: `AuthorizeRoles(issuer, subject, claims)`, `FindSessionPolicy(issuer, subject, role, claims)` (role- and condition-aware: the policy comes from the mapping that authorized the role), `IssuerSessionTags(issuer)`, `Validate()` (compiles anchored regex once, builds the index).
  _Go here when_ adding config keys, constraint logic, or remote-refresh behavior.

- **`internal/cache/`** → [CLAUDE.md](internal/cache/CLAUDE.md) — multi-tier JWKS cache behind one `Cache` interface. `NewCache(cfg)` selects `memory` (LRU, default), `dynamodb` (persistent/shared, production), or `s3` (large/cold objects).
  _Go here when_ changing cache backends, TTL handling, or eviction.

- **`internal/aws/`** → [CLAUDE.md](internal/aws/CLAUDE.md) — STS/S3/IAM via AWS SDK v2 behind `AwsConsumerInterface`. `AssumeRole` takes the caller-resolved `sessionTags` (built by `BuildSessionTags(rawClaims, tagSpec)` from the issuer's `session_tags` spec) and attaches them as ABAC session tags; clients are built once in `service_wrapper.go`.
  _Go here when_ touching AssumeRole, session tagging, S3 reads, or IAM calls.

## Other folders (no CLAUDE.md of their own)

- `internal/utils/` — helpers; `RedactToken` is the redaction helper to use if a log site ever needs to carry token material. No current log site does — the pipeline keeps tokens out of logs entirely rather than logging them redacted (see `ParseRequestBody`, which deliberately logs no body preview), so `RedactToken` has no callers by design.

## Commands

- `make check` — fmt + lint + vuln + test. Run before every commit.
- `make test` / `make test-coverage` — tests / HTML coverage.
- `make run` — local server on :8080 with `example-config.yaml`.
- `make build-lambda` — all Lambda variants (ARM64). Binary must be named `bootstrap`.

## Conventions

- Follow effective-Go idioms; structured logging with `log/slog` (never `fmt.Print`).
- Use interfaces for testability (`AwsConsumerInterface`, `TokenValidatorInterface`); table-driven tests.
- Sentinel errors in `internal/handler/types.go`, mapped to HTTP status in the frontend adapters.
- Config precedence: env vars > YAML > defaults.
- Maintain a clean, up-to-date `CHANGELOG.md`.

## Security

- Never log full tokens/credentials — redact via `internal/utils`.
- Validate JWT signature, issuer, audience, expiration.
- Subject patterns and conditions are auto-anchored regex (`^(?:...)$`); keep patterns specific. A bare `.*`/`.+` is **rejected by `Validate()`** for both (shared `bareWildcards` guard) — the check is literal, so an equivalent pattern still compiles. Conditions are AND'd.
- Validate JSON and bound reads (`io.LimitReader`) before processing external input.
- Never commit credentials/secrets. Sign commits and tags. Do not add a Claude co-author.

## Git

Branch from `main` (`feature/…`, `fix/…`). Conventional Commits. PRs need passing CI (test, lint, security scan). Ask before editing `example-config.yaml` with real values, force-pushing, or changing CI workflows.
