# AWS OIDC Warden

Go service that validates OIDC tokens (e.g. GitHub Actions) and exchanges them for short-lived AWS credentials via STS AssumeRole. Runs as a Lambda behind multiple front-ends, or as a local HTTP server.

Request flow: token validation → repository matching → constraint checking → session policy → role assumption (`internal/handler/processor.go`).

This file is the map. Each package below has its own `CLAUDE.md` with the detail — open the one for the area you're touching. The conventions, security, and git rules at the bottom are shared by all packages (each subdir file `Extends` this one).

## Package guide

- **`internal/handler/`** → [CLAUDE.md](internal/handler/CLAUDE.md) — core request pipeline shared by every deployment. `NewBootstrap()` wires DI (config, validator, cache, AWS consumer); `ProcessRequest()` runs the pipeline; `RequestData` + sentinel errors live in `types.go`; the per-frontend adapters (`apigateway.go` / `alb.go` / `lambdaurl.go`) differ only in event parse/serialize.
  _Go here when_ changing request flow, adding a frontend, or touching error→HTTP mapping.

- **`internal/validator/`** → [CLAUDE.md](internal/validator/CLAUDE.md) — JWT parse + JWKS signature/claims verification (`TokenValidatorInterface`). Allowed algorithms only (ES/RS 256–512, never `none`); verifies signature → issuer → audience → expiration → required claims; multi-audience handled in `Validate()`.
  _Go here when_ touching token verification, JWKS fetching, or audience handling.

- **`internal/config/`** → [CLAUDE.md](internal/config/CLAUDE.md) — Viper config (`AOW_` env prefix > file > defaults), repo/constraint matching, and the remote `Provider` (lazy refresh via injected `FetchFunc`, atomic swap from a pristine base). Key methods: `MatchRolesToRepoWithConstraints`, `FindSessionPolicyForRepo`, `Validate()` (compiles anchored regex once).
  _Go here when_ adding config keys, constraint logic, or remote-refresh behavior.

- **`internal/cache/`** → [CLAUDE.md](internal/cache/CLAUDE.md) — multi-tier JWKS cache behind one `Cache` interface. `NewCache(cfg)` selects `memory` (LRU, default), `dynamodb` (persistent/shared, production), or `s3` (large/cold objects).
  _Go here when_ changing cache backends, TTL handling, or eviction.

- **`internal/aws/`** → [CLAUDE.md](internal/aws/CLAUDE.md) — STS/S3/IAM via AWS SDK v2 behind `AwsConsumerInterface`. `AssumeRole` attaches ABAC session tags from `CreateSessionTags(claims)`; clients are built once in `service_wrapper.go`.
  _Go here when_ touching AssumeRole, session tagging, S3 reads, or IAM calls.

## Other folders (no CLAUDE.md of their own)

- `cmd/` — entry points, one per deployment: `apigateway/`, `alb/`, `lambdaurl/`, `local/`. All share core logic via `internal/handler`.
- `internal/types/` — shared structs: claims, JWKS, credentials, request/response types.
- `internal/utils/` — helpers; token/credential redaction (`RedactToken`) used before logging.
- `internal/s3logger/` — buffered S3 audit logging, flushed on `bootstrap.Cleanup()`.
- `internal/version/` — build/version metadata.
- `docs/` — `ARCHITECTURE.md`, `CONFIGURATION.md`, `SESSION_TAGGING.md`. `example-config.yaml` is the full config reference.

## Commands

- `make check` — fmt + lint + test. Run before every commit.
- `make test` / `make test-coverage` — tests / HTML coverage.
- `make run` — local server on :8080 with `example-config.yaml`.
- `make build-lambda` — all Lambda variants (ARM64). Binary must be named `bootstrap`.
- See `make help` for the full list (ko, release).

## Conventions

- Go 1.25+. Follow effective-Go idioms; structured logging with `log/slog` (never `fmt.Print`).
- Handle every error explicitly; defer-close all readers/connections.
- Use interfaces for testability (`AwsConsumerInterface`, `TokenValidatorInterface`); table-driven tests.
- Sentinel errors in `internal/handler/types.go`, mapped to HTTP status in the frontend adapters.
- Config precedence: env vars > YAML > defaults.
- Maintain a clean, up-to-date `CHANGELOG.md`.

## Security

- Never log full tokens/credentials — redact via `internal/utils`.
- Validate JWT signature, issuer, audience, expiration.
- Repo constraint regex is auto-anchored `^(?:...)$`; keep patterns specific, never `.*`. All constraints are AND.
- Validate JSON and bound reads (`io.LimitReader`) before processing external input.
- Never commit credentials/secrets. Sign commits and tags. Do not add a Claude co-author.

## Git

Branch from `main` (`feature/…`, `fix/…`). Conventional Commits. PRs need passing CI (test, lint, security scan). Ask before editing `example-config.yaml` with real values, force-pushing, or changing CI workflows.
