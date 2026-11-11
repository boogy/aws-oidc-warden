# AWS OIDC Warden

Go service that validates OIDC tokens (e.g. GitHub Actions) and exchanges them for short-lived AWS credentials via STS AssumeRole. Runs as a Lambda behind multiple front-ends, or as a local HTTP server.

Request flow: multi-issuer token validation → canonical-subject authorization (issuer-bound) → condition checking → session policy → role assumption (`internal/handler/processor.go`).

This file is the map. Each package has a short `CLAUDE.md`: where things are, plus the rules code cannot state. Read the code and tests for everything else.

Keep every `CLAUDE.md` under about 40 lines. Add a line only for a rule a reader cannot get from the code or a test name; put explanation in `docs/` and history in `CHANGELOG.md`.

## Packages

- `internal/handler/` → [CLAUDE.md](internal/handler/CLAUDE.md) — request pipeline, front-end adapters, error → HTTP mapping, audit.
- `internal/validator/` → [CLAUDE.md](internal/validator/CLAUDE.md) — JWT/JWKS verification, claims extractors (`self`/`apigw`/`alb`).
- `internal/config/` → [CLAUDE.md](internal/config/CLAUDE.md) — config loading, `Validate()`, subject/condition matching, tag-auth, hot reload.
- `internal/cache/` → [CLAUDE.md](internal/cache/CLAUDE.md) — JWKS cache backends (`memory`/`dynamodb`/`s3`).
- `internal/aws/` → [CLAUDE.md](internal/aws/CLAUDE.md) — STS/S3/IAM calls, session tags, cross-account.
- `internal/idp/` → [CLAUDE.md](internal/idp/CLAUDE.md) — warden-as-IdP signer, mint, JWKS/discovery; operator guide `docs/IDP.md`.
- `internal/utils/` — helpers. `FormatClaimValue` is the single formatter for a claim value going to an audit record or session tag. `RedactToken` has no callers by design: tokens stay out of logs entirely.

No infrastructure-as-code in this repo; the contract an operator's IaC must meet is in `docs/ARCHITECTURE.md`. Don't add IaC back.

## Commands

- `make check` — fmt + lint + vuln + test. Run before every commit.
- `make test` / `make test-coverage` — tests / HTML coverage.
- `make run` — local server on 127.0.0.1:8080 with `docs/examples/example-config.yaml`.
- `make build-lambda` — all Lambda variants (ARM64). Binary must be named `bootstrap`.

## Conventions

- Follow effective-Go idioms; log through `internal/logevent` with a catalog event (static `msg`, camelCase `slog.Attr` attrs) — never `log/slog` directly or `fmt.Print`. A new event needs a `docs/LOGGING.md` catalog row.
- Comments are short and rare: one line, only for a constraint the code cannot state itself. No paragraphs, no narration of what the code does, no rationale essays — that belongs in `CHANGELOG.md`, the PR, or `docs/`. Trim over-long comments in any file you touch.
- Use interfaces for testability (`AwsConsumerInterface`, `TokenValidatorInterface`); table-driven tests.
- Sentinel errors in `internal/handler/types.go`, mapped to HTTP status by `classifyError` (`internal/handler/errors.go`).
- Config precedence: env vars > YAML > defaults.
- Maintain a clean, up-to-date `CHANGELOG.md`: one phrase per entry, at most two or three sentences for complex topics; detail goes in `docs/`.

## Testing

A test exists only if it guards a security invariant, a documented contract, or a fixed regression. Before adding one, name the bug it would catch.

- No tests of getters, defaults, constructors, mocks, or the standard library. No always-skipped tests.
- Table-driven by default; a near-duplicate test is a new table row.
- No `time.Sleep`: inject a clock (`config.WithClock`) or use `testing/synctest`.
- Prove a new test: break the code it guards and confirm it fails, then restore.
- Untrusted-input parsers and security gates get a `Fuzz*` target with a property (differential oracle or invariant), not just "no panic". Commit fuzz-found inputs under `testdata/fuzz/` as regressions. `make fuzz FUZZTIME=…`.
- `make test` runs with `-race`.

## Security

- Never log full tokens/credentials — redact via `internal/utils`.
- Validate JWT signature, issuer, audience, expiration.
- Subject patterns and conditions are auto-anchored regex (`^(?:...)$`); keep patterns specific. A pattern that provably matches every string (`.*`, `.+`, `(?s).*`, `[\s\S]*`, `(.*)`, `^.*$`, `a|.*`) is **rejected by `Validate()`** for both (shared `isUniversal` parse-tree check); it is sound for what it accepts, not complete, so keep patterns specific anyway. Conditions at the same level are AND'd; `all_of`/`any_of`/`none_of` groups nest inside for richer logic (capped at 5 levels / 64 nodes, enforced in `Validate()`).
- Validate JSON and bound reads (`io.LimitReader`) before processing external input.
- Never commit credentials/secrets. Sign commits and tags. Do not add a Claude co-author.

## Git

Branch from `main` (`feature/…`, `fix/…`). Conventional Commits. PRs need passing CI (test, lint, security scan). Ask before editing `docs/examples/example-config.yaml` with real values, force-pushing, or changing CI workflows.
