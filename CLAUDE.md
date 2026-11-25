# AWS OIDC Warden

Go service that validates OIDC tokens (e.g. GitHub Actions) and exchanges them for short-lived AWS credentials via STS. Runs as a Lambda behind multiple front-ends, or as a local HTTP server.

Request flow: multi-issuer token validation → canonical-subject authorization (issuer-bound) → condition checking → session policy → role assumption (`internal/handler/processor.go`).

This file is the map; each package `CLAUDE.md` holds rules code cannot state. Keep every `CLAUDE.md` short (root about 60 lines, package files about 40): explanation goes in `docs/`, history in `CHANGELOG.md`.

## Packages

- `internal/handler/` → [CLAUDE.md](internal/handler/CLAUDE.md) — request pipeline, front-end adapters, error → HTTP mapping, audit.
- `internal/validator/` → [CLAUDE.md](internal/validator/CLAUDE.md) — JWT/JWKS verification, claims extractors (`self`/`apigw`/`alb`).
- `internal/config/` → [CLAUDE.md](internal/config/CLAUDE.md) — config loading, `Validate()`, subject/condition matching, tag-auth, hot reload.
- `internal/cache/` → [CLAUDE.md](internal/cache/CLAUDE.md) — JWKS cache backends (`memory`/`dynamodb`/`s3`).
- `internal/aws/` → [CLAUDE.md](internal/aws/CLAUDE.md) — STS/S3/IAM calls, session tags, cross-account.
- `internal/idp/` → [CLAUDE.md](internal/idp/CLAUDE.md) — warden-as-IdP signer, mint, JWKS/discovery; operator guide `docs/IDP.md`.
- `internal/utils/` — `FormatClaimValue` is the single formatter for claim values in audit records and session tags. `RedactToken` has no callers by design.

No IaC in this repo; the contract an operator's IaC must meet is in `docs/ARCHITECTURE.md`.

## Commands

`make check` (fmt + lint + vuln + `-race` test) before every commit · `make run` (local server, example config) · `make build-lambda` (ARM64, binary `bootstrap`) · `make fuzz FUZZTIME=…`.

## Conventions

- Log through `internal/logevent` with a catalog event (static `msg`, camelCase attrs), never `log/slog` or `fmt.Print`; a new event needs a `docs/LOGGING.md` row.
- Comments: one line, rare, only for a constraint the code cannot state. Trim over-long comments in files you touch.
- Sentinel errors in `internal/handler/types.go`, mapped to HTTP status by `classifyError`. Config precedence: env > YAML > defaults.
- `CHANGELOG.md`: one phrase per entry, two or three sentences max.

## Testing

- A test must guard a security invariant, documented contract, or fixed regression; prove it by breaking the guarded code. Table-driven; a near-duplicate is a new row.
- No `time.Sleep`: inject a clock (`config.WithClock`) or use `testing/synctest`.
- Untrusted-input parsers and security gates get a `Fuzz*` target with a property, not just "no panic"; commit found inputs under `testdata/fuzz/`.

## Security

- Never log tokens or credentials. Validate JWT signature, issuer, audience, expiration. Bound external reads (`io.LimitReader`).
- Subject and condition patterns are auto-anchored; `Validate()` rejects universal patterns (`isUniversal`) and caps condition trees at 5 levels / 64 nodes. Keep patterns specific.
- Never commit secrets. Sign commits and tags. No Claude co-author.

## Git

Branch from `main` (`feature/…`, `fix/…`), Conventional Commits. Ask before editing `docs/examples/example-config.yaml` with real values, force-pushing, or changing CI workflows.
