# PROGRESS — v2 Multi-Issuer (recovery ledger)

**This file + `git log` are the authoritative source of truth for where the implementation is.**
If they disagree, trust `git log` and reconcile this file.

## Recovery procedure (read first after any session reset)

1. `git status` — inspect/`git stash` uncommitted WIP; a `wip(group X):` HEAD commit = interrupted group, continue/amend it.
2. `git log --oneline -15` — find the last `feat/fix(group …)` commit.
3. Trust rows below marked `done` whose SHA exists in `git log`. **Never redo them.**
4. `make check && go test -race ./...` to confirm the checkpoint is green.
5. Resume at **NEXT** — hand a Sonnet subagent `SHARED.md` + that group's file (re-read it fresh; it's self-contained).
6. On completion: update this file (`done` + SHA, advance NEXT) and commit it.

## Branch

`feature/v2-multi-issuer` (from `main`).

## NEXT

**NEXT: Groups B and D (parallel)** — B (validator core) and D (authorization) both depend only on A, which is done. Run concurrently.

## Status ledger

| Group | Status | Commit SHA | Notes |
| --- | --- | --- | --- |
| Checkpoint 0 (plan files) | n/a | — | docs/plans/ is git-ignored (user decision); recovery via git log + this local ledger |
| A — config model & schema | done | 19d6412 | issuers[] + hardening knobs + fail-closed Validate; review A APPROVE (no findings) |
| B — validator multi-issuer core | in-progress | — | after A (parallel with D) |
| C — crypto/time hardening | todo | — | after B |
| D — authorization (rename/index/issuer-bind) | in-progress | — | after A (integrates B) |
| E — config distribution (fragments) | todo | — | after A, D |
| F — session tags & plumbing | todo | — | after B, D |
| G — delegated modes | todo | — | after B, F |
| I — logging/audit/observability | todo | — | cross-cutting; review after G |
| H — docs/visual | todo | — | last |
| Final full-surface security review | todo | — | before tagging v2.0.0 |

## Per-group definition of done

- `make check` green **and** `go test -race ./...` green.
- Group's security-review gate passed (adversarial for B/C/D/I); findings fixed.
- Conventional Commit made; this ledger updated + committed.

## Decision log (deviations from the plan during implementation)

_Record any approved deviation here with date + reason so recovery sessions don't re-litigate it._

- 2026-07-01: docs/plans/ is git-ignored (user decision) — Checkpoint 0 plan-file commit skipped; recovery via git log + this local ledger.
- 2026-07-01: Intermediate commits during the A→B→D hard-cutover are not repo-wide `make check`-green (breaking type/field removals ripple into consumers fixed by later groups). Each group's OWN packages are green (-race). Repo-wide green is restored once D (and F) land the consumer updates. Consistent with plan's accepted cutover behavior.
- 2026-07-01: **Group A review carry-forward (non-blocking lows) → fold into Group D (edits config.go/Validate):** (1) reject empty-string audience elements (`audiences: [""]` currently passes the len>0 check, config.go:~552); (2) document that `jwt_leeway: 0` / `max_token_bytes: 0` mean "use default", not "disable" (example-config.yaml / Group H). Info: JWKS/issuer scheme enforcement (allow_insecure_issuers) is Group C — already tracked.
- 2026-07-01: **Group B constructor decision:** single validator constructor is `NewTokenValidator(provider *config.Provider, jwksCache cache.Cache)` (no `NewTokenValidatorFromProvider`). Registry rebuilds via `builtFrom atomic.Pointer[config.Config]` identity check on hot-reload. leeway/maxLifetime/maxAge/maxTokenBytes captured once at construction, NOT hot-reloaded (only the issuer registry is) — Group C: confirm this is acceptable for the hardening knobs.
- 2026-07-01: **Group B adversarial review (by orchestrator): APPROVE, no must-fix defects.** Forward-notes:
  - **D/F:** downstream authz/session-tags MUST read `types.Claims.Subject` (canonical identity), NOT `types.Claims.Sub` (the raw `sub` claim, a separate depth-0 field). `.Raw` holds all verified claims for condition/session-tag lookup by provider-native name.
  - **C MUST wire (not yet enforced in Validate):** (a) `t.maxLifetime`/`t.maxAge` fields exist but are unused → no lifetime/age cap currently; (b) `use=sig` + explicit alg↔key-type pin (S3); (c) SSRF-hardened ctx-bound http client + block private/link-local/metadata on discovery/JWKS incl. redirects (S7) — `discoverJWKSURI`/`getJWKS` currently use plain `httpc.Get`, redirect-following, no ctx; (d) discovery `issuer`==configured validation (S8); (e) **DoS: `Validate` force-refetches JWKS on ANY `ErrKeyNotFound`** (validator.go:259) — random bogus kids hammer the issuer; add the per-(issuer,kid) cooldown limiter (C4/V9); (f) `sub` non-empty + `nbf` required.
- 2026-07-01: **Repo-green window:** handler won't compile until wiring is fixed — `bootstrap.go` (validator construction via `NewTokenValidator(provider,...)` + `newClaimsExtractor` reading `cfg.Issuers`), `cmd/local/main.go:61` (pass a `*config.Provider`, not `*config.Config`), `internal/aws/consumer_test.go:451` + `internal/aws/CLAUDE.md:10` (types.Claims). D fixes config-authz callers in processor.go + what it can in handler; the validator/bootstrap wiring + aws is finished in F. **Repo-wide `make check` green target: after F.**
