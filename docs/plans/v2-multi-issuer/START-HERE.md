# v2 Multi-Issuer — Implementation Entry Point

This is the **entry file**. Read it, then drive the implementation group-by-group.

The work converts the service from single-GitHub-issuer to **multi-issuer, any-provider** OIDC validation, hardens it for production IAM brokering, makes the config scale to thousands of entries, and renames the surface to be provider-neutral. It is a **v2.0.0 breaking change**.

## How this is organized

- `SHARED.md` — invariants, naming, engineering standards, the final `Validate` flow. **Prepend this to every subagent prompt** (implementer and reviewer). It is the non-negotiable contract.
- `A..I`, `H` group files — one self-contained task set each, with its own security-review gate and verification slice.
- `PROGRESS.md` — the recovery ledger. Updated and committed every step. **Single source of truth for "where are we".**
- The full master plan (rationale, all findings V1–V11, threat model) lives at `~/.claude/plans/how-can-we-make-encapsulated-marble.md` — consult it for the "why" behind any decision.

## Execution model

- Implement with **Sonnet subagents**, one group per subagent. Hand each subagent **`SHARED.md` + its one group file only**. Subagents do not spawn further (max depth 2); they return to the orchestrator on any ambiguity rather than guessing.
- After each group: a **separate Sonnet review subagent** runs the security review (`/security-review` + `/review` on the group diff). Groups **B, C, D, I** get an adversarial pass. Fix findings before advancing.
- Every group must be `make check`-green **and** `go test -race`-green before its review and commit.

## Dependency DAG (order)

```
A (config)  ──►  B (validator)  ──►  C (crypto/time)
   │                 │
   ├──►  D (authz/index/rename) ──►  E (fragments)
   │                 └──────────────►  F (session-tags/plumbing) ──►  G (delegated)
   I (logging) — cross-cutting, built alongside A–G, reviewed after G
   H (docs/visual) — last, after the code surface is final
```
- A unblocks everything. Once A lands, **B and D can run in parallel**. C follows B. E follows D. F follows B+D. G follows B+F.

## Group files

| Group | File | Depends on |
| --- | --- | --- |
| A | `A-config-model.md` | — |
| B | `B-validator-core.md` | A |
| C | `C-crypto-time-hardening.md` | B |
| D | `D-authorization.md` | A (integrates B) |
| E | `E-config-distribution.md` | A, D |
| F | `F-session-tags-plumbing.md` | B, D |
| G | `G-delegated-modes.md` | B, F |
| I | `I-logging-observability.md` | cross-cutting |
| H | `H-docs.md` | all |

## How to start (fresh)

1. `git checkout -b feature/v2-multi-issuer` (from `main`).
2. **Checkpoint 0:** commit these plan files + `PROGRESS.md` (`docs(plan): v2 multi-issuer split plan`).
3. Open `PROGRESS.md`, find `NEXT:` (initially Group A).
4. Spawn a Sonnet implementer with `SHARED.md` + `A-config-model.md`. TDD: tests first.
5. `make check` + `go test -race` green → spawn a Sonnet reviewer (SHARED + group file + the diff) → fix findings.
6. Commit the group (Conventional Commit). Update `PROGRESS.md` (status `done` + SHA, set new `NEXT:`). Commit `PROGRESS.md`.
7. Repeat down the DAG.

## How to RECOVER / CONTINUE (after a session reset or timeout)

Do this exactly:
1. `cd` into the repo; `git status`.
   - Uncommitted changes? Inspect them. If they're a coherent partial group, either finish it or `git stash` to inspect the last clean state.
   - Look for a `wip(group X):` commit at HEAD — that's an interrupted group; continue/amend it.
2. `git log --oneline -15` — find the last `feat/fix(group …)` commit.
3. Open `PROGRESS.md`:
   - Trust rows marked `done` whose recorded SHA exists in `git log`. **Do not redo them.**
   - Read the `NEXT:` line — that is exactly where to resume.
4. `make check && go test -race ./...` to confirm the checkpoint is green before continuing.
5. Resume at `NEXT:`: hand a Sonnet subagent `SHARED.md` + that group's file. Re-read the group file fresh (it is self-contained).
6. After completing it, update `PROGRESS.md` (`done` + SHA, advance `NEXT:`) and commit.

**Invariant for recovery:** `PROGRESS.md` + `git log` are authoritative. Never assume in-memory state survived. If `PROGRESS.md` and `git log` disagree, trust `git log` and reconcile `PROGRESS.md`.

## Hard rules (from repo + user CLAUDE.md)

- Every commit `make check`-green; Conventional Commits; **no Claude co-author / "generated with" trailer**.
- Do not push or open a PR until the user asks. Ask before editing `example-config.yaml` with real values or changing CI.
- Fail-closed everywhere; never log raw tokens/credentials.
