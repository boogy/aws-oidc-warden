---
name: fix-issue
description: Use when asked to analyze and fix a GitHub issue in this repo. Takes the issue number as argument.
---

# Fix Issue

Issue-to-PR workflow. `<N>` is the issue number passed as argument.

## Workflow

### 1. Understand

```bash
gh issue view <N>
```

Expected vs actual behavior, repro steps, affected components.

### 2. Read the package CLAUDE.md

Each `internal/<pkg>/CLAUDE.md` maps its package — read the one for the area being touched before changing it.

### 3. Implement

Follow codebase patterns: interfaces for testability, explicit error handling, `internal/logevent` catalog events (a new event needs a `docs/LOGGING.md` row), pre-compiled regex, validated and size-bounded external input. New sentinel errors go in `internal/handler/types.go` and are mapped to HTTP status in `classifyError` (`internal/handler/errors.go`).

### 4. Test

Add cases to the existing table-driven tests; cover edge cases.

### 5. Verify

```bash
make check          # fmt + lint + vuln + test — must pass
```

### 6. Commit

Conventional Commits, signed, no co-author:

```
fix: <brief description>

Fixes #<N>
```

### 7. PR (if requested)

```bash
gh pr create --title "fix: <description>" --body "Fixes #<N>"
```
