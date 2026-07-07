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

### 2. Locate

```bash
rg -n "<search term>" internal/
rg -n "func.*Handle" internal/handler/     # request pipeline
rg -n "Validate" internal/validator/       # token validation
rg -n "mapstructure:" internal/config/     # config keys
```

### 3. Read the package CLAUDE.md

Each `internal/<pkg>/CLAUDE.md` maps its package — read the one for the
area being touched before changing it.

### 4. Implement

Follow codebase patterns: interfaces for testability, explicit error
handling, `slog` structured logging, pre-compiled regex, validated and
size-bounded external input. New sentinel errors go in
`internal/handler/types.go` and must be mapped to HTTP status in every
frontend adapter (`apigateway.go`, `alb.go`, `lambdaurl.go`).

### 5. Test

Add cases to the existing table-driven tests; cover edge cases.

### 6. Verify

```bash
make check          # fmt + lint + vuln + test — must pass
```

If the fix touches `deploy/`, also run the deploy-check skill.

### 7. Commit

Conventional Commits, signed, no co-author:

```
fix: <brief description>

Fixes #<N>
```

### 8. PR (if requested)

```bash
gh pr create --title "fix: <description>" --body "Fixes #<N>"
```
