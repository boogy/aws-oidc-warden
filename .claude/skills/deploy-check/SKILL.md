---
name: deploy-check
description: Use when changes touch deploy/ — OpenTofu modules, CloudFormation quickstart, tfvars example, or deploy README — before committing or opening a PR.
---

# Deploy Check

Validate `deploy/` changes: OpenTofu fmt/validate/test, CloudFormation lint, docs sync.

## Scope

```bash
git diff --name-only main... -- deploy/
```

## Steps

### 1. OpenTofu (`deploy/opentofu/`)

```bash
cd deploy/opentofu
tofu fmt -check -recursive          # fix with: tofu fmt -recursive
[ -d .terraform ] || tofu init -backend=false -input=false
tofu validate
```

### 2. OpenTofu tests

`tofu test` (runs `hardening.tftest.hcl`) requires the Lambda zip — a
`fileexists(var.zip_path)` precondition fails otherwise:

```bash
[ -f dist/function.zip ] || ./build.sh
tofu test
```

Expect all runs to pass, none skipped.

### 3. CloudFormation (`deploy/cloudformation/`)

```bash
uvx cfn-lint deploy/cloudformation/quickstart.yaml
```

Watch for E2001: parameter logical IDs must be alphanumeric (no underscores).

### 4. Docs sync

- `deploy/README.md` updated to reflect the change (deploy changes are
  documented there, **not** in `CHANGELOG.md`).
- New/changed variables in `variables.tf` are reflected in
  `terraform.tfvars.example` and the README (incl. the hardening table).
- Module input/output changes are reflected in root `main.tf`/`outputs.tf`.

## Report

State pass/fail per step with failing output. Do not mark done with any
failing or skipped check.
