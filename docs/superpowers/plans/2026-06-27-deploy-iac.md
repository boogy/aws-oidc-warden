# AWS OIDC Warden — Infrastructure as Code Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
> **Canonical copy:** after approval, also save this file to `docs/superpowers/plans/2026-06-27-deploy-iac.md` in the repo.

**Goal:** Provide reusable OpenTofu modules (driven entirely by a `.tfvars` file) plus a single quick-start CloudFormation template that deploy AWS OIDC Warden as an API Gateway-fronted Lambda with optional DynamoDB cache, S3 buckets, IAM, and logging.

**Architecture:** A root OpenTofu module composes generic child modules (`s3`, `dynamodb`, `iam`, `lambda`, `apigateway`). The Lambda runs the `apigateway` handler as a Zip package on the `provided.al2023` runtime (ARM64). Application configuration — including `repo_role_mappings`, `audiences`, cache/tag-auth settings, and `jwt_validation.mode` — is rendered from tfvars into a `config.yaml`, uploaded to an S3 config bucket, and fetched by the Lambda at startup via `AOW_S3_CONFIG_BUCKET`/`AOW_S3_CONFIG_PATH`. Every optional AWS resource is gated by a boolean toggle so the modules stay generic. A standalone CloudFormation YAML offers a faster, less-configurable one-shot deploy (Lambda code supplied from an existing S3 object since CloudFormation cannot build Go). A `var.jwt_validation_mode` toggle (`"self"` / `"apigw"` / `"alb"`) controls whether the API Gateway module provisions a native JWT Authorizer (`aws_apigatewayv2_authorizer`) and whether the Lambda uses the `cmd/apigateway` (payload format 1.0) or `cmd/apigatewayv2` (payload format 2.0) binary variant.

**Tech Stack:** OpenTofu/Terraform ≥1.6 (HCL), AWS provider `hashicorp/aws` ~>5.x, AWS Lambda `provided.al2023` (ARM64), API Gateway v2 (HTTP API), DynamoDB, S3, IAM, CloudWatch Logs, CloudFormation. The deployment zip is built by `build.sh` with the `zip` CLI (preserves the `bootstrap` exec bit — `archive_file` does **not** and would cause `permission denied` at cold start).

**Repo-state caveat (read first):** the Go source lives under `internal/` (not `pkg/`), and the working tree currently has uncommitted mid-refactor changes. None of the IaC references Go package paths, so this does not affect the modules — but build via `make build-apigateway` from a clean, building checkout. Confirm `go build ./cmd/apigateway` succeeds before packaging.

## Global Constraints

- **Deploy code root:** `deploy/opentofu/` (root + `modules/`), `deploy/cloudformation/` (template), `deploy/README.md` (docs). Nothing under `pkg/`, `cmd/`, or CI workflows is modified.
- **Lambda binary name:** `bootstrap` (custom-runtime requirement). The Makefile produces `build/bootstrap-apigateway`; packaging must rename it to `bootstrap` inside the zip.
- **Runtime / arch:** `provided.al2023`, architecture `arm64` (matches `make build-apigateway` defaults `GOOS=linux GOARCH=arm64`).
- **Handler entrypoint:** `cmd/apigateway` (self/alb modes, payload format `1.0`) or `cmd/apigatewayv2` (apigw mode, payload format `2.0`). Controlled by `var.jwt_validation_mode`. The `apigatewayv2` binary is implemented in the delegated-JWT-validation feature plan (`docs/superpowers/plans/2026-06-28-delegated-jwt-validation.md`) and must exist in the repo before building the zip for `apigw` mode.
- **Config env contract (verbatim names):** prefix `AOW_`; nested keys use `_` (`cache.ttl` → `AOW_CACHE_TTL`). The Lambda reads its full config from S3 via `AOW_S3_CONFIG_BUCKET` + `AOW_S3_CONFIG_PATH`; `LOG_LEVEL` (no prefix) sets log level.
- **DynamoDB cache schema (verbatim):** partition key `Key` (type `S`), TTL attribute `TTL` (Number, Unix seconds). Other attributes (`Value`, `Expiration`, `CreatedAt`, `Size`) are written by the app and need no schema declaration. Billing default `PAY_PER_REQUEST`.
- **API route (verbatim):** `POST /verify`; health endpoint `GET /health` exists in code but is not required by API Gateway (only `/verify` is wired). The Lambda itself validates OIDC — API Gateway uses no authorizer.
- **No secrets in code.** Do not put real role ARNs or account IDs in committed `.tf`/`.yaml`; only in `terraform.tfvars.example` use placeholders like `arn:aws:iam::111122223333:role/example`.
- **Naming:** all resources derive names from `var.name_prefix` (default `aws-oidc-warden`). Tag every resource with `var.tags` merged with `{ "app" = var.name_prefix }`.
- **Validation gate per task:** `tofu fmt -recursive` then `tofu init -backend=false && tofu validate` must pass in the task's directory. If `tofu` is unavailable, `terraform` is an accepted substitute (identical HCL).

---

## File Structure

```
deploy/
├── README.md                              # Task 9 — usage docs
├── opentofu/
│   ├── versions.tf                        # Task 1 — required_providers, backend stub
│   ├── providers.tf                       # Task 1 — aws provider (region from var)
│   ├── variables.tf                       # Task 1 (skeleton) → Task 7 (full)
│   ├── main.tf                            # Task 7 — module wiring + config.yaml render
│   ├── outputs.tf                         # Task 1 (skeleton) → Task 7 (full)
│   ├── build.sh                           # Task 5 — builds dist/bootstrap via make
│   ├── terraform.tfvars.example           # Task 7 — fully-commented example
│   ├── .gitignore                         # Task 1 — ignore state, .terraform, dist/
│   └── modules/
│       ├── s3/{main,variables,outputs}.tf       # Task 2 — generic bucket
│       ├── dynamodb/{main,variables,outputs}.tf # Task 3 — cache table
│       ├── iam/{main,variables,outputs}.tf      # Task 4 — exec role + policies
│       ├── lambda/{main,variables,outputs}.tf   # Task 5 — function + log group + zip
│       └── apigateway/{main,variables,outputs}.tf # Task 6 — HTTP API + route
└── cloudformation/
    └── quickstart.yaml                    # Task 8 — single-file deploy
```

Each child module owns one responsibility and exposes a small typed interface. The root module is the only place that knows how the pieces connect; toggles live there.

---

### Task 1: Scaffold OpenTofu root

**Files:**

- Create: `deploy/opentofu/versions.tf`
- Create: `deploy/opentofu/providers.tf`
- Create: `deploy/opentofu/variables.tf` (skeleton — core vars only; expanded in Task 7)
- Create: `deploy/opentofu/outputs.tf` (empty-safe skeleton)
- Create: `deploy/opentofu/.gitignore`

**Interfaces:**

- Produces: provider/version pins reused by every task; `var.name_prefix` (string, default `"aws-oidc-warden"`), `var.region` (string), `var.tags` (map(string), default `{}`) consumed by Tasks 2–7.

- [ ] **Step 1: Write `versions.tf`**

```hcl
terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
  }
  # archive_file is intentionally NOT used — it does not preserve the bootstrap
  # exec bit, which breaks the provided.al2023 runtime. build.sh zips instead.

  # Configure a remote backend per environment, e.g.:
  # backend "s3" { bucket = "..." key = "aws-oidc-warden/terraform.tfstate" region = "..." }
}
```

- [ ] **Step 2: Write `providers.tf`**

```hcl
provider "aws" {
  region = var.region

  default_tags {
    tags = merge({ app = var.name_prefix }, var.tags)
  }
}
```

- [ ] **Step 3: Write skeleton `variables.tf`**

```hcl
variable "region" {
  description = "AWS region to deploy into."
  type        = string
}

variable "name_prefix" {
  description = "Prefix for all resource names."
  type        = string
  default     = "aws-oidc-warden"
}

variable "tags" {
  description = "Additional tags applied to all resources."
  type        = map(string)
  default     = {}
}
```

- [ ] **Step 4: Write empty-safe `outputs.tf`**

```hcl
# Outputs are populated in Task 7 once modules are wired.
```

- [ ] **Step 5: Write `.gitignore`**

```gitignore
.terraform/
.terraform.lock.hcl
*.tfstate
*.tfstate.*
*.tfvars
!*.tfvars.example
dist/
```

- [ ] **Step 6: Validate**

Run: `cd deploy/opentofu && tofu fmt -recursive && tofu init -backend=false && tofu validate`
Expected: `Success! The configuration is valid.`

- [ ] **Step 7: Commit**

```bash
git add deploy/opentofu/versions.tf deploy/opentofu/providers.tf deploy/opentofu/variables.tf deploy/opentofu/outputs.tf deploy/opentofu/.gitignore
git commit -m "feat(deploy): scaffold opentofu root for aws-oidc-warden"
```

---

### Task 2: Generic S3 bucket module

**Files:**

- Create: `deploy/opentofu/modules/s3/variables.tf`
- Create: `deploy/opentofu/modules/s3/main.tf`
- Create: `deploy/opentofu/modules/s3/outputs.tf`

**Interfaces:**

- Consumes: nothing from other modules.
- Produces: `module.<x>.bucket_id` (string), `module.<x>.bucket_arn` (string). Inputs: `bucket_name` (string), `force_destroy` (bool, default false), `versioning_enabled` (bool, default false), `lifecycle_expiration_days` (number, default 0 = disabled), `tags` (map(string), default {}).

- [ ] **Step 1: Write `variables.tf`**

```hcl
variable "bucket_name" {
  description = "Globally-unique S3 bucket name."
  type        = string
}

variable "force_destroy" {
  description = "Allow deletion of a non-empty bucket."
  type        = bool
  default     = false
}

variable "versioning_enabled" {
  description = "Enable object versioning."
  type        = bool
  default     = false
}

variable "lifecycle_expiration_days" {
  description = "Expire objects after N days. 0 disables the rule."
  type        = number
  default     = 0
}

variable "tags" {
  description = "Tags applied to the bucket."
  type        = map(string)
  default     = {}
}
```

- [ ] **Step 2: Write `main.tf`**

```hcl
resource "aws_s3_bucket" "this" {
  bucket        = var.bucket_name
  force_destroy = var.force_destroy
  tags          = var.tags
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id

  versioning_configuration {
    status = var.versioning_enabled ? "Enabled" : "Suspended"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  count  = var.lifecycle_expiration_days > 0 ? 1 : 0
  bucket = aws_s3_bucket.this.id

  rule {
    id     = "expire-objects"
    status = "Enabled"

    filter {}

    expiration {
      days = var.lifecycle_expiration_days
    }
  }
}
```

- [ ] **Step 3: Write `outputs.tf`**

```hcl
output "bucket_id" {
  description = "Bucket name."
  value       = aws_s3_bucket.this.id
}

output "bucket_arn" {
  description = "Bucket ARN."
  value       = aws_s3_bucket.this.arn
}
```

- [ ] **Step 4: Validate**

Run: `cd deploy/opentofu/modules/s3 && tofu fmt && tofu init -backend=false && tofu validate`
Expected: `Success! The configuration is valid.`

- [ ] **Step 5: Commit**

```bash
git add deploy/opentofu/modules/s3
git commit -m "feat(deploy): generic reusable s3 bucket module"
```

---

### Task 3: DynamoDB cache module

**Files:**

- Create: `deploy/opentofu/modules/dynamodb/variables.tf`
- Create: `deploy/opentofu/modules/dynamodb/main.tf`
- Create: `deploy/opentofu/modules/dynamodb/outputs.tf`

**Interfaces:**

- Consumes: nothing.
- Produces: `module.dynamodb.table_name` (string), `module.dynamodb.table_arn` (string). Inputs: `table_name` (string), `billing_mode` (string, default `"PAY_PER_REQUEST"`), `point_in_time_recovery` (bool, default false), `tags` (map(string), default {}). Hardcodes schema `Key`/`TTL` to match the app (do **not** parameterize key names).

- [ ] **Step 1: Write `variables.tf`**

```hcl
variable "table_name" {
  description = "DynamoDB table name for the JWKS cache."
  type        = string
}

variable "billing_mode" {
  description = "PAY_PER_REQUEST or PROVISIONED."
  type        = string
  default     = "PAY_PER_REQUEST"
}

variable "point_in_time_recovery" {
  description = "Enable point-in-time recovery."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags applied to the table."
  type        = map(string)
  default     = {}
}
```

- [ ] **Step 2: Write `main.tf`** (schema fixed to the app's contract: hash key `Key`, TTL attribute `TTL`)

```hcl
resource "aws_dynamodb_table" "cache" {
  name         = var.table_name
  billing_mode = var.billing_mode
  hash_key     = "Key"

  attribute {
    name = "Key"
    type = "S"
  }

  ttl {
    attribute_name = "TTL"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = var.point_in_time_recovery
  }

  tags = var.tags
}
```

- [ ] **Step 3: Write `outputs.tf`**

```hcl
output "table_name" {
  description = "Cache table name."
  value       = aws_dynamodb_table.cache.name
}

output "table_arn" {
  description = "Cache table ARN."
  value       = aws_dynamodb_table.cache.arn
}
```

- [ ] **Step 4: Validate**

Run: `cd deploy/opentofu/modules/dynamodb && tofu fmt && tofu init -backend=false && tofu validate`
Expected: `Success! The configuration is valid.`

- [ ] **Step 5: Commit**

```bash
git add deploy/opentofu/modules/dynamodb
git commit -m "feat(deploy): dynamodb jwks cache table module"
```

---

### Task 4: IAM execution role module

**Files:**

- Create: `deploy/opentofu/modules/iam/variables.tf`
- Create: `deploy/opentofu/modules/iam/main.tf`
- Create: `deploy/opentofu/modules/iam/outputs.tf`

**Interfaces:**

- Consumes: ARNs from Tasks 2 & 3 (cache table ARN, bucket ARNs) — all optional/nullable.
- Produces: `module.iam.role_arn` (string), `module.iam.role_name` (string). Inputs below; every resource ARN is nullable so unused features add no statements. Builds least-privilege inline policy with conditional statements.

Inputs:

- `name_prefix` (string)
- `assumable_role_arns` (list(string), default []) — targets of `sts:AssumeRole`; `[]` means none (degenerate but valid).
- `enable_iam_getrole` (bool, default false) — adds `iam:GetRole`/`iam:ListRoleTags` for tag-auth.
- `cache_dynamodb_table_arn` (string, default null)
- `cache_s3_bucket_arn` (string, default null)
- `config_bucket_arn` (string, default null) — grants `s3:GetObject` on `<arn>/*`.
- `session_policy_bucket_arn` (string, default null)
- `log_bucket_arn` (string, default null) — grants `s3:PutObject`.
- `tags` (map(string), default {})

- [ ] **Step 1: Write `variables.tf`**

```hcl
variable "name_prefix" {
  type        = string
  description = "Prefix for the role and policy names."
}

variable "assumable_role_arns" {
  type        = list(string)
  description = "Role ARNs the Lambda may assume (sts:AssumeRole/sts:TagSession)."
  default     = []
}

variable "enable_iam_getrole" {
  type        = bool
  description = "Grant iam:GetRole and iam:ListRoleTags for tag-based authorization."
  default     = false
}

variable "cache_dynamodb_table_arn" {
  type        = string
  description = "DynamoDB cache table ARN, or null."
  default     = null
}

variable "cache_s3_bucket_arn" {
  type        = string
  description = "S3 cache bucket ARN, or null."
  default     = null
}

variable "config_bucket_arn" {
  type        = string
  description = "S3 config bucket ARN, or null."
  default     = null
}

variable "session_policy_bucket_arn" {
  type        = string
  description = "S3 session-policy bucket ARN, or null."
  default     = null
}

variable "log_bucket_arn" {
  type        = string
  description = "S3 audit-log bucket ARN, or null."
  default     = null
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to IAM resources."
  default     = {}
}
```

- [ ] **Step 2: Write `main.tf`** (trust policy for Lambda + AWS-managed basic-execution + conditional inline policy via `dynamic` statements)

```hcl
data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  name               = "${var.name_prefix}-exec"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "basic" {
  role       = aws_iam_role.this.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "perms" {
  dynamic "statement" {
    for_each = length(var.assumable_role_arns) > 0 ? [1] : []
    content {
      sid       = "AssumeTargetRoles"
      actions   = ["sts:AssumeRole", "sts:TagSession"]
      resources = var.assumable_role_arns
    }
  }

  dynamic "statement" {
    for_each = var.enable_iam_getrole ? [1] : []
    content {
      sid       = "ReadRoleTags"
      actions   = ["iam:GetRole", "iam:ListRoleTags"]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = var.cache_dynamodb_table_arn != null ? [1] : []
    content {
      sid       = "CacheDynamoDB"
      actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"]
      resources = [var.cache_dynamodb_table_arn]
    }
  }

  dynamic "statement" {
    for_each = var.cache_s3_bucket_arn != null ? [1] : []
    content {
      sid       = "CacheS3"
      actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
      resources = [var.cache_s3_bucket_arn, "${var.cache_s3_bucket_arn}/*"]
    }
  }

  dynamic "statement" {
    for_each = var.config_bucket_arn != null ? [1] : []
    content {
      sid       = "ReadConfig"
      actions   = ["s3:GetObject"]
      resources = ["${var.config_bucket_arn}/*"]
    }
  }

  dynamic "statement" {
    for_each = var.session_policy_bucket_arn != null ? [1] : []
    content {
      sid       = "ReadSessionPolicies"
      actions   = ["s3:GetObject"]
      resources = ["${var.session_policy_bucket_arn}/*"]
    }
  }

  dynamic "statement" {
    for_each = var.log_bucket_arn != null ? [1] : []
    content {
      sid       = "WriteAuditLogs"
      actions   = ["s3:PutObject"]
      resources = ["${var.log_bucket_arn}/*"]
    }
  }
}

resource "aws_iam_role_policy" "this" {
  # Only attach when at least one statement exists.
  count  = length(data.aws_iam_policy_document.perms.statement) > 0 ? 1 : 0
  name   = "${var.name_prefix}-perms"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.perms.json
}
```

- [ ] **Step 3: Write `outputs.tf`**

```hcl
output "role_arn" {
  description = "Lambda execution role ARN."
  value       = aws_iam_role.this.arn
}

output "role_name" {
  description = "Lambda execution role name."
  value       = aws_iam_role.this.name
}
```

- [ ] **Step 4: Validate**

Run: `cd deploy/opentofu/modules/iam && tofu fmt && tofu init -backend=false && tofu validate`
Expected: `Success! The configuration is valid.`

- [ ] **Step 5: Commit**

```bash
git add deploy/opentofu/modules/iam
git commit -m "feat(deploy): least-privilege lambda iam role module"
```

---

### Task 5: Lambda module (Zip packaging + log group)

**Files:**

- Create: `deploy/opentofu/modules/lambda/variables.tf`
- Create: `deploy/opentofu/modules/lambda/main.tf`
- Create: `deploy/opentofu/modules/lambda/outputs.tf`
- Create: `deploy/opentofu/build.sh`

**Interfaces:**

- Consumes: `role_arn` from Task 4.
- Produces: `module.lambda.function_name` (string), `module.lambda.function_arn` (string), `module.lambda.invoke_arn` (string — for API Gateway integration in Task 6).
- Inputs: `function_name` (string), `role_arn` (string), `zip_path` (string — path to a prebuilt deployment zip containing an executable `bootstrap`), `architecture` (string, default `"arm64"`), `memory_size` (number, default 256), `timeout` (number, default 15), `environment_variables` (map(string), default {}), `log_retention_days` (number, default 14), `reserved_concurrency` (number, default -1 = unreserved), `tags` (map(string), default {}).

The module deploys a **prebuilt** zip (`var.zip_path`). `build.sh` produces it with the `zip` CLI so the `bootstrap` entry keeps its `0755` exec bit — `archive_file` would strip it and the runtime would fail with `fork/exec /var/task/bootstrap: permission denied`.

- [ ] **Step 1: Write `build.sh`** (builds the apigateway binary and zips it as `dist/function.zip` with the exec bit preserved)

```bash
#!/usr/bin/env bash
# Builds the Lambda binary and packages deploy/opentofu/dist/function.zip
# with the 'bootstrap' entry marked executable (required by provided.al2023).
#
# Usage: ./build.sh [apigateway|apigatewayv2]
#   apigateway   (default) — self/alb mode; payload format 1.0
#   apigatewayv2            — apigw mode (delegated JWT); payload format 2.0
#
# Run from anywhere; paths are resolved relative to this script.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DIST_DIR="${SCRIPT_DIR}/dist"
STAGE_DIR="${DIST_DIR}/stage"

VARIANT="${1:-apigateway}"
if [[ "${VARIANT}" != "apigateway" && "${VARIANT}" != "apigatewayv2" ]]; then
  echo "ERROR: unknown variant '${VARIANT}'. Use 'apigateway' or 'apigatewayv2'." >&2
  exit 1
fi

echo "Building ${VARIANT} Lambda binary (linux/arm64)..."
make -C "${REPO_ROOT}" build-${VARIANT}

rm -rf "${STAGE_DIR}"
mkdir -p "${STAGE_DIR}"
cp "${REPO_ROOT}/build/bootstrap-${VARIANT}" "${STAGE_DIR}/bootstrap"
chmod 755 "${STAGE_DIR}/bootstrap"

# zip from inside the stage dir so the archive contains 'bootstrap' at its root,
# with the executable bit retained (archive_file cannot do this).
( cd "${STAGE_DIR}" && zip -X -q "${DIST_DIR}/function.zip" bootstrap )
echo "Packaged ${DIST_DIR}/function.zip (variant: ${VARIANT})"
```

- [ ] **Step 2: `chmod +x` the script**

Run: `chmod +x deploy/opentofu/build.sh`

- [ ] **Step 3: Write `variables.tf`**

```hcl
variable "function_name" {
  type        = string
  description = "Lambda function name."
}

variable "role_arn" {
  type        = string
  description = "Execution role ARN."
}

variable "zip_path" {
  type        = string
  description = "Path to the prebuilt deployment zip (must contain an executable 'bootstrap')."
}

variable "architecture" {
  type        = string
  description = "Lambda architecture: arm64 or x86_64."
  default     = "arm64"
}

variable "memory_size" {
  type        = number
  description = "Memory (MB)."
  default     = 256
}

variable "timeout" {
  type        = number
  description = "Timeout (seconds)."
  default     = 15
}

variable "environment_variables" {
  type        = map(string)
  description = "Environment variables (AOW_* and LOG_LEVEL)."
  default     = {}
}

variable "log_retention_days" {
  type        = number
  description = "CloudWatch log retention (days)."
  default     = 14
}

variable "reserved_concurrency" {
  type        = number
  description = "Reserved concurrency; -1 leaves it unreserved."
  default     = -1
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to the function."
  default     = {}
}
```

- [ ] **Step 4: Write `main.tf`**

```hcl
resource "aws_cloudwatch_log_group" "this" {
  name              = "/aws/lambda/${var.function_name}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

resource "aws_lambda_function" "this" {
  function_name = var.function_name
  role          = var.role_arn
  runtime       = "provided.al2023"
  handler       = "bootstrap"
  architectures = [var.architecture]
  memory_size   = var.memory_size
  timeout       = var.timeout

  filename         = var.zip_path
  source_code_hash = filebase64sha256(var.zip_path)

  reserved_concurrent_executions = var.reserved_concurrency

  dynamic "environment" {
    for_each = length(var.environment_variables) > 0 ? [1] : []
    content {
      variables = var.environment_variables
    }
  }

  depends_on = [aws_cloudwatch_log_group.this]
  tags       = var.tags
}
```

- [ ] **Step 5: Write `outputs.tf`**

```hcl
output "function_name" {
  description = "Lambda function name."
  value       = aws_lambda_function.this.function_name
}

output "function_arn" {
  description = "Lambda function ARN."
  value       = aws_lambda_function.this.arn
}

output "invoke_arn" {
  description = "Lambda invoke ARN for API Gateway integration."
  value       = aws_lambda_function.this.invoke_arn
}
```

- [ ] **Step 6: Validate** (module validates without building — `filebase64sha256` is only evaluated at plan time, when `zip_path` is known)

Run: `cd deploy/opentofu/modules/lambda && tofu fmt && tofu init -backend=false && tofu validate`
Expected: validate prints `Success! The configuration is valid.`
Optional smoke-build of the package (needs Go + `make` + `zip`): `./deploy/opentofu/build.sh` → prints `Packaged .../dist/function.zip`. Then `unzip -l deploy/opentofu/dist/function.zip` should list `bootstrap`, and `unzip -Z deploy/opentofu/dist/function.zip bootstrap` should show mode `-rwxr-xr-x` (exec bit set).

- [ ] **Step 7: Commit**

```bash
git add deploy/opentofu/modules/lambda deploy/opentofu/build.sh
git commit -m "feat(deploy): lambda module with zip packaging and log group"
```

---

### Task 6: API Gateway (HTTP API) module

**Files:**

- Create: `deploy/opentofu/modules/apigateway/variables.tf`
- Create: `deploy/opentofu/modules/apigateway/main.tf`
- Create: `deploy/opentofu/modules/apigateway/outputs.tf`

**Interfaces:**

- Consumes: `invoke_arn` and `function_name` from Task 5.
- Produces: `module.apigateway.api_endpoint` (string — full HTTPS URL), `module.apigateway.api_id` (string).
- Inputs: `name` (string), `lambda_invoke_arn` (string), `lambda_function_name` (string), `route_key` (string, default `"POST /verify"`), `stage_name` (string, default `"$default"`), `throttling_burst_limit` (number, default 50), `throttling_rate_limit` (number, default 100), `payload_format_version` (string, default `"1.0"`), `enable_jwt_authorizer` (bool, default false), `jwt_authorizer_issuer` (string), `jwt_authorizer_audiences` (list(string)), `tags` (map(string), default {}).

- [ ] **Step 1: Write `variables.tf`**

```hcl
variable "name" {
  type        = string
  description = "API name."
}

variable "lambda_invoke_arn" {
  type        = string
  description = "Lambda invoke ARN."
}

variable "lambda_function_name" {
  type        = string
  description = "Lambda function name (for the invoke permission)."
}

variable "route_key" {
  type        = string
  description = "HTTP API route key."
  default     = "POST /verify"
}

variable "stage_name" {
  type        = string
  description = "Stage name."
  default     = "$default"
}

variable "throttling_burst_limit" {
  type        = number
  description = "Per-route burst limit."
  default     = 50
}

variable "throttling_rate_limit" {
  type        = number
  description = "Per-route steady-state rate limit."
  default     = 100
}

variable "payload_format_version" {
  type        = string
  description = "Lambda payload format version: '1.0' for cmd/apigateway, '2.0' for cmd/apigatewayv2."
  default     = "1.0"
}

variable "enable_jwt_authorizer" {
  type        = bool
  description = "Provision an API Gateway JWT Authorizer (jwt_validation_mode = 'apigw'). Requires payload_format_version = '2.0'."
  default     = false
}

variable "jwt_authorizer_issuer" {
  type        = string
  description = "OIDC issuer URL for the JWT Authorizer."
  default     = "https://token.actions.githubusercontent.com"
}

variable "jwt_authorizer_audiences" {
  type        = list(string)
  description = "Accepted audiences for the JWT Authorizer."
  default     = ["sts.amazonaws.com"]
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to API Gateway resources."
  default     = {}
}
```

- [ ] **Step 2: Write `main.tf`**

```hcl
resource "aws_apigatewayv2_api" "this" {
  name          = var.name
  protocol_type = "HTTP"
  tags          = var.tags
}

resource "aws_apigatewayv2_integration" "this" {
  api_id                 = aws_apigatewayv2_api.this.id
  integration_type       = "AWS_PROXY"
  integration_uri        = var.lambda_invoke_arn
  integration_method     = "POST"
  payload_format_version = var.payload_format_version
}

# JWT Authorizer: provisioned only when jwt_validation_mode = "apigw".
# API Gateway validates the JWT against the issuer JWKS before invoking Lambda;
# claims arrive in event.requestContext.authorizer.jwt.claims (format 2.0).
resource "aws_apigatewayv2_authorizer" "jwt" {
  count            = var.enable_jwt_authorizer ? 1 : 0
  api_id           = aws_apigatewayv2_api.this.id
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]
  name             = "${var.name}-jwt"

  jwt_configuration {
    audience = var.jwt_authorizer_audiences
    issuer   = var.jwt_authorizer_issuer
  }
}

resource "aws_apigatewayv2_route" "this" {
  api_id    = aws_apigatewayv2_api.this.id
  route_key = var.route_key
  target    = "integrations/${aws_apigatewayv2_integration.this.id}"

  # Attach JWT authorizer when provisioned; NONE otherwise (Lambda does self-validation).
  authorization_type = var.enable_jwt_authorizer ? "JWT" : "NONE"
  authorizer_id      = var.enable_jwt_authorizer ? aws_apigatewayv2_authorizer.jwt[0].id : null
}

resource "aws_apigatewayv2_stage" "this" {
  api_id      = aws_apigatewayv2_api.this.id
  name        = var.stage_name
  auto_deploy = true

  default_route_settings {
    throttling_burst_limit = var.throttling_burst_limit
    throttling_rate_limit  = var.throttling_rate_limit
  }

  tags = var.tags
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.this.execution_arn}/*/*"
}
```

> Note: `payload_format_version = "1.0"` is used with `cmd/apigateway` (self/alb modes). Set `"2.0"` when `jwt_validation_mode = "apigw"` to use `cmd/apigatewayv2` which expects `events.APIGatewayV2HTTPRequest`.

- [ ] **Step 3: Write `outputs.tf`**

```hcl
output "api_id" {
  description = "HTTP API ID."
  value       = aws_apigatewayv2_api.this.id
}

output "api_endpoint" {
  description = "Invoke URL for the verify route."
  value       = "${aws_apigatewayv2_stage.this.invoke_url}/verify"
}

output "jwt_authorizer_id" {
  description = "JWT Authorizer ID, or empty string when not provisioned."
  value       = var.enable_jwt_authorizer ? aws_apigatewayv2_authorizer.jwt[0].id : ""
}
```

- [ ] **Step 4: Validate**

Run: `cd deploy/opentofu/modules/apigateway && tofu fmt && tofu init -backend=false && tofu validate`
Expected: `Success! The configuration is valid.`

- [ ] **Step 5: Commit**

```bash
git add deploy/opentofu/modules/apigateway
git commit -m "feat(deploy): http api gateway module for verify route"
```

---

### Task 7: Root wiring, full variables, config render, tfvars example

**Files:**

- Modify: `deploy/opentofu/variables.tf` (append all feature variables)
- Create: `deploy/opentofu/main.tf`
- Modify: `deploy/opentofu/outputs.tf` (replace skeleton)
- Create: `deploy/opentofu/terraform.tfvars.example`

**Interfaces:**

- Consumes: all five child modules.
- Produces: root outputs `api_endpoint`, `lambda_function_name`, `execution_role_arn`, `config_bucket`, `cache_table_name`. Renders `config.yaml` from tfvars and uploads it to the config bucket; sets Lambda env to point at it.

- [ ] **Step 1: Append feature variables to `variables.tf`**

```hcl
# ---- Application config (rendered into config.yaml) ----
variable "issuer" {
  type        = string
  description = "OIDC issuer URL."
  default     = "https://token.actions.githubusercontent.com"
}

variable "audiences" {
  type        = list(string)
  description = "Accepted token audiences."
  default     = ["sts.amazonaws.com"]
}

variable "role_session_name" {
  type        = string
  description = "STS role session name."
  default     = "aws-oidc-warden"
}

variable "repo_role_mappings" {
  description = "Repository-to-role mappings (rendered verbatim into config.yaml)."
  type = list(object({
    repo                = string
    roles               = list(string)
    session_policy      = optional(string)
    session_policy_file = optional(string)
    constraints = optional(object({
      branch        = optional(string)
      ref           = optional(string)
      ref_type      = optional(string)
      event_name    = optional(string)
      workflow_ref  = optional(string)
      environment   = optional(string)
      actor_matches = optional(list(string))
    }))
  }))
  default = []
}

variable "tag_auth" {
  description = "Tag-based authorization settings. Set enabled=true to use."
  type = object({
    enabled                 = optional(bool, false)
    tag_prefix              = optional(string, "aow/")
    default_org             = optional(string)
    spoke_role_name         = optional(string, "aow-spoke")
    external_id             = optional(string)
    spoke_session_duration  = optional(string, "15m")
    transitive_session_tags = optional(bool, false)
    allowed_accounts        = optional(list(string), [])
  })
  default = { enabled = false }
}

# ---- Lambda sizing ----
variable "lambda_memory_size" {
  type        = number
  default     = 256
}

variable "lambda_timeout" {
  type        = number
  default     = 15
}

variable "lambda_architecture" {
  type        = string
  default     = "arm64"
}

variable "log_retention_days" {
  type        = number
  default     = 14
}

variable "log_level" {
  type        = string
  description = "Lambda LOG_LEVEL (debug/info/warn/error)."
  default     = "info"
}

# ---- Feature toggles ----
variable "enable_dynamodb_cache" {
  type        = bool
  description = "Provision a DynamoDB JWKS cache and set cache.type=dynamodb."
  default     = false
}

variable "enable_s3_cache" {
  type        = bool
  description = "Provision an S3 JWKS cache and set cache.type=s3."
  default     = false
}

variable "cache_ttl" {
  type        = string
  description = "JWKS cache TTL."
  default     = "1h"
}

variable "enable_s3_logs" {
  type        = bool
  description = "Provision an audit-log bucket and enable log_to_s3."
  default     = false
}

variable "enable_session_policy_bucket" {
  type        = bool
  description = "Provision an S3 bucket for session policy files."
  default     = false
}

variable "assumable_role_arns" {
  type        = list(string)
  description = <<-EOT
    Role ARNs the Lambda may assume (sts:AssumeRole/sts:TagSession). When
    tag_auth.enabled is true with cross-account hub/spoke, ALSO include the spoke
    role ARN pattern, e.g. "arn:aws:iam::*:role/aow-spoke", so the hub can reach
    member accounts. (sts:GetCallerIdentity needs no explicit permission.)
  EOT
  default     = []
}

variable "bucket_suffix" {
  type        = string
  description = "Suffix appended to S3 bucket names for global uniqueness. Empty = use the account ID."
  default     = ""
}

variable "force_destroy_buckets" {
  type        = bool
  description = "Allow tofu destroy to delete non-empty buckets."
  default     = false
}

# ---- JWT Validation Mode ----
variable "jwt_validation_mode" {
  type        = string
  description = "JWT validation mode: 'self' (default), 'apigw' (delegate to API GW JWT Authorizer), or 'alb' (verify ALB-signed OIDC data header)."
  default     = "self"
  validation {
    condition     = contains(["self", "apigw", "alb"], var.jwt_validation_mode)
    error_message = "jwt_validation_mode must be 'self', 'apigw', or 'alb'."
  }
}

variable "jwt_authorizer_issuer" {
  type        = string
  description = "OIDC issuer URL for the API Gateway JWT Authorizer. Only used when jwt_validation_mode = 'apigw'."
  default     = "https://token.actions.githubusercontent.com"
}

variable "jwt_authorizer_audiences" {
  type        = list(string)
  description = "Accepted audiences for the API Gateway JWT Authorizer. Only used when jwt_validation_mode = 'apigw'."
  default     = ["sts.amazonaws.com"]
}

variable "alb_expected_signer" {
  type        = string
  description = "Expected ALB ARN for x-amzn-oidc-data signer validation. Only used when jwt_validation_mode = 'alb'. Recommended to prevent cross-ALB spoofing."
  default     = ""
}
```

> Constraint: `enable_dynamodb_cache` and `enable_s3_cache` are mutually exclusive; a `precondition` in `main.tf` enforces it.

- [ ] **Step 2: Write `main.tf`** (locals compute names + config map; modules wired with `count`)

```hcl
data "aws_caller_identity" "current" {}

locals {
  cache_type = var.enable_dynamodb_cache ? "dynamodb" : (var.enable_s3_cache ? "s3" : "memory")

  # S3 bucket names are globally unique — suffix with the account ID (overridable
  # via var.bucket_suffix) so "aws-oidc-warden-config" does not collide.
  suffix = var.bucket_suffix != "" ? var.bucket_suffix : data.aws_caller_identity.current.account_id

  config_bucket_name         = "${var.name_prefix}-config-${local.suffix}"
  cache_bucket_name          = "${var.name_prefix}-cache-${local.suffix}"
  log_bucket_name            = "${var.name_prefix}-logs-${local.suffix}"
  session_policy_bucket_name = "${var.name_prefix}-session-policies-${local.suffix}"
  cache_table_name           = "${var.name_prefix}-cache"
  config_key                 = "config.yaml"

  # Rendered application configuration. yamlencode drops null/omitted attributes
  # via the compact() / try() filtering below so config.yaml stays minimal.
  app_config = merge(
    {
      issuer            = var.issuer
      audiences         = var.audiences
      role_session_name = var.role_session_name
      cache = merge(
        { type = local.cache_type, ttl = var.cache_ttl },
        var.enable_dynamodb_cache ? { dynamodb_table = local.cache_table_name } : {},
        var.enable_s3_cache ? { s3_bucket = local.cache_bucket_name, s3_prefix = "jwks/" } : {},
      )
      repo_role_mappings = var.repo_role_mappings
    },
    var.enable_s3_logs ? { log_to_s3 = true, log_bucket = local.log_bucket_name, log_prefix = "audit/" } : {},
    var.enable_session_policy_bucket ? { session_policy_bucket = local.session_policy_bucket_name } : {},
    var.tag_auth.enabled ? { tag_auth = var.tag_auth } : {},
    # Render jwt_validation block only when not using the default "self" mode.
    var.jwt_validation_mode != "self" ? {
      jwt_validation = merge(
        { mode = var.jwt_validation_mode },
        var.jwt_validation_mode == "alb" && var.alb_expected_signer != "" ? { alb_expected_signer = var.alb_expected_signer } : {},
      )
    } : {},
  )
}

# ---- Buckets ----
module "config_bucket" {
  source        = "./modules/s3"
  bucket_name   = local.config_bucket_name
  force_destroy = var.force_destroy_buckets
  tags          = var.tags
}

module "cache_bucket" {
  count         = var.enable_s3_cache ? 1 : 0
  source        = "./modules/s3"
  bucket_name   = local.cache_bucket_name
  force_destroy = var.force_destroy_buckets
  tags          = var.tags
}

module "log_bucket" {
  count                     = var.enable_s3_logs ? 1 : 0
  source                    = "./modules/s3"
  bucket_name               = local.log_bucket_name
  force_destroy             = var.force_destroy_buckets
  lifecycle_expiration_days = 90
  tags                      = var.tags
}

module "session_policy_bucket" {
  count         = var.enable_session_policy_bucket ? 1 : 0
  source        = "./modules/s3"
  bucket_name   = local.session_policy_bucket_name
  force_destroy = var.force_destroy_buckets
  tags          = var.tags
}

# ---- Cache table ----
module "dynamodb" {
  count      = var.enable_dynamodb_cache ? 1 : 0
  source     = "./modules/dynamodb"
  table_name = local.cache_table_name
  tags       = var.tags
}

# ---- Rendered config object ----
resource "aws_s3_object" "config" {
  bucket       = module.config_bucket.bucket_id
  key          = local.config_key
  content      = yamlencode(local.app_config)
  content_type = "application/x-yaml"

  lifecycle {
    precondition {
      condition     = !(var.enable_dynamodb_cache && var.enable_s3_cache)
      error_message = "enable_dynamodb_cache and enable_s3_cache are mutually exclusive."
    }
  }
}

# ---- IAM ----
module "iam" {
  source                    = "./modules/iam"
  name_prefix               = var.name_prefix
  assumable_role_arns       = var.assumable_role_arns
  enable_iam_getrole        = var.tag_auth.enabled
  cache_dynamodb_table_arn  = var.enable_dynamodb_cache ? module.dynamodb[0].table_arn : null
  cache_s3_bucket_arn       = var.enable_s3_cache ? module.cache_bucket[0].bucket_arn : null
  config_bucket_arn         = module.config_bucket.bucket_arn
  session_policy_bucket_arn = var.enable_session_policy_bucket ? module.session_policy_bucket[0].bucket_arn : null
  log_bucket_arn            = var.enable_s3_logs ? module.log_bucket[0].bucket_arn : null
  tags                      = var.tags
}

# ---- Lambda ----
module "lambda" {
  source        = "./modules/lambda"
  function_name = var.name_prefix
  role_arn      = module.iam.role_arn
  zip_path      = "${path.module}/dist/function.zip"
  architecture  = var.lambda_architecture
  memory_size   = var.lambda_memory_size
  timeout       = var.lambda_timeout
  log_retention_days = var.log_retention_days
  environment_variables = {
    AOW_S3_CONFIG_BUCKET = module.config_bucket.bucket_id
    AOW_S3_CONFIG_PATH   = local.config_key
    LOG_LEVEL            = var.log_level
  }
  tags = var.tags

  depends_on = [aws_s3_object.config]
}

# ---- API Gateway ----
module "apigateway" {
  source                   = "./modules/apigateway"
  name                     = var.name_prefix
  lambda_invoke_arn        = module.lambda.invoke_arn
  lambda_function_name     = module.lambda.function_name
  # "apigw" mode: use v2 payload format + provision a JWT Authorizer so API GW
  # validates the token before invoking Lambda (Lambda reads pre-validated claims).
  payload_format_version   = var.jwt_validation_mode == "apigw" ? "2.0" : "1.0"
  enable_jwt_authorizer    = var.jwt_validation_mode == "apigw"
  jwt_authorizer_issuer    = var.jwt_authorizer_issuer
  jwt_authorizer_audiences = var.jwt_authorizer_audiences
  tags                     = var.tags
}
```

- [ ] **Step 3: Replace `outputs.tf`**

```hcl
output "api_endpoint" {
  description = "POST this URL with {\"token\":\"...\",\"role\":\"...\"}."
  value       = module.apigateway.api_endpoint
}

output "lambda_function_name" {
  value = module.lambda.function_name
}

output "execution_role_arn" {
  value = module.iam.role_arn
}

output "config_bucket" {
  value = module.config_bucket.bucket_id
}

output "cache_table_name" {
  value = var.enable_dynamodb_cache ? module.dynamodb[0].table_name : null
}
```

- [ ] **Step 4: Write `terraform.tfvars.example`**

```hcl
region      = "eu-west-1"
name_prefix = "aws-oidc-warden"

tags = {
  environment = "prod"
  owner       = "platform-team"
}

# --- Token validation ---
issuer    = "https://token.actions.githubusercontent.com"
audiences = ["sts.amazonaws.com"]

# --- Cache: choose at most one backend (memory if both false) ---
enable_dynamodb_cache = true
enable_s3_cache       = false
cache_ttl             = "1h"

# --- Optional features ---
enable_s3_logs               = false
enable_session_policy_bucket = false

# --- Lambda sizing ---
lambda_memory_size = 256
lambda_timeout     = 15
log_level          = "info"

# --- Roles the warden may assume on behalf of repos ---
assumable_role_arns = [
  "arn:aws:iam::111122223333:role/github-actions-example",
]

# --- Repository -> role mappings ---
repo_role_mappings = [
  {
    repo  = "my-org/my-repo"
    roles = ["arn:aws:iam::111122223333:role/github-actions-example"]
    constraints = {
      branch     = "refs/heads/main"
      event_name = "push"
    }
  },
]

# --- Optional tag-based / cross-account authorization ---
# When enabled with cross-account hub/spoke, add the spoke role to
# assumable_role_arns above, e.g. "arn:aws:iam::*:role/aow-spoke".
# tag_auth = {
#   enabled          = true
#   default_org      = "my-org"
#   allowed_accounts = ["111122223333", "444455556666"]
# }

# --- JWT Validation Mode ---
# "self"  (default) — Lambda validates JWT signature itself using JWKS.
# "apigw" — API Gateway JWT Authorizer validates; Lambda reads pre-validated claims
#            from event.requestContext.authorizer.jwt.claims. Build with:
#            ./deploy/opentofu/build.sh apigatewayv2
#            SECURITY: Lambda resource policy restricts invocations to the API GW
#            (source_arn = execution_arn/*/*) — direct invocations are blocked.
# "alb"   — ALB OIDC validates; Lambda verifies ALB-signed x-amzn-oidc-data (ES256).
#            Build with the default: ./deploy/opentofu/build.sh
jwt_validation_mode = "self"
# jwt_authorizer_issuer    = "https://token.actions.githubusercontent.com"
# jwt_authorizer_audiences = ["sts.amazonaws.com"]
# alb_expected_signer      = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/my-alb/abc123"
```

- [ ] **Step 5: Validate the full root** (no AWS creds or zip needed for `validate`)

Run: `cd deploy/opentofu && tofu fmt -recursive && tofu init -backend=false && tofu validate`
Expected: `Success! The configuration is valid.`
A `tofu plan` requires AWS credentials (provider init + `aws_caller_identity`) and the built `dist/function.zip`; run it in Step 6 of the end-to-end verification, not here.

- [ ] **Step 6: Commit**

```bash
git add deploy/opentofu/variables.tf deploy/opentofu/main.tf deploy/opentofu/outputs.tf deploy/opentofu/terraform.tfvars.example
git commit -m "feat(deploy): wire root module, config render, and tfvars example"
```

---

### Task 8: CloudFormation quick-start template

**Files:**

- Create: `deploy/cloudformation/quickstart.yaml`

**Interfaces:**

- Standalone. Consumes a pre-uploaded Lambda zip from S3 (`LambdaCodeBucket`/`LambdaCodeKey`) because CloudFormation cannot compile Go. Mirrors the common case: IAM role, optional DynamoDB cache, Lambda (`provided.al2023`), HTTP API, route, permission, log group. Application config is passed via env vars for scalars; `repo_role_mappings` is supplied through an `AOW_S3_CONFIG_*` pair pointing at a config object the user uploads separately (documented in README).

- [ ] **Step 1: Write `quickstart.yaml`**

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: AWS OIDC Warden - quick-start (API Gateway + Lambda, optional DynamoDB cache)

Parameters:
  FunctionName:
    Type: String
    Default: aws-oidc-warden
  LambdaCodeBucket:
    Type: String
    Description: S3 bucket holding the bootstrap zip (binary named 'bootstrap').
  LambdaCodeKey:
    Type: String
    Description: S3 key of the bootstrap zip.
  Architecture:
    Type: String
    Default: arm64
    AllowedValues: [arm64, x86_64]
  MemorySize:
    Type: Number
    Default: 256
  Timeout:
    Type: Number
    Default: 15
  Issuer:
    Type: String
    Default: https://token.actions.githubusercontent.com
  Audiences:
    Type: String
    Default: sts.amazonaws.com
    Description: Comma-separated audiences.
  ConfigBucket:
    Type: String
    Default: ""
    Description: S3 bucket holding config.yaml (repo_role_mappings etc). Leave blank to rely on env only.
  ConfigKey:
    Type: String
    Default: config.yaml
  EnableDynamoDBCache:
    Type: String
    Default: "false"
    AllowedValues: ["true", "false"]
  AssumableRoleArns:
    Type: CommaDelimitedList
    Description: Role ARNs the Lambda may assume.
  LogLevel:
    Type: String
    Default: info
  JWTValidationMode:
    Type: String
    Default: self
    AllowedValues: [self, apigw, alb]
    Description: "self = Lambda validates JWT; apigw = delegate to API GW JWT Authorizer (use apigatewayv2 binary); alb = trust ALB OIDC header."
  JWTAuthorizer_Issuer:
    Type: String
    Default: "https://token.actions.githubusercontent.com"
    Description: JWT Authorizer issuer URL (used only when JWTValidationMode = apigw).
  JWTAuthorizer_Audience:
    Type: String
    Default: sts.amazonaws.com
    Description: JWT Authorizer audience (used only when JWTValidationMode = apigw).

Conditions:
  UseDynamoDB: !Equals [!Ref EnableDynamoDBCache, "true"]
  HasConfigBucket: !Not [!Equals [!Ref ConfigBucket, ""]]
  UseJWTAuthorizer: !Equals [!Ref JWTValidationMode, "apigw"]

Resources:
  CacheTable:
    Type: AWS::DynamoDB::Table
    Condition: UseDynamoDB
    Properties:
      TableName: !Sub "${FunctionName}-cache"
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - AttributeName: Key
          AttributeType: S
      KeySchema:
        - AttributeName: Key
          KeyType: HASH
      TimeToLiveSpecification:
        AttributeName: TTL
        Enabled: true

  LogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub "/aws/lambda/${FunctionName}"
      RetentionInDays: 14

  ExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub "${FunctionName}-exec"
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: { Service: lambda.amazonaws.com }
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
      Policies:
        - PolicyName: warden-perms
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Sid: AssumeTargetRoles
                Effect: Allow
                Action: [sts:AssumeRole, sts:TagSession]
                Resource: !Ref AssumableRoleArns
              - !If
                - UseDynamoDB
                - Sid: CacheDynamoDB
                  Effect: Allow
                  Action:
                    [dynamodb:GetItem, dynamodb:PutItem, dynamodb:DeleteItem]
                  Resource: !GetAtt CacheTable.Arn
                - !Ref AWS::NoValue
              - !If
                - HasConfigBucket
                - Sid: ReadConfig
                  Effect: Allow
                  Action: s3:GetObject
                  Resource: !Sub "arn:aws:s3:::${ConfigBucket}/*"
                - !Ref AWS::NoValue

  Function:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Ref FunctionName
      Runtime: provided.al2023
      Handler: bootstrap
      Architectures: [!Ref Architecture]
      MemorySize: !Ref MemorySize
      Timeout: !Ref Timeout
      Role: !GetAtt ExecutionRole.Arn
      Code:
        S3Bucket: !Ref LambdaCodeBucket
        S3Key: !Ref LambdaCodeKey
      Environment:
        Variables:
          AOW_ISSUER: !Ref Issuer
          AOW_AUDIENCES: !Ref Audiences
          AOW_CACHE_TYPE: !If [UseDynamoDB, dynamodb, memory]
          AOW_CACHE_DYNAMODB_TABLE:
            !If [UseDynamoDB, !Sub "${FunctionName}-cache", !Ref "AWS::NoValue"]
          AOW_S3_CONFIG_BUCKET:
            !If [HasConfigBucket, !Ref ConfigBucket, !Ref "AWS::NoValue"]
          AOW_S3_CONFIG_PATH:
            !If [HasConfigBucket, !Ref ConfigKey, !Ref "AWS::NoValue"]
          AOW_JWT_VALIDATION_MODE: !Ref JWTValidationMode
          LOG_LEVEL: !Ref LogLevel
    DependsOn: LogGroup

  HttpApi:
    Type: AWS::ApiGatewayV2::Api
    Properties:
      Name: !Ref FunctionName
      ProtocolType: HTTP

  JWTAuthorizer:
    Type: AWS::ApiGatewayV2::Authorizer
    Condition: UseJWTAuthorizer
    Properties:
      ApiId: !Ref HttpApi
      AuthorizerType: JWT
      IdentitySource:
        - $request.header.Authorization
      Name: !Sub "${FunctionName}-jwt"
      JwtConfiguration:
        Audience:
          - !Ref JWTAuthorizer_Audience
        Issuer: !Ref JWTAuthorizer_Issuer

  Integration:
    Type: AWS::ApiGatewayV2::Integration
    Properties:
      ApiId: !Ref HttpApi
      IntegrationType: AWS_PROXY
      IntegrationUri: !GetAtt Function.Arn
      # "2.0" when JWT Authorizer is used (apigatewayv2 binary); "1.0" otherwise.
      PayloadFormatVersion: !If [UseJWTAuthorizer, "2.0", "1.0"]

  Route:
    Type: AWS::ApiGatewayV2::Route
    Properties:
      ApiId: !Ref HttpApi
      RouteKey: POST /verify
      Target: !Sub "integrations/${Integration}"
      AuthorizationType: !If [UseJWTAuthorizer, JWT, NONE]
      AuthorizerId: !If [UseJWTAuthorizer, !Ref JWTAuthorizer, !Ref "AWS::NoValue"]

  Stage:
    Type: AWS::ApiGatewayV2::Stage
    Properties:
      ApiId: !Ref HttpApi
      StageName: $default
      AutoDeploy: true

  InvokePermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref Function
      Action: lambda:InvokeFunction
      Principal: apigateway.amazonaws.com
      SourceArn: !Sub "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${HttpApi}/*/*"

Outputs:
  ApiEndpoint:
    Description: Verify endpoint URL.
    Value: !Sub "https://${HttpApi}.execute-api.${AWS::Region}.amazonaws.com/verify"
  FunctionArn:
    Value: !GetAtt Function.Arn
```

- [ ] **Step 2: Validate template syntax**

Run: `aws cloudformation validate-template --template-body file://deploy/cloudformation/quickstart.yaml` (requires AWS creds).
Fallback if no creds: `python3 -c "import yaml,sys; yaml.safe_load(open('deploy/cloudformation/quickstart.yaml'))"` — note this errors on CFN short-form tags (`!Ref`), so instead use `ruby -ryaml -e 'YAML.load_file(ARGV[0])' deploy/cloudformation/quickstart.yaml` only if a CFN-aware linter (`cfn-lint deploy/cloudformation/quickstart.yaml`) is unavailable. Prefer `cfn-lint` when present.
Expected: no errors / `Template is valid`.

- [ ] **Step 3: Commit**

```bash
git add deploy/cloudformation/quickstart.yaml
git commit -m "feat(deploy): cloudformation quick-start template"
```

---

### Task 9: Deployment docs + final review

**Files:**

- Create: `deploy/README.md`

**Interfaces:** documents the workflow; no code dependencies.

- [ ] **Step 1: Write `deploy/README.md`** covering:
  - Prerequisites: Go toolchain + `make`, OpenTofu ≥1.6 (or Terraform), AWS creds.
  - OpenTofu flow: `./deploy/opentofu/build.sh [apigateway|apigatewayv2]` → `cp terraform.tfvars.example terraform.tfvars` (edit) → `tofu init` → `tofu plan -var-file=terraform.tfvars` → `tofu apply`. Output `api_endpoint` is the verify URL.
  - Toggle reference table (each `enable_*` var → what it provisions → IAM granted).
  - Cache choice note: memory (default) / dynamodb / s3 are mutually exclusive; memory needs no extra resources.
  - How `config.yaml` is generated from tfvars and delivered via S3 (`AOW_S3_CONFIG_BUCKET`/`AOW_S3_CONFIG_PATH`).
  - **JWT Validation Mode** section: table of the three modes, which binary to build, what infra is provisioned, client request format difference (`token` field in body for `self`; only `role` field + `Authorization: Bearer <jwt>` header for `apigw`). Security note: in `apigw` mode the Lambda resource policy (`source_arn`) already restricts invocations to the API GW execution ARN — direct Lambda invocations are rejected by the resource policy and also by the application if authorizer claims are absent.
  - CloudFormation flow: build the zip (`make build-apigateway` or `make build-apigatewayv2`, rename binary → `bootstrap`, zip, upload to S3), then `aws cloudformation deploy --template-file deploy/cloudformation/quickstart.yaml --stack-name aws-oidc-warden --capabilities CAPABILITY_NAMED_IAM --parameter-overrides LambdaCodeBucket=... LambdaCodeKey=... AssumableRoleArns=... JWTValidationMode=self`. Note it covers the common case only; full options live in OpenTofu.
  - Smoke test self mode: `curl -X POST <api_endpoint>/verify -d '{"token":"<jwt>","role":"<arn>"}'`.
  - Smoke test apigw mode: `curl -X POST <api_endpoint>/verify -H "Authorization: Bearer <jwt>" -d '{"role":"<arn>"}'`.
  - **Operational prerequisites:** (1) each target role in `assumable_role_arns` must have a trust policy allowing the warden execution role (`execution_role_arn` output) to assume it — the warden cannot grant itself this; (2) the Lambda runs **outside any VPC** so it has outbound internet to fetch the issuer JWKS (self/alb modes) or for the ALB key endpoint (alb mode) — if you later attach it to a VPC, provide a NAT path; (3) for `tag_auth` cross-account, member-account `aow-spoke` roles must trust the hub execution role and the hub policy must list the spoke ARN pattern.
  - **Bucket names** are suffixed with the account ID for global uniqueness; override with `bucket_suffix` if needed.

- [ ] **Step 2: Full-tree validation pass**

Run: `cd deploy/opentofu && tofu fmt -recursive -check && tofu validate`
Expected: no diff from fmt; `Success!`.

- [ ] **Step 3: Commit**

```bash
git add deploy/README.md
git commit -m "docs(deploy): add deployment guide for opentofu and cloudformation"
```

---

## Verification (end-to-end)

1. **Static:** from `deploy/opentofu/`, `tofu fmt -recursive -check`, `tofu init -backend=false`, `tofu validate` all pass. Each module also validates standalone (Tasks 2–6).
2. **Plan:** `tofu plan -var-file=terraform.tfvars.example -var region=<r>` renders the full resource set with no errors (config bucket + object, IAM role+policy, Lambda, log group, HTTP API/route/stage/integration/permission; plus DynamoDB when `enable_dynamodb_cache=true`).
3. **Apply (manual, in a sandbox account):** `./build.sh && tofu apply` → note `api_endpoint`. `POST` a real GitHub Actions OIDC token + role ARN; expect HTTP 200 with STS credentials JSON. Confirm CloudWatch log group `/aws/lambda/aws-oidc-warden` receives logs and (if DynamoDB enabled) a JWKS item appears in the cache table keyed by the issuer JWKS URL.
4. **CloudFormation parity:** deploy `quickstart.yaml` with a pre-uploaded zip; its `ApiEndpoint` output responds identically for the common case.
5. **Toggle matrix:** flip `enable_s3_cache`, `enable_s3_logs`, `enable_session_policy_bucket`, and `tag_auth.enabled` in tfvars; `tofu plan` shows the corresponding bucket/IAM statements appear/disappear with no other drift.

## Self-Review Notes

- **Spec coverage:** Lambda ✔ (Task 5), API Gateway ✔ (Task 6), DynamoDB-if-enabled ✔ (Task 3, gated Task 7), S3 buckets ✔ (Task 2, reused for config/cache/logs/policies), everything tfvars-driven ✔ (Task 7), generic modules ✔ (Tasks 2–6), CloudFormation for fast deploy ✔ (Task 8), split into subagent tasks ✔. JWT Validation Mode ✔ (Task 6 JWT Authorizer, Task 7 variables + app_config + module wiring, Task 8 CFN condition, build.sh variant).
- **Type consistency:** module output names (`bucket_arn`, `table_arn`, `role_arn`, `invoke_arn`, `function_name`) are referenced identically in root `main.tf`. DynamoDB schema `Key`/`TTL` matches `internal/cache/dynamodb.go`. Env var names verified against `internal/config/config.go` (`AOW_` prefix; `AOW_S3_CONFIG_BUCKET`, `AOW_S3_CONFIG_PATH`, `LOG_LEVEL`; `AOW_AUDIENCES`/`AOW_TAG_AUTH_ALLOWED_ACCOUNTS` comma-split at `config.go:266-276,368`; `AOW_JWT_VALIDATION_MODE` added by JWT validation plan). Route `POST /verify` matches `cmd/local/main.go` and the handler event shape (payload format `1.0` for self/alb, `2.0` for apigw).
- **Config delivery:** chosen S3-rendered `config.yaml` because `repo_role_mappings` (list of objects) cannot be expressed as a single env var; the app natively supports S3 config fetch.

## Blind Spots Reviewed & Resolved

- **Bootstrap exec bit:** `archive_file` does not preserve the `0755` bit → `provided.al2023` cold-start `permission denied`. Resolved: `build.sh` packages with the `zip` CLI; module consumes the prebuilt zip via `filebase64sha256`.
- **S3 global uniqueness:** bucket names now suffixed with account ID (override `bucket_suffix`).
- **Cross-account spoke roles:** `assumable_role_arns` doc + tfvars example call out adding `arn:aws:iam::*:role/aow-spoke`; `sts:GetCallerIdentity` needs no grant.
- **`AOW_AUDIENCES` comma parsing:** verified handled in code, so the CloudFormation env-var path supports multiple audiences.
- **`tofu plan` needs creds:** validation gates use `validate` only; `plan`/`apply` are explicitly the credentialed/manual steps.
- **Operational trust/VPC:** README documents target-role trust, no-VPC internet requirement, and hub/spoke trust.
- **Repo refactor (`pkg/`→`internal/`):** no IaC impact (no Go paths referenced); build from a clean checkout where `go build ./cmd/apigateway` succeeds.
- **Not handled by design (out of scope):** GitHub OIDC provider/target-role creation, remote state backend config (left as a commented stub), custom domain/TLS, WAF, and ALB OIDC infrastructure (ALB itself, listener rules, OIDC config) — all deliberately excluded to keep modules generic. ALB OIDC setup for `jwt_validation_mode = "alb"` requires the ALB to exist and be configured externally.
- **Dependency on JWT validation plan:** `cmd/apigatewayv2` binary and the `make build-apigatewayv2` Makefile target are implemented by `docs/superpowers/plans/2026-06-28-delegated-jwt-validation.md` (Task 9). The IaC modules reference these but cannot be end-to-end tested for `apigw` mode until that plan is executed first.
