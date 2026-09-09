# AWS OIDC Warden — Deployment Guide

Two deployment paths are provided: **OpenTofu** and **CloudFormation**. Both provision the same infrastructure (either API Gateway flavor, WAF, throttling, caches, optional buckets); the one functional difference is that OpenTofu also renders and uploads `config.yaml` by default, while with CloudFormation you upload it yourself. Set `manage_config = false` to get the CloudFormation behavior from OpenTofu too — see [Bringing your own config.yaml](#bringing-your-own-configyaml).

## Prerequisites

- Go toolchain + `make` (to build the Lambda binary)
- [OpenTofu](https://opentofu.org/) ≥ 1.6 **or** Terraform ≥ 1.6
- AWS credentials configured (`aws configure`, environment variables, or an IAM role)
- `zip` CLI (for `build.sh` — preserves the `bootstrap` exec bit)

---

## OpenTofu Deployment

### 1. Build the Lambda zip

```bash
./deploy/opentofu/build.sh              # default: apigateway (self mode)
./deploy/opentofu/build.sh apigatewayv2 # apigw mode (delegates JWT to API GW)
```

The script calls `make build-<variant>`, stages the binary as `bootstrap`, and produces `deploy/opentofu/dist/function.zip` with the exec bit preserved.

### 2. Configure tfvars

```bash
cp deploy/opentofu/terraform.tfvars.example deploy/opentofu/terraform.tfvars
# Edit terraform.tfvars — set region, role_mappings, assumable_role_arns, etc.
```

### 3. Init, plan, and apply

```bash
cd deploy/opentofu
tofu init
tofu plan -var-file=terraform.tfvars
tofu apply -var-file=terraform.tfvars
```

The `api_endpoint` output is the full verify URL (e.g. `https://<id>.execute-api.<region>.amazonaws.com/verify`).

---

## Toggle Reference

| Variable                       | Default | Provisions                                                                           | IAM granted                                      |
| ------------------------------ | ------- | ------------------------------------------------------------------------------------ | ------------------------------------------------ |
| `manage_config`                | `true`  | The `config.yaml` object in the config bucket (the bucket itself is unconditional)   | —                                                |
| `enable_dynamodb_cache`        | `false` | DynamoDB table `<prefix>-cache`                                                      | `dynamodb:GetItem/PutItem/DeleteItem`            |
| `enable_s3_cache`              | `false` | S3 bucket `<prefix>-cache-<suffix>`                                                  | `s3:GetObject/PutObject/DeleteObject/ListBucket` |
| `enable_s3_logs`               | `false` | S3 bucket `<prefix>-logs-<suffix>` (versioned, `audit_log_retention_days` lifecycle) | `s3:PutObject`, `s3:PutObjectTagging`            |
| `audit_required`               | `true`  | Implies `enable_s3_logs` (needs a bucket to write to)                                | `s3:PutObject`, `s3:PutObjectTagging`            |
| `log_claim_values`             | `true`  | No new resources                                                                     | —                                                |
| `enable_session_policy_bucket` | `false` | S3 bucket `<prefix>-session-policies-<suffix>`                                       | `s3:GetObject`                                   |
| `tag_auth.enabled`             | `false` | No new resources                                                                     | `iam:GetRole`                                    |
| `session_tags_transitive`      | `false` | No new resources                                                                     | —                                                |

**`audit_required` defaults to `true`** and provisions the log bucket on its own, so every allow decision's audit record is written to S3 synchronously before credentials are returned (fail-closed). Set it to `false` for the best-effort batched trail — in Lambda that path can lose buffered records at container reclaim (see [docs/LOGGING.md](../docs/LOGGING.md)).

**`log_claim_values` defaults to `true`** so each record identifies who made the request — for GitHub issuers, the full verified claim set (`claims.repo`, `claims.ref`, `claims.event_name`, `claims.actor`, and so on), plus the canonical `subject`. Set it to `false` to keep identities out of the log stream — decision, reason, role, and claim _names_ are still recorded.

**`session_tags_transitive` defaults to `false`, but turning it on is RECOMMENDED.** Without it, a session tag is dropped the moment the target role assumes another role, so any ABAC policy past that hop can no longer see who the original caller was. It defaults off only for upgrade safety: transitive tags are immutable downstream, so enabling it breaks a target role that re-tags with the same keys while chaining. If yours doesn't (the common case), set `session_tags_transitive = true`.

### Audit bucket retention

The log bucket holds the durable record of every credential the warden issued, so it is created with **versioning enabled**: an overwrite or a delete leaves the previous version recoverable, and the lifecycle rule expires noncurrent versions on the same schedule as current ones.

| Variable                     | Default | Effect                                                                                 |
| ---------------------------- | ------- | -------------------------------------------------------------------------------------- |
| `audit_log_retention_days`   | `90`    | Days audit objects (current and noncurrent versions) are kept before expiring.         |
| `audit_log_object_lock_mode` | `null`  | `"GOVERNANCE"`, `"COMPLIANCE"`, or `null` to leave S3 Object Lock off.                 |
| `audit_log_object_lock_days` | `365`   | Days each object version is retained under Object Lock. Ignored when the mode is null. |

Versioning alone protects against accident, not against an attacker with `s3:DeleteObjectVersion` on the bucket. Where the audit trail must survive a compromise of the account that writes it, set `audit_log_object_lock_mode`:

- **`GOVERNANCE`** — a principal holding `s3:BypassGovernanceRetention` can still delete a locked version. Use it while tuning the retention window.
- **`COMPLIANCE`** — no principal can delete or shorten a locked version, including the root account, for the full retention period. Choose the window deliberately: you cannot undo it, and you pay storage for every locked version until it expires.

Two constraints follow from how S3 implements Object Lock:

- **It can only be enabled when the bucket is created.** Setting `audit_log_object_lock_mode` on a stack whose log bucket already exists replaces the bucket; migrate by creating the new bucket, copying existing objects, then repointing `log_bucket`.
- **Keep `audit_log_retention_days` at or above `audit_log_object_lock_days`.** A version under lock is not deleted before its retention expires, so a shorter lifecycle silently leaves locked versions in place (and billed) rather than removing them.

CloudFormation exposes the same three knobs as `AuditLogRetentionDays`, `AuditLogObjectLockMode` (empty string = off), and `AuditLogObjectLockDays`.

**Cache backends are mutually exclusive.** `enable_dynamodb_cache` and `enable_s3_cache` cannot both be `true`; a `precondition` enforces this at plan time. Leaving both `false` uses in-memory cache (suitable for low traffic; cache lost on cold start).

---

## How config.yaml is delivered

By default `main.tf` renders the service config into a `config.yaml` object and uploads it to the config S3 bucket. What it renders:

- `var.issuers` — or, if unset, the `var.issuer`/`var.audiences` shorthand, rendered as a single GitHub `issuers[]` entry
- `var.role_mappings`
- cache settings
- `jwt_validation`

The Lambda fetches and parses that file on startup. All complex configuration (role mappings, nested objects) lives there; scalar overrides can also come from `AOW_*` env vars.

Three env vars are set on the Lambda itself:

| Env var                   | Value                                                                                                                                                                                             |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AOW_S3_CONFIG_BUCKET`    | Bucket name                                                                                                                                                                                       |
| `AOW_S3_CONFIG_PATH`      | Object key (`config.yaml`)                                                                                                                                                                        |
| `AOW_JWT_VALIDATION_MODE` | From `var.jwt_validation_mode`. **The extractor is wired at cold start from this env var, not from `config.yaml`** (which is hot-reloadable), so it must match the deployed Lambda binary variant |

### Bringing your own config.yaml

Set `manage_config = false` to keep the config file out of Terraform entirely. This is the right choice if you want to hand-write the YAML documented in [docs/CONFIGURATION.md](../docs/CONFIGURATION.md) — including the features listed under [`config.yaml`-only](#features-that-are-configyaml-only) — rather than express it through variables.

Terraform still creates the config bucket, sets `AOW_S3_CONFIG_BUCKET`/`AOW_S3_CONFIG_PATH`, and grants the Lambda `s3:GetObject` on it. It just doesn't own the object:

```bash
tofu apply
aws s3 cp config.yaml "s3://$(tofu output -raw config_bucket)/config.yaml"
```

The Lambda fetches `config.yaml` at cold start, so upload it before sending traffic — a missing object fails startup (`buildConfigProvider` returns the fetch error). With the object outside Terraform state, an `apply` will never revert an edit you made by hand.

Your YAML then becomes the only source of the service's own settings: `role_mappings`, `default_issuer`, `role_session_name`, `tag_auth`, `cross_account`, `session_tags_transitive` and the other rendered content stop having any effect as variables. The variables that **also** build or wire infrastructure keep working, and your YAML has to agree with them:

| Variable                                    | Still does                                                             |
| ------------------------------------------- | ---------------------------------------------------------------------- |
| `jwt_validation_mode`                       | Sets `AOW_JWT_VALIDATION_MODE` and selects the expected binary variant |
| `issuers` / `route_key`                     | One JWT Authorizer and route per issuer, in `apigw` mode               |
| `enable_dynamodb_cache` / `enable_s3_cache` | Provisions the cache table/bucket and the IAM to use it                |
| `audit_required` / `enable_s3_logs`         | Provisions the audit bucket and grants `s3:PutObject`                  |
| `enable_session_policy_bucket`              | Provisions the session-policy bucket and grants `s3:GetObject`         |

A mismatch here is the one real hazard of this mode — e.g. `cache.type: dynamodb` in your YAML with `enable_dynamodb_cache = false` leaves the service pointed at a table that was never created, and no IAM to read it.

The plan-time guardrails on infrastructure combinations (cache exclusivity, `apigw` requiring an HTTP API, WAF requiring a REST API, the authorizer rules) still apply — they live on `terraform_data.guardrails` rather than on the config object. Only the checks that validate rendered content go away with the render.

### `role_session_name` overrides

Each `var.role_mappings` entry may set `role_session_name` to override the global `var.role_session_name` for the roles it grants, so CloudTrail names the requester instead of the service.

STS accepts 2–64 characters from `[\w+=,.@-]` — **`/` is not in that set**, so a repository name cannot be used verbatim. An invalid value fails the service at boot rather than being silently reshaped.

### Features that are `config.yaml`-only

These exist in the service but are **not** exposed as module variables. A mapping that needs one belongs in a `config_fragments` file:

| Feature                         | Why it isn't a variable                                                                                   | Workaround                                               |
| ------------------------------- | --------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| `role_groups`                   | The DRY convenience for many subjects sharing one set of defaults                                         | `config.yaml` or a fragment                              |
| List-valued `subject`           | `var.role_mappings[].subject` is typed `string` and renders as a scalar (which the service still accepts) | One entry per subject, or a fragment                     |
| `role_mappings[].session_tags`  | Per-mapping additive session tags are not in the variable's object type                                   | A fragment; issuer-level `session_tags` **are** rendered |
| `all_of` / `any_of` / `none_of` | Boolean condition groups are not expressible in the variable schema                                       | A fragment                                               |

<!-- prettier-ignore -->
> [!IMPORTANT]
> **v3 condition schema.** `var.role_mappings[].conditions` follows the service's v3 schema — every key is the raw claim it checks. Rename these in `terraform.tfvars` before applying:
>
> | v2 | v3 |
> | --- | --- |
> | `branch` | `ref` |
> | `actor_matches` | `actor` |
> | *(runner type)* | `runner_environment` |
> | `environment` | Still `environment`, but now gates GitHub's **deployment**-environment claim |
>
> A plan against the old attribute names fails at plan time. An `environment` left unrenamed **plans clean but gates a different claim** — that is the dangerous one. See [docs/MIGRATION_V3.md](../docs/MIGRATION_V3.md).
>
> Beyond the named keys, `conditions.claims` is a `map(list(string))` reaching any other claim (`repository_visibility`, `base_ref`, a GitLab claim, or one named like a reserved key), each entry a list of OR-ed alternatives.

Two plan-time rejections protect against conditions that read as gates but gate nothing:

- **A `conditions` object with no usable field** — every field null, or only empties like `actor = []` / `claims = {}`. It reads as a gated mapping and gates nothing.
- **An empty value beside a real condition** — e.g. `ref = "refs/heads/main"` with `actor = []`. An empty pattern matches nothing, and the service refuses to boot on it rather than denying, so the apply would succeed and the Lambda would crash-loop.

---

## JWT Validation Mode

| Mode                | `jwt_validation_mode` | Binary         | Infra provisioned                                                             | Request format                                                                     |
| ------------------- | --------------------- | -------------- | ----------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| **Self** (default)  | `"self"`              | `apigateway`   | No extra infra                                                                | `POST /verify` body: `{"token":"<jwt>","role":"<arn>"}`                            |
| **API GW delegate** | `"apigw"`             | `apigatewayv2` | One JWT Authorizer + route per configured issuer (`var.issuers`), on HTTP API | `POST /verify` with `Authorization: Bearer <jwt>` header; body: `{"role":"<arn>"}` |

> **ALB mode is not supported by this stack.** `jwt_validation.mode: "alb"` requires the `alb` Lambda binary (`make build-alb`) deployed behind an Application Load Balancer, which neither the OpenTofu module nor the CloudFormation template provisions. The `apigateway` binary refuses to start in `alb` mode.

Both supported modes above are also the two where the audit trail's `sourceIp` is **attested by AWS** rather than taken from a client-supplied `X-Forwarded-For` header — API Gateway reports the source IP it observed, and the caller cannot set it. That is one more reason to prefer this stack over an ALB front-end, and `"apigw"` in particular, since a JWT Authorizer also rejects invalid tokens before the Lambda is invoked. See [Source IP trust model](../docs/LOGGING.md#source-ip-trust-model) for the per-frontend attestation table and the front-proxy caveat that applies to ALB deployments.

Build the correct binary before running `tofu apply`:

```bash
./deploy/opentofu/build.sh              # self mode
./deploy/opentofu/build.sh apigatewayv2 # apigw mode
```

<!-- prettier-ignore -->
> [!CAUTION]
> ### `apigw` mode: `lambda:InvokeFunction` **is** identity impersonation
>
> In `apigw` mode this service **does not verify the token's signature**. API Gateway's JWT Authorizer does that, upstream, and the Lambda trusts `event.requestContext.authorizer.jwt.claims` exactly as handed to it.
>
> The application's only guard against a direct invoke is **"claims must be non-empty"**. That stops an empty payload. It **cannot** stop a direct invoke carrying *forged, non-empty* claims — an arbitrary `iss`/`aud`/`sub`/`exp` passes straight through, because there is no signature left to check it against.
>
> **Therefore anyone holding `lambda:InvokeFunction` on this function can mint AWS credentials for any subject your `role_mappings` / `role_groups` / `tag_auth` would authorize.** The resource policy is not one layer of two — in `apigw` mode **it is the only line of defence.**
>
> The stack sets this correctly: invocation is granted to `apigateway.amazonaws.com` alone, narrowed by `source_arn` to the provisioned API.
>
> ```hcl
> resource "aws_lambda_permission" "apigw_only" {
>   statement_id  = "AllowInvokeFromThisApiOnly"
>   action        = "lambda:InvokeFunction"
>   function_name = module.lambda.function_name
>   principal     = "apigateway.amazonaws.com"
>   source_arn    = "${aws_apigatewayv2_api.this.execution_arn}/*/*"
> }
> ```
>
> **What you must not do**, in this stack or alongside it: grant `lambda:InvokeFunction` to a wildcard principal, to an account root, to a CI/deployment role, to a developer role for "testing", or to `apigateway.amazonaws.com` *without* a `source_arn`. Any of those hands out credential minting for every subject in your config. The same applies to anything that can invoke on your behalf — an EventBridge rule, a Step Functions state machine, a Function URL (`AuthType: NONE` especially), or a second API Gateway.
>
> Audit the deployed function's resource policy, and expect exactly one statement:
>
> ```bash
> aws lambda get-policy --function-name aws-oidc-warden \
>   --query Policy --output text | jq '.Statement[] | {Sid, Principal, Condition}'
> ```
>
> `self` mode does not carry this exposure in the same way — the Lambda verifies the token itself, so a forged direct invoke fails signature verification. `alb` mode also verifies the ALB's ES256 signature over `x-amzn-oidc-data` in-process. **Only `apigw` mode has no cryptographic backstop.** Full write-up: [docs/TOKEN_VALIDATION.md §2.2](../docs/TOKEN_VALIDATION.md#22-trust-boundary-lambdainvokefunction-is-identity-impersonation-in-apigw-mode).

---

## Hardening the Public Endpoint

The endpoint is public. The application already denies tokens from unconfigured issuers with 401 **before any JWKS fetch** (no SSRF surface, minimal CPU), but in `self` mode every request — valid or junk — still invokes the Lambda. Defense is layered; each layer stops traffic the previous one lets through:

| Layer                                                                           | Stops junk traffic…                                   | Knob                                              |
| ------------------------------------------------------------------------------- | ----------------------------------------------------- | ------------------------------------------------- |
| WAF (REST API only) or JWT Authorizer (`apigw` mode, one per configured issuer) | **before Lambda invocation**                          | `enable_waf` / `jwt_validation_mode`              |
| API Gateway stage throttling                                                    | before invocation, above rate cap                     | `throttling_burst_limit`, `throttling_rate_limit` |
| In-app validation (unknown issuer → 401 pre-JWKS)                               | inside the Lambda, cheaply                            | always on                                         |
| Lambda reserved concurrency                                                     | caps total concurrent invocations (cost/blast radius) | `lambda_reserved_concurrency`                     |

The pre-invocation layer depends on the API Gateway flavor (`api_gateway_type`), because AWS ties each protection to one flavor:

- **HTTP API (v2, `"http"`, default)** — supports the **JWT Authorizer**: with `jwt_validation_mode = "apigw"`, API Gateway provisions one authorizer and route per configured issuer (`var.issuers`), each validating that issuer's tokens against its own JWKS and rejecting everything else at the gateway — zero Lambda invocations for junk, from one issuer or several. Limit: AWS caps authorizers at 10 per HTTP API (default quota, raisable via Service Quotas); a `precondition` enforces this at plan time — beyond that, split across two APIs. **WAF cannot attach to HTTP APIs.**
- **REST API (v1, `"rest"`)** — supports **AWS WAF** (`enable_waf = true`): a per-source-IP rate-based rule (`waf_rate_limit`, default 300 req/5 min), `AWSManagedRulesCommonRuleSet`, and a request-shape rule that blocks anything other than `POST /verify`. This is the hardened posture for **`self` mode** (any issuer count), where the JWT Authorizer doesn't apply. Uses the same `apigateway` binary and self-mode request format — no rebuild needed when switching from `"http"` + self.

**Pick per mode:** using `jwt_validation_mode = "apigw"` (any issuer count, up to the 10-authorizer limit above) → `"http"`; staying on `self` mode → `"rest"` + `enable_waf = true` for the pre-invocation layer. Preconditions enforce the valid combinations at plan time.

**No IP allowlisting:** GitHub-hosted runners use vast, constantly-changing Azure IP ranges and self-hosted runners can be anywhere — WAF IP sets or resource policies would break legitimate callers, so neither posture uses them.

Both stacks support both postures: in OpenTofu via `api_gateway_type`/`enable_waf`, in CloudFormation via the `ApiGatewayType`/`EnableWAF` parameters (equivalent assertions run at stack creation).

---

## Multi-region deployment (resilience)

The request path is stateless, so resilience means **two independent stacks** — one per region — with the caller failing over. Nothing is shared at request time, and neither region needs to know the other exists.

Workflow-side failover example: [Multi-region failover](../docs/GITHUB_ACTIONS.md#multi-region-failover) — in both JavaScript and shell.

### Per-region vs. shared

| Resource                             | Scope                                       | Why                                                                                                                                 |
| ------------------------------------ | ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Lambda + API Gateway                 | **Per-region**                              | The point of the exercise                                                                                                           |
| Audit log bucket (`*-logs-*`)        | **Per-region — never shared**               | See the fail-closed trap below                                                                                                      |
| DynamoDB JWKS cache                  | **Per-region**                              | Do _not_ use Global Tables — see below                                                                                              |
| Config bucket (`*-config-*`)         | **Per-region**, rendered from shared tfvars | See [Keeping authorization identical](#keeping-authorization-identical)                                                             |
| Session policy bucket                | Per-region, safe to replicate               | Objects are operator-managed, not stack-managed                                                                                     |
| IAM execution role                   | **One, shared by every region**             | IAM is global, and this ARN is the service's public contract — see [One execution role](#one-execution-role-shared-by-both-regions) |
| Target roles (what workflows assume) | Shared                                      | Trust exactly **one** warden ARN, regardless of region count                                                                        |

### The fail-closed trap: never share the audit bucket

`audit_required` defaults to `true` and is fail-closed — an allow decision's audit record must be durably written **before** credentials are returned.

<!-- prettier-ignore -->
> [!CAUTION]
> Point both regions at one audit bucket and you have **inverted** the design: an S3 outage in the primary region makes the **secondary deny every request**, precisely when it is meant to take over.

The module already does the right thing — each stack creates its own versioned `${name_prefix}-logs-${suffix}` bucket, with optional Object Lock. Leave it that way and aggregate the two buckets when you query for compliance; `requestId` is the Lambda invocation UUID, so records from the two regions never collide.

### A distinct `name_prefix` per region is mandatory

S3 bucket names are **global**, and `suffix` defaults to the account ID — the same in both regions. Without distinct prefixes, `${name_prefix}-config-${suffix}`, `-logs-`, `-cache-` and `-session-policies-` all collide. (The DynamoDB table and the Lambda function are regional and would not collide, but one prefix per region keeps everything legible.)

```hcl
# eu-west-1.tfvars
region      = "eu-west-1"
name_prefix = "aws-oidc-warden-euw1"

# eu-central-1.tfvars
region      = "eu-central-1"
name_prefix = "aws-oidc-warden-euc1"
```

Use **separate state** per region — distinct backend keys, or a workspace each:

```bash
tofu init -backend-config="key=aws-oidc-warden/eu-west-1.tfstate"
tofu apply -var-file=authz.tfvars -var-file=eu-west-1.tfvars
```

The **execution role is deliberately excluded** from this per-region naming — see below.

### One execution role, shared by both regions

IAM is global, so one role serves every regional Lambda. This matters because the role ARN is this service's **public contract**: it is the one value every target-role owner, in every account, has to trust. Keep it region-free and that contract never changes, no matter how many regions you add.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:role/aws-oidc-warden-exec" },
      "Action": ["sts:AssumeRole", "sts:TagSession"],
      "Condition": {
        "StringEquals": { "aws:RequestTag/repo": "${aws:ResourceTag/repo}" }
      }
    }
  ]
}
```

Nothing about the role needs region-specific handling: its trust policy is the `lambda.amazonaws.com` service principal with **no `aws:SourceArn` or region condition**, so Lambda in any region can assume it as-is, and `AWSLambdaBasicExecutionRole` grants logs on `arn:aws:logs:*:*:*`.

#### Ownership: who creates what

| Owner                                              | Resource                                                                  | Scope                                |
| -------------------------------------------------- | ------------------------------------------------------------------------- | ------------------------------------ |
| **Bootstrap stack** (or your central IAM pipeline) | `aws-oidc-warden-exec` + its trust policy + `AWSLambdaBasicExecutionRole` | Once, globally                       |
| **Bootstrap stack**                                | `aws-oidc-warden-assume` managed policy — target roles + `iam:GetRole`    | Once, globally                       |
| **Each regional stack**                            | One **inline** policy, `<name_prefix>-perms` — and no role of its own     | That region's buckets and table only |

Keep the role in a **separate bootstrap stack**, not in one of the regional stacks. If region A's stack owned the role, `tofu destroy` there would delete the identity region B depends on, and the two stacks would stop being symmetric.

Point each regional stack at that role with `var.execution_role_arn`, and it creates none of its own:

```hcl
# eu-west-1.tfvars — and the same ARN in eu-central-1.tfvars
execution_role_arn  = "arn:aws:iam::123456789012:role/aws-oidc-warden-exec"
assumable_role_arns = [] # AssumeTargetRoles belongs in the shared managed policy
```

The module then skips both the role and its `AWSLambdaBasicExecutionRole` attachment — the bootstrap stack owns those — while still attaching the `${name_prefix}-perms` inline policy for the buckets and table that stack created. Leave `assumable_role_arns` empty so the statement that grows stays in the one shared managed policy rather than being duplicated into every region's inline budget (see the quotas below). `var.role_name` applies only when the module creates the role, so it has no effect here.

#### The bootstrap stack

The region-agnostic grants live here, attached **once**. This is deliberately where the list that _grows_ lives:

```hcl
resource "aws_iam_role" "warden" {
  name = "aws-oidc-warden-exec" # no region — this ARN is the public contract

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "basic" {
  role       = aws_iam_role.warden.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Region-agnostic. Attached once, NOT duplicated per region — this is the
# statement that grows with the number of target roles.
resource "aws_iam_policy" "assume_targets" {
  name = "aws-oidc-warden-assume"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AssumeTargetRoles"
        Effect = "Allow"
        Action = ["sts:AssumeRole", "sts:TagSession"]
        # A naming convention, not an enumeration — see the quota note below.
        Resource = ["arn:aws:iam::*:role/gha-*"]
      },
      {
        Sid      = "ReadRoleTags" # only needed when tag_auth is enabled
        Effect   = "Allow"
        Action   = "iam:GetRole"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "assume_targets" {
  role       = aws_iam_role.warden.name
  policy_arn = aws_iam_policy.assume_targets.arn
}
```

#### Per-region policy

Each regional stack attaches its own **inline** policy, scoped to that region's resources. Distinct names mean the two stacks never fight over one resource, and destroying a region removes only its own policy. `modules/iam` builds this for you from the buckets and table that stack enabled — the equivalent written out, so you can see what lands on the shared role:

```hcl
resource "aws_iam_role_policy" "region" {
  name = "${var.name_prefix}-perms" # "aws-oidc-warden-euw1-perms"
  role = "aws-oidc-warden-exec"     # the shared role

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadConfig"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "arn:aws:s3:::aws-oidc-warden-euw1-config-123456789012/*"
      },
      {
        Sid      = "WriteAuditLogs"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:PutObjectTagging"]
        Resource = "arn:aws:s3:::aws-oidc-warden-euw1-logs-123456789012/*"
      },
      {
        Sid      = "ReadSessionPolicies"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "arn:aws:s3:::aws-oidc-warden-euw1-session-policies-123456789012/*"
      },
      {
        Sid      = "CacheDynamoDB"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"]
        Resource = "arn:aws:dynamodb:eu-west-1:123456789012:table/aws-oidc-warden-euw1-cache"
      },
    ]
  })
}
```

The second region is the same block with `euc1` and `eu-central-1` substituted. No wildcards across regions, so each region still reaches only its own resources — you get the single shared ARN **and** exact per-region scoping.

#### Why inline per-region, managed for the shared part — the quotas

| IAM quota                                 | Value                                      | What it constrains here                                                                                                                                                        |
| ----------------------------------------- | ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Managed policy document size              | **6,144 characters** (whitespace excluded) | The shared `AssumeTargetRoles` policy. Enumerating hundreds of target-role ARNs will exceed this                                                                               |
| Managed policies attached per role        | **10** (adjustable to 20)                  | Why per-region policies are **inline**: managed ones would burn this cap one region at a time, and `AWSLambdaBasicExecutionRole` plus the shared assume policy already use two |
| Aggregate **inline** policy size per role | **10,240 characters**                      | The budget shared across all per-region policies. The block above is roughly 1 KB, so this comfortably holds far more regions than you will deploy                             |

The design consequence is the important part:

<!-- prettier-ignore -->
> [!IMPORTANT]
> **Express target roles as a naming convention, not a list.** `AssumeTargetRoles` is the only statement that grows without bound, so it must (a) live in the single shared policy rather than being duplicated per region, and (b) use a pattern like `arn:aws:iam::*:role/gha-*` instead of an enumeration. Duplicating a long list across per-region policies is what would actually exhaust the 10,240-character inline budget.
>
> The trade-off is explicit: **the naming convention becomes the security boundary.** Anyone who can create a role matching `gha-*` in a reachable account has created something the warden may assume — subject to that role's own trust policy, which still has to name the warden. Constrain role creation with a permissions boundary or SCP, and keep the pattern narrow.

If you must enumerate and exceed 6,144 characters, split into a second managed policy rather than pushing it inline — the 10-attachment cap has more headroom than the shared inline budget.

#### Revoking one region without a per-region role

A shared identity means you cannot revoke "region A's role". Two levers replace it:

| Lever                                                       | Effect                                                                                                                                                                                               |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `lambda_reserved_concurrency = 0` on that region's function | Stops all invocations. The most direct kill, and no IAM change                                                                                                                                       |
| A `Deny` on `sts:*` conditioned on `aws:RequestedRegion`    | Each Lambda calls its **own regional** STS endpoint, so this cuts off exactly one region's assume calls. Scope it to `sts:*`, not `*` — global services such as IAM report their own endpoint region |

The residual cost of sharing is blast radius on the service's _own_ infrastructure: credentials stolen from either region carry the union of both per-region policies, including `s3:PutObject` on the other region's audit prefix. Two properties already bound that damage — the role is granted `s3:PutObject`/`s3:PutObjectTagging` and **never `s3:DeleteObject`**, so audit records cannot be deleted; and the audit bucket is created with versioning enabled, so an overwrite at an existing key retains the prior version. The target-role grant is identical either way, so nothing is widened where it would matter most.

### Keeping authorization identical

Two regions mean two `config.yaml` objects, and a stale one is a **silent authorization difference** — the secondary could still grant a role you removed.

The module renders `config.yaml` from your variables, so the reliable way to keep them identical is to render both from the **same authorization tfvars** (with `manage_config = false` this sync is yours to own — upload the same file to both buckets in one pipeline step):

| File              | Contents                                                                                  | Shared?                |
| ----------------- | ----------------------------------------------------------------------------------------- | ---------------------- |
| `authz.tfvars`    | `issuers`, `role_mappings`, `role_session_name`, `tag_auth`, `cross_account`              | **Yes — both regions** |
| `<region>.tfvars` | `region`, `name_prefix`, `api_gateway_type`, `jwt_validation_mode`, cache and log toggles | No                     |

Apply both in the **same pipeline run**, so "authorization changed" and "both regions updated" are one atomic operation. Divergence then reduces to "did the second apply succeed", which CI can assert.

<!-- prettier-ignore -->
> [!IMPORTANT]
> **Do not put Cross-Region Replication on the *config* bucket.** `aws_s3_object.config` is the one S3 object the stack manages, and its rendered content embeds region-local names (`log_bucket`, `dynamodb_table`, `session_policy_bucket` — all built from `name_prefix`). The two regions' config objects are therefore *legitimately different*, and CRR would overwrite the secondary's copy with the primary's, after which the next `tofu plan` sees drift and writes it back — a loop, plus a secondary pointed at buckets in the wrong region.
>
> Replication *is* the right tool for the **session policy bucket**, whose objects you manage yourself rather than through the stack. CRR requires versioning on both source and destination; the module creates that bucket with versioning **disabled** (`versioning_enabled` defaults to `false` and only the audit bucket overrides it), so enable it on both before configuring replication.

To spot-check that the authorization content matches, compare the rendered objects. Buckets use SSE-S3 (`AES256`), so for a single-part upload the ETag is the content MD5:

```bash
aws s3api head-object --bucket aws-oidc-warden-euw1-config-<acct> --key config.yaml --query ETag --region eu-west-1
aws s3api head-object --bucket aws-oidc-warden-euc1-config-<acct> --key config.yaml --query ETag --region eu-central-1
```

These differ by design (region-local bucket names). Diff the objects themselves when you need certainty about the authorization sections:

```bash
diff <(aws s3 cp s3://aws-oidc-warden-euw1-config-<acct>/config.yaml - --region eu-west-1) \
     <(aws s3 cp s3://aws-oidc-warden-euc1-config-<acct>/config.yaml - --region eu-central-1)
```

Only the `cache`/`log_bucket`/`session_policy_bucket` lines should show up.

### Do not replicate the JWKS cache

Per-region DynamoDB tables, and **no Global Tables**. The cache holds public signing keys and is rebuildable from a single JWKS fetch, so replicating it buys nothing while adding a cross-region dependency to the one component that does not need one. A cold secondary simply re-fetches the JWKS on its first request.

### What each region does _not_ share

Both stacks resolve AWS clients through the default credential/region chain, so each Lambda uses `AWS_REGION` — the region it runs in — and SDK v2's **regional** STS endpoints. There is no shared global endpoint between the two deployments.

### One hostname instead of client-side failover?

Route 53 failover routing would avoid touching workflows, but health-checking it well is awkward with what this stack provisions: only `POST /verify` exists (no `GET /health` in any Lambda variant), and the REST flavour's WAF rule deliberately blocks anything that is not `POST /verify`. Route 53 health checks issue GET/HEAD, so you would get either a shallow check — an API Gateway mock route returning 200, which will not notice a broken Lambda or a bad config — or a synthetic canary doing a real `POST` into a CloudWatch alarm, with the health check reading the alarm state. The latter is a genuine deep check, but it is real extra machinery.

Client-side failover needs none of it, and the caller can distinguish a deterministic refusal from an outage, which a DNS health check cannot.

---

## Smoke Tests

**Self mode:**

```bash
curl -X POST <api_endpoint> \
  -H "Content-Type: application/json" \
  -d '{"token":"<github-actions-jwt>","role":"arn:aws:iam::111122223333:role/my-role"}'
```

**API GW mode:**

```bash
curl -X POST <api_endpoint> \
  -H "Authorization: Bearer <github-actions-jwt>" \
  -H "Content-Type: application/json" \
  -d '{"role":"arn:aws:iam::111122223333:role/my-role"}'
```

A successful response returns HTTP 200 with STS temporary credentials JSON.

---

## Operational Prerequisites

1. **Target-role trust policy:** Each role in `assumable_role_arns` must have a trust policy that allows the warden execution role (`execution_role_arn` output) to call `sts:AssumeRole` **and `sts:TagSession`**. The warden cannot grant itself this permission. `sts:TagSession` is required whenever the issuer has `session_tags` configured (e.g. `repo`, `actor`) — true by default for the GitHub shorthand — since AWS rejects an `AssumeRole` call carrying session tags unless the _target_ role's trust policy explicitly allows `sts:TagSession`, regardless of what the warden's own IAM policy grants it. Example trust policy statement:

   ```json
   {
     "Effect": "Allow",
     "Principal": { "AWS": "<execution_role_arn>" },
     "Action": ["sts:AssumeRole", "sts:TagSession"]
   }
   ```

2. **No VPC (default):** The Lambda runs outside any VPC and needs outbound internet access to fetch issuer JWKS (self/alb modes) or the ALB key endpoint (alb mode). If you later attach the Lambda to a VPC, provide a NAT gateway or VPC endpoint path.

3. **Cross-account trust:** With `cross_account.enabled = true`, AssumeRole goes direct — member-account target roles must trust the hub execution role for `sts:AssumeRole` and `sts:TagSession`, with no `sts:ExternalId` condition (the warden sends no external ID on direct assumes). Their ARNs/patterns go in `assumable_role_arns`. A convention-named spoke role (default `aow-spoke`) is only needed for cross-account `tag_auth`, where it acts as a tag-read broker with `iam:GetRole` only — it is never an assume target.

---

## Bucket Names

All S3 bucket names are suffixed with the AWS account ID for global uniqueness:

```
<name_prefix>-config-<account-id>
<name_prefix>-cache-<account-id>
<name_prefix>-logs-<account-id>
<name_prefix>-session-policies-<account-id>
```

Override the suffix with `var.bucket_suffix` if your naming convention requires it, or set a bucket's full name directly with `var.config_bucket_name` / `cache_bucket_name` / `log_bucket_name` / `session_policy_bucket_name`. The IAM role (`var.role_name`), Lambda function (`var.lambda_function_name`), API Gateway (`var.api_gateway_name`), and DynamoDB cache table (`var.cache_table_name`) have the same kind of override — each defaults to a `name_prefix`-derived name when left unset. `var.execution_role_arn` goes one step further: it reuses a role owned elsewhere instead of naming one this stack creates (see [One execution role](#one-execution-role-shared-by-both-regions)).

---

## CloudFormation Quick-Start

Infra parity with the OpenTofu stack (both API Gateway flavors, WAF, throttling, reserved concurrency, all cache backends, optional buckets). The one difference: CloudFormation cannot render `config.yaml` — you upload it to the config bucket yourself (step 3).

### 1. Build and upload the zip

```bash
make build-apigateway           # or make build-apigatewayv2 for apigw mode
cp build/bootstrap-apigateway /tmp/bootstrap
chmod 755 /tmp/bootstrap
cd /tmp && zip function.zip bootstrap
aws s3 cp /tmp/function.zip s3://<your-bucket>/aws-oidc-warden/function.zip
```

### 2. Deploy the stack

```bash
aws cloudformation deploy \
  --template-file deploy/cloudformation/quickstart.yaml \
  --stack-name aws-oidc-warden \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    LambdaCodeBucket=<your-bucket> \
    LambdaCodeKey=aws-oidc-warden/function.zip \
    AssumableRoleArns=arn:aws:iam::111122223333:role/github-actions-example \
    JWTValidationMode=self
```

For the hardened multi-issuer posture (REST API + WAF), add:

```
    ApiGatewayType=rest \
    EnableWAF=true
```

### 3. Upload config.yaml

By default the stack creates `<FunctionName>-config-<account-id>` (the `ConfigBucketName` output; set `ConfigBucket` to bring your own). `issuers[]` and `role_mappings` must come from this object — there are no `AOW_ISSUER`/`AOW_AUDIENCES` env vars, so the stack denies every request until it exists (see `example-config.yaml` at the repo root):

```bash
aws s3 cp config.yaml s3://<ConfigBucketName>/config.yaml
```

The `ApiEndpoint` stack output is the verify URL, and `ExecutionRoleArn` is the role your target roles must trust.

**`JWTValidationMode=apigw` note:** this template provisions exactly **one** JWT Authorizer, from the `JWTAuthorizerIssuer`/`JWTAuthorizerAudiences` parameters — it has no way to see inside the `config.yaml` you upload, so nothing checks that `JWTAuthorizerIssuer` actually matches one of your `issuers[].issuer` entries. If it doesn't, the stack still deploys and the endpoint still comes up, but every request 401s with `ErrUnknownIssuer` (the authorizer's verified `iss` has to exist in `issuers[]`). Multi-issuer `apigw` (one authorizer/route per issuer) needs the OpenTofu stack instead — this template stays single-issuer.

### Parameter mapping

CloudFormation parameters mirror the OpenTofu variables (`ApiGatewayType`, `EnableWAF`, `WAFRateLimit`, `WAFCommonRuleSet`, `ThrottlingBurstLimit`/`ThrottlingRateLimit`, `ReservedConcurrency`, `EnableDynamoDBCache`/`EnableS3Cache`/`CacheTTL`, `EnableS3Logs`, `AuditLogRetentionDays`/`AuditLogObjectLockMode`/`AuditLogObjectLockDays`, `EnableSessionPolicyBucket`, `EnableTagAuth`, `LogRetentionDays`, `BucketSuffix`), with the same defaults and the same plan-time assertions (WAF↔REST, apigw↔HTTP, cache exclusivity). Not parameters because they live elsewhere:

- `region`/`tags` — set via the AWS CLI (`--region`, `--tags`).
- `issuer`, `audiences`, `role_mappings`, `tag_auth` details, `cross_account` — belong in the uploaded `config.yaml` (OpenTofu renders these; CloudFormation cannot). `EnableTagAuth` still exists to grant the IAM side (`iam:GetRole`).
- `force_destroy_buckets` — no CloudFormation equivalent; empty buckets manually before stack deletion.

---

## Advanced: Remote State Backend

The `versions.tf` stub supports any S3-compatible backend. Uncomment and fill in:

```hcl
backend "s3" {
  bucket = "my-tf-state"
  key    = "aws-oidc-warden/terraform.tfstate"
  region = "eu-west-1"
}
```
