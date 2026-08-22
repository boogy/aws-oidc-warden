# AWS OIDC Warden — Deployment Guide

Two deployment paths are provided: **OpenTofu** and **CloudFormation**. Both provision the same infrastructure (either API Gateway flavor, WAF, throttling, caches, optional buckets); the one functional difference is that OpenTofu also renders and uploads `config.yaml`, while with CloudFormation you upload it yourself.

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

`main.tf` renders a v2 config — `var.issuers` (or, if unset, the `var.issuer`/`var.audiences` shorthand rendered as a single GitHub `issuers[]` entry), `var.role_mappings`, cache settings, and `jwt_validation` — into a `config.yaml` object and uploads it to the config S3 bucket. Each `var.role_mappings` entry may set `role_session_name` to override the global `var.role_session_name` for the roles it grants, so CloudTrail names the requester instead of the service — STS accepts 2–64 characters from `[\w+=,.@-]` (no `/`, so a repository name cannot be used verbatim); an invalid value fails the service at boot. `role_groups`, the analogous DRY convenience for many subjects sharing one set of defaults, is a `config.yaml`-only feature — it is not exposed as a Terraform variable in this module. The Lambda receives three env vars at startup:

- `AOW_S3_CONFIG_BUCKET` — bucket name
- `AOW_S3_CONFIG_PATH` — object key (`config.yaml`)
- `AOW_JWT_VALIDATION_MODE` — set from `var.jwt_validation_mode`; the extractor implementation is wired at cold start from this env var, not from `config.yaml` (which is hot-reloadable), so it must match the deployed Lambda binary variant

On startup the Lambda fetches and parses this file. All complex configuration (repo mappings, nested objects) lives here; scalar overrides can also be set via `AOW_*` env vars.

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

**Security note (apigw mode):** The Lambda resource policy (`source_arn = <api>.execute-api.<region>.amazonaws.com/*/*`) restricts invocations to the provisioned API Gateway — direct Lambda invocations are rejected by the resource policy and also by the application when authorizer claims are absent.

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

Override the suffix with `var.bucket_suffix` if your naming convention requires it.

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

By default the stack creates `<FunctionName>-config-<account-id>` (the `ConfigBucketName` output; set `ConfigBucket` to bring your own). `issuers[]` and `role_mappings` must come from this object — v2 has no `AOW_ISSUER`/`AOW_AUDIENCES` env vars, so the stack denies every request until it exists (see `docs/example-config.yaml`):

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
