# AWS OIDC Warden — Deployment Guide

Two deployment paths are provided: **OpenTofu** (full-featured, recommended) and **CloudFormation** (quick-start for common cases).

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

| Variable                       | Default | Provisions                                            | IAM granted                                      |
| ------------------------------ | ------- | ----------------------------------------------------- | ------------------------------------------------ |
| `enable_dynamodb_cache`        | `false` | DynamoDB table `<prefix>-cache`                       | `dynamodb:GetItem/PutItem/DeleteItem`            |
| `enable_s3_cache`              | `false` | S3 bucket `<prefix>-cache-<suffix>`                   | `s3:GetObject/PutObject/DeleteObject/ListBucket` |
| `enable_s3_logs`               | `false` | S3 bucket `<prefix>-logs-<suffix>` (90-day lifecycle) | `s3:PutObject`                                   |
| `enable_session_policy_bucket` | `false` | S3 bucket `<prefix>-session-policies-<suffix>`        | `s3:GetObject`                                   |
| `tag_auth.enabled`             | `false` | No new resources                                      | `iam:GetRole`, `iam:ListRoleTags`                |

**Cache backends are mutually exclusive.** `enable_dynamodb_cache` and `enable_s3_cache` cannot both be `true`; a `precondition` enforces this at plan time. Leaving both `false` uses in-memory cache (suitable for low traffic; cache lost on cold start).

---

## How config.yaml is delivered

`main.tf` renders a v2 config — `var.issuer`/`var.audiences` as a single GitHub `issuers[]` entry, `var.role_mappings`, cache settings, and `jwt_validation` — into a `config.yaml` object and uploads it to the config S3 bucket. The Lambda receives two env vars at startup:

- `AOW_S3_CONFIG_BUCKET` — bucket name
- `AOW_S3_CONFIG_PATH` — object key (`config.yaml`)

On startup the Lambda fetches and parses this file. All complex configuration (repo mappings, nested objects) lives here; scalar overrides can also be set via `AOW_*` env vars.

---

## JWT Validation Mode

| Mode                | `jwt_validation_mode` | Binary         | Infra provisioned          | Request format                                                                     |
| ------------------- | --------------------- | -------------- | -------------------------- | ---------------------------------------------------------------------------------- |
| **Self** (default)  | `"self"`              | `apigateway`   | No extra infra             | `POST /verify` body: `{"token":"<jwt>","role":"<arn>"}`                            |
| **API GW delegate** | `"apigw"`             | `apigatewayv2` | JWT Authorizer on HTTP API | `POST /verify` with `Authorization: Bearer <jwt>` header; body: `{"role":"<arn>"}` |

> **ALB mode is not supported by this stack.** `jwt_validation.mode: "alb"` requires the `alb` Lambda binary (`make build-alb`) deployed behind an Application Load Balancer, which neither the OpenTofu module nor the CloudFormation template provisions. The `apigateway` binary refuses to start in `alb` mode.

Build the correct binary before running `tofu apply`:

```bash
./deploy/opentofu/build.sh              # self mode
./deploy/opentofu/build.sh apigatewayv2 # apigw mode
```

**Security note (apigw mode):** The Lambda resource policy (`source_arn = <api>.execute-api.<region>.amazonaws.com/*/*`) restricts invocations to the provisioned API Gateway — direct Lambda invocations are rejected by the resource policy and also by the application when authorizer claims are absent.

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

1. **Target-role trust policy:** Each role in `assumable_role_arns` must have a trust policy that allows the warden execution role (`execution_role_arn` output) to call `sts:AssumeRole`. The warden cannot grant itself this permission.

2. **No VPC (default):** The Lambda runs outside any VPC and needs outbound internet access to fetch issuer JWKS (self/alb modes) or the ALB key endpoint (alb mode). If you later attach the Lambda to a VPC, provide a NAT gateway or VPC endpoint path.

3. **Tag-auth hub/spoke:** For cross-account `tag_auth`, member-account `aow-spoke` roles must trust the hub execution role. The hub IAM policy must list the spoke ARN pattern (e.g. `arn:aws:iam::*:role/aow-spoke`) in `assumable_role_arns`.

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

For a faster, less-configurable deploy (covers the common self-validation case):

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

The `ApiEndpoint` stack output is the verify URL.

> CloudFormation covers the common case only, and `ConfigBucket`/`ConfigKey` are effectively required: v2 has no `AOW_ISSUER`/`AOW_AUDIENCES` env vars, so `issuers[]` and `role_mappings` must come from a `config.yaml` you upload separately. Use OpenTofu if you want the config rendered automatically.

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
