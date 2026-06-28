# AWS OIDC Warden Configuration

This document explains how to configure AWS OIDC Warden using environment variables and configuration files.

## Configuration Methods

AWS OIDC Warden can be configured using:

1. Environment variables (prefixed with `AOW_`)
2. Configuration file (YAML, JSON, or TOML)
3. A combination of both (environment variables override config file values)

## Configuration Options

### Core Settings

| Environment Variable        | Config File Key         | Description                                 | Default                                       |
| --------------------------- | ----------------------- | ------------------------------------------- | --------------------------------------------- |
| `AOW_ISSUER`                | `issuer`                | OIDC issuer URL                             | `https://token.actions.githubusercontent.com` |
| `AOW_AUDIENCE`              | `audience`              | Expected audience for tokens (legacy)       | `sts.amazonaws.com`                           |
| `AOW_AUDIENCES`             | `audiences`             | Expected audiences for tokens (recommended) | `["sts.amazonaws.com"]`                       |
| `AOW_ROLE_SESSION_NAME`     | `role_session_name`     | AWS role session name                       | `aws-oidc-warden`                             |
| `AOW_S3_CONFIG_BUCKET`      | `s3_config_bucket`      | S3 bucket for config file                   |                                               |
| `AOW_S3_CONFIG_PATH`        | `s3_config_path`        | Path to config file in S3                   |                                               |
| `AOW_CONFIG_RELOAD_INTERVAL`| `config_reload_interval`| Hot-reload the S3 config at most this often (e.g. `5m`); `0` disables | `0` (disabled)                   |
| `AOW_SESSION_POLICY_BUCKET` | `session_policy_bucket` | S3 bucket for session policies              |                                               |

> **Note**: You can use either `audience` (single) or `audiences` (multiple). If both are specified, `audiences` takes precedence. For new deployments, use `audiences` for better flexibility.

> **Hot-reloading config without redeploying**: When `s3_config_bucket`/`s3_config_path` are set and `config_reload_interval` > 0, the running service re-fetches the S3 config object at most once per interval (checked lazily per request via `MaybeRefresh`) and atomically swaps it in. Update the object and changes take effect within the interval — no redeploy or container recycle needed. The S3 object uses the **same snake_case schema as the config file** (`repo_role_mappings`, `constraints`, etc.) and is re-validated on every reload; an invalid or unreachable config is logged and the previous config is kept. The token validator reads `issuer` and `audiences` live from the provider on every request, so hot-reloaded changes to those fields take effect immediately without a restart.

### Cache Settings

| Environment Variable       | Config File Key        | Description                       | Default  |
| -------------------------- | ---------------------- | --------------------------------- | -------- |
| `AOW_CACHE_TYPE`           | `cache.type`           | Cache type (memory, dynamodb, s3) | `memory` |
| `AOW_CACHE_TTL`            | `cache.ttl`            | Cache TTL                         | `1h`     |
| `AOW_CACHE_MAX_LOCAL_SIZE` | `cache.max_local_size` | Max size for memory cache         | `10`     |
| `AOW_CACHE_DYNAMODB_TABLE` | `cache.dynamodb_table` | DynamoDB table name               |          |
| `AOW_CACHE_S3_BUCKET`      | `cache.s3_bucket`      | S3 bucket name                    |          |
| `AOW_CACHE_S3_PREFIX`      | `cache.s3_prefix`      | S3 key prefix                     |          |
| `AOW_CACHE_S3_CLEANUP`     | `cache.s3_cleanup`     | Clean up old cache objects        | `false`  |

### Tag-Based Authorization Settings

Optional, disabled by default. When enabled, a repo may assume a role whose IAM tags authorize its OIDC claims, even if the role is not listed in `repo_role_mappings`. Roles in other accounts are reached via a per-account spoke role. See [TAG_BASED_AUTHORIZATION.md](TAG_BASED_AUTHORIZATION.md) for the tag reference and IAM setup.

| Environment Variable                  | Config File Key                  | Description                                              | Default     |
| ------------------------------------- | -------------------------------- | ------------------------------------------------------- | ----------- |
| `AOW_TAG_AUTH_ENABLED`                | `tag_auth.enabled`               | Enable tag-based authorization + cross-account assume   | `false`     |
| `AOW_TAG_AUTH_TAG_PREFIX`             | `tag_auth.tag_prefix`            | Namespace prefix for authorization tag keys             | `aow/`      |
| `AOW_TAG_AUTH_DEFAULT_ORG`            | `tag_auth.default_org`           | Org prefix for bare `aow/repo` tokens (e.g. `"api"` → `"<org>/api"`); empty = no expansion | (empty) |
| `AOW_TAG_AUTH_SPOKE_ROLE_NAME`        | `tag_auth.spoke_role_name`       | Role assumed in each member account for cross-account   | `aow-spoke` |
| `AOW_TAG_AUTH_EXTERNAL_ID`            | `tag_auth.external_id`           | Optional external ID for the hub→spoke trust            |             |
| `AOW_TAG_AUTH_SPOKE_SESSION_DURATION` | `tag_auth.spoke_session_duration`| Hub→spoke session length                                | `15m`       |
| `AOW_TAG_AUTH_TRANSITIVE_SESSION_TAGS` | `tag_auth.transitive_session_tags` | Mark repo/ref/actor session tags transitive (immutable through role chaining) | `false` |
| `AOW_TAG_AUTH_ALLOWED_ACCOUNTS`        | `tag_auth.allowed_accounts`        | Comma-separated member account IDs allowed as assume targets (hub always allowed; empty = any) | (empty) |

### Logging Settings

| Environment Variable | Config File Key | Description                              | Default |
| -------------------- | --------------- | ---------------------------------------- | ------- |
| `AOW_LOG_TO_S3`      | `log_to_s3`     | Enable S3 logging                        | `false` |
| `AOW_LOG_BUCKET`     | `log_bucket`    | S3 bucket for logs                       |         |
| `AOW_LOG_PREFIX`     | `log_prefix`    | S3 key prefix for logs                   |         |
| `LOG_LEVEL`          | N/A             | Logging level (debug, info, warn, error) | `info`  |

### JWT Validation Mode Settings

| Environment Variable | Config File Key | Description | Default |
| -------------------- | --------------- | ----------- | ------- |
| `AOW_JWT_VALIDATION_MODE` | `jwt_validation.mode` | JWT validation mode (`"self"`, `"apigw"`, or `"alb"`) | `"self"` |
| `AOW_JWT_VALIDATION_ALB_EXPECTED_SIGNER` | `jwt_validation.alb_expected_signer` | ARN of the trusted ALB (ALB mode only, recommended) | (empty) |

### Other Settings

| Environment Variable | Default Value                                        | Description                          | Default  |
| -------------------- | ---------------------------------------------------- | ------------------------------------ | -------- |
| `CONFIG_NAME`        | `config`                                             | Config file name (without extension) | `config` |
| `CONFIG_PATH`        | <ul><li>/etc/aws-oidc-warden/</li><li>$PWD</li></ul> | Config file path                     | `config` |

## Audience Configuration

AWS OIDC Warden supports both single and multiple audience configurations to validate OIDC tokens against different expected audiences.

### Single Audience (Legacy)

```yaml
# Legacy configuration - single audience
issuer: https://token.actions.githubusercontent.com
audience: sts.amazonaws.com
```

```bash
# Environment variable
export AOW_AUDIENCE=sts.amazonaws.com
```

### Multiple Audiences

```yaml
# New configuration - multiple audiences
issuer: https://token.actions.githubusercontent.com
audiences:
  - sts.amazonaws.com
  - https://api.mycompany.com
  - internal.mycompany.com
```

```bash
# Environment variable (comma-separated)
export AOW_AUDIENCES=sts.amazonaws.com,https://api.mycompany.com,internal.mycompany.com
```

### Backward Compatibility

- If only `audience` is specified, it will be automatically converted to `audiences: [audience]`
- If both `audience` and `audiences` are specified, `audiences` takes precedence
- For new deployments, use `audiences` for better flexibility

### Use Cases

1. **AWS STS Only**: For standard GitHub Actions to AWS integration

   ```yaml
   audiences: ["sts.amazonaws.com"]
   ```

2. **Multiple APIs**: When tokens need to work with various services

   ```yaml
   audiences:
     - sts.amazonaws.com
     - https://api.company.com
     - https://vault.company.com
   ```

3. **Internal Services**: For internal service-to-service authentication
   ```yaml
   audiences:
     - internal.company.com
     - microservice.company.internal
   ```

### GitHub Actions Integration

When using multiple audiences, GitHub Actions workflows can request tokens for specific audiences:

```javascript
const core = require("@actions/core");

// Request token for AWS STS
const awsToken = await core.getIDToken("sts.amazonaws.com");

// Request token for custom API
const apiToken = await core.getIDToken("https://api.mycompany.com");
```

The AWS OIDC Warden will validate tokens against any of the configured audiences. If the token's audience matches any of the expected audiences, validation succeeds.

## JWT Validation Mode

AWS OIDC Warden supports three JWT validation modes, selectable via the `jwt_validation.mode` configuration option:

### 1. Self Mode (Default)

**Mode**: `"self"`

This is the default and most straightforward mode. The service performs full JWT signature verification locally using JWKS keys fetched from the OIDC provider.

**When to use:**
- No trusted upstream service pre-validates tokens
- Full control over validation logic
- Direct Lambda URL or Lambda function invocations

**Request format:**
```bash
curl -X POST https://lambda-url.example.com \
  -H "Content-Type: application/json" \
  -d '{
    "token": "<full-github-actions-oidc-jwt>",
    "role": "arn:aws:iam::123456789012:role/MyRole"
  }'
```

**Configuration:**
```yaml
jwt_validation:
  mode: "self"
```

### 2. API Gateway HTTP API v2 Mode

**Mode**: `"apigw"`

Trust pre-validated JWT claims from API Gateway HTTP API v2 JWT Authorizer. The Lambda function receives authorizer-validated claims in the request context and skips re-validation.

**When to use:**
- API Gateway HTTP API v2 JWT Authorizer is configured upstream
- Avoiding duplicate JWT validation (API Gateway already verifies)
- Delegating signature verification to API Gateway

**Setup steps:**

1. **Create API Gateway JWT Authorizer:**
   - Issuer URL: `https://token.actions.githubusercontent.com`
   - Audience: One of the values in `audiences` config (e.g., `sts.amazonaws.com`)
   - Token source: `Authorization` header

2. **Deploy using API Gateway v2 binary:**
   ```bash
   make build-apigatewayv2
   # Deploy build/bootstrap-apigatewayv2 as Lambda function
   ```

3. **Restrict Lambda invocations:**
   Add a Lambda resource-based policy to allow only API Gateway execution role:
   ```json
   {
     "Effect": "Allow",
     "Principal": {
       "Service": "apigateway.amazonaws.com"
     },
     "Action": "lambda:InvokeFunction",
     "Resource": "arn:aws:lambda:region:account:function:function-name"
   }
   ```

4. **Configure the service:**
   ```yaml
   jwt_validation:
     mode: "apigw"
   ```

**Request format:**
When using API Gateway, the client sends the token in the `Authorization` header and only the role in the request body:
```bash
curl -X POST https://api.example.com/assume-role \
  -H "Authorization: Bearer <github-actions-oidc-jwt>" \
  -H "Content-Type: application/json" \
  -d '{"role": "arn:aws:iam::123456789012:role/MyRole"}'
```

**Security notes:**
- API Gateway validates the JWT signature before invoking Lambda
- Lambda must restrict invocations to API Gateway via resource-based policy (prevent direct invocation bypass)
- No token re-validation by Lambda; trust API Gateway's validation

### 3. ALB OIDC Mode

**Mode**: `"alb"`

Trust ALB OIDC authentication. The ALB signs OIDC tokens with ES256 and passes them in the `x-amzn-oidc-data` header. This service verifies the signature using the ALB's EC public key.

**When to use:**
- ALB is configured with GitHub OIDC as the identity provider
- Load balancer handles OIDC flow and token generation
- Need to validate ALB-signed tokens

**ALB Setup:**

1. **Configure ALB with GitHub OIDC:**
   - OIDC provider endpoint: `https://token.actions.githubusercontent.com`
   - Client ID: Use `sts.amazonaws.com` as the audience
   - Set ALB listener rule to authenticate via OIDC

2. **Deploy using ALB binary:**
   ```bash
   make build-alb
   # Deploy build/bootstrap-alb as Lambda function behind ALB
   ```

3. **Configure the service:**
   ```yaml
   jwt_validation:
     mode: "alb"
     alb_expected_signer: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/abc"
   ```

**Request format:**
ALB automatically injects the `x-amzn-oidc-data` header; clients send only the role:
```bash
# Client sends to ALB (no token needed in request)
curl -X POST https://alb.example.com/assume-role \
  -H "Content-Type: application/json" \
  -d '{"role": "arn:aws:iam::123456789012:role/MyRole"}'

# ALB intercepts, authenticates with GitHub OIDC, and injects x-amzn-oidc-data
# Lambda receives the OIDC token in the header
```

**Security notes:**
- ALB performs GitHub OIDC authentication and token generation
- Lambda verifies ALB-signed ES256 JWT from `x-amzn-oidc-data` header
- Set `alb_expected_signer` (ALB ARN) to prevent cross-ALB token injection
- `AWS_REGION` environment variable must be set (used for ALB public key lookup)

**Environment variables:**
```bash
export AWS_REGION=us-east-1
export AOW_JWT_VALIDATION_MODE=alb
export AOW_JWT_VALIDATION_ALB_EXPECTED_SIGNER="arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/abc"
```

## Configuration File Format

AWS OIDC Warden supports YAML, JSON, and TOML configuration files (format auto-detected via `FormatFromPath`). Here's an example YAML configuration:

```yaml
issuer: https://token.actions.githubusercontent.com
audience: sts.amazonaws.com
role_session_name: aws-oidc-warden
s3_config_bucket: my-config-bucket
s3_config_path: config/aws-oidc-warden.yaml
session_policy_bucket: my-policy-bucket
log_to_s3: true
log_bucket: my-log-bucket
log_prefix: logs/

cache:
  type: dynamodb
  ttl: 1h
  max_local_size: 20
  dynamodb_table: jwks-cache
  s3_bucket: my-cache-bucket
  s3_prefix: cache/
  s3_cleanup: true

repo_role_mappings:
  - repo: owner/repo1
    roles:
      - arn:aws:iam::123456789012:role/GitHubActionsRole
    constraints:
      branch: main
      event_name: push

  - repo: owner/repo2
    session_policy: |
      {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Effect": "Deny",
            "Action": ["iam:*"],
            "Resource": "*"
          }
        ]
      }
    roles:
      - arn:aws:iam::123456789012:role/ReadOnlyRole
    constraints:
      ref: refs/heads/dev
      workflow_ref: owner/repo/.github/workflows/deploy.yml
      actor_matches:
        - dependabot.*
        - github-actions.*
```
