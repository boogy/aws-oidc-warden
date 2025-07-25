# AWS OIDC Warden Configuration

This document explains how to configure AWS OIDC Warden using environment variables and configuration files.

## Configuration Methods

AWS OIDC Warden can be configured using:

1. Environment variables (prefixed with `AOW_`)
2. Configuration file (YAML or JSON)
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
| `AOW_SESSION_POLICY_BUCKET` | `session_policy_bucket` | S3 bucket for session policies              |                                               |

> **Note**: You can use either `audience` (single) or `audiences` (multiple). If both are specified, `audiences` takes precedence. For new deployments, use `audiences` for better flexibility.

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

### Logging Settings

| Environment Variable | Config File Key | Description                              | Default |
| -------------------- | --------------- | ---------------------------------------- | ------- |
| `AOW_LOG_TO_S3`      | `log_to_s3`     | Enable S3 logging                        | `false` |
| `AOW_LOG_BUCKET`     | `log_bucket`    | S3 bucket for logs                       |         |
| `AOW_LOG_PREFIX`     | `log_prefix`    | S3 key prefix for logs                   |         |
| `LOG_LEVEL`          | N/A             | Logging level (debug, info, warn, error) | `info`  |

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
const core = require('@actions/core');

// Request token for AWS STS
const awsToken = await core.getIDToken('sts.amazonaws.com');

// Request token for custom API
const apiToken = await core.getIDToken('https://api.mycompany.com');
```

The AWS OIDC Warden will validate tokens against any of the configured audiences. If the token's audience matches any of the expected audiences, validation succeeds.

## Configuration File Format

AWS OIDC Warden supports both YAML and JSON configuration files. Here's an example YAML configuration:

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
