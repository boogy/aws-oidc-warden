> [!WARNING]
> This project is still under active development and may not be production-ready. Features and functionality are subject to change. Use with caution and check back for updates.

[![Build](https://github.com/boogy/aws-oidc-warden/actions/workflows/build.yml/badge.svg?style=flat)](https://github.com/boogy/aws-oidc-warden/actions/workflows/build.yml) [![CodeQL](https://github.com/boogy/aws-oidc-warden/actions/workflows/codeql.yml/badge.svg)](https://github.com/boogy/aws-oidc-warden/actions/workflows/codeql.yml) [![Docker Pulls](https://img.shields.io/docker/pulls/boogy/aws-oidc-warden)](https://hub.docker.com/r/boogy/aws-oidc-warden) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Dependabot](https://img.shields.io/badge/Dependabot-enabled-brightgreen?logo=dependabot)](https://github.com/boogy/aws-oidc-warden/security/dependabot) [![Go Version](https://img.shields.io/github/go-mod/go-version/boogy/aws-oidc-warden)](https://github.com/boogy/aws-oidc-warden/blob/main/go.mod)

# AWS OIDC Warden

![AWS OIDC Warden Architecture](./docs/img/aws-oidc-warden.png)

## Overview

**AWS OIDC Warden** is a secure, lightweight Go service that validates OIDC tokens (e.g. GitHub Actions) and exchanges them for short-lived AWS credentials via STS AssumeRole. It acts as a trusted intermediary between CI/CD workflows and AWS resources, enforcing fine-grained access control based on repository, branch, actor, and other configurable constraints — without storing long-lived credentials.

> [!CAUTION]
> Not all OIDC claims can be trusted. See the great tool and table created [PaloAltoNetworks/GitHub OIDC Utils](https://github.com/PaloAltoNetworks/github-oidc-utils) for a comprehensive list of claims.
>
> This lambda allows you to include specific constraints for a repository before it can obtain credentials from a role. Choose wisely based on the table that Palo Alto Networks has provided in the repository linked above.

---

## Documentation

| Document                                                           | What's inside                                                                         |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------------------- |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md)                     | Full config reference — all keys, env vars, remote S3 reload, cache, session policies |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)                       | Component diagram, deployment options, full build/deploy commands                     |
| [docs/SESSION_TAGGING.md](docs/SESSION_TAGGING.md)                 | Session tags applied to every STS call, ABAC patterns                                 |
| [docs/TAG_BASED_AUTHORIZATION.md](docs/TAG_BASED_AUTHORIZATION.md) | Tag-based authorization, hub/spoke cross-account model                                |

---

## Features

- **Universal OIDC Validation**: Validates tokens from GitHub Actions and any OIDC provider with JWKS endpoints
- **Multiple Deployment Options**: API Gateway, Lambda URLs, Application Load Balancer, and a local development server
- **Fine-Grained Access Control**: Regex-based repo/branch/actor/event/workflow constraints; all constraints are AND-ed
- **Session Policy Support**: Inline JSON or S3-stored policy files to scope AWS permissions per-repo
- **Session Tagging & ABAC**: GitHub claims are forwarded as STS session tags for auditability and attribute-based access control — see [docs/SESSION_TAGGING.md](docs/SESSION_TAGGING.md)
- **Tag-Based Authorization & Cross-Account (hub/spoke)**: Authorize role assumptions via IAM role tags without enumerating roles in config; extend to other AWS accounts through a spoke role — see [docs/TAG_BASED_AUTHORIZATION.md](docs/TAG_BASED_AUTHORIZATION.md)
- **Hot Config Reload**: Update `repo_role_mappings` and session policies in S3 without redeploying — the Lambda picks up changes within the configured interval (see [docs/CONFIGURATION.md](docs/CONFIGURATION.md))
- **Multi-Tier Caching**: Memory (LRU), DynamoDB (persistent/shared), and S3 backends for JWKS
- **Multi-Architecture Support**: Native ARM64 and AMD64 builds; pre-built container images on GHCR

---

## Getting Started

### Installation

1. Clone the repository:

   ```bash
   git clone git@github.com:boogy/aws-oidc-warden.git
   cd aws-oidc-warden
   ```

2. Install dependencies:

   ```bash
   go mod tidy
   ```

3. Build the binary:
   ```bash
   make build
   ```

**Alternative methods:**

- **Pre-built binaries**: [Releases](https://github.com/boogy/aws-oidc-warden/releases) page
- **Container images**: `ghcr.io/boogy/aws-oidc-warden:latest` (see [Deployment](#deploying-to-aws-lambda))
- **Build with ko**: `make ko-build`

---

### Configuration

AWS OIDC Warden reads config from environment variables (`AOW_` prefix), a YAML/JSON/TOML file, or an S3 object. A minimal example:

```yaml
issuer: https://token.actions.githubusercontent.com
audiences:
  - sts.amazonaws.com

cache:
  type: dynamodb
  ttl: 1h
  dynamodb_table: aws-oidc-warden-cache

repo_role_mappings:
  - repo: "my-org/my-repo"
    roles:
      - arn:aws:iam::123456789012:role/github-actions-role
    constraints:
      branch: "refs/heads/main"
```

For the full reference — all keys, constraint fields, session-policy options, remote S3 hot-reload, and tag-auth config — see [docs/CONFIGURATION.md](docs/CONFIGURATION.md) and [`example-config.yaml`](example-config.yaml).

---

### Usage

#### Request Format

Send a POST request with the OIDC token and desired AWS role ARN:

```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "role": "arn:aws:iam::123456789012:role/github-actions-role"
}
```

#### Running Locally

```bash
# Start local development server (default port 8080)
make run

# With custom options
go run cmd/local/main.go -port 9090 -config example-config.yaml -log-level debug
```

The local server loads config at startup from a static provider — there is no live S3 hot-reload locally. Hot-reload is a Lambda deployment feature; see [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

Endpoints:

- `POST /verify` — token validation (matches Lambda behavior)
- `GET /health` — health check

#### Using in GitHub Actions Workflows

The recommended approach uses `@actions/core` to request an OIDC token with a specific audience:

```yaml
name: AWS Deployment

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Get AWS credentials via OIDC warden
        uses: actions/github-script@v7
        with:
          script: |
            const core = require('@actions/core');
            const token = await core.getIDToken('sts.amazonaws.com');

            const response = await fetch('https://your-api-gateway-url.execute-api.region.amazonaws.com/prod/verify', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                token: token,
                role: 'arn:aws:iam::123456789012:role/github-actions-role'
              })
            });

            const { data } = await response.json();
            core.setSecret(data.AccessKeyId);
            core.setSecret(data.SecretAccessKey);
            core.setSecret(data.SessionToken);
            core.exportVariable('AWS_ACCESS_KEY_ID', data.AccessKeyId);
            core.exportVariable('AWS_SECRET_ACCESS_KEY', data.SecretAccessKey);
            core.exportVariable('AWS_SESSION_TOKEN', data.SessionToken);

      - name: Use AWS credentials
        run: aws sts get-caller-identity
```

> **curl alternative**: You can also call the endpoint directly via `curl` using `$ACTIONS_ID_TOKEN_REQUEST_URL`. The `@actions/core` method above is preferred for cleaner audience control.

#### Deploying to AWS Lambda

Three deployment modes are available — API Gateway (recommended for production), Lambda URLs (simple setups), and ALB (high traffic). All share the same core logic; only the entry point differs.

**Quickstart with pre-built container images (recommended):**

```bash
# API Gateway variant
aws lambda create-function \
  --function-name aws-oidc-warden \
  --package-type Image \
  --code ImageUri=ghcr.io/boogy/aws-oidc-warden:latest \
  --role arn:aws:iam::ACCOUNT:role/lambda-execution-role

# ALB variant
aws lambda create-function \
  --function-name aws-oidc-warden-alb \
  --package-type Image \
  --code ImageUri=ghcr.io/boogy/aws-oidc-warden:alb-latest \
  --role arn:aws:iam::ACCOUNT:role/lambda-execution-role

# Lambda URL variant
aws lambda create-function \
  --function-name aws-oidc-warden-lambdaurl \
  --package-type Image \
  --code ImageUri=ghcr.io/boogy/aws-oidc-warden:lambdaurl-latest \
  --role arn:aws:iam::ACCOUNT:role/lambda-execution-role
```

For full build commands, ECR pull-through cache setup, and infrastructure details see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Tag-Based Authorization (Cross-Account)

Tag-based authorization lets a repository assume an IAM role authorized by **tags on the role itself**, without listing the role in `repo_role_mappings`. This is especially useful when roles are managed across many accounts or teams: add `aow/repo`, `aow/ref`, and similar tags to the IAM role and the warden will evaluate them against the OIDC claims.

For cross-account (hub/spoke) scenarios, the warden reads and assumes roles in member accounts by first assuming a convention-named spoke role (`aow-spoke` by default) in the target account. Explicit `repo_role_mappings` are always evaluated first; tag-auth is a fallback path only.

The feature is opt-in (`tag_auth.enabled: true`, default `false`) and supports transitive session tags, a target-account allow-list, and an external ID for spoke-role trust. See [docs/TAG_BASED_AUTHORIZATION.md](docs/TAG_BASED_AUTHORIZATION.md) for setup, tag reference, and IAM examples.

---

## API Responses

### Success Response

```json
{
  "success": true,
  "statusCode": 200,
  "requestId": "12258876-a981-452b-a7ae-415f8fa737b6",
  "processingMs": 254,
  "message": "Token validation successful and role assumed",
  "data": {
    "AccessKeyId": "ASIA1234567890EXAMPLE",
    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "SessionToken": "FwoGZXIvYXdzEPH//////////wEaDKLZ3MQOJZBKxR1JDiLBARJhUlx1g09xLW+oIYHDt15IZY4...",
    "Expiration": "2023-09-29T20:31:14Z"
  }
}
```

### Error Response

```json
{
  "success": false,
  "statusCode": 403,
  "requestId": "12258876-a981-452b-a7ae-415f8fa737b6",
  "processingMs": 383,
  "message": "Permission denied for the requested operation",
  "errorCode": "permission_denied",
  "errorDetails": "role not allowed for repository or doesn't meet constraints"
}
```

---

## Security Considerations

- Use specific repository patterns; avoid overly broad patterns like `.*`
- Apply multiple constraints for sensitive roles, and session policies to scope AWS permissions
- Follow least-privilege when defining IAM roles; review CloudWatch logs regularly

Session tags (`repo`, `actor`, `ref`, `event-name`, `repo-owner`, `ref-type`) are attached to every STS session for auditing, cost allocation, and ABAC — see [docs/SESSION_TAGGING.md](docs/SESSION_TAGGING.md).

---

## How It Works

1. **Receive Request**: GitHub Actions sends OIDC token + role ARN
2. **Fetch JWKS**: JWKS retrieved (from cache if available) and token signature verified
3. **Validate Token**: Issuer, audience, and expiration checked
4. **Check Repository Mapping**: Repository claim matched against configured patterns
5. **Apply Constraints**: Branch, actor, and other constraints evaluated
6. **Apply Session Policy**: Optional custom session policy applied
7. **Assume Role**: AWS role assumed with session tags ([AWS Role Session Tags](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html))
8. **Return Credentials**: Temporary AWS credentials returned

---

## Troubleshooting

- **Token validation fails** — ensure the workflow has `id-token: write`; verify the repository name matches your configured patterns and the issuer/audience settings.
- **Role assumption fails** — confirm the Lambda execution role can assume the target role; check for conflicting constraints or overly restrictive session policies.
- **Cache issues** — DynamoDB needs a TTL field configured; S3 needs bucket read/write; raise `max_local_size` for high traffic.
- **Tag-auth / cross-account** — set `tag_auth.enabled: true`, ensure the spoke role (`aow-spoke` by default) exists in each member account and trusts the hub Lambda role, grant `iam:GetRole`, and list the target account in `tag_auth.allowed_accounts` if used. See [docs/TAG_BASED_AUTHORIZATION.md](docs/TAG_BASED_AUTHORIZATION.md).

---

## Contributing

1. Fork the repository
2. Clone your fork: `git clone git@github.com:your-username/aws-oidc-warden.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make changes and write tests
5. Run checks: `make check`
6. Submit a pull request with a clear description

> [!TIP]
> If you find a bug please don't just create an issue. Create a pull request with your fix so that everyone can benefit from it.

---

## AWS Infrastructure Requirements

- **Lambda Function** — runs the validator service
- **IAM Role for Lambda** — assume target roles (`sts:AssumeRole`, `sts:TagSession`), read role tags for tag-auth (`iam:GetRole`), DynamoDB cache access, S3 read/write (logs/policies), and CloudWatch Logs
- **DynamoDB Table** — persistent caching (optional)
- **S3 Bucket** — logs and session policies (optional)

> [!TIP]
> A generic role with broader privileges can be given to Lambda, then scoped per-repo with session policies. This reduces the total number of IAM roles needed.

For the complete IAM policy and infrastructure details, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#required-iam-permissions).

---

## License

This project is licensed under the Apache License 2.0.

---

## Acknowledgments

- This project started from the need for secure GitHub Actions integration with AWS at scale for thousands of repositories.
- Inspired by [AOEpeople/lambda_token_auth](https://github.com/AOEpeople/lambda_token_auth)
- Thanks to [PaloAltoNetworks/GitHub OIDC Utils](https://github.com/PaloAltoNetworks/github-oidc-utils) for their research on GitHub OIDC claims
- Thanks to Jonathan for the tool name inspiration
