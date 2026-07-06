[![Release](https://github.com/boogy/aws-oidc-warden/actions/workflows/release.yml/badge.svg?style=flat)](https://github.com/boogy/aws-oidc-warden/actions/workflows/release.yml) [![CodeQL](https://github.com/boogy/aws-oidc-warden/actions/workflows/codeql.yml/badge.svg)](https://github.com/boogy/aws-oidc-warden/actions/workflows/codeql.yml) [![Docker Pulls](https://img.shields.io/docker/pulls/boogy/aws-oidc-warden)](https://hub.docker.com/r/boogy/aws-oidc-warden) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Dependabot](https://img.shields.io/badge/Dependabot-enabled-brightgreen?logo=dependabot)](https://github.com/boogy/aws-oidc-warden/security/dependabot) [![Go Version](https://img.shields.io/github/go-mod/go-version/boogy/aws-oidc-warden)](https://github.com/boogy/aws-oidc-warden/blob/main/go.mod)

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

| Document                                                           | What's inside                                                                                                    |
| ------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------- |
| [docs/TOKEN_VALIDATION.md](docs/TOKEN_VALIDATION.md)               | **How token validation works** — the security core: modes, JWKS, crypto hardening, claim checks, SSRF protection |
| [docs/MULTI_ISSUER.md](docs/MULTI_ISSUER.md)                       | Onboard any OIDC provider — discovery, `provider`, `claim_mappings`, per-issuer audiences                        |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md)                     | Full config reference — all keys, env vars, remote S3 reload, cache, session policies                            |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)                       | Component diagram, request pipeline, deployment options, full build/deploy commands                              |
| [docs/SESSION_TAGGING.md](docs/SESSION_TAGGING.md)                 | Per-issuer session tags applied to every STS call, ABAC patterns                                                 |
| [docs/TAG_BASED_AUTHORIZATION.md](docs/TAG_BASED_AUTHORIZATION.md) | Tag-based authorization, hub/spoke cross-account model                                                           |
| [docs/LOGGING.md](docs/LOGGING.md)                                 | Structured logging, durable audit trail, `audit_required`, SIEM signals, alerts                                  |
| [docs/MIGRATION_V2.md](docs/MIGRATION_V2.md)                       | Upgrading from v1 (single-issuer) to the v2 `issuers[]` model — breaking-change checklist                        |

---

## Features

- **Multi-Issuer, Any-Provider Validation**: Trust any number of OIDC issuers at once (`issuers[]`); GitHub Actions has native support, and `provider: generic` onboards any OIDC IdP by mapping its claims — see [docs/MULTI_ISSUER.md](docs/MULTI_ISSUER.md)
- **Hardened Token Validation**: Strict algorithm allow-list (RS/ES 256–512, never `none`/`HS*`), `kid`+`alg`+key-type key pinning, RSA≥2048 / EC on-curve checks, SSRF-safe JWKS fetching, and bounded time/size — full detail in [docs/TOKEN_VALIDATION.md](docs/TOKEN_VALIDATION.md)
- **Delegated Validation Modes**: Let API Gateway (HTTP API v2 JWT Authorizer) or ALB OIDC verify the signature, while the service still re-validates every claim (`jwt_validation.mode: self`/`apigw`/`alb`)
- **Multiple Deployment Options**: API Gateway (REST v1 + HTTP v2), Lambda URLs, Application Load Balancer, and a local development server
- **Fine-Grained Access Control**: Authorization on a provider-neutral canonical **subject**; auto-anchored regex `conditions` on any verified claim (branch/actor/event/workflow/environment + arbitrary claims), all AND-ed
- **Session Policy Support**: Inline JSON or S3-stored policy files to scope AWS permissions per mapping
- **Per-Issuer Session Tagging & ABAC**: Claims are forwarded as STS session tags for auditability and attribute-based access control — see [docs/SESSION_TAGGING.md](docs/SESSION_TAGGING.md)
- **Tag-Based Authorization & Cross-Account (hub/spoke)**: Authorize role assumptions via IAM role tags without enumerating roles in config; extend to other AWS accounts through a spoke role — see [docs/TAG_BASED_AUTHORIZATION.md](docs/TAG_BASED_AUTHORIZATION.md)
- **Structured Audit Trail**: One JSON record per allow/deny decision, secret-safe redaction, and an optional fail-closed `audit_required` mode — see [docs/LOGGING.md](docs/LOGGING.md)
- **Hot Config Reload**: Update issuers, `role_mappings`, and session policies in S3 without redeploying — the Lambda picks up changes within the configured interval, fail-safe on a bad reload
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
issuers:
  - issuer: https://token.actions.githubusercontent.com
    provider: github
    audiences:
      - sts.amazonaws.com

cache:
  type: dynamodb
  ttl: 1h
  dynamodb_table: aws-oidc-warden-cache

role_mappings:
  - subject: "my-org/my-repo"
    roles:
      - arn:aws:iam::123456789012:role/github-actions-role
    conditions:
      branch: "refs/heads/main"
```

> **v2 note:** the top-level `issuer`/`audiences` and `repo_role_mappings`/`constraints` keys from v1 were replaced by `issuers[]`, `role_mappings`, and `conditions`. See [docs/MIGRATION_V2.md](docs/MIGRATION_V2.md).

For the full reference — all keys, condition fields, session-policy options, remote S3 hot-reload, multi-issuer setup, and tag-auth config — see [docs/CONFIGURATION.md](docs/CONFIGURATION.md), [docs/MULTI_ISSUER.md](docs/MULTI_ISSUER.md), and [`example-config.yaml`](example-config.yaml).

---

### Usage

#### Request Format

The wire contract depends on `jwt_validation.mode` — specifically, **who verifies the token**. The role ARN is always in the JSON body; the token's location differs.

| Mode             | `Authorization` header                | Request body                      | Token verified by          |
| ---------------- | ------------------------------------- | --------------------------------- | -------------------------- |
| `self` (default) | none                                  | `{"token": "...", "role": "..."}` | This service               |
| `apigw`          | `Authorization: Bearer <token>`       | `{"role": "..."}`                 | API Gateway JWT Authorizer |
| `alb`            | none — ALB injects `x-amzn-oidc-data` | `{"role": "..."}`                 | ALB OIDC                   |

> **The token is never sent twice.** In `apigw` mode it lives **only** in the `Authorization` header — a `token` field in the body is ignored (`ParseRoleOnlyRequestBody` reads only `role`), and a missing header makes API Gateway reject the call before this service runs. See [docs/TOKEN_VALIDATION.md §2.1](docs/TOKEN_VALIDATION.md#21-request-contract-per-mode).

**Self mode** (default) — POST the OIDC token and role ARN in the body:

```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "role": "arn:aws:iam::123456789012:role/github-actions-role"
}
```

**apigw mode** — send the token as a Bearer header (API Gateway validates it); the body carries only the role:

```http
POST /verify HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{"role": "arn:aws:iam::123456789012:role/github-actions-role"}
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

The recommended approach uses `@actions/core` to request an OIDC token with a specific audience. The example below targets **self mode** (token in the body). For **apigw mode**, see the variant that follows.

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

**apigw mode variant** — send the token as an `Authorization: Bearer` header (API Gateway's JWT Authorizer validates it) and put only the role in the body:

```yaml
- name: Get AWS credentials via OIDC warden (apigw mode)
  uses: actions/github-script@v7
  with:
    script: |
      const core = require('@actions/core');
      const token = await core.getIDToken('sts.amazonaws.com');

      const response = await fetch('https://your-api-gateway-url.execute-api.region.amazonaws.com/prod/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
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
```

The audience requested by `getIDToken(...)` must match the audience configured on both the API Gateway JWT Authorizer and this service's issuer.

#### Deploying to AWS Lambda

Four Lambda variants are available — API Gateway REST v1 (recommended for production, `self` mode), API Gateway HTTP v2 (`apigw` delegated mode), Lambda URLs (simple setups), and ALB (high traffic). All share the same core logic; only the entry point differs.

**Quickstart with pre-built container images (recommended):**

```bash
# API Gateway (REST v1) variant — self mode
aws lambda create-function \
  --function-name aws-oidc-warden \
  --package-type Image \
  --code ImageUri=ghcr.io/boogy/aws-oidc-warden:latest \
  --role arn:aws:iam::ACCOUNT:role/lambda-execution-role

# API Gateway (HTTP v2) variant — apigw mode (JWT Authorizer)
aws lambda create-function \
  --function-name aws-oidc-warden-apigwv2 \
  --package-type Image \
  --code ImageUri=ghcr.io/boogy/aws-oidc-warden:apigatewayv2-latest \
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

Tag-based authorization lets a repository assume an IAM role authorized by **tags on the role itself**, without listing the role in `role_mappings`. This is especially useful when roles are managed across many accounts or teams: add `aow/subject` (or the legacy `aow/repo`), `aow/ref`, and similar tags to the IAM role and the warden will evaluate them against the OIDC claims.

For cross-account (hub/spoke) scenarios, enable the separate top-level `cross_account` block: the warden reads and assumes roles in member accounts by first assuming a convention-named spoke role (`aow-spoke` by default) in the target account. The transport is independent of tag-auth — explicit `role_mappings` can target member-account ARNs on their own. Explicit `role_mappings` are always evaluated first; tag-auth is a fallback path only.

Both features are opt-in (`tag_auth.enabled` / `cross_account.enabled`, default `false`); cross-account supports a target-account allow-list and an external ID for spoke-role trust, and tag-auth supports transitive session tags. See [docs/TAG_BASED_AUTHORIZATION.md](docs/TAG_BASED_AUTHORIZATION.md) for setup, tag reference, and IAM examples, and [docs/examples/cross-account/](docs/examples/cross-account/) for a full worked cross-account example (config + IAM roles + StackSets template).

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
  "errorCode": "permission_denied"
}
```

Error responses carry only the classified `errorCode`/`message`; internal
error detail stays in the server-side logs, correlatable via `requestId`.

---

## Security Considerations

- Use specific subject patterns; avoid overly broad patterns like `.*` (patterns are auto-anchored `^(?:...)$`)
- Apply multiple `conditions` for sensitive roles, and session policies to scope AWS permissions
- Follow least-privilege when defining IAM roles; review CloudWatch logs and the audit trail regularly (`audit_required` for a fail-closed durable trail — see [docs/LOGGING.md](docs/LOGGING.md))
- Understand the validation guarantees before relying on any claim — see [docs/TOKEN_VALIDATION.md](docs/TOKEN_VALIDATION.md)

Per-issuer session tags are attached to every STS session for auditing, cost allocation, and ABAC — see [docs/SESSION_TAGGING.md](docs/SESSION_TAGGING.md).

---

## How It Works

1. **Receive Request**: a CI job sends an OIDC token + desired role ARN
2. **Route by Issuer**: the unverified `iss` selects the configured issuer spec (routing only — never trusted for identity)
3. **Verify Signature**: the issuer's JWKS is fetched (cache-first) and the signature verified against a `kid`+`alg`+key-type–pinned key
4. **Validate Claims**: issuer re-asserted, audience (ANY-match), expiration, `nbf`/`iat`, lifetime/age caps, and `required_claims` checked — all fail-closed
5. **Derive Canonical Subject**: the authorization identity is derived from config (`claim_mappings.subject` / GitHub `repository`), never self-asserted
6. **Authorize**: the subject is matched (issuer-bound) against `role_mappings`, then evaluated against auto-anchored regex `conditions`; a tag-auth fallback can authorize via IAM role tags
7. **Apply Session Policy**: optional inline or S3 session policy scopes the credentials
8. **Assume Role**: the role is assumed with per-issuer [STS session tags](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html)
9. **Audit + Return**: the allow/deny decision is recorded and temporary credentials are returned

Token validation is the security core of the service. The fail-closed
validation pipeline (self mode):

![Token validation pipeline](docs/img/token-validation.svg)

For the full step-by-step flow, crypto hardening, JWKS handling, and SSRF
protection see **[docs/TOKEN_VALIDATION.md](docs/TOKEN_VALIDATION.md)**.

---

## Troubleshooting

- **Token validation fails** — ensure the workflow has `id-token: write`; verify the repository name matches your configured patterns and the issuer/audience settings.
- **Role assumption fails** — confirm the Lambda execution role can assume the target role; check for conflicting constraints or overly restrictive session policies.
- **Cache issues** — DynamoDB needs a TTL field configured; S3 needs bucket read/write; raise `max_local_size` for high traffic.
- **Cross-account** — set `cross_account.enabled: true`, ensure the spoke role (`aow-spoke` by default) exists in each member account and trusts the hub Lambda role, grant `iam:GetRole`, and list the target account in `cross_account.allowed_accounts`. See [docs/TAG_BASED_AUTHORIZATION.md](docs/TAG_BASED_AUTHORIZATION.md) and [docs/examples/cross-account/](docs/examples/cross-account/).

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
