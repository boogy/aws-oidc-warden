# Session Tagging

The AWS OIDC Warden attaches STS session tags when assuming a role, for ABAC,
audit trails, and cost allocation.

## v2: session tags are per-issuer and spec-driven

Each issuer declares its own `session_tags` map — **STS tag key ← raw claim
name** — and only those tags are attached for that issuer's tokens. There is no
hard-coded GitHub tag set; a tag's value is the verified claim's value, taken
verbatim.

```yaml
issuers:
  - issuer: "https://token.actions.githubusercontent.com"
    provider: "github"
    session_tags:
      repo: "repository" # NOTE: full "owner/repo" (see below)
      repo-owner: "repository_owner"
      ref: "ref"
      ref-type: "ref_type"
      actor: "actor"
      event-name: "event_name"
```

Tag **keys** must match `[A-Za-z0-9 _.:/=+@-]{1,128}`; values are capped at 256
chars. An invalid key or value is **skipped and logged — never sanitized or
truncated**, so an ABAC condition can trust that a tag it sees carries the
exact claim value (a silently mangled value would be a security bug).

> **Breaking change from v1:** the default `repo` tag now carries the **full
> `owner/repo`** (the raw `repository` claim). v1 stripped the owner to a bare
> repo name. If an ABAC policy matched a bare repo name, update it — or map
> `repo` to a claim that is already bare.

### Example tags for the mapping above

| Tag Key      | Source claim       | Example Value      |
| ------------ | ------------------ | ------------------ |
| `repo`       | `repository`       | `my-org/repo-name` |
| `repo-owner` | `repository_owner` | `my-org`           |
| `ref`        | `ref`              | `refs/heads/main`  |
| `ref-type`   | `ref_type`         | `branch`           |
| `actor`      | `actor`            | `username`         |
| `event-name` | `event_name`       | `push`             |

For a non-GitHub (`generic`) issuer, key the tags on that provider's raw claim
names (e.g. GitLab `project_path`, `ref`). See [MULTI_ISSUER.md](MULTI_ISSUER.md).

> **Session tagging vs. tag-based authorization.** This page covers the STS
> session tags attached to every assumed-role session (for ABAC policy
> conditions, audit, and cost allocation). A separate, opt-in mechanism —
> [tag-based authorization](TAG_BASED_AUTHORIZATION.md) — lets a role's own
> IAM tags _grant_ the authorization decision itself (in place of
> `role_mappings`), which is the recommended path once you're managing
> authorization for hundreds/thousands of roles or need cross-account
> hub/spoke delegation. The two compose: an IAM-tag-authorized role still gets
> the same per-issuer `session_tags` attached on assumption.

## Security Benefits

### 1. Enhanced Audit Trail

Session tags provide detailed information about the source of AWS API calls:

```json
{
  "awsRegion": "us-east-1",
  "eventName": "AssumeRole",
  "userIdentity": {
    "type": "AssumedRole",
    "principalId": "AROA...:GitHubActions-owner-repo-1234567890",
    "sessionContext": {
      "sessionIssuer": {
        "tags": {
          "repo": "repo-name",
          "actor": "username",
          "ref": "refs/heads/main",
          "event-name": "push",
          "repo-owner": "owner",
          "ref-type": "branch"
        }
      }
    }
  }
}
```

### 2. IAM Policy Conditions

You can use session tags in IAM policies to restrict access based on GitHub context:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::my-bucket/*",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalTag/repo": "repo-name",
          "aws:PrincipalTag/ref": "refs/heads/main",
          "aws:PrincipalTag/repo-owner": "owner",
          "aws:ResourceTag/owner": "${aws:PrincipalTag/repo}"
        }
      }
    },
    {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalTag/event-name": ["push", "release"]
        }
      }
    }
  ]
}
```

### 3. Cost Allocation

Session tags can be used for cost allocation and billing:

- Track costs by repository or organization
- Allocate infrastructure costs to specific projects
- Monitor resource usage patterns by workflow type

## Example GitHub Workflow

```yaml
name: Deploy to AWS
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read

    steps:
      - name: Get AWS credentials
        run: |
          # Request credentials from AWS OIDC Warden
          RESPONSE=$(curl -X POST https://your-warden-endpoint.com/assume-role \
            -H "Content-Type: application/json" \
            -d '{
              "token": "'${{ github.token }}'",
              "role": "arn:aws:iam::123456789012:role/GitHubActionsRole"
            }')

          # Extract credentials and set as environment variables
          export AWS_ACCESS_KEY_ID=$(echo $RESPONSE | jq -r '.credentials.AccessKeyId')
          export AWS_SECRET_ACCESS_KEY=$(echo $RESPONSE | jq -r '.credentials.SecretAccessKey')
          export AWS_SESSION_TOKEN=$(echo $RESPONSE | jq -r '.credentials.SessionToken')

      - name: Deploy application
        run: |
          # Your deployment commands here
          aws s3 sync ./dist s3://my-app-bucket/
```

## CloudTrail Log Example

When the above workflow runs, CloudTrail will show detailed session information:

```json
{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "AssumedRole",
    "principalId": "AROA...:GitHubActions-owner-repo-1234567890",
    "arn": "arn:aws:sts::123456789012:assumed-role/GitHubActionsRole/GitHubActions-owner-repo-1234567890",
    "accountId": "123456789012",
    "sessionContext": {
      "sessionIssuer": {
        "type": "Role",
        "principalId": "AROA...",
        "arn": "arn:aws:iam::123456789012:role/GitHubActionsRole",
        "accountId": "123456789012",
        "userName": "GitHubActionsRole",
        "tags": {
          "repo": "repo-name",
          "actor": "username",
          "ref": "refs/heads/main",
          "event-name": "push",
          "repo-owner": "owner",
          "ref-type": "branch"
        }
      },
      "attributes": {
        "creationDate": "2025-05-24T10:30:00Z",
        "mfaAuthenticated": "false"
      }
    }
  },
  "eventTime": "2025-05-24T10:30:15Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "PutObject",
  "resources": [
    {
      "accountId": "123456789012",
      "type": "AWS::S3::Bucket",
      "ARN": "arn:aws:s3:::my-app-bucket"
    }
  ]
}
```

## Monitoring and Alerting

You can create CloudWatch alarms and alerts based on session tags:

### Unusual Repository Access

Alert when an unexpected repository tries to access your AWS resources:

```sql
SELECT *
FROM cloudtrail_logs
WHERE userIdentity.sessionContext.sessionIssuer.tags.repo NOT IN ('repo1', 'repo2')
  AND userIdentity.sessionContext.sessionIssuer.tags."repo-owner" NOT IN ('trusted-org1', 'trusted-org2')
  AND eventSource = 'iam.amazonaws.com'
  AND eventName = 'AssumeRole'
```

### Production Access from Non-Main Branch

Alert when production resources are accessed from non-main branches:

```sql
SELECT *
FROM cloudtrail_logs
WHERE userIdentity.sessionContext.sessionIssuer.tags.ref != 'refs/heads/main'
  AND resources[0].ARN LIKE '%production%'
```

## Best Practices

1. **Use session tags in IAM policies** to enforce GitHub-based access controls
2. **Monitor CloudTrail logs** for unusual patterns in session tag values
3. **Set up alerts** for access from unexpected repositories or branches
4. **Use cost allocation tags** to track spending by repository or team
5. **Regularly audit** which repositories have access to which roles
6. **Implement least privilege** by combining session tags with restrictive policies

## Limitations

- Session tags are limited to 50 tags per session
- Each tag key and value has character and length restrictions
- Session tags only apply to the assumed role session, not the underlying IAM role
- An invalid tag key or value is **skipped and logged, never sanitized or
  truncated** — an ABAC condition can trust that any tag it sees carries the
  exact verified claim value (see the note above)
