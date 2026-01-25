# Session Tagging Example

This document demonstrates how the AWS OIDC Warden applies session tags when assuming IAM roles based on GitHub OIDC token claims.

## How Session Tagging Works

When a GitHub Actions workflow requests temporary AWS credentials through the AWS OIDC Warden, the service automatically applies session tags based on the GitHub OIDC token claims. These tags provide enhanced security, audit trails, and cost allocation capabilities.

## Session Tags Applied

The following session tags are automatically applied when assuming a role:

| Tag Key      | Description                                | Example Value                     |
| ------------ | ------------------------------------------ | --------------------------------- |
| `repo`       | The repository name (without owner)        | `repo-name`                       |
| `actor`      | The GitHub user who triggered the workflow | `username`                        |
| `ref`        | The Git reference (branch/tag)             | `refs/heads/main`                 |
| `event-name` | The event that triggered the workflow      | `push`, `pull_request`, `release` |
| `repo-owner` | The owner of the repository                | `my-org`                          |
| `ref-type`   | The type of Git reference                  | `branch`, `tag`                   |

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
- Tags are automatically sanitized to comply with AWS requirements
