# AWS Package - AWS Service Interactions

**Technology**: Go, AWS SDK v2, STS, IAM, S3
**Entry Point**: `consumer.go` (operations), `service_wrapper.go` (client init)
**Parent Context**: This extends [../../CLAUDE.md](../../CLAUDE.md)

---

## Development Commands

### From Package Directory

```bash
go test ./...              # Run AWS package tests
go test -v ./...           # Verbose output
```

### From Root

```bash
go test -v ./pkg/aws/      # Test this package
```

---

## Architecture

### Directory Structure

```
pkg/aws/
├── consumer.go           # AWS operations (AssumeRole, S3, IAM)
├── consumer_test.go      # Unit tests with mocks
├── service_wrapper.go    # AWS client initialization
└── service_wrapper_test.go
```

### Operation Flow

```
Handler → AwsConsumer → AWS SDK v2 → AWS Services (STS/S3/IAM)
```

---

## Code Organization Patterns

### Interface Pattern (Critical for Testing)

The consumer implements `AwsConsumerInterface` for mockability:

```go
// ✅ DO: Use the interface for dependency injection
type AwsConsumerInterface interface {
    ReadS3Configuration() error
    AssumeRole(roleARN, sessionName string, sessionPolicy *string, duration *int32, claims *types.GithubClaims) (*types.Credentials, error)
    GetS3Object(bucket, key string) (io.ReadCloser, error)
    GetRole(role string) (*iam.GetRoleOutput, error)
}

// In handlers, accept the interface
func NewRequestProcessor(cfg *config.Config, consumer aws.AwsConsumerInterface, ...) *RequestProcessor
```

### AssumeRole with Session Tags

Session tags are automatically applied for audit trails:

```go
// ✅ DO: Apply session tags for ABAC and audit
func (a *AwsConsumer) AssumeRole(roleARN, sessionName string, sessionPolicy *string, duration *int32, claims *types.GithubClaims) (*types.Credentials, error) {
    input := &sts.AssumeRoleInput{
        RoleArn:         aws.String(roleARN),
        RoleSessionName: aws.String(sessionName),
        Tags: []ststypes.Tag{
            {Key: aws.String("repo"), Value: aws.String(claims.RepositoryName)},
            {Key: aws.String("actor"), Value: aws.String(claims.Actor)},
            {Key: aws.String("ref"), Value: aws.String(claims.Ref)},
            {Key: aws.String("event-name"), Value: aws.String(claims.EventName)},
            {Key: aws.String("repo-owner"), Value: aws.String(claims.RepositoryOwner)},
            {Key: aws.String("ref-type"), Value: aws.String(claims.RefType)},
        },
    }

    // Apply session policy if provided
    if sessionPolicy != nil {
        input.Policy = sessionPolicy
    }

    result, err := a.stsClient.AssumeRole(ctx, input)
    if err != nil {
        return nil, fmt.Errorf("failed to assume role: %w", err)
    }

    return result.Credentials, nil
}
```

### S3 Object Retrieval Pattern

```go
// ✅ DO: Return io.ReadCloser, let caller handle closing
func (a *AwsConsumer) GetS3Object(bucket, key string) (io.ReadCloser, error) {
    result, err := a.s3Client.GetObject(ctx, &s3.GetObjectInput{
        Bucket: aws.String(bucket),
        Key:    aws.String(key),
    })
    if err != nil {
        return nil, fmt.Errorf("failed to get S3 object: %w", err)
    }

    return result.Body, nil
}

// Caller must close:
reader, err := consumer.GetS3Object(bucket, key)
if err != nil {
    return err
}
defer reader.Close()
```

### Service Wrapper Pattern

AWS clients are initialized once and reused:

```go
// ✅ DO: Initialize clients once in service_wrapper.go
type AwsServices struct {
    STSClient *sts.Client
    S3Client  *s3.Client
    IAMClient *iam.Client
}

func NewAwsServices(ctx context.Context) (*AwsServices, error) {
    cfg, err := config.LoadDefaultConfig(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to load AWS config: %w", err)
    }

    return &AwsServices{
        STSClient: sts.NewFromConfig(cfg),
        S3Client:  s3.NewFromConfig(cfg),
        IAMClient: iam.NewFromConfig(cfg),
    }, nil
}
```

---

## Key Files

### Core Files

- `consumer.go` - Main AWS operations
  - `AssumeRole()` - STS role assumption with session tags
  - `GetS3Object()` - S3 object retrieval
  - `GetRole()` - IAM role lookup
  - `ReadS3Configuration()` - Load config from S3

- `service_wrapper.go` - AWS SDK client initialization

### Test Files

- `consumer_test.go` - Unit tests with mock AWS services
- `service_wrapper_test.go` - Client initialization tests

---

## Quick Search Commands

### Find AWS Operations

```bash
# Find AssumeRole implementation
rg -n "func.*AssumeRole" pkg/aws/

# Find session tags
rg -n "ststypes.Tag\|Tags:" pkg/aws/

# Find S3 operations
rg -n "GetObject\|PutObject" pkg/aws/
```

### Find Interface Methods

```bash
# Find interface definition
rg -n "type.*Interface" pkg/aws/

# Find mock implementations
rg -n "Mock.*struct" pkg/aws/
```

---

## Session Tags

Session tags are applied to all assumed roles for audit and ABAC:

| Tag          | Source                   | Example           |
| ------------ | ------------------------ | ----------------- |
| `repo`       | `claims.RepositoryName`  | `myrepo`          |
| `actor`      | `claims.Actor`           | `github-user`     |
| `ref`        | `claims.Ref`             | `refs/heads/main` |
| `event-name` | `claims.EventName`       | `push`            |
| `repo-owner` | `claims.RepositoryOwner` | `myorg`           |
| `ref-type`   | `claims.RefType`         | `branch`          |

### Using Session Tags in IAM Policies

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::bucket/${aws:PrincipalTag/repo}/*",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalTag/ref-type": "branch"
        }
      }
    }
  ]
}
```

---

## Error Handling

### AWS Error Wrapping

```go
// ✅ DO: Wrap AWS errors with context
result, err := a.stsClient.AssumeRole(ctx, input)
if err != nil {
    return nil, fmt.Errorf("failed to assume role %s: %w", roleARN, err)
}

// ✅ DO: Check specific error types when needed
var accessDenied *ststypes.AccessDeniedException
if errors.As(err, &accessDenied) {
    return nil, fmt.Errorf("access denied for role %s: %w", roleARN, err)
}
```

---

## Common Gotchas

- **Session Duration**: Default is 1 hour, max is 12 hours (role-dependent)
- **Tag Value Limits**: 256 characters max per tag value
- **Session Policy Size**: Max 2048 characters for inline policy
- **S3 Object Lifecycle**: Always close `io.ReadCloser` from `GetS3Object()`
- **Region**: Uses default SDK region resolution (env var, config file, instance metadata)

---

## Testing Guidelines

### Mock Interface

```go
// Create mock for testing
type MockAwsConsumer struct {
    AssumeRoleFunc    func(roleARN, sessionName string, sessionPolicy *string, duration *int32, claims *types.GithubClaims) (*types.Credentials, error)
    GetS3ObjectFunc   func(bucket, key string) (io.ReadCloser, error)
}

func (m *MockAwsConsumer) AssumeRole(roleARN, sessionName string, sessionPolicy *string, duration *int32, claims *types.GithubClaims) (*types.Credentials, error) {
    if m.AssumeRoleFunc != nil {
        return m.AssumeRoleFunc(roleARN, sessionName, sessionPolicy, duration, claims)
    }
    return nil, errors.New("not implemented")
}
```

### Unit Test Example

```go
func TestAssumeRole_Success(t *testing.T) {
    mockConsumer := &MockAwsConsumer{
        AssumeRoleFunc: func(roleARN, sessionName string, sessionPolicy *string, duration *int32, claims *types.GithubClaims) (*types.Credentials, error) {
            return &types.Credentials{
                AccessKeyId:     aws.String("AKIAIOSFODNN7EXAMPLE"),
                SecretAccessKey: aws.String("secret"),
                SessionToken:    aws.String("token"),
                Expiration:      aws.Time(time.Now().Add(1 * time.Hour)),
            }, nil
        },
    }

    creds, err := mockConsumer.AssumeRole("arn:aws:iam::123:role/test", "session", nil, nil, claims)

    assert.NoError(t, err)
    assert.NotNil(t, creds)
    assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", *creds.AccessKeyId)
}
```

---

## IAM Role Requirements

The Lambda execution role needs these permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["sts:AssumeRole", "sts:TagSession"],
      "Resource": ["arn:aws:iam::*:role/github-actions-*"]
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": ["arn:aws:s3:::session-policies-bucket/*"]
    },
    {
      "Effect": "Allow",
      "Action": ["iam:GetRole"],
      "Resource": ["arn:aws:iam::*:role/github-actions-*"]
    }
  ]
}
```

Target roles must trust the Lambda execution role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::LAMBDA_ACCOUNT:role/aws-oidc-warden-execution"
      },
      "Action": ["sts:AssumeRole", "sts:TagSession"]
    }
  ]
}
```
