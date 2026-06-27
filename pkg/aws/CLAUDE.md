# AWS — Service Interactions

Extends [../../CLAUDE.md](../../CLAUDE.md). STS/S3/IAM via AWS SDK v2. `consumer.go` (operations), `service_wrapper.go` (client init).

## Interface

```go
type AwsConsumerInterface interface {
    ReadS3Configuration() error
    AssumeRole(roleARN, sessionName string, sessionPolicy *string, duration *int32, claims *types.GithubClaims) (*types.Credentials, error)
    GetS3Object(bucket, key string) (io.ReadCloser, error)
    GetRole(role string) (*iam.GetRoleOutput, error)
}
```

Handlers accept the interface for mockability. Clients are built once in `service_wrapper.go`.

## Session tags

`AssumeRole` attaches tags from `CreateSessionTags(claims)` for audit and ABAC: `repo`, `actor`, `ref`, `event-name`, `repo-owner`, `ref-type`. Empty values are dropped; keys/values are sanitized to AWS limits (128/256 chars). `repo` is the bare repo name (owner stripped).

## Conventions

- Wrap AWS errors with context; use `errors.As` for typed errors (e.g. `AccessDeniedException`).
- `GetS3Object` returns an `io.ReadCloser` — the caller must close it.

## Gotchas

- Session duration: 1h default, up to role-defined max (≤12h).
- Inline session policy max ~2048 chars.
- Region via default SDK resolution.

IAM: execution role needs `sts:AssumeRole`+`sts:TagSession` on target roles, `s3:GetObject` on the policy bucket, `iam:GetRole`. Target roles must trust the execution role.

## Tag-based auth & cross-account

When `cfg.TagAuth.Enabled`, `AssumeRole` and `GetRoleTags` are account-aware: the account ID is parsed from the role ARN (`ParseRoleARN`), and for a non-hub account the consumer assumes a convention-named spoke role (`spokeCredsFor`, cached) and uses `AssumeRoleAs`/`GetRoleAs`. Same-account → default hub clients (identical to legacy). Hub also needs `sts:GetCallerIdentity` and cross-account `sts:AssumeRole` on `arn:aws:iam::*:role/<spoke>`. See `docs/TAG_BASED_AUTHORIZATION.md`.
