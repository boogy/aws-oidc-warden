# AWS — Service Interactions

Extends [../../CLAUDE.md](../../CLAUDE.md). STS/S3/IAM via AWS SDK v2. `consumer.go` (operations), `service_wrapper.go` (client init).

## Interface

```go
type AwsConsumerInterface interface {
    ReadS3Configuration() error
    AssumeRole(roleARN, sessionName string, sessionPolicy *string, duration *int32, claims *types.Claims, sessionTags map[string]string) (*types.Credentials, error)
    GetS3Object(bucket, key string) (io.ReadCloser, error)
    GetRole(role string) (*iam.GetRoleOutput, error)
}
```

Handlers accept the interface for mockability. Clients are built once in `service_wrapper.go`.

## Session tags

`AssumeRole`'s `sessionTags` param is the issuer's `session_tags` spec (STS tag key → raw claim name, from `cfg.IssuerSessionTags(claims.Issuer)`). It attaches tags via `BuildSessionTags(claims.Raw, sessionTags)`: for each spec entry, the raw claim value is read from `claims.Raw`, stringified, and emitted as that tag — nil/empty values are skipped. Keys/values that violate STS limits (128/256 chars) or charset (`[A-Za-z0-9 _.:/=+@-]`) are **skipped and logged via `slog.Warn`, never sanitized or truncated** — a bad value must not silently become a different value. Output is capped at 50 tags (STS limit); extras are skipped and warned. Spec keys are processed in sorted order for deterministic truncation/logging.

## Conventions

- Wrap AWS errors with context; use `errors.As` for typed errors (e.g. `AccessDeniedException`).
- `GetS3Object` returns an `io.ReadCloser` — the caller must close it.

## Gotchas

- Session duration: 1h default, up to role-defined max (≤12h).
- Inline session policy max ~2048 chars.
- Region via default SDK resolution.

IAM: execution role needs `sts:AssumeRole`+`sts:TagSession` on target roles, `s3:GetObject` on the policy bucket, `iam:GetRole`. Target roles must trust the execution role.

## Tag-based auth & cross-account

When `cfg.TagAuth.Enabled`, `AssumeRole` and `GetRoleTags` are account-aware: the account ID is parsed from the role ARN (`ParseRoleARN`), and for a non-hub account the consumer assumes a convention-named spoke role (`spokeCredsFor`, cached) and uses `AssumeRoleAs`/`GetRoleAs`. Same-account → default hub clients (identical to legacy). Hub also needs `sts:GetCallerIdentity` and cross-account `sts:AssumeRole` on `arn:aws:iam::*:role/<spoke>`. `IsTargetAccountAllowed` enforces `cfg.TagAuth.AllowedAccounts` (hub implicit, empty=any). When `cfg.TagAuth.TransitiveSessionTags` is true, `AssumeRole` into the target passes `TransitiveTagKeys: [repo, ref, actor]`; cross-account sessions are clamped to 1 h. See `docs/TAG_BASED_AUTHORIZATION.md`.
