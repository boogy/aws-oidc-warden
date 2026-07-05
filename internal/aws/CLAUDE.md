# AWS — Service Interactions

Extends [../../CLAUDE.md](../../CLAUDE.md). STS/S3/IAM via AWS SDK v2. `consumer.go` (operations), `service_wrapper.go` (client init).

## Interface

```go
type AwsConsumerInterface interface {
    ReadS3Configuration() error
    AssumeRole(roleARN, sessionName string, sessionPolicy *string, duration *int32, claims *types.Claims, sessionTags map[string]string) (*types.Credentials, error)
    GetS3Object(bucket, key string) (io.ReadCloser, error)
    GetRole(role string) (*iam.GetRoleOutput, error)
    GetRoleTags(roleARN string) (map[string]string, error)
    IsTargetAccountAllowed(roleArn string) (bool, error)
}
```

Handlers accept the interface for mockability. Clients are built once in `service_wrapper.go`.

## Session tags

`AssumeRole`'s `sessionTags` param is the issuer's `session_tags` spec (STS tag key → raw claim name, from `cfg.IssuerSessionTags(claims.Issuer)`). It attaches tags via `BuildSessionTags(claims.Raw, sessionTags)`: for each spec entry, the raw claim value is read from `claims.Raw`, stringified, and emitted as that tag — nil/empty values are skipped. Keys/values that violate STS limits (128/256 chars) or charset (`[A-Za-z0-9 _.:/=+@-]`) are **skipped and logged via `slog.Warn`, never sanitized or truncated** — a bad value must not silently become a different value. Output is capped at 50 tags (STS limit); extras are skipped and warned. Spec keys are processed in sorted order for deterministic truncation/logging.

## Conventions

- Wrap AWS errors with context; use `errors.As` for typed errors (e.g. `AccessDeniedException`).
- `GetS3Object` returns an `io.ReadCloser` — the caller must close it.

## Gotchas

- Session duration: 1h default, up to role-defined max (≤12h) — but capped
  hard at 1h whenever the warden's own credentials are a role session
  (`GetCallerIdentityInfo`'s `isRoleSession`), which is always true on Lambda,
  same-account assumes included: STS *fails* (does not clamp)
  `DurationSeconds` > 3600 on a chained `AssumeRole`, so `AssumeRole` clamps
  the request itself before calling STS. Only `local` server mode running
  with IAM user credentials (not a role session) can get a session up to the
  target role's own max, cross-account targets included.
- Inline session policy max ~2048 chars.
- Region via default SDK resolution.

IAM: execution role needs `sts:AssumeRole`+`sts:TagSession` on target roles, `s3:GetObject` on the policy bucket, `iam:GetRole`. Target roles must trust the execution role.

## Tag-based auth & cross-account

`AssumeRole` always assumes the target role **directly** with the warden's own (hub) credentials, one hop, whether same-account or cross-account — it never uses spoke credentials. `cfg.CrossAccount.Enabled` is a policy gate, checked inline in `AssumeRole`: if the target account differs from the hub (`ParseRoleARN` + `GetCallerIdentityInfo`) and `CrossAccount` is nil/disabled, the call fails closed with an error; otherwise `accountAllowed` enforces `cfg.CrossAccount.AllowedAccounts` (hub implicit, empty=any).

`GetRoleTags` is the one operation that *is* account-aware via the spoke: for a non-hub account it calls `spokeCredsFor` (assumes the convention-named spoke role, cached) and reads tags with `GetRoleAs`; `spokeCredsFor` itself fails closed if `CrossAccount` is nil/disabled or the account isn't allowed. This is independent of `cfg.TagAuth.Enabled` — explicit mappings targeting member-account ARNs still get their tags read the same way if tag_auth is also on. Same-account → default hub clients via `GetRole` (identical to legacy).

Hub execution role IAM: `sts:GetCallerIdentity` (`GetCallerIdentityInfo`, also used for the hub account ID and the chained-session check), `sts:AssumeRole`+`sts:TagSession` directly on member-account target roles (prefer per-account patterns over `arn:aws:iam::*:role/*`), and — only if `tag_auth` reads roles cross-account — `sts:AssumeRole` on `arn:aws:iam::*:role/<spoke>`.

When `cfg.TagAuth.TransitiveSessionTags` is true, `AssumeRole` into the target marks all configured session tags transitive (`TransitiveTagKeys`), not just a fixed `repo`/`ref`/`actor` set — key names are operator-defined per issuer. See `docs/TAG_BASED_AUTHORIZATION.md`.
