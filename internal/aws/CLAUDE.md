# AWS

Extends [../../CLAUDE.md](../../CLAUDE.md). STS/S3/IAM/KMS through AWS SDK v2.

This file is a map plus the rules code cannot state. Read `consumer.go` before changing a call; IAM requirements are in `docs/ARCHITECTURE.md`, cross-account in `docs/examples/cross-account/`.

## Where things are

- `consumer.go` — `AwsConsumerInterface` and its operations, `BuildSessionTags`, spoke credentials, role-tag cache.
- `service_wrapper.go` — clients, built once. `stserr.go` — STS error → `ErrWebIdentity*` sentinels.

## Rules

- `AssumeRole` attaches the caller-built tags as given; build them once with `BuildSessionTags`, which formats through `utils.FormatClaimValue`.
- `AssumeRole` is always direct hub → target with the warden's own credentials; spoke credentials are only for `GetRoleTags`.
- Cross-account is fail-closed: `cross_account` disabled or account not allowed is an error, in `AssumeRole`, `AssumeRoleWithWebIdentity` and `GetRoleTags` alike.
- `GetRoleTags` checks the account against live config before its cache.
- STS fails (does not clamp) a chained `AssumeRole` over 1h; the consumer clamps first.
- S3 reads are capped at `max_config_bytes`; over-cap is an error, never a truncation. `GetS3Object` callers close the body.
- Session names are fitted with the `utils` STS helpers: substitute, never delete characters.
- Wrap AWS errors with context; use `errors.As` for typed ones.
