# Split configuration example

Two files, two owners:

| File                             | Owner          | Holds                                                                      |
| -------------------------------- | -------------- | -------------------------------------------------------------------------- |
| [`service.yaml`](service.yaml)   | Platform team  | Issuers, hardening, `idp`, where the mappings live and how often to reload |
| [`mappings.yaml`](mappings.yaml) | Workload teams | Who may assume which role: `role_sets`, `role_mappings`, `role_groups`     |

The warden loads `service.yaml` at startup, then reads `mappings.yaml` from the location in `mappings_file` and re-reads it every `config_reload_interval`. Workload teams change access by uploading a new `mappings.yaml`; no redeploy. Reference: [CONFIGURATION.md § Split configuration](../../CONFIGURATION.md#split-configuration).

Both files load in CI: `TestSplitConfigExamplesLoad` (`internal/config/docs_yaml_test.go`) asserts every outcome in the table below.

## service.yaml

| Key                        | Meaning                                                                                                           |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `issuers`                  | Inbound token issuers. GitHub's canonical subject is the repository (`octo-org/api`); GitLab's is `project_path`. |
| `default_issuer`           | Issuer a mapping binds to when it omits `issuer`. Set `issuer` on every mapping anyway.                           |
| `mappings_file`            | `s3://bucket/key` or a local path. With it set, `role_mappings`/`role_groups` may not appear in this file.        |
| `s3_config_bucket_owner`   | Required for `s3://`. The read fails unless the bucket belongs to this account.                                   |
| `config_reload_interval`   | Re-read the mappings at most once per interval (conditional GET; unchanged file = 304, no re-parse).              |
| `mappings_max_stale`       | Default 3x the interval. Past it, requests get `503 config_stale`.                                                |
| `idp.max_session_duration` | Hard ceiling for any `/idp/token` session.                                                                        |
| `idp.allowed_roles`        | The only roles any mapping may reach through `/idp/token`.                                                        |

## mappings.yaml

A mapping says: a token from `issuer` whose canonical subject matches `subject`, and whose claims satisfy `conditions`, may assume `roles`.

```yaml
role_mappings:
  - issuer: "https://token.actions.githubusercontent.com" # which issuer signed the token
    subject: "octo-org/api" # the repository; anchored regex, so this is an exact match
    roles: ["arn:aws:iam::111122223333:role/ApiDeploy"] # ARNs, or "@name" for a role_sets entry
    conditions: # every key is a token claim; all must match
      ref: "refs/heads/main"
```

The four building blocks in `mappings.yaml`:

- **`role_sets`**: named lists of ARNs, referenced as `"@api-deployers"`. Rename a role once, not in every mapping.
- **`role_mappings`**: one grant per entry. `subject` may be a list; each element gets the same roles and conditions.
- **`role_groups`**: many subjects, one shared `defaults` block. Use it for fleets of repos with identical access.
- **IdP fields** (`idp_token`, `idp_max_session_duration`): opt a mapping into `/idp/token` for sessions longer than 1h. Without `idp_token`, the mapping gets `/verify` only.

## What each caller gets

| Caller (issuer, subject, claims)                    | Matching entry             | `/verify` (AssumeRole, 1h) | `/idp/token`            |
| --------------------------------------------------- | -------------------------- | -------------------------- | ----------------------- |
| GitHub `octo-org/api`, `ref=refs/heads/main`        | `@api-deployers`           | `ApiDeploy`, `ApiMigrate`  | denied (no `idp_token`) |
| GitHub `octo-org/api`, `ref=refs/heads/feature`     | none (condition fails)     | denied                     | denied                  |
| GitHub `octo-org/web`, any ref                      | `@readonly` (list subject) | `ReadOnly`                 | denied                  |
| GitHub `octo-org/data-pipeline`, main               | `LongDeploy`, `idp_token`  | `LongDeploy`               | `LongDeploy`, up to 4h  |
| GitLab `platform/infra`, `ref=main`                 | `@readonly`                | `ReadOnly`                 | denied                  |
| GitHub token claiming `platform/infra`              | none (bound to GitLab)     | denied                     | denied                  |
| GitHub `octo-org/tool-a`, `event_name=push`         | `role_groups` entry        | `ReadOnly`                 | denied                  |
| GitHub `octo-org/tool-a`, `event_name=pull_request` | none (condition fails)     | denied                     | denied                  |
| GitHub `octo-org/other`                             | none                       | denied                     | denied                  |

The `/idp/token` row works only because `LongDeploy` is in `idp.allowed_roles` and the role trusts the warden's own OIDC provider ([IDP.md § Trust policy](../../IDP.md)). The 4h is the smaller of the mapping's `idp_max_session_duration` and `idp.max_session_duration`.

## What the mappings file cannot do

Any of these rejects the whole file. The warden keeps serving the last good version and logs the error.

A key other than `default_issuer`, `role_sets`, `role_mappings`, `role_groups`:

```text
idp:
  max_session_duration: 12h
```

```text
key "idp" is not allowed in a config fragment (only role_mappings, role_groups, role_sets, default_issuer may be set here; issuers/hardening knobs/tag_auth/allow_insecure_issuers are base-only)
```

A bare wildcard subject or condition:

```text
role_mappings:
  - issuer: "https://token.actions.githubusercontent.com"
    subject: ".*"
    roles: ["@readonly"]
```

An `idp_max_session_duration` or `allow_session_name` without `idp_token: true`.

Not a load error: `idp_token: true` on a role missing from `idp.allowed_roles` loads, but `/idp/token` refuses it with `403 idp_not_permitted`. The platform team's `allowed_roles` always wins over the mappings file.

The reverse also fails, at startup: `role_mappings` or `role_groups` inside `service.yaml` while `mappings_file` is set.

```text
mappings_file is set: role_mappings and role_groups belong in the mappings file, not the service config
```

## Reload and staleness

With `config_reload_interval: 60s` and the default `mappings_max_stale` (180s):

| Time  | Event                                  | Requests                                                 |
| ----- | -------------------------------------- | -------------------------------------------------------- |
| 0s    | Last successful read                   | Served from that version                                 |
| 60s   | New upload is invalid; refresh fails   | Still served from the 0s version                         |
| 120s+ | Retries back off (2x, 4x, 8x interval) | Still served from the 0s version                         |
| 180s  | No successful refresh for 3x interval  | Every `/verify` and `/idp/token` gets `503 config_stale` |
| later | A valid file is uploaded and read      | Served again from the new version                        |

A `304 Not Modified` counts as a successful refresh, so an unchanged file never goes stale. Deleting a grant takes effect on the next refresh; deleting or breaking the file does not revoke anything until it goes stale.

## Deploying the mappings file

1. Create a versioned bucket in the account named by `s3_config_bucket_owner`.
2. Let the warden's Lambda role read the object only: `s3:GetObject` on `arn:aws:s3:::EXAMPLE-BUCKET/mappings.yaml`, plus `kms:Decrypt` if the bucket uses SSE-KMS. No `s3:ListBucket`.
3. Restrict writes to the role that deploys mappings (typically the CI job that reviews `mappings.yaml`):

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Sid": "OnlyMappingsDeployerWrites",
         "Effect": "Deny",
         "Principal": "*",
         "Action": ["s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion"],
         "Resource": "arn:aws:s3:::EXAMPLE-BUCKET/*",
         "Condition": {
           "ArnNotEquals": {
             "aws:PrincipalArn": "arn:aws:iam::111122223333:role/MappingsDeployer"
           }
         }
       }
     ]
   }
   ```

4. Alarm on `PutObject`/`DeleteObject` for the key (CloudTrail data events).
5. Upload: `aws s3 cp mappings.yaml s3://EXAMPLE-BUCKET/mappings.yaml`.

Full IaC contract: [ARCHITECTURE.md § Infrastructure as code](../../ARCHITECTURE.md).

## Running locally

```sh
go run ./cmd/local -config docs/examples/split-config/service.yaml -mappings docs/examples/split-config/mappings.yaml
```

`-mappings` overrides `mappings_file`, so the local file is used instead of S3. A local path never goes stale. The `idp` block needs AWS credentials that can use the KMS key; drop it for a `/verify`-only test.
