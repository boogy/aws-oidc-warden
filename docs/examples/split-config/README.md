# Split configuration example

Two files, two owners:

| File                             | Owner          | Holds                                                                      |
| -------------------------------- | -------------- | -------------------------------------------------------------------------- |
| [`service.yaml`](service.yaml)   | Platform team  | Issuers, hardening, `idp`, where the mappings live and how often to reload |
| [`mappings.yaml`](mappings.yaml) | Workload teams | Who may assume which role: `role_sets`, `role_mappings`, `role_groups`     |

The warden loads `service.yaml` at startup, then reads `mappings.yaml` from the location in `mappings_file` and re-reads it every `config_reload_interval`. Workload teams change access by uploading a new `mappings.yaml`; no redeploy. Reference: [CONFIGURATION.md § Split configuration](../../CONFIGURATION.md#split-configuration).

Both files load in CI: `TestSplitConfigExamplesLoad` (`internal/config/docs_yaml_test.go`) asserts every outcome in the table below.

## service.yaml

| Key                      | Meaning                                                                                                           |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| `issuers`                | Inbound token issuers. GitHub's canonical subject is the repository (`octo-org/api`); GitLab's is `project_path`. |
| `default_issuer`         | Issuer a mapping binds to when it omits `issuer`. Set `issuer` on every mapping anyway.                           |
| `mappings_file`          | `s3://bucket/key` or a local path. With it set, `role_mappings`/`role_groups`/`role_sets` may not appear here.    |
| `s3_config_bucket_owner` | Required for `s3://`. The read fails unless the bucket belongs to this account.                                   |
| `config_reload_interval` | Re-read the mappings at most once per interval (conditional GET; unchanged file = 304, no re-parse).              |
| `mappings_max_stale`     | Default 3x the interval. Past it, requests get `503 config_stale`.                                                |
| `session_policy_bucket`  | Bucket holding the files named by a mapping's `session_policy_file`.                                              |
| `session_tags`           | Per issuer: STS session tags taken from token claims, for ABAC in the target account.                             |
| `cache`                  | JWKS cache in DynamoDB, shared by every Lambda environment in the region.                                         |
| `log_to_s3`, `audit_*`   | Audit record per decision in S3; `audit_required` returns no credentials if the write fails.                      |

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

The building blocks in `mappings.yaml`:

- **`role_sets`**: named lists of ARNs, referenced as `"@api-deployers"`. Rename a role once, not in every mapping.
- **`role_mappings`**: one grant per entry. `subject` may be a list; each element gets the same roles and conditions.
- **`role_groups`**: many subjects, one shared `defaults` block. Use it for fleets of repos with identical access.
- **Session policies** (`session_policy`, `session_policy_file`): narrow what one mapping's session may do. The session gets the intersection of the role's permissions and the policy, so one broad role can serve several callers with different scopes. `session_policy` is inline JSON; `session_policy_file` is a key in `session_policy_bucket`. Set one per mapping. They apply to `AssumeRole` and IdP-issued sessions alike.
- **IdP fields**: `max_session_duration` over 1h, or `idp_token: true`, issue a mapping's roles through the warden's IdP. Otherwise the mapping gets `AssumeRole`, capped at 1h.

## What each caller gets

| Caller (issuer, subject, claims)                        | Matching entry                  | `/verify` up to 1h                           | `/verify` over 1h       | Session name                                   |
| ------------------------------------------------------- | ------------------------------- | -------------------------------------------- | ----------------------- | ---------------------------------------------- |
| GitHub `octo-org/api`, `ref=refs/heads/main`            | `@api-deployers`                | `ApiDeploy`, `ApiMigrate` (AssumeRole)       | denied (AssumeRole cap) | caller's `sessionName`, else `aws-oidc-warden` |
| GitHub `octo-org/api`, `ref=refs/heads/feature`         | none (condition fails)          | denied                                       | denied                  |                                                |
| GitHub `octo-org/web`, any ref                          | `@readonly` (list subject)      | `ReadOnly` (AssumeRole)                      | denied (AssumeRole cap) | caller's `sessionName`, else `aws-oidc-warden` |
| GitHub `octo-org/batch`, any ref                        | `BatchRunner`, `idp_token`      | `BatchRunner` (IdP)                          | denied (1h ceiling)     | `aws-oidc-warden`                              |
| GitHub `octo-org/data-pipeline`, main                   | `LongDeploy`, 4h                | `LongDeploy` (IdP)                           | `LongDeploy`, up to 4h  | `aws-oidc-warden`                              |
| GitHub `octo-org/nightly-backup`, `event_name=schedule` | two roles, 12h                  | `BackupRunner`, `BackupVerify` (IdP)         | either role, up to 12h  | always `nightly-backup`                        |
| GitHub `octo-org/nightly-backup`, `event_name=push`     | none (condition fails)          | denied                                       | denied                  |                                                |
| GitHub `octo-org/reports`, any ref                      | `ReportsReader` + inline policy | `ReportsReader`, read-only on `octo-reports` | denied (AssumeRole cap) | `aws-oidc-warden`                              |
| GitHub `octo-org/terraform`, main                       | `TerraformApply` + policy file  | `TerraformApply`, scoped by `terraform.json` | denied (AssumeRole cap) | always `terraform-apply`                       |
| GitHub `octo-org/terraform`, other ref                  | none (condition fails)          | denied                                       | denied                  |                                                |
| GitLab `platform/infra`, `ref=main`                     | `@readonly`                     | `ReadOnly` (AssumeRole)                      | denied (AssumeRole cap) | `aws-oidc-warden`                              |
| GitHub token claiming `platform/infra`                  | none (bound to GitLab)          | denied                                       | denied                  |                                                |
| GitHub `octo-org/tool-a`, `event_name=push`             | `role_groups` entry             | `ReadOnly` (AssumeRole)                      | denied (AssumeRole cap) | `aws-oidc-warden`                              |
| GitHub `octo-org/tool-a`, `event_name=pull_request`     | none (condition fails)          | denied                                       | denied                  |                                                |
| GitHub `octo-org/etl-orders`, main                      | `role_groups` entry, `@etl`, 6h | `EtlExtract`, `EtlLoad` (IdP)                | either role, up to 6h   | `aws-oidc-warden`                              |
| GitHub `octo-org/other`                                 | none                            | denied                                       | denied                  |                                                |

The IdP rows are IdP-issued at every duration: their mappings set `max_session_duration` over 1h (4h, 12h, 6h), or `idp_token: true` (`octo-org/batch`, capped at 1h). Their roles trust the warden's own OIDC provider ([IDP.md § Trust policy](../../IDP.md)). A caller's `sessionName` is used only where the mapping sets `allow_session_name: true` (here `octo-org/api` and `octo-org/web`); elsewhere it is ignored. A forced `role_session_name` always wins.

Every request goes to `/verify`; `durationSeconds` and `sessionName` are optional:

```json
{ "token": "<oidc>", "role": "arn:aws:iam::111122223333:role/ApiDeploy" }
{ "token": "<oidc>", "role": "arn:aws:iam::111122223333:role/ApiDeploy", "durationSeconds": 1800, "sessionName": "api-release-42" }
{ "token": "<oidc>", "role": "arn:aws:iam::111122223333:role/LongDeploy", "durationSeconds": 14400 }
{ "token": "<oidc>", "role": "arn:aws:iam::111122223333:role/BackupRunner", "durationSeconds": 43200, "sessionName": "ignored" }
```

The first gets 1h under `aws-oidc-warden`; the second 30m named `api-release-42`; the third 4h through the IdP; the fourth 12h named `nightly-backup`, because that mapping forces its name. `"durationSeconds": 7200` for `ApiDeploy` gets `403 idp_not_permitted`.

A session policy comes from the first mapping, in file order, that matches the caller and grants the requested role. Give scoped grants their own roles (`ReportsReader`, `TerraformApply`). If a role's first grant has no policy and a later grant does, the later policy is never applied, and the warden logs a warning at load.

## What the mappings file cannot do

Any of these rejects the whole file. The warden keeps serving the last good version and logs the error.

A key other than `default_issuer`, `role_sets`, `role_mappings`, `role_groups`:

```text
idp:
  enabled: false
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

A `max_session_duration` over 1h while `service.yaml` has no `idp` block.

The reverse also fails, at startup: `role_mappings`, `role_groups` or `role_sets` inside `service.yaml` while `mappings_file` is set.

```text
mappings_file is set: role_mappings, role_groups and role_sets belong in the mappings file, not the service config
```

## Reload and staleness

With `config_reload_interval: 60s` and the default `mappings_max_stale` (180s):

| Time  | Event                                  | Requests                                |
| ----- | -------------------------------------- | --------------------------------------- |
| 0s    | Last successful read                   | Served from that version                |
| 60s   | New upload is invalid; refresh fails   | Still served from the 0s version        |
| 120s+ | Retries back off (2x, 4x, 8x interval) | Still served from the 0s version        |
| 180s  | No successful refresh for 3x interval  | Every `/verify` gets `503 config_stale` |
| later | A valid file is uploaded and read      | Served again from the new version       |

A `304 Not Modified` counts as a successful refresh, so an unchanged file never goes stale. Deleting a grant takes effect on the next refresh; deleting or breaking the file does not revoke anything until it goes stale.

## Deploying the mappings file

1. Create a versioned bucket in the account named by `s3_config_bucket_owner`.
2. Let the warden's Lambda role read the object only: `s3:GetObject` on `arn:aws:s3:::octo-aow-config-111122223333/mappings.yaml`, plus `kms:Decrypt` if the bucket uses SSE-KMS. No `s3:ListBucket`. With `session_policy_file` mappings, also `s3:GetObject` on `arn:aws:s3:::octo-aow-session-policies-111122223333/session-policies/*`.
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
         "Resource": "arn:aws:s3:::octo-aow-config-111122223333/*",
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
5. Upload: `aws s3 cp mappings.yaml s3://octo-aow-config-111122223333/mappings.yaml`.

Full IaC contract: [ARCHITECTURE.md § Infrastructure as code](../../ARCHITECTURE.md).

## Running locally

```sh
go run ./cmd/local -config docs/examples/split-config/service.yaml -mappings docs/examples/split-config/mappings.yaml
```

`-mappings` overrides `mappings_file`, so the local file is used instead of S3. A local path never goes stale. Without AWS access, drop the `idp` block and run with `AOW_CACHE_TYPE=memory AOW_LOG_TO_S3=false`.
