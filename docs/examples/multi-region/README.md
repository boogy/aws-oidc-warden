# Multi-region example

One warden, two regions (eu-west-1 primary, us-east-1 secondary), account `111122223333`. Each region is a complete, independent deployment: nothing in the request path calls another region.

| File                             | Holds                                                               |
| -------------------------------- | ------------------------------------------------------------------- |
| [`config.yaml`](config.yaml)     | Shared config, identical in every region, shipped in the package    |
| [`eu-west-1.env`](eu-west-1.env) | Lambda environment variables for eu-west-1: that region's resources |
| [`us-east-1.env`](us-east-1.env) | Lambda environment variables for us-east-1: that region's resources |

Deploy the same artifact and `config.yaml` everywhere. Set each region's own resources as `AOW_*` environment variables on its Lambda; env beats the config file, including on every hot reload. Every key has an env var: [CONFIGURATION.md § Environment Variable Reference](../../CONFIGURATION.md#environment-variable-reference).

## Per region or shared

| Resource                          | Where                           | Set by                                             | Why                                                                                                                                           |
| --------------------------------- | ------------------------------- | -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Lambda + front-end (API GW / ALB) | Per region                      | Your IaC                                           | One endpoint per region; callers fail over between them                                                                                       |
| JWKS cache table                  | Per region                      | `AOW_CACHE_DYNAMODB_TABLE`                         | Rebuildable from one JWKS fetch. Never a Global Table: replication buys nothing and couples the regions                                       |
| Audit bucket                      | Per region                      | `AOW_LOG_BUCKET`                                   | With `audit_required`, a shared bucket fails the secondary closed during a primary-region S3 outage                                           |
| Mappings file                     | Per region (same content)       | `AOW_MAPPINGS_FILE`                                | A cross-region read makes the primary's S3 a dependency of every region                                                                       |
| Session-policy bucket             | Per region (same content)       | `AOW_SESSION_POLICY_BUCKET`                        | Same reason                                                                                                                                   |
| S3 config overlay (optional)      | Per region (same content)       | `AOW_S3_CONFIG_BUCKET`, `AOW_S3_CONFIG_PATH`       | Same reason                                                                                                                                   |
| Issuers, hardening, `idp` block   | Shared                          | `config.yaml`                                      | Authorization must answer the same in every region, or failover changes the outcome                                                           |
| IdP signing key                   | One MRK, one replica per region | `idp.signing_keys`, `idp.kms_allowed_regions`      | Each region signs with its local replica; same key material gives one JWKS. See [IDP.md § Multi-region](../../IDP.md#multi-region-deployment) |
| IdP JWKS and discovery            | Global                          | Static hosting (S3 + CloudFront from `idp-export`) | STS fetches it; a regional Lambda would tie STS to one region                                                                                 |
| IAM OIDC provider, IAM roles      | Global                          | Your IaC                                           | IAM is global                                                                                                                                 |

Keep the per-region copies identical: CI uploads `mappings.yaml` and session-policy files to every region's bucket in the same job, or S3 replication copies them. A region whose upload failed keeps serving its last good file until `mappings_max_stale`, then returns `503 config_stale`, which callers treat as a failover signal.

## Execution role and target-role trust

- One execution role (IAM is global) or one per region. With one per region, every target role's trust policy must list **every** region's execution role; otherwise failover passes the gateway and fails at `sts:AssumeRole`.
- The role needs `s3:GetObject` on each region's mappings and policy objects, `s3:PutObject` on each region's audit bucket, and DynamoDB access to each region's table. Narrow each region's policy to its own resources when roles are per region.
- IdP-issued roles trust the warden's IAM OIDC provider, not the execution role, so they need no per-region change.

## Callers

Clients list both endpoints and fail over on unreachable or transient errors only; refusals (`400`/`401`/`403`) are final, because every region answers the same. Client code: [GITHUB_ACTIONS.md § Multi-region failover](../../GITHUB_ACTIONS.md#multi-region-failover).

## Adding a region

1. Create the region's table, audit bucket and config buckets; upload the current mappings and policy files.
2. If the IdP is enabled: add the region to `idp.kms_allowed_regions` in `config.yaml`, deploy every region, then `ReplicateKey` into the new region.
3. Deploy the Lambda with the new region's `.env`.
4. Add the endpoint to callers' failover lists.

Both files load in CI: `TestMultiRegionExampleLoads` (`internal/config/docs_yaml_test.go`) loads `config.yaml` under each region's environment.
