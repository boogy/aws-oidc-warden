# Migrating to v3 (claim-named conditions)

v3 makes `conditions:` say what it checks. Every key is now the **raw verified claim name**, for every issuer, and every value takes one anchored pattern or a list of them. The three keys whose names did not match their claim are gone, and nothing is deprecated-but-working: an old spelling is either renamed or it means something else.

One thing outside `conditions:` changes with it: the `aow/environment` IAM role tag followed the same rename (see [Tag-based authorization](#tag-based-authorization-follows-the-same-rename)). Issuers, subjects, role sets, session policies, session tags, caching, and the request/response shape are identical to v2.

## Rename table

| v2 key                         | v3 key                                | Claim checked                                           |
| ------------------------------ | ------------------------------------- | ------------------------------------------------------- |
| `branch: "refs/heads/main"`    | `ref: "refs/heads/main"`              | `ref` — unchanged; `branch` never checked a branch name |
| `actor_matches: [...]`         | `actor: [...]`                        | `actor` — unchanged                                     |
| `environment: "github-hosted"` | `runner_environment: "github-hosted"` | `runner_environment` — **read the warning below**       |

A leftover `branch:` or `actor_matches:` does **not** stop the service from starting. Both now read as predicates on claims of those literal names, which GitHub does not issue, so the mapping denies every request and the boot log carries a warning naming the key (step 5 of the checklist). Fail-closed, but the failure shows up as a broken pipeline rather than a failed deploy — do the rename before you ship, not after.

With one exception, which is the reason to do the rename rather than wait for the pipeline to break: **inside a `none_of`, the polarity inverts.** A member that can never match is a veto that can never fire, so the group passes and the mapping authorizes exactly the caller the rule was written to refuse. Deny-listing a branch or an actor is the natural `none_of` use case, so this is precisely where a leftover `branch:`/`actor_matches:` is most likely to sit. The boot WARN for that placement says so in those words — it is worded differently from the ordinary unknown-claim warning for this reason.

## `environment` is the one that bites

`environment` still exists as a condition key, but it no longer means what it meant in v2.

| Version | `environment:` checks                                                                                           |
| ------- | --------------------------------------------------------------------------------------------------------------- |
| v2      | the `runner_environment` claim (`github-hosted` / `self-hosted`)                                                |
| v3      | the `environment` claim — the deployment environment a job declares (`environment: production` in the workflow) |

A v2 config that carries `environment: "github-hosted"` **loads without error in v3** and then denies: it is now asking for a deployment environment literally named `github-hosted`, which no job declares. Rename it to `runner_environment` before upgrading.

This is also what v3 buys you: the deployment-environment claim was unreachable in v2, because the key that would have named it was taken. Gating on "this job ran in the `production` environment" is now one line.

```yaml
conditions:
  environment: "production" # deployment environment declared by the job
  runner_environment: "github-hosted" # runner type — a different claim
```

## Tag-based authorization follows the same rename

Role tags name claims the same way conditions do, so the tag moved with the key:

| Tag                      | v2 claim             | v3 claim             |
| ------------------------ | -------------------- | -------------------- |
| `aow/environment`        | `runner_environment` | `environment`        |
| `aow/runner-environment` | —                    | `runner_environment` |

A role tagged `aow/environment: github-hosted` stops matching (fail-closed, same as the condition key). Retag it `aow/runner-environment: github-hosted`. Nothing else about tag-auth changes.

## Reserved keys and the `claims:` escape hatch

Four keys under `conditions:` are not read as claim names: `all_of`, `any_of`, `none_of`, and `claims`. If an issuer mints a claim named like one of them, nest it under `claims:`, whose keys are **always** raw claim names:

```yaml
conditions:
  ref: "refs/heads/main"
  claims:
    all_of: "a-claim-really-named-all_of"
    environment: "production" # identical to writing it at the top level
```

Entries under `claims:` are AND-ed with everything else on the node. It is a spelling, not a separate evaluation mode.

## Checklist

1. `grep -n 'branch:\|actor_matches:\|environment:' <your config>` — inside `conditions:` blocks only.
2. `branch:` → `ref:`, `actor_matches:` → `actor:`.
3. `environment:` → `runner_environment:` **unless** you actually meant the deployment environment, in which case leave it.
4. Anything under a `constraints:` key is still v1 — see [MIGRATION_V2.md](MIGRATION_V2.md) first.
5. Start the service and read the boot log. On a `provider: github` issuer, a condition naming a claim GitHub does not issue is reported by name — that catches a typo'd rename, since a claim that does not exist can never match and would otherwise deny silently.
6. `aws resourcegroupstaggingapi get-resources --tag-filters Key=aow/environment` — any role that turns up needs the tag renamed to `aow/runner-environment`, unless it really meant a deployment environment.
7. Remove any condition key you left written with no value (`environment:` and nothing after it), and any `conditions:` written with nothing under it — including an explicit `conditions: null` from a generator, which YAML cannot tell apart from the typo. v3 rejects both at load: they used to decode as if the key were absent, so the mapping authorized more than the file said. An unconditional mapping omits the key.
8. Values may now be lists (`actor: ["release-bot", "release-manager"]`), which often collapses a duplicated mapping or an `any_of` group into one line.

## Also new in v3: boolean groups

`all_of` / `any_of` / `none_of` are new in this release. They nest inside a `conditions:` block for logic the implicit AND cannot express, up to 5 levels deep and 64 nodes per mapping (both enforced at load). A v2 config contains none of them, so there is nothing to migrate — they are what a decision that used to need two separate mappings can now collapse into one.

## What did NOT change

- Entries at the same level are AND-ed; patterns within one key are OR-ed.
- Every pattern is auto-anchored (`^(?:pattern)$`), and a bare `.*` / `.+` is rejected wherever it gates a decision.
- A claim whose value is a list matches when any element matches.
