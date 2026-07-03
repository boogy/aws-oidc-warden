# Migrating to v2 (multi-issuer)

v2 turns the single-GitHub-issuer broker into a multi-issuer, any-provider one.
Authorization is now provider-neutral: it keys on a canonical **subject** and
generalized **conditions** instead of GitHub-specific `repo`/`constraints`.
This is a breaking release — work through the checklist below before upgrading.

## Rename table

| v1                                                 | v2                                             |
| -------------------------------------------------- | ---------------------------------------------- |
| top-level `issuer` / `audience` / `audiences`      | `issuers[]` entries (`issuer`, `audiences`, …) |
| `AOW_ISSUER` / `AOW_AUDIENCE` / `AOW_AUDIENCES`    | removed (configure `issuers[]`)                |
| `repo_role_mappings`                               | `role_mappings`                                |
| mapping key `repo:`                                | `subject:`                                     |
| mapping key `constraints:`                         | `conditions:`                                  |
| `repo_role_groups`                                 | `role_groups`                                  |
| Go `types.GithubClaims`                            | `types.Claims`                                 |
| Go `CreateSessionTags(claims)`                     | `BuildSessionTags(rawClaims, tagSpec)`         |
| Go `MatchRolesToRepoWithConstraints(repo, claims)` | `AuthorizeRoles(issuer, subject, claims)`      |
| Go `FindSessionPolicyForRepo(repo)`                | `FindSessionPolicy(issuer, subject)`           |
| Go `MatchRolesToRepo`                              | removed                                        |

## Config: before → after

v1:

```yaml
issuer: "https://token.actions.githubusercontent.com"
audiences: ["sts.amazonaws.com"]
repo_role_mappings:
  - repo: "org/api"
    roles: ["arn:aws:iam::123456789012:role/deploy"]
    constraints:
      branch: "refs/heads/main"
```

v2:

```yaml
issuers:
  - issuer: "https://token.actions.githubusercontent.com"
    provider: "github"
    audiences: ["sts.amazonaws.com"]
    required_claims: ["repository"]
    session_tags:
      repo: "repository"
      repo-owner: "repository_owner"
      ref: "ref"
      actor: "actor"
default_issuer: "https://token.actions.githubusercontent.com"
role_mappings:
  - subject: "org/api" # was `repo:`
    roles: ["arn:aws:iam::123456789012:role/deploy"]
    conditions: # was `constraints:`
      branch: "refs/heads/main"
```

With a single issuer you may omit `default_issuer` (mappings inherit the sole
issuer). With **two or more** issuers, each mapping must set `issuer:` or rely
on `default_issuer`.

## Breaking-change checklist

1. **Issuers.** Move `issuer`/`audience(s)` into `issuers[]`. Each issuer needs
   ≥1 `audiences` entry. Keep GitHub as `provider: github`.
2. **Mappings.** Rename `repo_role_mappings`→`role_mappings`, `repo:`→`subject:`,
   `constraints:`→`conditions:`, `repo_role_groups`→`role_groups`.
3. **default_issuer.** Add it (referencing a configured issuer) if you have
   more than one issuer and any mapping omits `issuer:`.
4. **Session tags.** They are now per-issuer under each issuer's `session_tags`
   (STS tag key ← raw claim name). **Behavior change:** the default `repo` tag
   now holds the **full `owner/repo`** (raw `repository` claim); v1 stripped the
   owner. Update ABAC policies/conditions that expected a bare repo name, or map
   `repo` to a claim that is already bare.
5. **Tag-based auth.** If you use it, add `aow/issuer` to your roles and prefer
   `aow/subject` for identity. `aow/repo` / `aow/repo-owner` still work as
   aliases during the v2 migration window — plan to move to `aow/subject`.
6. **Delegated modes.** `apigw`/`alb` now require **exactly one** configured
   issuer.
7. **snake_case S3/JSON config.** `PascalCase` keys are rejected (carried over
   from the prior release).
8. **Go embedders.** Update any code using the renamed types/functions above;
   `AssumeRole` now takes a trailing `sessionTags map[string]string`.

## Onboarding a non-GitHub provider

See `docs/MULTI_ISSUER.md`. In short: add an `issuers[]` entry with
`provider: generic`, a `claim_mappings.subject` pointing at the provider's
identity claim (e.g. GitLab `project_path`), `required_claims`, per-issuer
`audiences`, and (optionally) `session_tags` keyed on that provider's claims.

## New capabilities you may want to adopt

- `role_sets` (named ARN lists referenced as `@name`) and `role_groups` to cut
  repetition; `config_fragments` to split large mapping sets across local
  files today (safe, sha256-gated reload — remote `s3://` sources are defined
  but not yet wired into the shipped binaries).
- Hardening knobs: `max_token_lifetime` / `max_token_age` / `max_token_bytes` /
  `jwt_leeway` / `jwks_refetch_cooldown`.
- Audit + logging: `audit_required`, `log_claim_values`, `log_level`
  (see `docs/LOGGING.md`).
