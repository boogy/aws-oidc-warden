# Tag-Based Authorization & Cross-Account

Tag-based authorization lets a repository assume any IAM role whose **tags**
authorize the request, without listing the role in `repo_role_mappings`. It also
enables serving roles from **other AWS accounts** through a per-account spoke
role. The feature is opt-in (`tag_auth.enabled`, default `false`) and additive:
explicit `repo_role_mappings` are evaluated first; tag-based authorization is a
fallback when no explicit mapping authorizes the requested role.

## How it works

1. The workflow requests a role ARN as usual.
2. If `repo_role_mappings` already authorizes that role, it is used (unchanged
   behavior; explicit mappings also keep owning session-policy selection).
3. Otherwise, when `tag_auth.enabled` is `true`, the warden reads the role's IAM
   tags (`iam:GetRole`) and checks them against the token claims. If they match,
   the role is assumed.
4. The account ID is parsed from the requested role ARN. If the role lives in a
   different account than the warden (the *hub*), the warden first assumes a
   convention-named **spoke** role in that account and uses those credentials
   for both the tag read and the final `sts:AssumeRole`. Same-account requests
   skip this hop.

Assumed spoke credentials are cached until ~5 minutes before expiry; role tag
reads are cached for ~60 seconds.

## Tag reference

Tag keys use a configurable prefix (`tag_auth.tag_prefix`, default `aow/`). A tag
value is a single value or a **space-separated list** (OR within a tag). All
present tags must pass (**AND** across tags).

| Tag (default prefix) | Claim checked                         | Notes |
| -------------------- | ------------------------------------- | ----- |
| `aow/repo`           | `repository` (e.g. `acme/api`)        | exact or space-list |
| `aow/repo-owner`     | `repository_owner` (e.g. `acme`)      | whole org; OR with `aow/repo` |
| `aow/branch`         | `ref` **or** short branch name        | `main` or `refs/heads/main` |
| `aow/ref-type`       | `ref_type` (`branch`/`tag`)           | exact or space-list |
| `aow/event-name`     | `event_name` (`push`, ...)            | exact or space-list |
| `aow/environment`    | `runner_environment`                  | mirrors the existing `constraints.environment` behavior |
| `aow/actor`          | `actor`                               | exact or space-list |

**Identity gate:** a role must carry at least an `aow/repo` or `aow/repo-owner`
tag and match it (`repo` OR `owner`). A role with neither tag is never assumable
via tag-auth. The two together mean "this repo, or any repo in this org".

> **AWS tag charset:** tag values allow only letters, digits, spaces, and
> `_ . : / = + - @`. No regex/wildcards — matching is exact. Use a space-list to
> allow multiple specific repos, or `aow/repo-owner` for a whole org.

### Example

A role tagged:

```
aow/repo:        "acme/api acme/web"
aow/branch:      "refs/heads/main"
aow/event-name:  "push"
```

is assumable by `acme/api` or `acme/web`, only on a push to `main`.

## IAM setup

### Hub (the account running the warden)

The warden's execution role needs:

- `sts:GetCallerIdentity` (to learn its own account).
- Same-account roles: `iam:GetRole`, `sts:AssumeRole`, `sts:TagSession` on the
  target roles.
- Cross-account: `sts:AssumeRole` on `arn:aws:iam::*:role/<spoke_role_name>`
  (default `aow-spoke`).

### Spoke role (one per member account)

Create a role named `<spoke_role_name>` (default `aow-spoke`) in each member
account.

- **Trust policy:** trusts the hub execution role. Optionally require
  `sts:ExternalId` matching `tag_auth.external_id`.
- **Permissions:** `iam:GetRole` (read target tags), plus `sts:AssumeRole` and
  `sts:TagSession` on the target roles in that account.

### Target role (the role workflows assume)

- **Trust policy:** trust the spoke role (cross-account) or the hub execution
  role (same account). Optionally add `aws:RequestTag/...` conditions as
  defense-in-depth alongside the warden's tag checks.
- **Tags:** the `aow/*` tags from the reference above.

## Configuration

```yaml
tag_auth:
  enabled: true
  tag_prefix: "aow/"
  spoke_role_name: "aow-spoke"
  external_id: ""            # optional
  spoke_session_duration: "15m"
```

Or via environment variables: `AOW_TAG_AUTH_ENABLED`, `AOW_TAG_AUTH_TAG_PREFIX`,
`AOW_TAG_AUTH_SPOKE_ROLE_NAME`, `AOW_TAG_AUTH_EXTERNAL_ID`,
`AOW_TAG_AUTH_SPOKE_SESSION_DURATION`.
