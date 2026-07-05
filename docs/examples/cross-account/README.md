# Cross-Account Example: one warden, many accounts

This example shows how to run the warden in **one central (hub) account** and
let CI workloads assume roles in **any number of member accounts**. It contains:

| File | Purpose |
| --- | --- |
| [`config.yaml`](config.yaml) | Annotated warden configuration for the hub |
| [`member-account-roles.yaml`](member-account-roles.yaml) | CloudFormation for each member account (spoke + example target role), StackSets-ready |
| This README | The IAM roles, trust policies, and rollout steps |

Background reading: [TAG_BASED_AUTHORIZATION.md](../../TAG_BASED_AUTHORIZATION.md)
(hub/spoke model, tag reference), [SESSION_TAGGING.md](../../SESSION_TAGGING.md) (ABAC).

Accounts used throughout:

```
Hub    111111111111   runs the warden Lambda
Member 222222222222   staging workloads
Member 333333333333   production workloads
```

---

## Architecture

```
GitHub Actions ──OIDC token──▶ Warden (hub 111111111111)
                                  │ 1. validate token, authorize role
                                  │ 2. sts:AssumeRole aow-spoke        (member account)
                                  │ 3. iam:GetRole target tags         (via spoke creds)
                                  │ 4. sts:AssumeRole target role      (via spoke creds)
                                  ▼
                     temporary credentials for
                     arn:aws:iam::222222222222:role/aow/deploy-staging
```

Three roles are involved:

1. **Hub execution role** — the warden Lambda's own role. The *only* principal
   any member account needs to trust.
2. **Spoke role** (`aow-spoke`) — a small broker role deployed **once per
   member account**. Trusts the hub execution role (with an external ID) and
   can read tags on / assume only the target roles in its account.
3. **Target roles** — the roles workloads actually receive credentials for.
   They trust only their local spoke role.

Adding a new member account = deploying one CloudFormation stack (the spoke)
and adding its account ID to `cross_account.allowed_accounts`. No warden redeploy,
no new trust edges to the hub.

> **Choosing a pattern.** The spoke transport activates with
> `cross_account.enabled: true` and is the recommended pattern for many
> accounts. It is independent of tag-based authorization — explicit
> `role_mappings` reach member accounts through the spoke with `tag_auth`
> off. A simpler **direct-trust** alternative (no spoke) exists for a handful
> of roles — see [the last section](#alternative-direct-trust-without-the-spoke).
> Note the two don't mix: once `cross_account.enabled` is on, **every**
> cross-account assumption goes through the spoke, so target roles must trust
> the spoke, not the hub role.

---

## Step 1 — Hub account: warden execution role

Grant the warden's Lambda execution role (in addition to its usual logs/S3/
cache permissions):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ResolveOwnAccount",
      "Effect": "Allow",
      "Action": "sts:GetCallerIdentity",
      "Resource": "*"
    },
    {
      "Sid": "AssumeSpokeRolesInMemberAccounts",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": [
        "arn:aws:iam::222222222222:role/aow-spoke",
        "arn:aws:iam::333333333333:role/aow-spoke"
      ]
    },
    {
      "Sid": "SameAccountTargets",
      "Effect": "Allow",
      "Action": ["iam:GetRole", "sts:AssumeRole", "sts:TagSession"],
      "Resource": "arn:aws:iam::111111111111:role/aow/*"
    }
  ]
}
```

Notes:

- List the spoke ARNs per account as above, or use
  `arn:aws:iam::*:role/aow-spoke` and rely on `cross_account.allowed_accounts`
  plus each spoke's trust policy — explicit ARNs are the tighter default.
- `sts:GetCallerIdentity` is how the warden learns its own (hub) account ID to
  decide when the spoke hop is needed. (It is allowed for any principal by
  default; the explicit statement just survives restrictive boundaries.)
- The `SameAccountTargets` statement is only needed if some target roles live
  in the hub account itself (they skip the spoke and are assumed directly).

## Step 2 — Member accounts: deploy the spoke (and target roles)

Deploy [`member-account-roles.yaml`](member-account-roles.yaml) to every member
account. From one central place, use **CloudFormation StackSets** so a single
operation covers the whole organization (and new accounts get the spoke
automatically via auto-deployment):

```sh
aws cloudformation create-stack-set \
  --stack-set-name aws-oidc-warden-spoke \
  --template-body file://member-account-roles.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --parameters \
    ParameterKey=HubAccountId,ParameterValue=111111111111 \
    ParameterKey=HubExecutionRoleName,ParameterValue=aws-oidc-warden-execution-role \
    ParameterKey=ExternalId,ParameterValue=CHANGE-ME-org-wide-external-id

aws cloudformation create-stack-instances \
  --stack-set-name aws-oidc-warden-spoke \
  --deployment-targets OrganizationalUnitIds=ou-abcd-11111111 \
  --regions us-east-1
```

(IAM is global — one region per account is enough. For a small number of
accounts, `aws cloudformation deploy` per account works just as well.)

What the template creates:

**The spoke role** — trust policy (only the hub execution role, gated by the
external ID):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111111111111:role/aws-oidc-warden-execution-role"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": { "sts:ExternalId": "CHANGE-ME-org-wide-external-id" }
      }
    }
  ]
}
```

and a permissions policy scoped to the `/aow/` path, so only roles deliberately
created under that path are reachable through the warden:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadTargetRoleTags",
      "Effect": "Allow",
      "Action": "iam:GetRole",
      "Resource": "arn:aws:iam::222222222222:role/aow/*"
    },
    {
      "Sid": "AssumeTargetRoles",
      "Effect": "Allow",
      "Action": ["sts:AssumeRole", "sts:TagSession"],
      "Resource": "arn:aws:iam::222222222222:role/aow/*"
    }
  ]
}
```

**Target roles** — each trusts only the local spoke, with an optional
`aws:RequestTag` condition as defense-in-depth (session tags are attached by
the warden from *verified* token claims, so the condition holds independently
of warden configuration):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::222222222222:role/aow-spoke" },
      "Action": ["sts:AssumeRole", "sts:TagSession"],
      "Condition": {
        "StringEquals": { "aws:RequestTag/repo-owner": "acme" }
      }
    }
  ]
}
```

`sts:TagSession` must be in the trust policy's `Action` — the warden always
attaches the issuer's session tags, and STS rejects a tagged AssumeRole
without it.

## Step 3 — Hub: warden configuration

Use [`config.yaml`](config.yaml). The cross-account essentials:

```yaml
cross_account:
  enabled: true # activates the spoke transport
  spoke_role_name: "aow-spoke" # must match the role name in member accounts
  external_id: "CHANGE-ME-org-wide-external-id" # must match the spokes' trust condition
  allowed_accounts: # REQUIRED in production — empty list = ANY account
    - "222222222222"
    - "333333333333"

role_mappings:
  - subject: "acme/api"
    roles:
      - arn:aws:iam::222222222222:role/aow/deploy-staging
    conditions:
      branch: "refs/heads/main"
```

Authorization works exactly as in a single account — a member-account role ARN
in `role_mappings` needs nothing special, and `tag_auth` can stay disabled.
Optionally enable `tag_auth` as well: roles tagged with `aow/*` tags become
assumable without any mapping, cross-account included (see
[TAG_BASED_AUTHORIZATION.md](../../TAG_BASED_AUTHORIZATION.md)).

## Step 4 — Verify

From a workflow of an authorized repo (e.g. `acme/api` on `main`):

```sh
curl -sS -X POST "$WARDEN_URL" \
  -H "Content-Type: application/json" \
  -d '{"token":"'"$OIDC_TOKEN"'","role":"arn:aws:iam::222222222222:role/aow/deploy-staging"}'
```

Expected: temporary credentials for the member-account role, session ≤ 1 hour.
Then confirm in the **member account's** CloudTrail: an `AssumeRole` of
`aow-spoke` by the hub execution role, followed by an `AssumeRole` of the
target role by the spoke session, carrying the session tags (`repo`, `ref`,
`actor`, …).

Denial checks worth doing once:

- A role ARN in an account **not** in `allowed_accounts` → `403` (`ErrAccountNotAllowed`).
- A repo/branch not matching any mapping (and no matching `aow/*` tags) → `403` (`ErrRoleNotPermitted`).

---

## Operational notes

- **1-hour session cap.** Cross-account assumption is role chaining, so AWS
  caps the final session at 1 hour regardless of the target role's
  `MaxSessionDuration`. Same-account (hub) targets can still get up to 12 h.
- **`allowed_accounts` fails open when empty.** An empty list means *any*
  account reachable via a spoke. Always populate it in production; the hub
  account is always implicitly allowed and doesn't need listing.
- **External ID.** One org-wide value is fine — it defends against a
  confused-deputy misuse of the hub role, not against member-vs-member
  isolation (that comes from each spoke being scoped to its own account).
  Rotate by updating the spokes' trust policies, then the warden config.
- **Caching.** Spoke credentials are cached until ~5 min before expiry and
  role tags for ~60 s — tag changes on target roles take up to a minute to
  apply.
- **Scoping the spoke.** The `/aow/` role path is the containment boundary in
  each member account: the spoke can only see and assume roles under it.
  Creating a target role under `/aow/` is the deliberate act that exposes it
  to the warden.
- **Session policies** apply only on the mapping path; tag-authorized roles
  get no inline session policy — keep them least-privilege at the IAM level.

## Alternative: direct trust (without the spoke)

For a *small, fixed* set of cross-account roles you can skip the spoke: leave
`cross_account.enabled: false`, list the member-account ARNs in
`role_mappings`, grant the hub execution role `sts:AssumeRole` +
`sts:TagSession` on those exact ARNs, and have each target role trust the hub
execution role directly:

```json
{
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::111111111111:role/aws-oidc-warden-execution-role"
  },
  "Action": ["sts:AssumeRole", "sts:TagSession"]
}
```

Trade-offs: no role chaining (sessions up to 12 h), one less hop — but every
target role in every account must individually trust the hub role, there is no
per-account containment boundary, no external ID, and no `allowed_accounts`
gate (that check activates with `cross_account.enabled`). The hub-and-spoke
pattern above scales better and is the recommended default; the two patterns
don't mix, since enabling `cross_account` reroutes all cross-account calls
through the spoke.
