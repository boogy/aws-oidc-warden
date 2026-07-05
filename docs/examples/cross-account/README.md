# Cross-Account Example: one warden, many accounts

This example shows how to run the warden in **one central (hub) account** and
let CI workloads assume roles in **any number of member accounts**. It contains:

| File                                                     | Purpose                                                                                |
| -------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| [`config.yaml`](config.yaml)                             | Annotated warden configuration for the hub                                             |
| [`member-account-roles.yaml`](member-account-roles.yaml) | CloudFormation for each member account (target role + optional spoke), StackSets-ready |
| This README                                              | The IAM roles, trust policies, and rollout steps                                       |

Background reading: [TAG_BASED_AUTHORIZATION.md](../../TAG_BASED_AUTHORIZATION.md)
(cross-account model, tag reference), [SESSION_TAGGING.md](../../SESSION_TAGGING.md) (ABAC).

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
                                  │ 2. (tag_auth only) iam:GetRole target tags
                                  │    — via the per-account spoke role
                                  │ 3. sts:AssumeRole target role — DIRECT,
                                  │    using the warden's own (hub) credentials
                                  ▼
                     temporary credentials for
                     arn:aws:iam::222222222222:role/aow/deploy-staging
```

Two roles are involved for a plain `role_mappings` setup:

1. **Hub execution role** — the warden Lambda's own role. It assumes every
   target role directly, same-account and cross-account alike — the _only_
   principal any member account's target roles need to trust.
2. **Target roles** — the roles workloads actually receive credentials for.
   They trust the hub execution role directly.

A third role, the **spoke** (`aow-spoke`), is only needed if you enable
`tag_auth` for roles in member accounts. IAM has no resource-based policies,
so the warden cannot read a role's tags in another account using its own
identity — it needs an identity _in_ that account. The spoke is a small role,
deployed once per member account, whose only job is `iam:GetRole` for that
tag read. **It is never used to assume the target role** — the final
`AssumeRole` always goes directly hub → target, in one hop, with the warden's
own credentials.

`cross_account.enabled` is a **policy gate**, not a transport choice: `false`
(or the `cross_account` block omitted) hard-blocks _every_ cross-account
operation — both assumes and tag reads fail closed with an error. Set it
`true` and populate `allowed_accounts` to reach member-account roles, whether
through `role_mappings` or `tag_auth`.

Adding a new member account = deploying its target role(s) (and the spoke,
only if `tag_auth` reads roles in that account) and adding the account ID to
`cross_account.allowed_accounts`. No warden redeploy.

---

## Step 1 — Hub account: warden execution role

Grant the warden's Lambda execution role (in addition to its usual logs/S3/
cache permissions):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ResolveOwnIdentity",
      "Effect": "Allow",
      "Action": "sts:GetCallerIdentity",
      "Resource": "*"
    },
    {
      "Sid": "AssumeTargetRolesInMemberAccounts",
      "Effect": "Allow",
      "Action": ["sts:AssumeRole", "sts:TagSession"],
      "Resource": [
        "arn:aws:iam::222222222222:role/aow/*",
        "arn:aws:iam::333333333333:role/aow/*"
      ]
    },
    {
      "Sid": "SameAccountTargets",
      "Effect": "Allow",
      "Action": ["iam:GetRole", "sts:AssumeRole", "sts:TagSession"],
      "Resource": "arn:aws:iam::111111111111:role/aow/*"
    },
    {
      "Sid": "AssumeSpokeRolesForTagReads",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": [
        "arn:aws:iam::222222222222:role/aow-spoke",
        "arn:aws:iam::333333333333:role/aow-spoke"
      ]
    }
  ]
}
```

Notes:

- Prefer per-account target-role patterns
  (`arn:aws:iam::<member>:role/aow/*`) over a blanket
  `arn:aws:iam::*:role/aow/*` — a tighter blast radius if `role_mappings` or
  `allowed_accounts` is ever misconfigured.
- `sts:GetCallerIdentity` is how the warden learns its own account ID _and_
  whether its own credentials are a role session — both feed the
  `allowed_accounts` check and the session-duration clamp (see
  [Operational notes](#operational-notes)). It's allowed for any principal by
  default; the explicit statement just survives restrictive permission
  boundaries.
- `AssumeSpokeRolesForTagReads` is only needed when `tag_auth` reaches roles
  in member accounts. Omit it if you authorize purely through
  `role_mappings`.
- `SameAccountTargets` is only needed if some target roles live in the hub
  account itself.

## Step 2 — Member accounts: deploy target roles (and the spoke, if needed)

Deploy [`member-account-roles.yaml`](member-account-roles.yaml) to every member
account. From one central place, use **CloudFormation StackSets** so a single
operation covers the whole organization (and new accounts are provisioned
automatically via auto-deployment):

```sh
aws cloudformation create-stack-set \
  --stack-set-name aws-oidc-warden-member \
  --template-body file://member-account-roles.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --parameters \
    ParameterKey=HubAccountId,ParameterValue=111111111111 \
    ParameterKey=HubExecutionRoleName,ParameterValue=aws-oidc-warden-execution-role \
    ParameterKey=ExternalId,ParameterValue=CHANGE-ME-org-wide-external-id

aws cloudformation create-stack-instances \
  --stack-set-name aws-oidc-warden-member \
  --deployment-targets OrganizationalUnitIds=ou-abcd-11111111 \
  --regions us-east-1
```

(IAM is global — one region per account is enough. For a small number of
accounts, `aws cloudformation deploy` per account works just as well.)

What the template creates:

**Target roles** — each trusts the **hub execution role directly** (no
`sts:ExternalId` condition; the warden sends none on this direct assume), with
an optional `aws:RequestTag` condition as defense-in-depth (session tags are
attached by the warden from _verified_ token claims, so the condition holds
independently of warden configuration):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111111111111:role/aws-oidc-warden-execution-role"
      },
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

**The spoke role** (`aow-spoke`) — deploy only if `tag_auth` reads role tags
in this account. Its trust policy is unchanged from before (hub principal,
optional external ID):

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

but its permissions policy is now scoped to **`iam:GetRole` only** — it is
never used to assume anything:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadTargetRoleTags",
      "Effect": "Allow",
      "Action": "iam:GetRole",
      "Resource": "arn:aws:iam::222222222222:role/aow/*"
    }
  ]
}
```

If you authorize exclusively through `role_mappings`, skip the spoke resource
entirely — it has no role in the assume path.

## Step 3 — Hub: warden configuration

Use [`config.yaml`](config.yaml). The cross-account essentials:

```yaml
cross_account:
  enabled: true # policy gate: required for ANY cross-account use (assumes and tag reads)
  spoke_role_name: "aow-spoke" # only used for cross-account tag reads (tag_auth)
  external_id: "CHANGE-ME-org-wide-external-id" # hub->spoke trust only; never sent on the hub->target assume
  allowed_accounts: # REQUIRED in production — empty list = ANY account, once enabled
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

Expected: temporary credentials for the member-account role, session ≤ 1 hour
(the warden's Lambda credentials are always a role session, so chaining clamps
the duration — see [Operational notes](#operational-notes)). Then confirm in
the **member account's** CloudTrail: a single `AssumeRole` of the target role
by the hub execution role, directly, carrying the session tags (`repo`, `ref`,
`actor`, …). If `tag_auth` reached this role, you'll also see an `AssumeRole`
of `aow-spoke` followed by a `GetRole` call using those credentials — that
call never appears in the final `AssumeRole`'s chain.

Denial checks worth doing once:

- A role ARN in an account **not** in `allowed_accounts` (or with
  `cross_account` disabled/absent) → `403`/`500` (`ErrAccountNotAllowed` /
  assume-role failure).
- A repo/branch not matching any mapping (and no matching `aow/*` tags) → `403` (`ErrRoleNotPermitted`).

---

## Operational notes

- **`cross_account.enabled` fails closed.** Leaving it `false` or omitting the
  block hard-blocks every cross-account operation — assumes _and_ tag reads —
  with an error. There is no fail-open behavior.
- **Session duration is about chained credentials, not cross-account.** STS
  fails (does not clamp) a chained `AssumeRole`'s `DurationSeconds` over 1
  hour. The warden's own credentials are always a role session on Lambda, so
  _any_ assume it performs — same-account included — is clamped to 1 hour.
  Only `local` server mode running with long-lived IAM user credentials can
  request up to the target role's own `MaxSessionDuration` (≤ 12h), even for a
  cross-account target.
- **External ID protects only the hub→spoke tag-read hop.** It defends
  against a confused-deputy misuse of the hub role reading tags in the wrong
  account — it has no bearing on the hub→target assume, which the warden
  performs with no external ID at all. Member target-role trust policies must
  **not** require `sts:ExternalId`.
- **`allowed_accounts` fails open only once enabled.** With
  `cross_account.enabled: true`, an empty list means _any_ account is
  reachable. Always populate it in production; the hub account is always
  implicitly allowed and doesn't need listing.
- **Caching.** Spoke credentials (when used) are cached until ~5 min before
  expiry and role tags for ~60 s — tag changes on target roles take up to a
  minute to apply.
- **Scoping the spoke.** The `/aow/` role path is the containment boundary in
  each member account for tag reads: the spoke can only see roles under it.
  Creating a target role under `/aow/` is the deliberate act that exposes it
  to tag-based authorization.
- **Session policies** apply only on the mapping path; tag-authorized roles
  get no inline session policy — keep them least-privilege at the IAM level.
