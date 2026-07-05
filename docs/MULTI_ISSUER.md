# Multi-issuer & onboarding any OIDC provider

v2 validates tokens from any number of OIDC issuers. Each issuer is one entry
in `issuers[]`; a token is routed to its issuer by an exact `iss` match, its
signature is verified against that issuer's JWKS, and its claims are normalized
to a canonical **subject** used for authorization.

## The two providers

- **`provider: github`** — natively unmarshals the full GitHub Actions claim
  set. The canonical `subject` defaults to the `repository` claim (override via
  `claim_mappings.subject`).
- **`provider: generic`** (default) — no native struct. You **must** map the
  canonical `subject` from a provider claim with `claim_mappings.subject`.
  Conditions and session tags reference the provider's **raw claim names**.

Adding a provider requires no code changes — just an `issuers[]` entry.

## Issuer fields

| field             | required                                 | meaning                                                                              |
| ----------------- | ---------------------------------------- | ------------------------------------------------------------------------------------ |
| `issuer`          | yes                                      | exact `iss` value trusted (no normalization)                                         |
| `provider`        | no                                       | `github` or `generic` (default `generic`)                                            |
| `audiences`       | yes (≥1)                                 | accepted `aud` values (ANY-match)                                                    |
| `jwks_uri`        | no                                       | explicit JWKS URL; omit to use OIDC discovery                                        |
| `claim_mappings`  | github: no / generic: `subject` required | canonical field ← raw claim name; may not target `iss`/`aud`/`exp`/`nbf`/`iat`/`sub` |
| `required_claims` | no                                       | raw claim names that must be present + non-empty                                     |
| `session_tags`    | no                                       | STS tag key ← raw claim name (key charset `[A-Za-z0-9 _.:/=+@-]{1,128}`)             |

Issuer and `jwks_uri` must be HTTPS (loopback `http://` only with
`allow_insecure_issuers`, dev/test only).

## Example: GitHub + GitLab

```yaml
issuers:
  - issuer: "https://token.actions.githubusercontent.com"
    provider: "github"
    audiences: ["sts.amazonaws.com"]
    required_claims: ["repository"]
    session_tags: { repo: "repository", ref: "ref", actor: "actor" }

  - issuer: "https://gitlab.com"
    provider: "generic"
    audiences: ["https://gitlab.com"]
    claim_mappings:
      subject: "project_path" # canonical subject = GitLab project path
    required_claims: ["project_path"]
    session_tags: { project: "project_path", ref: "ref" }
```

Then bind roles per issuer:

```yaml
default_issuer: "https://token.actions.githubusercontent.com"
role_mappings:
  - subject: "myorg/api" # inherits default_issuer (GitHub)
    roles: ["arn:aws:iam::123456789012:role/gh-api"]
    conditions: { branch: "refs/heads/main" }

  - subject: "mygroup/myproject" # GitLab
    issuer: "https://gitlab.com"
    roles: ["arn:aws:iam::123456789012:role/gl-ci"]
    conditions: { ref: "main" }
```

## How to onboard a new provider

1. Find the provider's issuer URL and confirm its discovery document at
   `<issuer>/.well-known/openid-configuration` (or set `jwks_uri` directly).
2. Pick the claim that identifies the workload and map it:
   `claim_mappings.subject: <that claim>`.
3. Choose the audience(s) the provider mints tokens for and list them under
   `audiences`.
4. Add `required_claims` for any claim your `conditions`/authorization rely on.
5. Optionally define `session_tags` keyed on the provider's raw claims for ABAC
   and audit.
6. Add `role_mappings` (or a `role_group`) bound to the new `issuer`.

## Delegated modes are single-issuer only

`jwt_validation.mode: apigw` / `alb` trust an upstream (API Gateway JWT
Authorizer, ALB OIDC) that verified the token against a **single** issuer — the
upstream cannot tell this service *which* issuer it checked. Both modes
therefore require **exactly one** entry in `issuers[]`; `NewBootstrap()` fails
at cold start otherwise (`jwt_validation.mode %q supports exactly one
configured issuer, got %d`). Multi-issuer configs are `self`-mode only.

## Tag-based authorization across issuers

With tag-based authorization ([TAG_BASED_AUTHORIZATION.md](TAG_BASED_AUTHORIZATION.md))
the canonical identity tag is `aow/subject`, matched against any issuer's
canonical subject (`aow/repo`/`aow/repo-owner` remain accepted as legacy
GitHub-shaped aliases). Once **more than one** issuer is configured, a role
must also carry a matching `aow/issuer` tag or tag-auth fails closed for it —
otherwise a role scoped to one issuer's subjects would be reachable by another
issuer's identically-shaped subject (e.g. a GitHub `owner/repo` colliding with
a GitLab `group/project`). Add `aow/issuer` to tag-authorized roles **before**
adding a second issuer.

## Security notes

- The unverified `iss` is used only for routing; every identity/role decision
  uses post-signature-verified claims, and the verified `iss` is re-asserted
  against the matched spec.
- An issuer's audience set is isolated from every other issuer's — a token's
  `aud` is only ever checked against the spec resolved by its own verified
  `iss`, and role mappings are issuer-bound (no cross-issuer subject collision).
- A token can never self-assert an unmapped `subject`: it comes only from
  `claim_mappings.subject` (or the GitHub `repository` default).
