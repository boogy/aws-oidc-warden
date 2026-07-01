# SHARED — invariants, naming, standards (prepend to every subagent prompt)

This is the non-negotiable contract for every group. Read it fully before touching code.

## What we're building

Single-GitHub-issuer → **multi-issuer, any-provider** OIDC validation that brokers production AWS IAM credentials. Per-issuer audiences, per-provider claim mapping to a canonical **subject**, generalized **conditions**, selectable **session tags**, scalable config (thousands of mappings), professional logging/audit. **v2.0.0 breaking** — no back-compat aliases except a TagAuth tag migration window.

## Naming & terminology (provider-neutral — authoritative)

OIDC claims are provider-global. The authz surface is named around **subject** (identity authorized) and **conditions** (claim predicates) — never "repo".

| Old | New |
| --- | --- |
| config `repo_role_mappings` | `role_mappings` |
| mapping key `repo:` | `subject:` |
| mapping `constraints:` | `conditions:` |
| `repo_role_groups` | `role_groups` |
| Go `RepoRoleMapping` | `RoleMapping` (fields `Subject`,`Issuer`,`Conditions`,`Roles`,`SessionPolicy`/`SessionPolicyFile`) |
| Go `Constraint` | `Condition` |
| `MatchRolesToRepoWithConstraints(repo, claims)` | `AuthorizeRoles(issuer, subject, claims)` |
| `MatchRolesToRepo` | removed (no callers) |
| `FindSessionPolicyForRepo(repo)` | `FindSessionPolicy(issuer, subject)` |
| `types.GithubClaims` | `types.Claims` (no exported `GithubClaims`) |
| `CreateSessionTags(claims)` | `BuildSessionTags(claims, tagSpec)` |

**Authz model:** the engine operates on `(verified issuer, canonical subject string, claims map[string]any)`.
- **subject** is derived per issuer from `claim_mappings.subject: <providerClaim>` (github default `repository`; gitlab e.g. `project_path`). It is the only required canonical projection.
- **conditions** and **session_tags** reference **raw verified claim names** (provider-native). No GitHub struct needed for the generic path.
- Native struct unmarshal into `types.Claims` happens **only** for `provider: github`.

**TagAuth tags:** canonical identity tag `<prefix>subject` (+ `<prefix>issuer` when multi-issuer). `<prefix>repo`/`<prefix>repo-owner` accepted as aliases through v2 (migration window).

## Security threat model & invariants (each gets an explicit test)

1. **Token never selects the role.** Requested role ARN must be ∈ the matched mapping's resolved `roles` (resolve `role_sets` aliases first). Same for TagAuth `AllowedAccounts` cross-account gate.
2. **Issuer authenticity before identity.** The unverified `iss` peek is for routing only; identity/role decisions use only post-signature-verified claims, re-asserted against the spec. Unknown/unverifiable issuer → fail closed.
3. **No cross-issuer identity collision.** Role mappings **and TagAuth** are issuer-bound (`RoleMapping.Issuer`; TagAuth `<prefix>issuer`); issuer-B token can never match an issuer-A rule even if subjects collide.
4. **No self-asserted canonical identity.** Canonical `subject` comes only from an explicit `claim_mappings.subject` (github default `repository`); native unmarshal only for `provider: github`. A token cannot self-assert an unmapped subject.
5. **Algorithm/key integrity.** Methods RS/ES 256–512 only (never `none`/HS*); JWKS key pinned by `kid` + `alg` + `use=sig` + key-type↔alg-family; RSA ≥2048; EC on-curve. Duplicate-`kid` different-type JWKS cannot cause wrong-key selection.
6. **Bounded time & size.** `exp` and `iat` required; leeway ≤120s; `max_token_lifetime`/`max_token_age` cap replay; token length capped pre-parse (`max_token_bytes`, 8 KB default); JWKS/payload reads bounded (`io.LimitReader`). Applies in `self` **and** delegated modes.
7. **Transport integrity / no SSRF.** Issuer + `jwks_uri` HTTPS-only unless `allow_insecure_issuers` (dev); outbound fetches can never reach private/loopback/link-local/metadata IPs (incl. on redirects); discovery `issuer` validated; forced JWKS refetch rate-limited per-(issuer,kid).
8. **Fail-closed throughout.** Any error in routing, verification, normalization, condition evaluation, or tag building → deny. No partial credentials.
9. **Config fragments cannot weaken security.** Fragment allowlist = `{role_mappings, role_groups, role_sets, default_issuer}` only; `issuers`/hardening-knobs/`allow_insecure_issuers`/`tag_auth` are base-only and rejected in fragments.
10. **Index is matching-equivalent.** Owner-bucketed index is byte-identical to a linear scan (parity test on a large generated config).
11. **Auditability & secret-safety.** Every decision (allow **and** deny) is audit-logged durably (synchronous when `audit_required`); no path logs a raw JWT/credential or (when `log_claim_values=off`) sensitive claim values.
12. **Reload fails safe.** A failed/invalid/tampered config reload retains last-good; never opens/closes access via a partial/empty config; never reverts to the zero-config GitHub seed.
13. **Residual (accepted, documented):** no `jti` replay cache (stateless); replay window = `min(remaining exp, max_token_age)`.

## Final `Validate(token)` flow (self mode)

0. Length guard (`max_token_bytes`, default 8 KB) before any parse.
1. `ParseUnverified` → read `iss` only (untrusted; routing).
2. `spec := snapshot.registry[iss]` (exact match, no normalization); unknown → deny, no fetch.
3. Per-call parser: `WithIssuer(iss)`, `WithValidMethods(RS/ES 256-512)`, `WithExpirationRequired()`, `WithIssuedAt()` (iat required), `WithLeeway(leeway)`.
4. Verify signature via `GenKeyFunc` against that issuer's cached JWKS (per-issuer; SSRF-hardened fetch; in-process pre-parsed-key memo).
4b. Re-assert verified `claims.Issuer == spec.Issuer`.
5. Key pinning: `kid` + `use=sig|""` + `alg` match + key-type↔alg-family.
6. Require `sub` non-empty; `nbf` enforced when present.
7. Reject if `exp-iat > maxTokenLifetime` or `now-iat > maxTokenAge` (when set).
8. Audience ANY-match vs `spec.Audiences` only (handle `aud` string|array); empty/missing → deny.
9. `required_claims` (raw verified claims) present/non-empty — replaces the hard `repository` requirement.
10. `normalizeClaims(raw, provider, mappings)` → canonical `subject` + raw claims map. Fail closed.

Delegated `apigw`/`alb`: same claim-bounds (exp/iat/nbf/sub/leeway/max-age) + audience/required-claims + mapping; `apigw` trusts upstream signature, `alb` verifies the ALB signature; both adopt `claim_mappings`/`required_claims`/`session_tags` for their single issuer. Not a weaker path.

## Engineering standards (acceptance criteria for every group)

- **DI:** constructors take interfaces, wired once in `NewBootstrap`. New collaborators (registry, index, claim mappers, `BuildSessionTags`, audit logger) injected, not globals. Don't add to the `config` `sync.Once`.
- **Provider extensibility (open/closed):** a `ProviderAdapter` interface (`Subject(claims)`, `Normalize(claims)`, native-unmarshal opt-in) behind the registry. Adding a provider = implement interface + config entry, **no core edits**. Test proves it.
- **Concurrency = race-free by construction:** build new `{registry, index, compiled conditions, role_sets}` off the request path, publish via one `atomic.Pointer[snapshot]`; readers load once, read immutable. JWKS cache value immutable `{rawJWKS, map[kid]parsedKey}`. Guard mutable maps (refetch limiter) with `sync.RWMutex`/`sync.Map`. `singleflight` for fetch dedup; `errgroup` (bounded + ctx + deterministic merge) for fragment/JWKS prefetch. **`go test -race` is part of `make check`.**
- **Cold-start:** all expensive setup (config load+`Validate()`/regex/index/registry, SDK clients, cache, audit logger, one reused `http.Client`) happens **once in bootstrap before `lambda.Start`**, never per request. Optional non-fatal JWKS warm-prefetch during INIT. Init failure on invalid config is **fatal**.
- Small focused files/functions; sentinel errors wrapped `%w`; defer-close readers; `log/slog` only. Don't over-engineer (atomic snapshot over fine-grained locks; goroutines only where latency hides).

## Commit / recovery rules

- Branch `feature/v2-multi-issuer`. Every commit `make check`+`-race` green. Conventional Commits. **No Claude co-author trailer.**
- After each group: commit, then update + commit `PROGRESS.md` (status `done` + SHA, advance `NEXT:`).
- Return to orchestrator on ambiguity; **do not edit files outside this group's scope.**
