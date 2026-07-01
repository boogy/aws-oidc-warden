# Group D — Authorization: rename + scaling index + issuer binding

Prereqs: A (integrates with B). Files: `internal/config/config.go`, `internal/config/tagauth.go`, new `internal/config/index.go`.
**Read `SHARED.md` first** — invariants 1, 3, 10 and the Naming table.

## Tasks

- **D0 — Full rename (per Naming table).** Config keys: `repo_role_mappings`→`role_mappings`, `repo:`→`subject:`, `constraints:`→`conditions:`, `repo_role_groups`→`role_groups`. Go: `RepoRoleMapping`→`RoleMapping` (`Subject`/`Issuer`/`Conditions`/`Roles`/`SessionPolicy`/`SessionPolicyFile`), `Constraint`→`Condition`, `satisfiesConstraints`→`satisfiesConditions`, `MatchRolesToRepoWithConstraints`→`AuthorizeRoles(issuer, subject, claims)`, `FindSessionPolicyForRepo`→`FindSessionPolicy(issuer, subject)`. **Remove** `MatchRolesToRepo` (config.go:582, no non-test callers — verified). Update all callers (incl. `processor.go`) + tests. This is a mechanical rename commit; keep it isolated and green.
- **D1 — Issuer binding.** `RoleMapping.Issuer` resolved at load (inherited from `default_issuer` when omitted). `Validate()`: when `len(Issuers) > 1`, every mapping must resolve to exactly one configured issuer (else error). Matching considers only mappings whose resolved issuer == the token's **verified** issuer. **Issuer-bind TagAuth** (V1, high): `Authorize(roleTags, claims, verifiedIssuer)` — when multi-issuer, role must carry `<prefix>issuer` matching the verified issuer (exact, space-list = OR); roles lacking it not assumable. `<prefix>subject` canonical; `<prefix>repo`/`repo-owner` aliases through v2.
- **D2 — Sub-linear index** (`index.go`): `index[issuer] = {exact map[subject][]*mapping, byOwner map[owner][]*mapping, any []*mapping}`. Classify each `subject` at load (literal → exact; literal first segment → byOwner; non-literal → any). `AuthorizeRoles`/`FindSessionPolicy` use `index[verifiedIssuer]`: check `exact[subject]`, then `byOwner[subjectOwner]` + `any`. Regex compiled only for true patterns. Build inside the immutable config snapshot (atomic swap).
- **D3 — DRY layers:** `default_issuer` (source-level) inheritance; `role_groups` (`{issuer?, defaults:{roles?,conditions?,session_policy?/file?}, subjects:[...]}`) with per-field inheritance; `role_sets` (`{name:[arns]}`, referenced `roles: ["@name", arn]`) resolved at load **before** the requested-role-∈-roles gate (invariant #1).
- **D4 — Generic conditions:** `conditions:` map (`claimName → regex`) over **raw verified claims**, auto-anchored `^(?:...)$`, all AND, fail-closed (non-string/missing → deny). Reject empty / bare `.*`. Named GitHub fields become sugar over the same mechanism.

## Security review D (ADVERSARIAL)

cross-issuer collision closed in **both** mapping and TagAuth paths; **index↔linear parity** (no dropped/widened match) on a large generated config; `default_issuer`/group inheritance can't escalate issuer or roles; condition fail-closed; ReDoS (RE2 ok) + `.*` rejection; `role_sets` resolution can't smuggle a role outside the matched mapping.

## Verification slice

- Cross-issuer: issuer-B token, subject == an issuer-A mapping → no role; TagAuth role `aow/subject=org/foo` w/o `aow/issuer` under multi-issuer → not assumable.
- Index parity property test + `AuthorizeRoles` bench at 10k mappings (~constant).
- DRY golden test: inheritance/`role_sets` expand to the same effective mappings.
- `make check` + `go test -race ./internal/config/...` green.

## Commits

`refactor(config): provider-neutral rename (role_mappings/subject/conditions)` (D0), then `feat(config): issuer-bound authz, owner-bucketed index, DRY layers` → update `PROGRESS.md`.
