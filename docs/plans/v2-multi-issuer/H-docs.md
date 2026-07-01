# Group H — Documentation, visual/architecture docs, examples, changelog

Prereqs: all code groups (do last, after the surface is final). 
**Read `SHARED.md` first.**

## Tasks

- **H1 Config reference** — `docs/CONFIGURATION.md`: `issuers[]` (issuer/provider/audiences/jwks_uri/claim_mappings/required_claims/session_tags), hardening knobs (`jwt_leeway`/`max_token_lifetime`/`max_token_age`/`max_token_bytes`/`jwks_refetch_cooldown`/`allow_insecure_issuers`/`audit_required`/`log_level`/`log_claim_values`), `default_issuer`, `role_groups`, `role_sets`, `config_fragments`. Update the env-var table (drop `AOW_ISSUER`/`AOW_AUDIENCE(S)`; add scalar knobs). `example-config.yaml` — full v2 example with a GitHub + GitLab two-issuer setup + a fragment example. **Ask the user before editing `example-config.yaml`** (repo rule).
- **H2 Architecture** — `docs/ARCHITECTURE.md`: rewrite the request-flow narrative for multi-issuer (peek `iss` → registry spec → verify → normalize subject → index match → conditions → session tags → assume); document the registry, claim-normalization, owner-bucketed index, fragment merge/reload, TagAuth-vs-mapping decision path, cold-start init, and the replay residual + least-privilege for cache/config stores.
- **H3 Visual docs** — follow the existing convention (ARCHITECTURE mermaid + hand-authored `docs/images/*.svg` in the `tag-auth-*.svg` style). Update the mermaid flow; add `multi-issuer-flow.svg`, `claim-normalization.svg`, `config-scaling.svg`, `authz-decision.svg`. (Draft via the mermaid-expert agent, export to SVG, keep style consistent.)
- **H4 Provider/migration/ops guides** — new `docs/MULTI_ISSUER.md` (onboard any OIDC provider: discovery, provider, claim_mappings.subject, required_claims, per-issuer audiences; GitHub + GitLab examples), `docs/MIGRATION_V2.md` (legacy → `issuers[]`; renames `repo_role_mappings`→`role_mappings` etc.; TagAuth `aow/repo`→`aow/subject` window; breaking-change checklist), `docs/LOGGING.md` (field reference, audit schema, `audit_required`, SIEM signals, CloudWatch alerts). Update `docs/SESSION_TAGGING.md` (per-issuer `session_tags` + ABAC trust caveat). Cross-link `TAG_BASED_AUTHORIZATION.md` as the enterprise-scale path.
- **H5 Repo docs** — `CHANGELOG.md` (v2.0.0), root + per-package `CLAUDE.md` (validator/config/aws/handler) for multi-issuer/registry/index/fragments/session-tags/logging.

## Gates

- **Docs-accuracy check:** every documented field/env/default matches the implemented struct + `Validate()`; SVGs/mermaid match the final pipeline.
- **Final full-surface security review** across the whole v2 diff + the adversarial matrix (`SHARED.md` + master plan Verification section) before tagging **v2.0.0**.

## Commit

`docs: v2 multi-issuer configuration, architecture, migration, visuals` → update `PROGRESS.md` (mark all done + final review).
