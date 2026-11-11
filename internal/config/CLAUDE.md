# Config

Extends [../../CLAUDE.md](../../CLAUDE.md). Viper loading, `Validate()`, issuer-bound authorization, hot reload.

This file is a map plus the rules code cannot state. Read the source and the named test before changing behaviour; operator semantics live in `docs/CONFIGURATION.md`.

## Where things are

- `config.go` — `Config`, `IssuerConfig`, `RoleMapping`, `Validate()`, `Authorize`/`AuthorizeRoles`/`FindSessionPolicy`/`EffectiveSessionTags`, `TagAuthMayGrant`.
- `condition.go` — condition tree (`all_of`/`any_of`/`none_of`), compile and match. `patterns.go` — `Patterns`, anchoring, `isUniversal`, decode hooks.
- `role_entry.go` — per-role settings (`expandRoles`, `overlay`). `index.go` — owner-bucketed subject index.
- `tagauth.go` — tag-based authorization. `idp.go`, `idp_template.go` — `idp` block.
- `provider.go` — hot-reload `Provider`. `fragments.go` — `config_fragments` / `mappings_file`. `auditable.go` — claims an audit record may carry.

## Rules

- Compile regex only in `Validate()`, never per request. Subjects and conditions go through `regexCache.anchor`; do not add a second path.
- Clone a `*Condition` before compiling it (`appendEffective`, by value) and keep `cloneCondition` deep: a shared node is transiently empty, and empty means pass. `TestHotReloadConditionRace`, `TestHotReloadNestedConditionRace`.
- `valueMatches` is the only reading of a claim value, in both polarities, via `utils.FormatClaimValue`. `TestNoneOfReadsNonStringClaimValues`.
- An ambiguous claim name (case-folded collision) denies the whole evaluation, not the leaf. `TestExactHitDoesNotResolveACollision`.
- Index bucketing must be sound: classify from the parse tree, never the pattern text. `TestIndexParity`.
- Settings that pick a role's scoping (`FindSessionPolicy`, session name, tags) resolve through the same `Decision` that authorized it.
- A role object's settings replace the entry's, `conditions` included: a role can be wider than its entry.
- A role any mapping names is never tag-authorized (`TagAuthMayGrant`). Under `idp.only` a tag grant goes through the IdP.
- Session tags are additive: a mapping key the issuer already defines is a load error.
- New `Config`/`Condition` fields need `mapstructure` and `json` tags and must be exported: reload deep-copies through JSON. `TestNestedConditionsSurviveJSONClone`.
- Viper lower-cases config keys; claim names are matched exact, then case-folded.
- Unknown nested keys are load errors (`rejectUnusedKeys`); top-level ones only warn.
- Frozen across reloads: `jwt_validation.mode`, every `idp` key except `enabled`/`only`, and the base-only S3/size keys.
