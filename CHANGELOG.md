# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2026-08-25

Conditions become claim-native. Every key under `conditions:` is now the name of the claim it checks — for any issuer, not just GitHub — each key takes one pattern or a list of alternatives, and `all_of`/`any_of`/`none_of` compose them into a readable expression. A condition on a list-valued claim, which could never match before, now does. The top level stays an implicit AND.

**Breaking:** the three keys whose names did not match their claim are **removed**, not deprecated: `branch` → `ref`, `actor_matches` → `actor`, and `environment` → `runner_environment`. `environment` still exists but now checks GitHub's deployment-environment claim of that name, which no key could reach before. There is no deprecation window and no shim: `branch:`/`actor_matches:` are now read as claims of those literal names, which GitHub does not issue, so the mapping stops authorizing anything (fail-closed — except inside a `none_of`, where a veto that can never fire authorizes exactly what it was written to refuse) and startup logs a warning naming the key, in those words; an `environment:` left unrenamed keeps loading and silently changes meaning. The `aow/environment` IAM role tag follows the same rename. See [docs/MIGRATION_V3.md](docs/MIGRATION_V3.md); the rename is mechanical and every other config key is unchanged.

### Added

- **Condition keys are claim names, for every issuer.** A condition key is now read as the raw verified claim it checks: `ref`, `actor`, `event_name`, `repository_owner` for GitHub, and equally `project_path`, `groups`, `namespace_path`, or whatever a GitLab, Okta, Entra, Buildkite, or in-house issuer mints. There is one mechanism, not two — the named fields (`ref`, `ref_type`, `event_name`, `workflow_ref`) are discoverability sugar over the same generic path, so a claim with a field and a claim without behave identically. Previously the vocabulary was a fixed set of GitHub-shaped fields plus a differently-documented "extra claims" map, and a non-GitHub deployment could gate only on the subject.

- **Every condition value accepts a list of alternatives.** `actor: ["release-bot", "release-manager"]` matches either; `actor: "release-bot"` still matches one. Patterns listed for **one** claim are OR-ed, separate claims are AND-ed — so the common "any of these principals" case no longer needs an `any_of` group, and a list-valued claim (a `groups` array) matches when any element matches any pattern. Both YAML shapes decode to the same type on both config paths, file load and remote hot-reload alike, and a comma inside a regex (`v[0-9]{1,3}`) survives decoding intact.

- **Boolean logic in `conditions`: `all_of`, `any_of`, and `none_of`.** Every entry in a `conditions:` block was AND-ed, so "the main branch **or** a version tag" could only be expressed by duplicating the whole mapping — and a duplicated mapping is exactly the shape that drops a privileged role's `session_policy`, since `FindSessionPolicy` resolves the policy from the lowest-`order` mapping that grants the role. The three group keys take a list of nested conditions and compose: on any node the claim predicates and all three groups are AND-ed together, so **the top level stays an implicit AND and every existing config keeps its exact meaning**. Groups nest, which makes the operator set functionally complete — every boolean expression is expressible as nested `any_of`-of-`all_of`, and a one-entry `none_of` is a `not` — so no `not`/`xor`/`n_of` operator was added. `none_of` is exact negation: a member naming a claim the token does not carry cannot match, so its negation holds and the group passes; pair it with `required_claims` when presence matters. Evaluation allocates nothing and compiles nothing per request — the tree is cloned and compiled once in `Validate()`, as every condition pattern already was.

- **Load-time guards on condition complexity.** `Validate()` rejects an empty group (`any_of: []`) and a group member that gates nothing (`- {}`): both reduce their group to a constant, an always-true member making an `any_of` always pass and a `none_of` always fail. The same check now applies to the whole block: a `conditions:` node that compiles to no predicate at all — `conditions: {}`, or a key written with nothing after it — is rejected instead of authorizing every request that reaches it. Drop the key when a mapping is meant to be unconditional. Nesting is capped at 5 levels and one mapping's tree at 64 nodes: readability limits first, since a gate a reviewer cannot hold in their head is a gate nobody reviews, and per-request cost limits second. The bare-wildcard rejection (`.*`/`.+`) applies at every nesting level, and every error names the offending node by path (`conditions.any_of[1].all_of[0]`).

- **Tag-based authorization can constrain any claim, for any issuer: `aow/claim.<name>`.** Every tag suffix `Authorize()` understood — `repo`, `repo-owner`, `branch`, `ref`, `ref-type`, `event-name`, `workflow-ref`, `environment`, `runner-environment`, `actor` — names a GitHub Actions claim, so a non-GitHub issuer could tag-authorize a role on `aow/subject` and nothing else: there was no way to say "this GitLab role additionally requires `project_path: acme/api`". `aow/claim.<name>` reads the raw verified claim `<name>` and ANDs with every other gate, giving tag-auth the same claim-native reach `conditions:` gained this release. It is **not** an identity tag — a role carrying only `aow/claim.*` tags is still denied by the identity gate — so it can narrow access but never grant it, and the issuer and identity gates run first and unchanged. A list-valued claim matches when any string element matches, mirroring conditions; any other shape never matches. Unlike a `conditions:` key, the claim name is matched **case-sensitively**: IAM stores tag keys verbatim, so no case is lost on the way in and the exact name the operator wrote is the one that is read. Existing roles are unaffected — a role with no `aow/claim.*` tag behaves exactly as before.

### Fixed

- **A condition on a list-valued claim could never match.** Claim matching type-asserted `.(string)`, so a claim whose JSON value is an array — a GitLab `groups`, an Okta or Entra group/scope/role list — failed the assertion and the condition denied unconditionally, with nothing in the config or the logs to say why. A list claim now matches when **any** string element matches the anchored pattern, which is what "the caller is in group X" means and what makes `any_of`/`none_of` usable against group membership. Non-string elements are ignored, and numbers, bools, objects, nulls, and absent claims still never match, so every previously-denying shape except the array case denies exactly as before. No element cap is needed: `max_token_bytes` (default 8192) already bounds how many elements a request can carry.

- **A `none_of` veto on a mixed-case claim could never fire, authorizing what it was written to refuse.** Viper lower-cases every config key it reads — the main file, remote overlays, and every fragment alike — so a condition key written in the case the issuer actually mints (`isContractor:`, `emailVerified:`) reached the matcher as `iscontractor`/`emailverified` and matched no claim. Under a plain AND that denied, which looked like fail-closed behavior and was documented as such. `none_of` inverts the direction: a member whose claim can never resolve can never veto, so `none_of: [{isContractor: "true"}]` authorized precisely the caller it was written to exclude, with nothing in the config or the logs to say so. The documented escape hatch was no escape — `claims:` keys are lower-cased on the same path — and no warning fired, since the misspelled-claim check runs only for `provider: github`. Claim lookup is now **collision-first, then exact, then case-folded**: the token's claim names are compared case-insensitively, and a folded name that two or more differently-cased claims map to is ambiguous and denies the whole mapping rather than guessing. The collision check runs *before* the exact lookup and is deliberately not skipped when that lookup would succeed. The config key has already been lower-cased by then, so `iscontractor` is exactly as consistent with an operator who wrote `isContractor` as with one who wrote it lower-case; preferring the exactly-named claim therefore decides the gate on a claim the config may never have named. Under `none_of` that is the same inert-veto bypass by a second route, and it works in either direction — the decoy can be the mixed-case twin *or* the lower-case one, whichever happens to match the folded key. Denying the whole mapping rather than only the offending leaf is deliberate for the same reason the fallback exists: a leaf that merely fails to match is polarity-dependent, so under a negation it would disarm the veto instead of firing it. An all-lowercase config — every GitHub deployment, since GitHub Actions mints only lowercase claim names — builds no index at all and takes the identical path it always did, and the folded fallback fires only where the previous answer was an unconditional "no value". Mixed-case claim names are now gateable for every issuer.

- **A hot config reload could split one request across two config generations.** `ProcessRequest` captures a single `*Config` after `MaybeRefresh` and threads it through `AuthorizeRoles`, `FindSessionPolicy` and `IssuerSessionTags` — but claim extraction did not use it. All three extractors called `provider.Get()` again, a second read of a pointer a concurrent reload can have swapped in between, so one request could be token-validated against generation N+1 — its issuers, audiences, claim mappings and time bounds — while being authorized against generation N. This is not the benign case of an in-flight request seeing a stale config, where one consistent generation decides everything: a refresh that widens validation while narrowing authorization, such as rotating an audience and retiring a role mapping in the same push, authorizes a caller that **neither** generation allows on its own — the token clears N+1's audience while N's since-removed mapping grants the role. `ExtractionInput.Config` now carries the request's pinned generation and every extractor uses it; nil still means "read the provider", so hand-built inputs are unaffected. `SelfExtractor` reaches it through an unexported `pinnedValidator` seam that only `*TokenValidator` can satisfy, leaving `TokenValidatorInterface` and every external mock of it unchanged. `TestSelfExtractorIsDecidedByThePinnedConfig` fails when the pin is ignored. A full-pipeline guard, `TestProcessRequestNeverAuthorizesAcrossGenerations`, drives the real `Provider`/validator/extractor/processor wiring through `ProcessRequest` under a concurrent reload that oscillates between the two generations and asserts the illegal combination never reaches `AssumeRole`; with the pin reverted it reports ~1,000 cross-generation authorizations out of 3,600 requests.

- **A hot config reload could hand a request another config's issuer registry.** `TokenValidator` published its issuer snapshot and the identity of the config that snapshot was built from as two independent atomic pointers — `snap.Store(snap)` followed by `builtFrom.Store(cfg)`. A goroutine preempted between those two stores lets a second goroutine publish its own pair in between, and the pointers are left crossed: the registry projected from config B labelled as built from config A. The identity fast path then returned B's registry to every caller holding A — B's audience set and B's `claim_mappings`, so a token could be checked against an audience the operator had just removed, or have its canonical subject derived by the wrong mapping, while the rest of that same request authorized against A. Requests in flight when a refresh lands do hold the previous config pointer, so this is reachable in production and not only under a stress harness. The registry and its provenance are now one value — `builtFrom` lives inside `snapshot` — published by a single atomic store, so a reader can never observe one without the other, and `rebuildSnapshot` returns the snapshot it just built rather than re-loading the field, so a caller is served its own config's registry even when a concurrent rebuild wins the store. A racing publisher can now only cause a redundant map build, never a wrong answer. `TestSnapshotForNeverServesAnotherConfigsRegistry` drives 32 goroutines over two alternating config pointers and fails when the pair is split back into two atomics.

- **A `none_of` veto on a bool or numeric claim could never fire either, for the same polarity reason.** Condition patterns are anchored regexes, so `valueMatches` can only decide them against a string or an array of strings; a claim present as a bool, a number, an object, or an array carrying a non-string element answered `false`. Under a plain AND that denies, which is correct and is what the previous entry's list-claim fix deliberately preserved. Under `none_of` the same `false` is a veto that can never fire, so `none_of: [{email_verified: "false"}]` against a token whose `email_verified` is the JSON bool `false` — not the string — authorized exactly the caller it names, and `none_of: [{risk_score: "9"}]` did the same for a numeric score. GitHub Actions mints only string claims, so no GitHub deployment could reach this; every issuer that mints a bool or a number (`email_verified`, a risk score, a numeric group id) hits it on the most natural deny-list there is. Under negation a leaf `valueMatches` declined is now **re-decided on the claim's value rather than on its Go type**: a scalar is compared through its canonical text — `utils.FormatClaimValue`, the same formatter the audit record and the STS session tag use for that claim — so `none_of: [{email_verified: "false"}]` vetoes the JSON bool `false` and, just as importantly, does **not** veto `true`. `none_of` means "not this claim at this value", and a value the gate can read must be judged on its own merits whatever JSON type it arrived as. Only a shape with no text at all — an object, or a list carrying one — is undecidable, and there the veto fires. Three boundaries are deliberate. **Absence is excluded** — `nil`, from a missing claim or a JSON `null`, is a known state, its negation genuinely holds, and `none_of`'s documented exact-negation semantics are unchanged (this is also why a leftover v2 `branch:` key under a `none_of` still fails open, as the Breaking note above says). **Positive polarity is untouched** — outside a `none_of` a non-string claim still simply fails to match, which already denied, so no config that authorized before starts denying now and no config that denied starts authorizing. **The deny is local, not sticky** — unlike an ambiguous case-folded lookup, which poisons the whole evaluation because no reading of the claim can be trusted, a sibling `any_of` branch that has decided on its own evidence is still trustworthy and still authorizes. Polarity toggles per group rather than latching, so a `none_of` nested inside a `none_of` is positive again, which is the double negation the operator wrote. `TestNoneOfReadsNonStringClaimValues` covers bool, number, array, and object claims in both directions (the refused value vetoes, a different value of the same type does not), the positive-polarity control, the `any_of` locality, and the double/triple-negation toggle; it fails both when the fix is removed and when it is coarsened back into a blanket type-based deny.

- **`claim_mappings` was validated on the wrong side of the map, so the guard could never fire.** `Validate()` rejected an entry whose **key** was a JWT-reserved name (`iss`, `aud`, `exp`, `nbf`, `iat`, `sub`), on the stated grounds that it "could shadow a verified claim". A key is a canonical *field* name, not a claim name — the only key anything reads is `subject` — so no key could shadow anything, and the one config the check rejected was harmless. The real risk is on the **value** side, where the check was absent: `claim_mappings.subject: iss` (or `aud`) makes the canonical subject a string that is byte-identical in every token the issuer mints, collapsing every caller from that IdP onto one subject, at which point any authenticated caller satisfies any other caller's subject pattern and the `role_mappings` for that issuer stop distinguishing anyone. `subject` may now no longer target `iss`, `aud`, `exp`, `nbf`, or `iat`. `sub` is explicitly **allowed** — it is the ordinary mapping for most non-GitHub IdPs, and `claim_mappings` is a read-only projection over already-verified claims, so naming a claim there cannot shadow or override it. Keys other than `subject` remain accepted rather than rejected: the validator ignores them, but each entry's value joins that issuer's auditable-claim set, so a non-`subject` entry is a supported way to say "also record this claim". The test that covered the old guard passed against a config that was never dangerous, which is what let the dead check look alive.

- **Every log line for a non-GitHub issuer identified the caller as four empty strings.** The request-scoped logger and the deny path both stamped `repository`, `ref`, `branch`, and `actor` — GitHub-only fields on the claims struct, filled in only by the `github` provider adapter — so a `provider: generic` request (GitLab, Okta, Entra, Auth0, Kubernetes, in-house) logged `repository="" ref="" branch="" actor=""` and omitted `subject`, the one field that identifies who was asking. The authorization decision was never affected: it reads the raw claim map throughout. Logs now always carry `subject`, and add the GitHub fields only when they are actually populated. The deny reason lost its GitHub flavour with them — "role not allowed for repository" is now "role not allowed for this subject or its conditions are not met". The reason string is server-side only; `classifyError` maps the sentinel to a fixed `permission_denied` response, so no client-visible output changes.
- **A non-GitHub issuer's audit record omitted the claim that decided the request.** `claims` in the audit record was restricted to the claims that issuer's `claim_mappings` reference, which is the set that gives claims _canonical names_ — not the set that gates authorization. A mapping gated on `groups`, `plan_tier`, or an `isContractor` veto produced a record in which the deciding value was simply absent, so the record could not explain its own decision, and a `required_claims` entry or a `session_tags` source was equally invisible. The record now carries every claim that issuer's own config references: `claim_mappings` targets, `required_claims`, `session_tags` targets, and every claim named by a condition (including inside `all_of`/`any_of`/`none_of`) on a `role_mapping` bound to it. Claims the operator never referenced anywhere — an `email`, a `name` an arbitrary issuer happens to mint — are still never copied out, and `provider: github` is unchanged (full claim set, as before). `log_claim_values: false` remains the separate switch that suppresses claim values everywhere.
- **BREAKING: `config_fragment_checksums` is a list, because as a map it could not pin any real fragment.** The URI was the map key, and the config loader case-folds every key it reads _and splits it on `.`_ — so `"/etc/aow/fragments/team.yaml": "sha256:…"` was parsed as a nested map under the truncated path `/etc/aow/fragments/team` and failed to decode outright. Every fragment path ends in `.yaml`/`.yml`, so the integrity pin — the control that quarantines tampered fragment content — could not be applied to a single fragment that actually existed, and the documented example did not load. It is now a list of `{uri, checksum}` entries: a URI written as a _value_ is passed through byte for byte. `Validate()` additionally rejects a pin whose `uri` matches no `config_fragments` entry, which previously read as a pinned fragment while checking nothing. Both shipped examples were broken as written and are corrected.
- **A `role_sets` name containing an upper-case letter could not be referenced.** The name is a config key and is case-folded on load; the `"@name"` reference is a config _value_ and is not, so `ProdDeployers:` and `roles: ["@ProdDeployers"]` in the same file could not see each other and startup failed with `role_sets: "ProdDeployers" is not defined`. References now resolve exact-first, then case-folded. Unlike a condition key this needs no ambiguity check: `role_sets` names are config *keys*, so viper has already folded every one of them and two differently-cased names cannot coexist to collide.
- **Documented `session_tags` keys as lower-case-only, which is what the loader has always produced.** A tag key is a config key and is case-folded before any code sees it, so `CostCenter: cost_center` reaches STS as `costcenter`; the case is gone before validation could object to it. The docs advertised `[A-Za-z0-9 …]` and so implied an upper-case key would survive. No behaviour change — only the documentation was wrong, and silently so, since the attached tag differed from the file that asked for it.

- **Documentation corrected against v3 behaviour, and the checks that would have caught it made automatic.** A sweep of the shipped documentation found claims that no longer described the code: the README's opening sentence still advertised access control "based on repository, branch, actor", two of which this release removes; `docs/ARCHITECTURE.md` omitted the `apigatewayv2` entry point entirely, though it is the only front-end that can delegate validation to an API Gateway JWT Authorizer, and its authorization flowchart showed `ref` → `actor` → `event_name` as privileged sequential gates, a pre-v3 shape contradicting the flat AND the engine actually walks; `docs/LOGGING.md` described the `repository`→`repo` audit rename as unconditional when it is suppressed on collision; `internal/validator/CLAUDE.md` listed three test files this release renamed away and cited a planning document that is not in the repository. The entry-point diagrams said "GitHub Actions" where any configured issuer applies. `TestDocumentedYAMLLoadsAndValidates` now also covers `docs/examples/`, and no longer skips a block because it contains an unrecognised top-level key — the loader ignores unknown keys silently, so that skip meant an example with one stale key was reported as passing rather than failing.

- **A second, line-by-line pass over the shipped documentation.** The first sweep was mechanical; reading every document as prose against v3 behaviour turned up statements no grep could see. `docs/MIGRATION_V2.md` claimed `PascalCase` config keys "are rejected" — they are silently **ignored**, so a mis-cased `RoleMappings:` loads clean, leaves no role mappings at all, passes `Validate()`, and denies every request; the entry now says so. `README.md` described cross-account as assuming a spoke role and then the target role — the target assume is always direct hub→target in one hop, and the spoke role exists only to read a member-account role's tags for cross-account tag-auth (`spokeCredsFor` has exactly one caller, `GetRoleTags`), which is what `docs/ARCHITECTURE.md`, `deploy/README.md`, and the cross-account example already said. `README.md` also recommended API Gateway REST v1 for production while `docs/LOGGING.md` recommended HTTP v2 as the most secure front-end on two independent axes; the README now matches. `docs/MIGRATION_V3.md` listed `all_of`/`any_of`/`none_of` under "What did NOT change", though the groups are new in this release and a v2 config has none to migrate. `docs/CONFIGURATION.md` still gave the `session_tags` key charset without the case-folding caveat the fix above added to `docs/SESSION_TAGGING.md` — which in turn never mentioned `session_tags_transitive`, the switch that decides whether the caller's identity survives a role-chain hop. `docs/LOGGING.md` wrote the mode as a flat `jwt_validation_mode:` key (that is the OpenTofu variable name); the config key is nested `jwt_validation.mode`, and since an unknown top-level key is ignored in silence, an operator copying the line would run in `self` mode believing they had delegated. `docs/ARCHITECTURE.md` summarised the request flow as GitHub-only and pinned the API Gateway JWT Authorizer to GitHub's issuer URL, when it is one authorizer per configured issuer. `internal/validator/CLAUDE.md` numbered the hardening work as "steps 5-7" (those steps are audience, `required_claims`, and normalization) and carried the repository's last dangling "Group C" planning-document citation; `internal/handler/CLAUDE.md` listed 8 of the package's 12 files. Stale `v2` labels were dropped from headings and prose in `docs/MULTI_ISSUER.md`, `docs/SESSION_TAGGING.md`, `docs/CONFIGURATION.md`, and `docs/ARCHITECTURE.md`. One code comment was corrected with them: `internal/cache/dynamodb.go` described its 400KB item cap as "a smaller limit for safety" when it is exactly DynamoDB's own hard limit. A third pass over the example config found the last of these: `example-config.yaml` applied the single-issuer restriction to "delegated modes" in the plural, when only `alb` carries it — `apigw` provisions one JWT Authorizer per issuer and resolves the spec per request from the authorizer-verified `iss`, and `newClaimsExtractor` calls `singleDelegatedIssuer` in the `alb` case alone. Every other document already said so; the annotated example, which is what an operator copies, was the sole outlier and would have argued a reader out of a supported multi-issuer deployment.

- **`utils.RedactToken` panicked instead of redacting, in both directions.** The helper sliced `token[:firstN]` and `token[tokenLen-lastN:]` after a single guard that only covered the too-short case, so a negative `firstN` or `lastN` sliced out of range and panicked — inside the log call the helper exists to make safe. Clamping the negatives alone turned out to leave the mirror-image case open: the two counts are **summed** before the too-short guard, so a pair near `MaxInt` overflows and wraps negative, making `tokenLen <= firstN+lastN` false and falling through to the same guaranteed out-of-range slice. Each count is now clamped to the token length *before* the sum, which makes the overflow unreachable and collapses every oversized window onto the fully-masked result it should have given. The doc comment also said "characters" where the counts are byte offsets. No caller could reach either case: the pipeline keeps token material out of logs entirely rather than logging it redacted, which is why the helper has no callers by design and why the bug survived. `internal/utils` had 12.5% test coverage and now has 100%, with the clamp, the short-token full mask, `ExtractBranchFromRef`'s non-branch pass-through, `ParseLogLevel`'s fail-loud default, and `GetEnv`'s set-but-empty case each proven by mutation.

- **`example-config.yaml` no longer emits an unscoped-grant warning at boot.** Its S3 session-policy example reused `@deployers`, whose roles a policy-less mapping earlier in the file also grants; `warnUnscopedRoleGrants` shares roles rather than computing subject overlap, so it warned even though the two subjects are disjoint literals and the policy does apply. The example now names its own role, and the file that operators copy boots clean — the advisory about mappings inheriting `default_issuer` is expected here and is now called out in a comment where `default_issuer` is set.

- **The `internal/config` suite passed only in declaration order, so two `none_of` bypass guards were not actually guarding.** `TestLoadConfigFromEnvVars` sets `CONFIG_NAME=nonexistent-config-file` to force the env-var path, but `CONFIG_NAME` was missing from its save/restore list, so the value leaked for the remainder of the test binary: every later test that loads a real `config.yaml` found none, silently loaded an **empty** config, and authorized nothing. Two tests then passed for the wrong reason under `go test -shuffle` — `TestNoneOfVetoOnCamelCaseClaimDeniesEndToEnd`, the regression guard for the case-folding bypass above, and the new `TestLeftoverV2KeyUnderNoneOfAuthorizes`. A second, independent leak sat beside it: `viper.AddConfigPath` **accumulates** and `LoadConfig` drives viper's package-level singleton, so a test that reset only the `once` singleton (`TestNewConfig`) inherited every path an earlier test had registered and read a `t.TempDir()` that had already been removed. `CONFIG_NAME` is now restored, the two affected tests reset viper and load into a fresh `Config` instead of the `sync.Once`-cached one, and the package passes under `-shuffle` across seeds. No production code was involved — the defect was that a security regression guard could stop guarding without anyone noticing.

### Changed

- **BREAKING: `branch`, `actor_matches`, and `environment` are removed; `environment` is repointed at the claim of that name.** Their names never matched their claim: `branch` checked `ref` (and always did — it was never a bare branch name), `actor_matches` checked `actor`, and `environment` checked `runner_environment`, **not** the GitHub deployment-environment claim of the same name. Now that every key is read as the claim it names, `branch` and `actor_matches` are gone — a config still using them parses them as claim predicates on claims named `branch`/`actor_matches`, which GitHub never issues, so every request against that mapping is **denied** (fail-closed) and `Validate()` logs a warning naming the key. One placement inverts that, and it is the only way a stale v2 key fails **open**: inside a `none_of`, a member that can never match is a veto that can never fire, so the mapping authorizes precisely the caller the leftover key was written to refuse — which is the natural placement for a `branch`/`actor_matches` deny-list. The warning says so in those words, and `TestLeftoverV2KeyUnderNoneOfAuthorizes` pins both halves — the leftover key authorizing the push, and the renamed key refusing it — and `environment` gates the `environment` claim, which no key could reach before. Rename `branch:` → `ref:`, `actor_matches:` → `actor:`, and `environment:` → `runner_environment:`; the last one is the one that bites, because an unrenamed `environment:` keeps loading and quietly checks a different claim. No deprecation shim ships: a key that works but means something else is worse than one that stops working loudly. (The startup warning fires for `provider: github` issuers, which is where these keys were ever usable; a `provider: generic` issuer has no known-claim vocabulary to check against, so a stale key there only shows up as a denial.) `actor_matches` was the only key that accepted a list, and every key does now, so nothing is lost. See [docs/MIGRATION_V3.md](docs/MIGRATION_V3.md).

- **A condition key naming a claim GitHub does not issue now warns at load.** A misspelled claim (`event-name`, `reposiory`) never matches, so the mapping simply stops authorizing with nothing in the config or the logs to say why — a fail-closed silence that reads exactly like a policy decision. `Validate()` names the mapping and the key. The check runs only on `provider: github`, whose vocabulary is derived by reflection from the struct the validator unmarshals into and so cannot drift from it, plus anything that issuer's own `claim_mappings`, `required_claims`, or `session_tags` declare; a generic issuer's claims are whatever its provider mints, so it is never warned about. Advisory only — nothing is rejected.

- **An empty condition pattern is now rejected instead of ignored.** `ref: ""` was silently skipped, and `ref: []` would have read as an absent key: in both cases a line that looks like a gate gated nothing. Both are now load-time errors naming the node. A key that is genuinely optional should be omitted, not left blank.

- **A condition key that names no claim is rejected, and compile errors are now deterministic.** `"": "pattern"` — easy to produce with a stray quote or a dangling YAML key — used to compile into a leaf gating a claim named `""`, which no token carries: a line that reads as a gate but can only ever deny. It is now a load-time error naming the node. Separately, claim keys are compiled in sorted order, so a block with more than one bad entry reports the _same_ entry on every start instead of one at random (Go map iteration order), which is what makes fixing a broken config a finite loop.

- **`all_of`, `any_of`, `none_of`, and `claims` are reserved keys under `conditions:`.** Generic claim predicates are collected by a remain-map, which only ever gathered keys no named field claimed, so a raw claim literally named `all_of`/`any_of`/`none_of` now parses as a boolean group. In practice the only affected config is one that gave such a key a plain string value — the pre-3.0.0 remain-map was `map[string]string`, so a list value never decoded — and that config now fails to load with a decode error rather than quietly changing meaning. `claims:` is the escape hatch that makes the reservation lossless: its keys are **always** raw claim names, never operators, so a claim named `any_of` (or `ref`, or anything else a named field would otherwise capture) stays gateable. A `claims:` block is AND-ed with everything else on the same node, and its errors are reported under a `claims.` path.

- **BREAKING: the `aow/environment` role tag now checks the deployment-environment claim, and `aow/runner-environment` checks the runner type.** Tag suffixes are claim names with underscores written as dashes, so `aow/environment` checking `runner_environment` left the same word meaning two different claims depending on whether it was written as a tag or as a condition — the exact mismatch this release removes from `conditions:`. A role still tagged `aow/environment: github-hosted` no longer matches (fail-closed, like the condition key): retag it `aow/runner-environment: github-hosted`. `aws resourcegroupstaggingapi get-resources --tag-filters Key=aow/environment` lists the roles to check. Nothing else about tag-auth changes.

- **A condition key written with no value at all is rejected.** `environment:` with nothing after it decoded to exactly what omitting the key decoded to — mapstructure skips a field whose input is nil — so the file said the mapping was gated and the compiled condition gated nothing, and the mapping authorized every request that reached it. The decoder now hands such a key to the compiler, which rejects it, and a block that compiles to no predicate at all is rejected as a whole (which is what catches a named key like `environment:` written alone). This was the one shape in the condition engine that failed **open**. `conditions:` itself written with nothing under it (or an explicit `conditions: null`, which YAML cannot tell apart) is rejected for the same reason — omit the key for an unconditional mapping.

- **A typo inside a `none_of` is warned about in stronger terms.** Everywhere else a claim key that can never match makes the mapping stop authorizing; inside a `none_of` it makes a veto that can never fire, so the mapping authorizes exactly what the operator wrote it to refuse. The unknown-claim warning now says so when the key sits under a `none_of` (`provider: github` only, as before). `docs/CONFIGURATION.md` also documents the related footgun: a `none_of` member with two keys is a negated AND, not two separate vetoes — write one member per thing you mean to refuse.

- **The condition engine moved to `internal/config/condition.go`** — the `Condition` type, cloning, compilation, structural validation, and evaluation — so the authorization gate can be read in one sitting instead of spread across a 1500-line `config.go`. No behavior change.

- **Code cleanup, and the non-GitHub path proven rather than assumed.** Two exported helpers carried doc comments naming their old unexported selves (`extractBranchFromRef`, `parseLogLevel`), `GetEnv` had none, and `RedactToken` still carried a commented-out alternative for its mask string. `internal/handler/audit.go` carried a `TODO(v2)` two majors after v2 shipped; it is now stated as the deliberate non-goal it is. The four `context.TODO()` calls in the AWS client constructors are `context.Background()`: those constructors take no context by design, so the root context is the settled answer, not an unresolved one. No dead exported symbol was found — every exported function in `internal/` and `cmd/` has a non-test caller — and `RedactToken` stays, having no callers by design.

  Multi-issuer support gained the tests it was missing. `IssuerSessionTags` had **zero** test references despite deciding which claims reach STS as session tags; it now has per-issuer isolation, unknown-issuer, exact-match, and no-spec-declared cases. `Validate()`'s provider rules — default to `generic`, reject an unknown or mis-cased provider name, require `claim_mappings.subject` for any non-github issuer — are pinned. Tag-based authorization for a non-GitHub issuer is now exercised through the real pipeline rather than `TagAuth.Authorize` alone: `aow/claim.<name>` authorizing a GitLab-shaped token, narrowing but never granting, matching a list claim element-wise, and GitHub's named dimensions (`aow/repo`, `aow/repo-owner`) failing closed against an issuer that mints no such claim rather than treating the absent claim as a wildcard. Each of the 15 new guarantees was proven by mutating the code it protects and confirming the test fails. The new cases live in the suite files that already covered their subject rather than in ten new single-purpose files: the consolidation step took `internal/` from 42 test files to 32 with all 502 test functions preserved, so a reader looking for the condition-engine tests finds all of them in `condition_test.go`. Across the release as a whole the count went from 71 files and 432 test functions at v2.4.1 to 32 files and 504 functions — fewer, larger, subject-organised files carrying substantially more tests. A later pass found one fix in this release shipping unguarded: the request log line's identity fields were asserted by no test, because every pipeline case that reaches them discards log output, so reverting them to the pre-v3 unconditional form passed the entire suite. That behaviour is now pinned against real captured JSON output for a GitHub and a generic issuer at once — `subject` present in both, the GitHub fields absent for the generic one, on the allow path and the deny path — and proven by both the full revert and a narrower mutation that keeps `subject` and drops only the emptiness guards.

- **Dependencies updated, and `mapstructure` promoted to a direct requirement.** The AWS SDK v2 modules move up a patch level or two (`aws-sdk-go-v2` 1.43.5 → 1.43.7, `config` 1.32.36 → 1.32.38, `credentials` 1.19.35 → 1.19.37, `dynamodb` 1.63.2 → 1.63.4, `iam` 1.59.0 → 1.59.2, `s3` 1.107.1 → 1.107.3, `sts` 1.45.5 → 1.45.7, plus their internal modules) and `smithy-go` goes 1.27.7 → 1.28.0. `github.com/go-viper/mapstructure/v2` moves out of the indirect block: this release's condition decoder imports it directly (`internal/config/patterns.go`), so listing it as indirect had been inaccurate since that file landed. `govulncheck` reports no vulnerabilities, and no dependency changed behaviour the suite can see — the full suite passes unchanged.

## [2.4.1] - 2026-08-22

Follow-up to the 2.4.0 audit hardening. A review of that release found defects in the audit path itself: paths that only open up after a hot reload, an ALB configuration in which no request header was visible at all, and three ways the audit record could disagree with the request it describes.

### Added

- **A boot warning when `tag_auth` can bypass a mapping's scoping.** Tag-based authorization is a fallback that grants a role from the role's own IAM tags, so it resolves no `role_mappings` entry — which means neither the `session_policy` nor the `role_session_name` declared on a mapping for that same role applies to a tag-authorized session. A role scoped by a session policy in config could therefore be assumed unscoped through the tag path, and one named for the requester could be assumed under the global name. That is the documented design of the fallback, not a defect, but it is invisible in the config file: `Validate()` now warns once per affected role, naming the role, the subject of the mapping that scopes it, and whether the bypassed control is the `session_policy` or the `role_session_name`.

### Fixed

- **A hot reload that switched on `log_to_s3` + `log_bucket` bricked credential issuance until the next cold start.** `NewS3Logger` built the S3 client exactly once, from the boot config, so a container that started with S3 logging off never had one. `AuditEnforced()` is re-derived per snapshot, so the reload correctly engaged the fail-closed contract — but the enforced write then failed on the missing client for every allow decision on that warm container, and nothing rebuilt it. No credentials were ever issued without a durable record (the contract held, fail-closed), but the service was unavailable for issuance rather than newly audited, contradicting the "no restart" promise in [docs/LOGGING.md](docs/LOGGING.md). `WriteRecord` now builds the client on demand, once, when the live config enables S3 audit logging. A container whose live config still has S3 logging off keeps failing closed exactly as before — the lazy path never invents a destination.

- **Boolean `AOW_` environment variables were parsed differently at boot and on reload.** Boot went through viper's `cast.ToBool` (i.e. `strconv.ParseBool`); the remote-config refresh used a hand-rolled truthy check that recognized only `true`/`1`/`True`/`TRUE`. `AOW_AUDIT_REQUIRED=t` was therefore honoured at boot and silently flipped to **false** on the first refresh, downgrading the fail-closed audit contract to best-effort with nothing in the logs. Both paths now share `strconv.ParseBool`, so every form Go accepts (`t`, `T`, `f`, `F`, `TRUE`, `FALSE`, `0`, `1`, …) means the same thing in both. A value neither parser accepts (`yes`, `on`, a typo) now warns and leaves the current value alone instead of quietly assigning `false` — these knobs default to `true`, and a typo must not silently disable a security control. Applies to `log_to_s3`, `log_claim_values`, `audit_required`, `allow_insecure_issuers`, `session_tags_transitive`, `cache.s3_cleanup`, `tag_auth.enabled`, `tag_auth.transitive_session_tags`, and `cross_account.enabled`.

- **The ALB adapter read no request header on a multi-value target group.** An ALB target group with `lambda.multi_value_headers.enabled = true` populates `multiValueHeaders` and leaves `headers` empty; the adapter read only `headers`. Every header was therefore invisible on such a target group: `x-amzn-oidc-data`, so a correctly configured `jwt_validation.mode: "alb"` deployment fell back to token-in-body and failed closed with a misleading error; `x-forwarded-for`, so the audit record's `sourceIp` was blank; and `user-agent`. Both maps are now read, with repeated values folded on `", "` per RFC 9110 §5.3 — the form `X-Forwarded-For` already uses, so the rightmost-hop rule is unaffected, and the only non-list header involved (`x-amzn-oidc-data`) is corrupted by folding rather than resolved to one of two attacker-chosen values, which fails closed at validation.

- **Header lookups picked a random value when a caller sent the same header twice in different cases.** Lambda event header maps are plain Go maps, so ranging over them to match a name case-insensitively visited keys in a random order. A caller sending both `X-Forwarded-For` and `x-forwarded-for` could have either value recorded, varying per invocation — so two invocations of the same request could be audited with different origins, at the caller's choosing. Lookups are now deterministic: the exact canonical key wins, otherwise the lexicographically smallest case variant.

- **The deny `reason` on the audit record ignored `log_claim_values`.** Reasons derived from an error embed the values the error carries — a failed subject match quotes the canonical subject, e.g. the private `owner/repo` behind the request. With `log_claim_values: false`, `subject`, `jwtSub`, and `claims` were all redacted while `reason` printed the same values verbatim, both in the record and on the decision log line, defeating the gate for the deployments that set it. Error-derived reasons are now replaced with a claim-free stage summary when the gate is off; the record's shape is unchanged (`reason` is always present), and operator-authored static reasons, which contain no claim values, are unaffected.

- **A claim alias could silently overwrite a different claim in the audit record.** GitHub claims are reported under stable audit names (`repository` → `repo`, `repository_id` → `repo_id`). The rename was applied without checking whether the target name was already being emitted, so an issuer whose `claim_mappings` also emitted a raw `repo` claim had one of the two values overwrite the other, and the record showed a value under a name it did not belong to. The alias is now applied only when the target name is not itself emitted — evaluated against the same drop rules that decide what reaches the record, so a target that is absent, excluded, or empty still leaves the alias free to apply.

- **The batch-flush timer never started when S3 logging was enabled by a hot reload**, so best-effort records buffered after the reload sat in memory until a batch filled or `Cleanup` ran. The timer now starts with the client, whether that happens at boot or on demand, and starts at most once.

- **The best-effort S3 write paths gated on the boot config while resolving the bucket from the live one.** `WriteLogToS3` and `WriteSingleLog` checked the construction-time `log_to_s3` snapshot, so after a reload turned S3 logging on, every buffered record was dropped — while the bucket those same functions resolved was already the reloaded value. Both now read the live config, so one object no longer holds two notions of the current config.

- **The enforced audit write ran on the logger's background context** instead of the request's, so it did not inherit the caller's deadline even though the request blocks on it before credentials are returned. Batched writes, which no request awaits, keep the background context.

- **S3 object tags were serialized without URL-encoding.** The audit object's tag set was joined by hand rather than encoded, so a tag value containing `&` or `=` produced a malformed tag header and a rejected write — under `audit_required` that fails the request closed. The tagging string is now `url.Values`-encoded, which is the wire format S3 expects.

- **`FormatClaimValue` rendered 2^53 in scientific notation.** The exact-integer guard used a strict `<`, but 2^53 is the largest float64 for which every integer below is exactly representable and is itself exact, so the boundary value was formatted as `9.007199254740992e+15` rather than as the integer it is. A claim value formatted this way is written identically to the audit record and to the STS session tag it becomes, so an ABAC policy matching on the integer form would not match the tag.

## [2.4.0] - 2026-08-21

Audit and observability hardening. The durable S3 audit trail becomes the default rather than an opt-in, every record identifies who made the request and from where, and the CloudWatch decision line becomes machine-queryable without post-filtering. Three fail-open or broken-by-default defects in the audit path are fixed.

### Added

- **`claims` in the durable audit record** — the S3 audit record now carries the identifying claims behind the decision, on both allow **and** deny, so the trail answers "who did this" without a cross-reference. Also emitted on the standardized decision log line. GitHub issuers report the **full verified claim set** — every GitHub Actions OIDC claim, not a curated subset — with `repository`/`repository_id` renamed to `repo`/`repo_id` so the audit vocabulary is stable regardless of the raw claim name; every other issuer reports the claims its own `claim_mappings` reference. These are claim VALUES, so they are gated by `log_claim_values` and redacted alongside `subject`/`jwtSub` — set `log_claim_values: true` to see them. See [docs/LOGGING.md](docs/LOGGING.md).

- **Top-level `session_tags_transitive`** (env `AOW_SESSION_TAGS_TRANSITIVE`), promoted out of `tag_auth.transitive_session_tags` — the mechanism is unchanged, but the gate no longer lives under a block operators disable via `tag_auth.enabled: false`. **RECOMMENDED to enable**: without it, a session tag is dropped the moment the target role assumes another role, so any ABAC policy past that hop can no longer see who the original caller was. Defaults to `false` for upgrade safety — transitive tags are immutable downstream, so turning this on breaks a target role that re-tags with the same keys while chaining. The deprecated `tag_auth.transitive_session_tags` key still works as a fallback (either key enabling it wins); `Validate()` warns when only the deprecated key is set. See [docs/TAG_BASED_AUTHORIZATION.md](docs/TAG_BASED_AUTHORIZATION.md#role-chaining--transitive-session-tags).

- **`sourceIp` and `sourceIpFrom` on the audit record**, on both allow and deny. `sourceIpFrom` records the value's provenance — `frontend` when AWS attested the address (API Gateway v1/v2, Lambda Function URLs) or `x-forwarded-for` when it could only be read from a client-supplied header (ALB, which has no source-IP field). Provenance is stored rather than inferred, because an auditor reading a record months later cannot otherwise tell an observed address from an asserted one. Authorization never consults the IP, so a forged one grants nothing — but it could otherwise misattribute an entry in the compliance artifact. An IP is personal data under GDPR; review retention on the audit bucket. See [Source IP trust model](docs/LOGGING.md#source-ip-trust-model).

- **`frontendRequestId` on the decision log line and the durable audit record** for the three frontends that issue an ID of their own, kept as the join key back to API Gateway access logs now that `requestId` is the Lambda invocation UUID (see _Changed_). ALB issues no request ID, so the attribute is absent there rather than emitted empty.

- **`Config.AuditEnforced()`** — audit enforcement is now derived from the active config snapshot on every call instead of being resolved once at boot, so supplying `log_to_s3` + `log_bucket` through a hot reload engages the fail-closed contract immediately, with no restart and without restating `audit_required`.

- **Per-mapping `role_session_name`** — `role_mappings[].role_session_name` and `role_groups[].defaults.role_session_name` override the global `role_session_name` for the roles that mapping grants, so CloudTrail names the requester instead of the service. The override is resolved through the same `(issuer, subject, role, conditions)` match as the session policy, so the two always come from the same grant — a name from one mapping paired with a policy from another would attribute the session to an identity that is not the one whose policy scoped it. The name is a static string, not a template: a mapping whose `subject` is a regex matching many repositories gets **one** name for the whole set. Also exposed on the OpenTofu `role_mappings` variable. See [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

- **`sessionName` on the audit record and the decision log line** — the STS session name actually used for the assumption. Operator-declared static config, never claim-derived, so it is deliberately **not** suppressed by `log_claim_values=false`.

### Changed

- **`audit_required` now defaults to `true`.** Previously `false` by default (best-effort, batched S3 audit trail). The durable, fail-closed guarantee still only actually engages once `log_to_s3=true` + `log_bucket` are also configured — with either unset, `audit_required=true` stays a no-op (a warning is logged at boot instead of a hard failure), so zero-dependency startup with no S3 bucket configured is unaffected. Set `audit_required: false` explicitly to opt back into the best-effort, batched trail even with S3 logging configured.

  **Behavior change on upgrade.** A deployment that already has `log_to_s3: true` + `log_bucket` set and never stated `audit_required` silently moves from best-effort batching to fail-closed: an allow decision whose audit write fails now returns `ErrAuditWriteFailed` (HTTP 500) instead of credentials. That is the intended posture, but it makes the audit sink a hard dependency of credential issuance — confirm the Lambda's role can write to `log_bucket` (both `s3:PutObject` **and** `s3:PutObjectTagging`, since the writer always sets object tagging) and alert on `errorCode=audit_write_failed` before upgrading. Set `audit_required: false` to keep the previous behavior.

  **OpenTofu consequence.** `audit_required` implies a destination, so the module now derives `enable_s3_logs || audit_required` and provisions the audit-log bucket on its own. With the new default that means `tofu apply` creates the bucket unless you set `audit_required = false`. Without it the flag would silently degrade to a no-op, losing the guarantee it asks for. See [deploy/README.md](deploy/README.md).

- **`log_claim_values` now defaults to `true`** (was `false`), so decision logs and audit records carry the requesting identity — canonical subject, `jwtSub`, audience, resolved session-tag values, and the `claims` set — instead of only claim _names_.

  **Privacy note for upgrades.** A deployment configured through YAML or environment variables that never stated `log_claim_values` will begin recording identifying values, including the GitHub `actor` username alongside the new `sourceIp` field. A username paired with an IP address is personal data; review your audit bucket's retention policy and access controls before upgrading. Deployments provisioned by the OpenTofu module are unaffected — that module already set it to `true`. Set `log_claim_values: false` to keep the previous behavior; claim names, decision, reason, and role are still recorded either way.

- **`requestId` is now the Lambda invocation UUID in every frontend mode**, replacing each frontend's own identifier. The per-frontend IDs are not interchangeable — API Gateway v2 issues opaque tokens like `CPyipjveDoEEPIA=`, REST v1 and Lambda URLs issue UUIDs, and ALB issues nothing — so a query spanning frontends had no single shape to match on. The frontend's own ID is preserved as `frontendRequestId`.

- **The decision log line no longer duplicates `sourceIp`, `sourceIpFrom`, and `frontendRequestId`.** Previously each was emitted twice — once by the frontend adapter's request-scoped logger and once by the decision line's own attribute set — so every decision line carried two keys with the same name. Each of the three now has exactly one writer, the adapter-bound logger, matching how `requestId` was already handled above.

- **The decision log line now omits empty attributes** instead of emitting them blank, so a CloudWatch Insights query never has to filter `field != ""`. This covers both the decision line's own attribute set — deny-only `stage`/`reason` are absent on an allow, and with `log_claim_values=false` claim values are absent rather than blanked — and the adapter-bound request attributes: `frontendRequestId` and `sourceIp` are absent rather than emitted as an empty string when the frontend has none (ALB issues no frontend request ID, and has no source IP without a usable `x-forwarded-for`). `sourceIpFrom` is emitted only when the IP was _not_ platform-attested, since a constant on every line is noise; the durable record keeps it unconditionally. Timing attributes are millisecond integers named `validationMs`/`totalMs`/`durationMs`, consistent with `processingMs`.

  All log output is JSON and is now pinned as such by test, so downstream parsers can rely on every line being valid JSON.

- **`role_session_name` is now validated at boot instead of being sanitized at runtime.** STS accepts 2–64 characters from `[\w+=,.@-]`; a value outside that set is rejected by `Validate()` rather than reshaped on its way to `AssumeRole`. This value is an identity — it appears in the assumed-role ARN, in `aws:userid`, in CloudTrail, and is conditionable via `sts:RoleSessionName` — so a silently mangled name means IAM conditions and audit queries are written against a string the operator never chose.

  **Behavior change on upgrade.** This applies to the **global** `role_session_name` as well as the new per-mapping overrides. A deployment whose global name contains a character STS rejects (a space, or a `/` from pasting an `owner/repo` value) boots today with that character silently stripped and will **refuse to boot** after this change. Check the value before upgrading. The overrides are new keys, so they cannot affect an existing config. Hot reload still fails safe: a rejected config is discarded and the last-good one keeps serving.

  The runtime sanitizer remains as defense in depth but now **substitutes** disallowed characters with `-` rather than deleting them, and warns on truncation. Deleting collapsed distinct identities onto one name — `acme/api` and `ac/meapi` both became `acmeapi` — which is an audit-attribution failure.

### Fixed

- **`audit_required` disabled itself permanently.** `Validate()` mutated the field to `false` when `log_to_s3`/`log_bucket` were unset. Because `Provider.refresh` clones a pristine base, a later reload supplying the bucket could never re-engage enforcement — the service went on issuing credentials with no durable audit record, fail-open, with nothing in the logs to say enforcement had been dropped. Declared intent is no longer mutated; enforcement is derived per snapshot via `AuditEnforced()`, and the unmet-prerequisite case is a boot warning.

- **Audit-log writes failed with `AccessDenied` in both deployment templates.** The writer always sets object tagging on the audit object, but IAM granted only `s3:PutObject`, so every synchronous audit write was rejected — which under `audit_required` fails the request closed. Both templates now grant `s3:PutObject` **and** `s3:PutObjectTagging`. Enumerated rather than `s3:PutObject*`, which would also grant `PutObjectRetention` and `PutObjectLegalHold` and let the writer weaken object-lock on its own records.

- **ALB requests logged the ELB target-group ARN in the `sourceIp` field.** Every frontend now logs a validated IP address or nothing at all. ALB derives it from the **rightmost** `X-Forwarded-For` hop — the entry the load balancer itself appended, and the only one with an attester — rather than a leftmost value the caller chooses. The correctly-parsed ALB client IP was already being stored in the request context and read by nothing.

- **The durable S3 audit record carried no source IP at all**, so the compliance-facing artifact could not answer where a request originated.

- **Lambda URL requests logged the path under `rawPath`** while every other frontend used `path`, so `path`-filtered queries silently omitted them.

- **`requestMeta` minted its own request ID** when the context value was empty, so a response could report a `requestId` that appeared in no log line.

- **The claim-extraction debug line logged `mode`** while the audit record and decision line both used `jwtMode`.

- **`"Assuming role"` and `"Successfully assumed role"` were each logged twice per request** — once from `internal/aws` through the package-level logger, with no `requestId` correlation. The uncorrelated duplicates are removed and the processor's own correlated line is promoted to `Info`, so the record immediately before a privileged credential is minted stays visible at the default level. The error path keeps its log.

- **The requested role ARN was repeated three times in a single log line** (`request.role`, `role`, `matchedRole`).

- **Numeric claim values were recorded in scientific notation.** Claims are decoded into `map[string]any`, so every JSON number arrives as a `float64`, and the default float formatting rendered a 10-digit epoch second as `1.7555904e+09` — an `exp` no auditor reads as a timestamp and no SIEM parses as a number. Integral values are now rendered as integers. The fix is shared by the audit record and `BuildSessionTags` (`utils.FormatClaimValue`), so the documented guarantee that a claim reported in `claims` and the same claim attached as a session tag can never disagree still holds — a session tag mapped to a numeric claim was previously sent to `sts:TagSession` in scientific notation too.

- **A claim rename could silently drop a verified claim.** If a token carried both `repository` and `repo`, the `repository`→`repo` rename landed both on one key and one value vanished, with the survivor decided by Go's randomized map iteration order — a lossy, non-reproducible audit record. A rename is now skipped when the token already carries a claim under the alias target.

- **Unused IAM permissions in both deployment templates.** `iam:ListRoleTags` is never called — tag-based authorization reads role tags out of the `GetRole` response — and the OpenTofu module granted it as `iam:ListRole*`, which additionally allowed `iam:ListRoles` (enumerate every role in the account). The S3 action wildcards are enumerated for the same reason as the audit-writer statement above: `s3:PutObject*`/`s3:DeleteObject*` on the JWKS cache bucket also granted `PutObjectRetention`/`PutObjectLegalHold` and `DeleteObjectVersion`, and `s3:GetObject*` on the config and session-policy buckets also granted `GetObjectVersion` — which would let a compromised Lambda read a superseded, possibly more permissive revision of a policy document that has since been tightened.

## [2.3.0] - 2026-08-12

Multi-issuer support in `apigw` validation mode, end to end. The service now resolves the issuer per request from the JWT Authorizer's verified `iss` claim instead of requiring exactly one configured issuer, and the OpenTofu stack provisions one authorizer and one route per issuer on a single API Gateway. `alb` mode is unchanged and still requires exactly one issuer — an ALB has one OIDC IdP, so a multi-issuer config is genuinely ambiguous there.

Existing single-issuer deployments are unaffected at the config level: the singular `issuer`/`audiences` shorthand still works and existing configs boot unchanged. Existing **`apigw`** OpenTofu deployments need a one-time state migration before the first apply — see Breaking Changes.

### Added

- **Multi-issuer `apigw` mode** — `jwt_validation.mode: apigw` no longer requires exactly one configured issuer. Each entry in `issuers[]` gets its own API Gateway JWT Authorizer and route, resolved at runtime by the token's authorizer-verified `iss` claim; a token presented to another issuer's route is rejected by API Gateway before the Lambda is invoked. `alb` mode is unchanged and still requires exactly one issuer.
- **`issuers` Terraform variable** (`deploy/opentofu/variables.tf`) — a map of issuer name to `issuer`/`provider`/`audiences`/`session_tags`/`route_key` (plus optional `claim_mappings`/`required_claims`/`jwks_uri`), alternative to the singular `issuer`/`audiences` shorthand. Drives both the rendered `config.yaml` and, in `apigw` mode, the per-issuer authorizers/routes.
- **`config.yaml` is now rendered from a template** (`templates/config.yaml.tftpl`) with unquoted YAML keys, instead of `jsonencode`'d values — readable in the S3 console and in diffs. A plan-time precondition compares the rendered file against the config object to catch template drift.

### Fixed

- **`aws_iam_role_policy` count fix** (`874ea91`) — kept the resource's `count` known at plan time so `tofu plan` no longer fails against a fresh account.
- **Multi-issuer + `role_mappings` rendered a config the service refused to boot.** `var.role_mappings` had no `issuer` attribute and nothing rendered `default_issuer`, so `tofu plan`/`apply` succeeded but every Lambda invocation then failed cold start (`internal/config/config.go`'s "issuer must be set explicitly" error) once more than one issuer was configured. Added `issuer` to `var.role_mappings` and a new `var.default_issuer`, both rendered into `config.yaml`, plus a precondition that catches the missing combination at plan time.
- **The zero-config GitHub seed could leak its `required_claims`/ `session_tags` into a hand-written or Terraform-rendered issuer.** `MergeBytes` decoded an S3/remote config onto the existing `Issuers` slice, so a `null`/partial `required_claims`/`session_tags` for `issuers[0]` inherited the built-in GitHub defaults (mapstructure merges maps and keeps existing values on `null`) instead of being treated as unset — a non-GitHub issuer could end up with GitHub's session tags attached to its STS sessions. `MergeBytes` now replaces `Issuers` outright when the payload declares an `issuers` key, so each issuer decodes onto a fresh struct; config fragments (`config_fragments`) are unaffected — they never touch `issuers`.
- **A backslash in any rendered config value broke `tofu plan`.** The `config.yaml` template interpolated strings straight into double-quoted YAML scalars with no escaping, so an ordinary anchored regex — `myorg/repo\.git` in a `subject`, `\.yml` in a `workflow_ref` condition — failed the drift precondition's `yamldecode` with "unknown escape character". Every interpolated scalar now goes through `jsonencode`, which emits valid escaped YAML. Keys inside `claim_mappings`/`session_tags` are quoted as a result; all structural keys stay unquoted.
- **A mismatched Lambda binary variant panicked on every invocation instead of failing at plan time.** `jwt_validation_mode` and the packaged binary (`build.sh apigateway` vs `apigatewayv2`) were unlinked — `validateAdapterMode` (`internal/handler/bootstrap.go`) only catches the mismatch at cold start. `build.sh` now records the variant it built next to the zip (`dist/variant`); `modules/lambda` compares it against the `jwt_validation_mode`-derived `expected_variant` in a plan-time precondition. A pre-existing zip with no marker is treated as unknown and passes — this is a deliberate weakening so upgrading doesn't break a working deploy.
- **The `jwt_authorizer_issuer`/`jwt_authorizer_audiences` escape hatch could silently deny every request.** `apigw` mode's `resolveIssuerSpec` (`internal/validator/delegated_claims.go`) requires the JWT Authorizer's verified `iss` to exactly match an `issuers[]` entry; a documented "escape hatch" that let `jwt_authorizer_issuer` diverge from the app config's issuer therefore guaranteed `ErrUnknownIssuer` on every request. Added a plan-time precondition rejecting issuer divergence. `jwt_authorizer_audiences` may still diverge, but only in the safe (narrowing) direction — `variables.tf` now documents that distinction precisely instead of describing both as an unconditional escape hatch.
- **`var.route_key` accepted `null` and any string.** `nullable = false` and a `"<METHOD> <path>"` format validation now match the checks `var.issuers[*].route_key` already had.
- **`var.role_mappings` accepted an empty `roles` list**, which plans clean and then dies at boot (`internal/config/config.go`). Added a validation block requiring at least one role per mapping.
- **The Lambda-variant guard broke `tofu test` for anyone who had actually run `build.sh`.** The suite plans `jwt_validation_mode = "self"` and `"apigw"` against one local `dist/function.zip`/marker, so no single `expected_variant` could satisfy every run once the marker existed. Added `var.check_lambda_variant` (default `true`, enforced for every real deploy); `hardening.tftest.hcl` sets it `false` for itself only, with the reason documented next to both the variable and the precondition.
- **`roles = null` / `audiences = null` hit an opaque `length(): argument must not be null` instead of the intended validation message.** Both fields are required (non-`optional`) list types, but Terraform still accepts an explicit `null`. Added a `!= null` guard ahead of `length()` on `var.role_mappings[*].roles` and `var.issuers[*].audiences`.
- **The multi-issuer/`role_mappings` precondition (round 1) checked only that an `issuer`/`default_issuer` value was _present_, never that it was one of the configured issuers** — and short-circuited entirely with a single issuer, exactly where round 1 also hardcoded a mapping `issuer` into `terraform.tfvars.example`'s default single-issuer state. An operator (e.g. GHES/self-hosted) who edited the top-level `issuer` without touching the mapping's got a clean plan and a dead cold start on a URL they never typed (`internal/config/config.go`'s issuer-membership checks). Added two additive preconditions on `aws_s3_object.config` — deliberately without the single-issuer short-circuit — checking `var.default_issuer` and every `role_mappings[*].issuer` against the actual configured issuer set. Commented out the hardcoded mapping `issuer` in `terraform.tfvars.example`'s single-issuer default (redundant there; that sole issuer applies regardless), so the trap can't be sprung by editing `issuer` alone.

### Breaking Changes

- **Existing `apigw`-mode deploys need a manual state migration.** The single issuer's authorizer and route move from fixed addresses (`aws_apigatewayv2_authorizer.jwt[0]` / `aws_apigatewayv2_route.this`) to ones keyed by issuer name — a `moved` block cannot target an arbitrary map key, so this requires `tofu state mv` before the first `tofu apply` against this version, or the plan destroys and recreates the authorizer and route. See the "Upgrading" section of [deploy/opentofu/README.md](deploy/opentofu/README.md) for the exact commands. Self-mode deploys need no action — a `moved` block handles that migration automatically.
- **CloudFormation `apigw` deploys where `JWTAuthorizerIssuer` diverges from the uploaded `config.yaml`'s issuer now 401 every request instead of working.** Before this release, `apigw` mode resolved the sole configured issuer's spec regardless of the token's `iss`, so a mismatched `JWTAuthorizerIssuer` still worked; `resolveIssuerSpec` (`internal/validator/delegated_claims.go`) now requires an exact match, so a divergent value means every request fails with `ErrUnknownIssuer`. The CloudFormation template cannot detect this at deploy time (it never sees inside the uploaded `config.yaml`), so the stack creates and deploys fine and the break surfaces only as 401s at request time. Affects only CloudFormation `apigw` deploys whose `JWTAuthorizerIssuer` parameter doesn't match their `issuers[].issuer`; verify the two match before upgrading. `JWTAuthorizerIssuer`'s parameter description and [deploy/README.md](deploy/README.md) now say so explicitly.
- **A remote config payload with `issuers: null` now fails to boot instead of silently trusting the GitHub Actions issuer.** `MergeBytes`'s replace-the- seed guard used `v.InConfig("issuers")`, which returns `false` for an explicit `null` (viper can't distinguish "absent" from "present but nil"), so `issuers: null` fell through to the additive merge and kept the zero-config GitHub seed — fail-**open**. It is now treated as declared, same as any other value, so `Validate()`'s "at least one issuer is required" check applies. Unreachable from this Terraform stack (which emits `[]`, never `null`); only a hand-written or non-Terraform S3 config could hit it.

### Changed

- **Dependencies** — AWS SDK for Go v2 patch bumps across the board (`aws-sdk-go-v2` 1.43.4 → 1.43.5, `config` 1.32.35 → 1.32.36, `credentials` 1.19.34 → 1.19.35, `dynamodb` 1.63.1 → 1.63.2, `iam` 1.58.1 → 1.58.2, `s3` 1.106.5 → 1.107.1, `sts` 1.45.4 → 1.45.5, `smithy-go` 1.27.6 → 1.27.7, plus the transitive `internal/*` modules), and `golang.org/x/text` 0.40.0 → 0.41.0. No API changes; `go mod verify`, `govulncheck` and the full test suite pass unchanged.
- **Go toolchain** — 1.26.5 → 1.26.6, fixing 6 stdlib vulnerabilities (`net/url` `resolvePath`, `crypto/tls` post-handshake message limits, `net/http` H2C `ReadHeaderTimeout`, `encoding/xml` and `encoding/asn1` recursion guards, `golang.org/x/net` idna punycode validation). `govulncheck ./...` now reports no vulnerabilities.

## [2.2.2] - 2026-08-06

A follow-up review pass over the areas 2.2.0 changed. Both fixes are mutation-tested — each was confirmed to fail its regression test when the fix is removed. No authorization bypass was found, and no released deployment was affected: both gaps were reachable only from the local dev server or with `log_level: debug`.

### Security

- **`audit_required` no longer fails open when no audit sink is wired.** 2.2.0 closed the case where the sink existed but held a stale config; the case where no sink was passed at all still degraded silently to log-only. `recordDecision` returned early on a nil sink _before_ consulting `cfg.AuditRequired`, so `audit_required: true` was ignored and credentials were returned with no durable record. `config.Validate()` cannot catch this — it sees `log_to_s3` and `log_bucket`, not whether the constructor was handed a sink. A missing sink is now treated as an unmet requirement rather than an absent one and reported as `ErrAuditWriteFailed`. Reachable only via `cmd/local` (the only entry point that passes `nil`; the four Lambda variants always pass `bootstrap.S3Logger`, which was already fail-closed), and `cmd/local` is not a published artifact — `ko publish` ships only the Lambda variants.

- **`log_claim_values: false` now holds in `getSessionPolicy`'s debug logs.** Three debug sites emitted the canonical subject through the **package-level** `slog` with no `cfg.LogClaimValues` gate, so at `log_level: debug` the subject appeared in the log stream while the audit record correctly suppressed it. They now go through the request-scoped logger and a shared `subjectAttr` gate that applies the same blanking as `auditLogAttrs`. The pre-existing log-stream suppression test could not catch this: a package-level `slog` call writes past the logger the test installed, so the leak landed outside the captured buffer — the regression test now also asserts these lines _reach_ the request logger. Low impact (needs `log_level: debug`, and the value is a repository path rather than a secret), but a documented control that did not hold.

### Added

- Regression test for the hot-reload promise itself (`TestHotReload_AuthorizationDecisionFollowsRemoteConfig`): a role withdrawn from the remote config stops being assumable, and one added becomes assumable, on the next request — no redeploy, no cold start — while a config that fails `Validate()` leaves the last-good grants in place. Config-level reload was already covered, but nothing asserted that a reload changes the authorization **outcome** through `ProcessRequest`; neutralizing its leading `provider.MaybeRefresh(ctx)` call now fails the test instead of silently serving the cold-start config forever.

### Removed

- Dead code, each confirmed unreferenced via the Go language server before removal: `AwsConsumer.GetSessionPolicyFromS3` (never on `AwsConsumerInterface`, referenced only by its own test, and the one remaining unbounded `io.ReadAll` on an S3 body — the live path uses `GetS3Object` + `io.LimitReader`), and the four unused `(*S3Logger).With…` builder methods, which duplicated the functional options in `test_helpers.go` that tests actually use. `utils.RedactToken` and `config.WithFragmentFetcher` were also audited and **kept** — the latter is used by seven tests, and the former is retained as the documented helper for the case where a log site must carry token material (no site does; the docs no longer claim otherwise).

### Changed

- AWS SDK v2 dependency bumps (`aws-sdk-go-v2` 1.43.2 → 1.43.4, `config` 1.32.33 → 1.32.35, `credentials` 1.19.32 → 1.19.34, `dynamodb` 1.62.2 → 1.63.1, `iam` 1.57.0 → 1.58.1, `s3` 1.106.2 → 1.106.5, `sts` 1.45.2 → 1.45.4, `smithy-go` 1.27.5 → 1.27.6, plus transitive `// indirect` updates).

## [2.2.1] - 2026-07-30

Maintenance release: dependency and CI-action updates only. No code changes, so no behavior change and nothing to do on upgrade.

### Changed

- AWS SDK v2 and transitive dependency bumps (`go.mod`/`go.sum`).
- CI action bumps: `actions/checkout` 7.0.0 → 7.0.1, `docker/login-action` 4.4.0 → 4.5.1, and `github/codeql-action` (`init`/`autobuild`/`analyze`) 4.37.1 → 4.37.3.

## [2.2.0] - 2026-07-22

Findings from a whole-codebase security review that covered the packages the 2.1.0/2.1.1 sweeps had not reached (`internal/cache`, `internal/s3logger`, the SSRF/JWKS fetch path, fragment integrity, and the AWS spoke/tag caches). Every fix is mutation-tested — each was confirmed to fail its regression test when the fix is removed. Three behavior changes; see Upgrade notes.

No authorization bypass was found. The two most consequential properties were re-confirmed rather than changed: the SSRF block is enforced at **dial** time against the already-resolved IP (so DNS rebinding is structurally prevented, not merely time-windowed) and on every redirect hop; and the JWKS refetch limiter cannot be used to pin a stale key set after a rotation, because a forced refetch that the limiter _allows_ write-through repairs the cache — spending the slot is the act that installs the new keys.

### Upgrade notes

- **Enable `audit_required` by redeploy, not by hot reload.** With the fail-open closed, a reload that turns on `audit_required` from a boot config with `log_to_s3: false` leaves the sink with no S3 client, and every request now fails closed until a cold start. Previously it silently returned credentials with no audit record.
- **The SSRF guard blocks more ranges.** If a JWKS or issuer host resolves into `100.64.0.0/10` or `0.0.0.0/8`, or is reached through the NAT64 well-known prefix, it will now be refused. Public issuers are unaffected; `allow_insecure_issuers` still relaxes loopback only.
- **`iam:GetRole` rejects a role whose name exceeds 64 characters** instead of truncating it. Such a name never denoted a real role, so a request that previously "worked" was already reading the wrong role's tags.

### Security

- **`audit_required` no longer fails open after a hot reload** — `S3Logger` captures the `*config.Config` handed to it at bootstrap, but the hot-reload provider swaps in a **new** `Config` on every refresh, so that snapshot could disagree with the live config the processor reads. `WriteRecord` gated on the stale snapshot's `LogToS3`, so a reload that turned on `audit_required` + `log_to_s3` left it a silent no-op that **returned success** — credentials were released with no audit record, the exact inverse of `audit_required`'s fail-closed contract. Durability now rests on whether an S3 client actually exists, and `WriteRecord` never no-ops. Static deployments were unaffected: `Validate()` gates the `audit_required` → `log_to_s3` pairing within a single config.

- **S3 writes follow a hot-reloaded `log_bucket`** — the bucket was captured at construction, so rotating `log_bucket` by reload (e.g. to a locked-down bucket during an incident) kept writing to the previous bucket while the write reported success: it "succeeded" somewhere the operator no longer intended. `S3Logger` now takes a live-config source (`SetConfigSource`, the same seam `AwsConsumer` already uses) and resolves the bucket per write. **Every** write path uses it — durable audit, batched, and single — since honoring the live value in only one would split records across two buckets on a rotation, which is worse for forensics than consistently using either.

  **Known residuals.** (a) A reload that enables `audit_required` from a boot config with `log_to_s3: false` now correctly refuses every request (fail-closed) until a cold start rather than silently leaking — enable it by redeploy, not reload. (b) The best-effort `BufferRecord` path still consults the boot snapshot, so records are dropped when `log_to_s3` is enabled only by reload; that path is explicitly best-effort and never gates credentials.

- **`config_fragments` checksum pins are enforced on every refresh** — the pin was compared only on the "changed" path, so a cache hit (`etag == prevETag`) skipped it entirely and a pin newly added or rotated to quarantine already-applied fragment content was silently inert — precisely the incident-response case pinning exists for. Cold starts always enforced it, which bounded the exposure.

- **`iam:GetRole` no longer truncates an over-long role name** — a name longer than IAM's 64-character maximum was silently truncated and the lookup ran against the truncated name, reading the tags of a _different_ role than the ARN named. Since those tags drive tag-based authorization, silently rewriting the identifier is the wrong reflex; it is now rejected. Not exploitable (an over-long name never denotes a real role, and the subsequent `AssumeRole` uses the full ARN), but it matches the "skip/reject, never coerce" rule `BuildSessionTags` already follows. The cap is measured on the role **name** — the segment after the last `/` — because a role identifier may carry a path (`/team/sub/Name`); measuring the whole string would reject a valid role with a deep path and a short name.

- **`ExternalId` is no longer logged** — the too-short-external-ID rejection path logged the value. Only reachable for a one-character secret, so nothing meaningful leaked, but it printed a configured shared secret.

- **`Cache-Control: no-store` on all API responses** — a 200 carries live AWS credentials. The handlers do not inspect the HTTP method (a GET is processed identically to a POST), so the usual "caches don't store POST responses" reasoning could not be relied on; the requirement is now stated explicitly rather than inherited from the method.

- **SSRF guard covers IPv6 carrier forms and the remaining reserved IPv4 ranges** — `isBlockedIP` saw through only the IPv4-mapped `::ffff:x.x.x.x` form. It now also resolves the deprecated IPv4-compatible `::x.x.x.x` form and the NAT64 well-known prefix `64:ff9b::/96` (which a NAT64 gateway rewrites to the embedded IPv4, loopback and link-local included), and blocks `100.64.0.0/10` (RFC 6598 shared address space, used by AWS for ECS `awsvpc` and EKS pod networking) and `0.0.0.0/8`. None was exploitable — reaching any required controlling DNS for an already-trusted issuer, and the IPv4-compatible forms are unroutable — but the guard already blocked RFC1918, so leaving these open was an inconsistency rather than a considered exception. A companion test pins that public addresses and the `100.64.0.0/10` boundaries are **not** over-blocked.

- **`GetRoleTags` authorizes the target account before consulting its cache** — the role-tag cache was read first, so for up to `roleTagCacheTTL` (60s) after an operator revoked an account, a warm entry kept handing back that account's IAM tags for tag-based authorization to act on. Revocation now takes effect on the next request. `spokeCredsFor` already validated before _its_ cache, so the two caches in that file now follow one rule; more importantly, this layer no longer depends on `ProcessRequest` happening to call `IsTargetAccountAllowed` earlier in the pipeline — a cross-package ordering nothing enforces, and the only reason the stale window was previously unreachable. The check applies the same policy the post-cache path already enforced, so it changes _when_ the decision is made, not what it decides.

- **`GetRoleAs` rejects a nil credentials provider** — it would otherwise leave the hub credentials in place and read a same-named role in the **hub** account while the caller believed it read a member account's. Unreachable via its one caller; the guarantee no longer depends on that caller.

- **`GetRoleTags` returns a copy of its cached tag map** — it handed out the cached map itself on **both** the hit and miss paths, so any caller that mutated the result would poison every later authorization decision for that role. The sole caller only reads, so this is defensive, but the failure mode would be silent and cross-request.

### Added

- **Config-load warning for implicit issuer binding** — a mapping that declares no `issuer` binds to `default_issuer`. With one configured issuer that is unambiguous; once a second exists, those mappings silently move into whichever namespace `default_issuer` names — so a remote overlay that adds an issuer **and** sets `default_issuer` in one merge re-homes every previously-implicit grant with no redeploy, moving a GitHub-bound grant to another IdP. Fragments are already guarded (`mergeFragment` requires a base-defined, non-conflicting `default_issuer`); the primary overlay was not, so `Validate()` now warns.

- **Config-load warning for unscoped role grants** — when the lowest-`order` mapping granting a role carries no `session_policy` but a higher-order one does, `Validate()` now warns, because `FindSessionPolicy` is lowest-order-wins and the scoped policy is silently dropped. This is most acute across the `role_mappings`/`role_groups` boundary: `Validate()` appends every `role_mapping` before every `role_group`, so a `role_group`'s session policy can **never** outrank a policy-less `role_mapping` for the same role, and — unlike the intra-`role_mappings` case — no file ordering can fix it. The selection rule itself is unchanged and remains pinned by `TestOrderWinsAmongMappingsGrantingTheSameRole`; this makes the footgun loud rather than changing authorization semantics.

- **Regression tests for the reviewed areas** — JWKS cache issuer isolation and concurrency (`internal/cache`), SSRF guard depth proving the block is enforced at **dial** time and on every redirect hop (`internal/validator`), role-tag / spoke-credential cache keying and expiry (`internal/aws`), fragment integrity and merge scoping (`internal/config`), and the `audit_required` contract (`internal/handler`, `internal/s3logger`).

## [2.1.1] - 2026-07-21

Hardening release closing the last unenforced authorization footgun found by an independent verification sweep of the 2.1.0 authorization layer, plus the adversarial test suite that sweep produced. One behavior change: a config that uses a bare wildcard as a `subject` now fails to load instead of silently authorizing everything — see Upgrade notes.

### Security

- **Bare wildcard `subject` patterns are now rejected** — `Validate()` refused a bare `.*`/`.+` in `conditions`, but never applied the same rule to a `role_mapping.subject` or a `role_groups.subjects` entry, even though the subject is the primary identity gate. `subject: ".*"` therefore compiled happily and granted that mapping's roles to **every** subject of the bound issuer — for the default GitHub issuer, every repository in every organization that can mint a token GitHub signs. The documentation has said "keep patterns specific, never `.*`" since 1.x; nothing enforced it. Both paths into the effective mapping set now share one guard (`bareWildcards`), so subjects and conditions can no longer drift apart.

  The check is deliberately literal — it matches the two shapes operators actually type. An equivalent pattern written another way (`(.*)`, `[\s\S]*`) still compiles; this stops the accident, not a determined operator.

### Added

- **Adversarial authorization test suite** — 36 tests across the four security layers, written independently of the existing tests and verified to have teeth by mutation testing (each was confirmed to fail when the fix it covers is removed):
  - `internal/config/authz_adversarial_test.go` — includes a differential fuzz (400 random configs × 21 adversarial subject patterns × 18 subjects) that diffs the owner-bucketed index against a reference linear scan for both `AuthorizeRoles` and `FindSessionPolicy`. An index false _negative_ is fail-open — a policy-bearing mapping dropped from the scan while a broader policy-less one still authorizes yields an unscoped assumption — so this is fuzzed rather than example-tested. Reverting the 2.1.0 `classifySubject` fix makes it re-derive that bug unaided.
  - `internal/validator/trust_boundary_test.go` — cross-issuer key confusion, `alg:none`, HS256/RSA algorithm confusion, payload splicing, time bounds, and proof that an unconfigured `iss` triggers zero network requests (no SSRF primitive via the `iss` claim).
  - `internal/aws/assume_adversarial_test.go` — cross-account fail-closed paths, malformed-ARN guard bypass attempts, session-tag charset/limit handling (skipped, never truncated or sanitized), transitive-tag opt-in, duration clamping.
  - `internal/handler/pipeline_e2e_test.go` — the scoping policy actually reaching STS, every deny path stopping before STS, and a failed or invalid-JSON session-policy file denying rather than assuming unscoped.

### Upgrade notes

- **A config with `subject: ".*"` (or `.+`) will now fail to load.** This is intentional and fail-closed: the service refuses to start rather than run an authorization rule that matches every repository. If you hit this, replace the wildcard with a pattern scoped to the organizations you actually trust (e.g. `myorg/.*`), which continues to work unchanged. Patterns that merely _contain_ a wildcard — `org/service-.*`, `myorg/.*`, `.*/shared-lib` — are unaffected; only a subject that is _entirely_ `.*` or `.+` is rejected. No mapping in `example-config.yaml` or the shipped documentation used one.

## [2.1.0] - 2026-07-21

Security-hardening release: three authorization-layer defects found in an audit of the token→AssumeRole path, each fixed with a regression test that fails before the change. No config-schema or deployment changes — existing configs keep working — but authorization behavior is now stricter where the old code was wrong (a role that was silently assumed unscoped now carries its intended session policy, and conditions can no longer be transiently bypassed), so review the Security notes before upgrading.

### Security

- **Session policy scoping bound to the granting role** — `FindSessionPolicy` resolved by `(issuer, subject)` only and returned the first-declared mapping matching the subject, ignoring which mapping granted the requested role. A broad, policy-less `role_mapping` declared before a narrow mapping that deliberately scopes a privileged role with a `session_policy` caused that role to be assumed **unscoped**. The lookup is now role- and condition-aware: the scoping policy always comes from the mapping that authorized the role (subject match + conditions satisfied + grants the role). Signature changed to `FindSessionPolicy(issuer, subject, role, claims)`.

- **Hot-reload condition race fixed (authorization bypass)** — a `config_fragment`'s `*Condition` was shared across config snapshots, and each hot reload recompiled it in place (`Validate` → `compileCondition`) while concurrent requests read the served snapshot with no lock. A reader observing the transiently-empty compiled list had all conditions silently pass. Fragment and role-group conditions are now cloned into per-snapshot private memory before compilation, so a reload can never mutate a condition another request is evaluating. Affected configs using `config_reload_interval` + `config_fragments` with `conditions`; base-config conditions were unaffected.

- **Correct index bucketing for quantified-slash subject patterns** — the authorization index inferred a mapping's owner bucket from the raw text before the first `/`. A subject pattern whose first slash is quantified (e.g. `owner/?repo-.*`, `owner/*repo`) also matches slash-less subjects, so the index could drop a mapping a full scan would find — diverging from the authorize decision and mis-scoping the session policy. Bucketing now uses the compiled pattern's guaranteed literal prefix (`regexp.LiteralPrefix`), so a mapping is owner-scoped only when every match provably starts with `owner/`. Operator-config-only and fail-closed for authorization; no attacker vector.

### Upgrade notes

Two consequences of the session-policy fix above. Neither is a new code change; both describe behavior as shipped in 2.1.0, called out because they can be observed as a difference in production.

- **Tag-authorized roles now correctly receive no session policy.** Session policies have always been documented as coming only from `role_mappings`, with a tag-authorized role "scoped solely by its own IAM permissions" (see `docs/TAG_BASED_AUTHORIZATION.md` → Security model & foot-guns #3). Because the pre-fix lookup keyed on `(issuer, subject)` alone, a role authorized via `tag_auth` could nevertheless pick up the session policy of an unrelated mapping that merely matched the same subject. The role-aware lookup removes that accident, so the code now matches the documented contract. If you run `tag_auth` alongside `role_mappings` carrying `session_policy`, tag-authorized sessions that were incidentally being scoped no longer are — confirm those roles are least-privilege at the IAM level, which is the documented expectation. `tag_auth.enabled` defaults to `false`, so this affects opt-in configurations only.

- **`session_policy` selection remains order-sensitive among mappings that grant the same role.** First-declared still wins, but the candidate set is now correctly narrowed to mappings that actually grant the requested role and satisfy their conditions. One consequence survives and is worth auditing: if a broad mapping grants a role with **no** `session_policy` and a later, narrower mapping grants that _same_ role _with_ one, the broad mapping wins on order and the role is assumed **unscoped**. This is consistent with the union semantics of `AuthorizeRoles` — the broad entry did explicitly grant the role — and is unchanged from previous releases, but it is rarely intended. Declare the scoped mapping first, or avoid granting a policy-scoped role from a broader, policy-less entry. See `docs/CONFIGURATION.md`.

### Performance

- **JWKS warm prefetch on cold start** — `NewBootstrap()` now prefetches every issuer's JWKS during Lambda INIT (self mode only, 3s bounded), so the first request no longer pays an inline OIDC discovery + JWKS fetch. Best-effort: a slow/unreachable issuer is abandoned at the timeout and fetched on demand.

## [2.0.1] - 2026-07-08

### Security

- **Go 1.26.5** — toolchain bump fixing GO-2026-5856 (Encrypted Client Hello privacy leak in `crypto/tls`), reachable via the HTTPS paths the warden uses (JWKS fetch, S3 reads, local server).

### Fixed

- **OpenTofu `api_endpoint` output** — the `$default` stage `invoke_url` ends with a trailing slash, so the output rendered `…amazonaws.com//verify`; HTTP APIs do not normalize double slashes, making the documented smoke-test URL a 404. The slash is now trimmed before appending `/verify`.

### Changed

- **OpenTofu quick-setup guardrails** — a missing `dist/function.zip` now fails `plan` with a clear "run deploy/opentofu/build.sh first" precondition instead of a raw `filebase64sha256` error, and the API Gateway JWT Authorizer (`apigw` mode) now defaults to `var.issuer` / `var.audiences` so the authorizer and the rendered `config.yaml` cannot drift apart (`jwt_authorizer_issuer` / `jwt_authorizer_audiences` remain as explicit overrides).

## [2.0.0] - 2026-07-02

Multi-issuer, any-provider release. v2 validates OIDC tokens from any number of issuers/providers, keys authorization on a provider-neutral canonical **subject**, and scales to thousands of mappings. This is a breaking release — see `docs/MIGRATION_V2.md` for the upgrade path.

### Breaking Changes

- **Multi-issuer config model** — the top-level `issuer` / `audience` / `audiences` keys are **removed**. Trusted issuers are now declared under `issuers[]` (each with `issuer`, `provider`, `audiences`, optional `jwks_uri` / `claim_mappings` / `required_claims` / `session_tags`). The `AOW_ISSUER` / `AOW_AUDIENCE` / `AOW_AUDIENCES` env vars are removed.
- **Provider-neutral authorization renames** — `repo_role_mappings` → `role_mappings` (mapping key `repo:` → `subject:`, `constraints:` → `conditions:`), `repo_role_groups` → `role_groups`. The old keys are no longer accepted.
- **Authorization keys on a canonical `subject`** — derived per issuer (GitHub default = the `repository` claim). Non-`github` providers **must** set `claim_mappings.subject`. A token can never self-assert an unmapped subject.
- **Session tags are per-issuer and spec-driven** — configured via each issuer's `session_tags` (STS tag key ← raw claim name). The default GitHub `repo` tag now carries the **full `owner/repo`** (the raw `repository` claim); v1 stripped the owner to a bare name. Update any ABAC policies that matched a bare repo name. Invalid tag values are **skipped and logged, never sanitized/truncated** (a mangled value must not silently reach an ABAC condition).
- **Delegated modes (`apigw` / `alb`) require exactly one configured issuer** and fail closed otherwise; they re-validate the same claim bounds as `self`.
- **Tag-based authorization is issuer-bound** — set `aow/issuer` on the role; the canonical identity tag is `aow/subject`. `aow/repo` / `aow/repo-owner` remain accepted as aliases through the v2 migration window.
- **Go API** — `types.GithubClaims` → `types.Claims`; `CreateSessionTags` → `BuildSessionTags(rawClaims, tagSpec)`; `MatchRolesToRepoWithConstraints` → `AuthorizeRoles(issuer, subject, claims)`; `FindSessionPolicyForRepo` → `FindSessionPolicy(issuer, subject)`; `AwsConsumer.AssumeRole` gained a `sessionTags` parameter. `MatchRolesToRepo` and the exported `GithubClaims` are removed.
- **S3/JSON config files must use `snake_case` keys** — `PascalCase` keys (`RepoRoleMappings`, `RoleSessionName`, etc.) are no longer accepted. Migrate any S3-hosted JSON configs to `snake_case` before upgrading (#230)
- **`workflow_ref` constraint regex is now auto-anchored** — previously matched as a substring; now compiled as `^(?:...)$` like all other constraints. Patterns relying on partial matching must be updated (#237)

### Added

- **Multi-issuer registry routing** — an incoming token's unverified `iss` is used only to route to that issuer's spec (exact match); identity/role decisions use only post-signature-verified, re-asserted claims. Per-issuer audiences, `claim_mappings`, and `required_claims`.
- **Any-provider support** — `provider: generic` validates tokens from any OIDC IdP by mapping raw claims to the canonical `subject` (GitHub keeps its native claim struct via `provider: github`). Adding a provider needs no core code changes (open/closed `providerAdapter` seam).
- **Generic `conditions`** — gate a mapping on any raw verified claim by name (named fields `branch`/`ref`/`ref_type`/`event_name`/`workflow_ref`/ `environment`/`actor_matches` plus arbitrary `claim: regex` entries).
- **Config scaling** — `default_issuer`, `role_sets` (named ARN lists referenced as `@name`), `role_groups`, and `config_fragments` (additional sources merged onto the base config; local filesystem paths today, remote fetchers pluggable via `config.WithFragmentFetcher` but not yet wired into the shipped binaries; sha256-gated safe reload; optional `config_fragment_checksums` integrity pins). An owner-bucketed authorization index keeps matching fast at thousands of mappings, proven byte-identical to a linear scan.
- **Token hardening knobs** — `jwt_leeway` (≤120s), `max_token_lifetime`, `max_token_age`, `max_token_bytes`, `jwks_refetch_cooldown`, `allow_insecure_issuers`.
- **Structured audit trail** — one JSON record per allow/deny decision via `internal/s3logger`; `audit_required` makes the issuance record durable before credentials are returned (fail-closed); `log_level` and `log_claim_values` knobs; a standardized structured-logging field contract.
- **Cross-account role assumption** — a top-level `cross_account` block (`enabled`, `spoke_role_name`, `external_id`, `spoke_session_duration`, `allowed_accounts`; env prefix `AOW_CROSS_ACCOUNT_*`). The warden assumes member-account target roles **directly** (one hop, its own hub credentials); target roles trust the hub execution role for `sts:AssumeRole` + `sts:TagSession` with **no `sts:ExternalId` condition** (none is sent on the direct assume). `enabled` is a fail-closed **policy gate**: `false` (or the block omitted) hard-denies every cross-account operation. `allowed_accounts` restricts member accounts (empty = any once enabled; hub always allowed). Independent of tag-auth — explicit `role_mappings` can target member-account ARNs. For cross-account **tag-based authorization**, a convention-named spoke role (default `aow-spoke`, permissions policy `iam:GetRole` only) acts solely as a tag-read broker — IAM has no resource-based policies, so a target-account identity is needed for that one read; `external_id` applies only to that hub→spoke hop, and `spoke_session_duration` is capped at 1 h (the spoke hop is itself a chained session). Full worked example (hub config + member-account roles + StackSets template) under `docs/examples/cross-account/` (#236)
- Transitive session tags — `tag_auth.transitive_session_tags` marks the attached session tags transitive so they flow immutably across further role chaining by the target role (#233)
- Short `aow`/`repo` session tags via `tag_auth.default_org` — when a default org is set, the org prefix is stripped from session tag values to stay within the 256-char STS limit (#234)
- EC key support restored (ES256/384/512) — EC tokens were incorrectly rejected in prior versions (#230)
- Hot-reload now propagates to the AWS consumer — `allowed_accounts`, tag-auth enable/disable, spoke role, and external-id changes take effect without a Lambda cold start (#237)
- Validator reads issuer/audiences from the live config on every call — revoked audiences are enforced immediately after an S3 config reload (#230)
- `jwt_validation.mode` config option (`"self"` / `"apigw"` / `"alb"`) to delegate JWT verification to API Gateway HTTP API v2 JWT Authorizer or ALB OIDC.
- `ClaimsExtractorInterface` in `internal/validator/` with `SelfExtractor`, `APIGWExtractor`, and `ALBExtractor` implementations.
- `AwsApiGatewayV2` Lambda adapter (`internal/handler/apigatewayv2.go`) and `cmd/apigatewayv2/` entry point for HTTP API v2 deployments.
- `ParseRoleOnlyRequestBody` for delegated-mode requests (only `role` ARN required in body).
- `AOW_JWT_VALIDATION_MODE` and `AOW_JWT_VALIDATION_ALB_EXPECTED_SIGNER` environment variables.
- In-memory ALB public key cache (5-minute TTL) in `ALBExtractor` to avoid per-request HTTP latency.
- OpenTofu deployment (`deploy/opentofu/`) — modular root wiring reusable `s3`, `dynamodb` (JWKS cache), `iam` (least-privilege Lambda role), `lambda` (zip packaging + log group), and `apigateway` (HTTP API verify route) modules, with config rendered from `terraform.tfvars` (#243)
- CloudFormation quick-start template (`deploy/cloudformation/quickstart.yaml`) and deployment guide (`deploy/README.md`) (#243)

### Security

- **Algorithm/key pinning** — RS/ES 256–512 only (never `none`/HS\*); a JWKS key is pinned by `kid` + `alg` + `use=sig` + key-type↔alg-family, so a duplicate-`kid` JWKS cannot cause wrong-key selection. RSA ≥2048; EC verified on its declared curve.
- **RSA public exponent validated** — `parseRSAKey` now rejects a JWKS `e` that decodes to more than 4 bytes or to a value `< 3` or even, closing a path where an oversized exponent could silently truncate/overflow through `big.Int.Int64()`→`int` and produce an unintended `rsa.PublicKey`.
- **`max_token_lifetime` / `max_token_age` now default to 1h, not "no cap"** — previously an unset (zero) value meant unbounded; `Validate()` now applies a 1h default (same pattern as `max_token_bytes`) so a stolen/leaked long-lived token isn't usable indefinitely by default. Still fully overridable per-deployment; negative values remain rejected.
- **Bounded time and size in `self` AND delegated modes** — `exp`/`iat` required, leeway ≤120s, optional lifetime/age caps, pre-parse token-length cap; a single shared claim-check path guarantees delegated modes are not a weaker path.
- **SSRF-hardened JWKS/discovery fetch** — outbound fetches can never reach private/loopback/link-local/metadata IPs (enforced at dial time, including on redirects); OIDC discovery `issuer` is validated; forced JWKS refetches are rate-limited per `(issuer, kid)`.
- **ALB public-key cache bounded** — the in-process ALB signer-key success cache (`albKeyCache`) now caps at 128 distinct `kid` entries, clearing itself before growing past the cap (mirrors the existing JWKS key-memo overflow pattern), so a flood of distinct/rotating kids can only cost re-fetches, never unbounded memory.
- **`TokenValidatorInterface` narrowed to `Validate` only** — `FetchJWKS` and `GenKeyFunc` remain on the concrete `*TokenValidator` (used by tests and `WarmPrefetch`) but are no longer part of the interface contract, since neither is a standalone, audience-checked validation entry point.
- **Fragments cannot weaken security** — a fragment may only set `role_mappings` / `role_groups` / `role_sets` / `default_issuer`; `issuers`, hardening knobs, `allow_insecure_issuers`, and `tag_auth` are base-only.
- **Reload fails safe** — a failed/invalid/tampered reload retains the last-good config and never reverts to the zero-config seed.
- **Secret-safe logging** — no path logs a raw JWT or credential; with `log_claim_values=false` (default), claim values are suppressed in both the log stream and the audit records while names/decision/reason are retained.
- **`apigw` mode trust boundary documented** — `lambda:InvokeFunction` on this function is equivalent to full identity impersonation in `apigw` mode (no signature check on upstream-injected claims; the bypass guard only rejects empty claims, not forged ones). See `docs/TOKEN_VALIDATION.md` §2.2 and `docs/ARCHITECTURE.md` for the required invoke-policy mitigation.

### Removed

- Top-level `issuer` / `audience` / `audiences` config keys and the `AOW_ISSUER` / `AOW_AUDIENCE` / `AOW_AUDIENCES` env vars (use `issuers[]`).
- `repo_role_mappings` / `repo_role_groups` config keys (use `role_mappings` / `role_groups`).
- Exported `types.GithubClaims`, `CreateSessionTags`, and `MatchRolesToRepo`.

### Fixed

- `config_fragments` are now merged when no S3 config source is configured — previously a file-based deployment (or `cmd/local`) listing local-path fragments got a static provider that silently ignored every fragment. Bootstrap now builds a fragment-merging provider (initial merge at startup, re-resolved per `config_reload_interval` when > 0) whenever fragments are listed; an invalid fragment fails startup instead of silently serving the base config.
- Error responses no longer include the raw internal error string (`errorDetails` removed): JWT-library parse internals, JWKS/discovery/S3 failure detail, and config mismatch text stay in the server-side logs, correlatable via `requestId`. The per-adapter marshal-failure fallback body is a static JSON constant instead of interpolating `err.Error()` unescaped.
- API Gateway delegated mode (`apigw`) now decodes a bracketed multi-value `aud` (`"[aud1 aud2]"`, the JWT Authorizer's stringified array form) into individual audiences before ANY-match, instead of never matching.
- The standardized decision log line no longer emits a duplicate `requestId` JSON key (it comes from the request-scoped logger only; the durable audit record keeps its own `requestId` field).
- Request-body parse failures no longer log a 100-char body preview (a malformed body can contain a partial bearer token); only the parse error and body size are logged.
- Adapter binaries now fail fast at startup when `jwt_validation.mode` is incompatible with the deployed adapter (panic with a clear message) instead of failing silently per request.
- ALB public-key cache no longer has a read/write data race and now evicts expired entries on read, preventing unbounded growth of stale keys.
- ALB and API Gateway delegated modes now enforce token expiration (`exp` required) and reject future-`iat` tokens, matching self-mode strictness.
- RSA JWKS keys shorter than 2048 bits are now rejected, and EC JWKS keys are validated to lie on their declared curve (defense-in-depth against a compromised JWKS source).
- Malformed role ARNs now return the dedicated `ErrInvalidRoleFormat` sentinel (still HTTP 400) instead of being misreported as an empty role.
- Frontend adapters (`alb`, `apigateway`, `lambdaurl`) now share the `classifyError` helper, removing duplicated/dead error-classification switches.
- Invalid `LOG_LEVEL` now logs a well-formed structured warning instead of a malformed printf-style line; full claims log at Debug rather than Info.
- JWT validation failures now return HTTP 401 instead of HTTP 500 (#230)
- S3 config hot-reload no longer triggers N concurrent fetches at the interval boundary — exactly one fetch per interval (#230)
- `AOW_*` env-var overrides are preserved across S3 hot-reloads (#230)
- S3Logger now initialises after the config provider so `log_bucket`/`log_prefix` from remote config are respected (#230)
- Authorization now builds its claim set from the verified raw claims (`claims.Raw`) instead of a JSON round-trip of the typed struct, which dropped non-GitHub claims and wrongly denied legitimate `generic`-issuer / custom-claim requests.
- `transitive_session_tags` now marks **every** operator-configured session tag transitive; a hardcoded `repo`/`ref`/`actor` set previously dropped custom-named tags from `TransitiveTagKeys`, breaking ABAC across assumed roles. `TAG_BASED_AUTHORIZATION.md`, `CONFIGURATION.md`, `ARCHITECTURE.md`, and the `config.go` field comment were corrected to match.
- **deploy: OpenTofu stack rendered a v1 config that v2 rejects at startup.** `main.tf` emitted top-level `issuer`/`audiences` and `repo_role_mappings` (with `repo:`/`constraints:`) — keys removed in 2.0.0 — so the deployed Lambda failed config load with "at least one issuer is required". It now renders the v2 schema: a single GitHub `issuers[]` entry (with `required_claims` and the standard `session_tags` spec) plus `role_mappings` (`subject:`/`conditions:`); the tf variable was renamed `repo_role_mappings` → `role_mappings` accordingly. The unusable `jwt_validation_mode = "alb"` option was removed from the OpenTofu and CloudFormation stacks (it requires the `alb` binary behind an ALB, which neither provisions — the `apigateway` binary refuses to start in `alb` mode), along with the now-orphaned `alb_expected_signer` variable.
- deploy: CloudFormation quickstart set the `AOW_ISSUER`/`AOW_AUDIENCES` env vars removed in 2.0.0; dropped them (and the `Issuer`/`Audiences` parameters) and documented that `ConfigBucket`/`ConfigKey` are effectively required for a working v2 deployment.
- docs: refreshed `TAG_BASED_AUTHORIZATION.md` to the v2 model — `role_mappings`/`conditions` naming, the canonical `aow/subject` identity tag and the multi-issuer `aow/issuer` gate in the tag reference and corner cases, and the session-tag `repo` value (full `owner/repo` since 2.0.0, not the bare name shown in the ABAC examples).
- docs: `SESSION_TAGGING.md` workflow example could never work — it sent `github.token` (not an OIDC ID token) to a nonexistent `/assume-role` endpoint and parsed a `.credentials` response field. Replaced with the `core.getIDToken()` → `POST /verify` → `.data` flow, and updated the CloudTrail/ABAC examples to the full `owner/repo` tag value.
- docs: `ARCHITECTURE.md` drift — corrected the config-precedence order (env > S3 > file > defaults), replaced the fictitious memory→DynamoDB→S3 cache-cascade diagram (backends are alternatives selected by `cache.type`) and invented cache-hit-rate/latency figures, removed the nonexistent "automatic credential rotation" and iat-based cache invalidation claims, updated the stale `RequestProcessor`/`AwsConsumerInterface`/`Cache` interface listings, and marked `alb_expected_signer` as required in `alb` mode.
- docs: added the `MULTI_ISSUER.md` "Delegated modes are single-issuer only" section that `CONFIGURATION.md` linked to (broken anchor) plus a cross-issuer tag-auth section; README now lists all four Lambda variants including the `apigatewayv2-latest` image; root/package `CLAUDE.md` files updated (consumer interface methods, `alb_expected_signer` required, `newClaimsExtractor` signature, Go 1.26, `make check` includes vuln).
- docs: documented the per-mode request contract (`self`/`apigw`/`alb`). The only prior request example showed the self-mode body (`{token, role}`) with no note that it is mode-specific — an `apigw` user would wrongly put the token in the body and omit the `Authorization: Bearer` header API Gateway requires. Added a contract table + `apigw` GitHub Actions example to `README.md`, and a new "§2.1 Request contract per mode" section to `docs/TOKEN_VALIDATION.md`.
- docs: JWKS label in the token-validation sequence diagram used semicolons — mermaid statement separators that broke rendering; switched to commas.
- Audit records buffer into the amortized batch by default; a per-request synchronous S3 `PutObject` fires only when `audit_required=true` (which stays synchronous and fail-closed), not on every decision.
- A required-audit write failure is classified before the wrapped deny sentinel, so it surfaces as `audit_write_failed`/500 instead of being masked as a plain deny.
- An explicit `jwt_leeway: 0` is honored instead of being coerced back to the 30s default.
- `FindSessionPolicy` runs once per allow decision instead of twice.
- CI: `build.yml` image-pull retry loop now fails loudly after the last attempt (previously the failure branch checked `attempt -eq 5` inside a 3-iteration loop and never fired).
- CI: `apigatewayv2` container image is now vulnerability-scanned and listed in the release summary — it was built, signed, and attested but skipped by both.
- **cache: DynamoDB/S3 writes are now synchronous** — persistent-tier writes (and expired-object deletes) ran in fire-and-forget goroutines that Lambda freezes on handler return, silently losing them; every new container then refetched JWKS from the IdP.
- cache: unified the S3 item size limit to 512KB on both read and write — the write path previously accepted up to 1MB while the read path rejected anything over 512KB, so items between the two limits were stored but never readable.
- cache: the memory backend now honors `cache.ttl` and `cache.max_local_size`; both were silently ignored (hardcoded 10m / 100 entries).
- cache: `cache.s3_cleanup` is now functional — it gates deletion of expired objects discovered on read; previously the flag was parsed but never used (deletion was unconditional).
- cache: local-tier race fixes — a `Get` racing a `Set` could resurrect a stale value or delete a freshly stored one; local tiers now do the full lookup-and-update under one lock.
- cache: DynamoDB items with a missing or malformed `Expiration` attribute are treated as expired (fail closed) instead of never expiring.
- cache: local tiers keep the item's real expiration when repopulated from DynamoDB/S3, instead of extending it by the default TTL.
- cache: no spurious LRU eviction when overwriting an existing key at capacity.

### Changed

- **Session durations are clamped to 1 hour whenever the warden's own credentials are a role session** (always true on Lambda, same-account assumes included): AWS role chaining _fails_ a `DurationSeconds` above 3600 on a chained `AssumeRole` rather than clamping it, so the warden clamps first and logs a warning instead of surfacing an STS error. Only `local` server mode running with IAM user credentials can issue sessions beyond 1 hour (single hop, up to the target role's configured max, cross-account targets included).
- CI: consolidated `build.yml` into `release.yml` — a single tag-triggered workflow with one concurrency group and a combined summary. The GoReleaser (archives) and ko (image) jobs stay independent so neither blocks the other. Replaced the duplicated tag-extraction steps with the built-in `github.ref_name`.
- CI: `release.yml` and `make ko-publish` pass `--tags` explicitly per module (`<module>-<tag>` / `<module>-latest`, plus bare `<tag>` / `latest` for the `apigateway` default module) — ko has no config-file tag scheme, so a prior attempt to drive this from a `.ko.yaml` per-build `tags:` key was silently a no-op (every module published only `:latest`, caught by a `v2.0.0-rc.1` dry-run release before the real tag went out).
- CI: lint is now a blocking check (removed `continue-on-error`) and `golangci-lint` is pinned to `v2.12.2`; a shared `.golangci.yml` makes `make lint` and CI use the same linter set.
- CI: added a blocking `govulncheck` job (and a `make vuln` target) for Go-native vulnerability scanning; Trivy/gosec remain advisory.
- CI: added `concurrency` groups to all workflows — PR/branch runs auto-cancel superseded runs; tag-triggered publish/release runs do not.

- Moved `pkg/` to `internal/` — all shared packages are now under `internal/` in line with Go conventions
- `ProcessRequest` signature now accepts `validator.ExtractionInput` to carry per-request extraction data.
- `RequestProcessor` holds `ClaimsExtractorInterface` instead of `TokenValidatorInterface` directly.
- `jwt_leeway` / `max_token_lifetime` / `max_token_age` / `max_token_bytes` are read live from the config provider on every `Validate()` call, so a hot-reloaded change takes effect without a Lambda restart; delegated `apigw`/`alb` extractors likewise resolve the issuer spec, time bounds, and `alb_expected_signer` live on each `Extract()`.
- `normalizeClaims` populates the raw `sub` for every provider, so the audit record's `jwtSub` is present for generic (non-GitHub) issuers too.
- cache internals: removed unused `RefreshClient`/`Cleanup`/`GetStats` methods; AWS clients sit behind `dynamoDBAPI`/`s3API` interfaces for testability; the package now has a test suite.

### Dependencies

- actions/checkout 6.0.3 → 7.0.0
- securego/gosec 2.26.1 → 2.27.1
- codecov/codecov-action 6.0.1 → 7.0.0
- github/codeql-action 4.36.0 → 4.36.2
- docker/login-action 4.1.0 → 4.2.0
- golangci/golangci-lint-action 9.2.0 → 9.2.1
- goreleaser/goreleaser-action 7.2.1 → 7.2.2
- aquasecurity/trivy-action 0.35.0 → 0.36.0
- securego/gosec 2.25.0 → 2.26.1

---

## [1.3.6] - 2026-01-25

### Changed

- Updated dependencies and documentation (#125)

### Dependencies

- actions/setup-go 6.1.0 → 6.2.0
- golangci/golangci-lint-action 9.1.0 → 9.2.0
- github/codeql-action 4.31.4 → 4.31.11
- actions/checkout 6.0.0 → 6.0.1
- codecov/codecov-action 5.5.1 → 5.5.2
- securego/gosec 2.22.10 → 2.22.11

---

## [1.3.5] - 2025-11-30

### Dependencies

- Updated Go dependencies (#109)
- actions/setup-go 6.0.0 → 6.1.0
- golangci/golangci-lint-action 8.0.0 → 9.1.0
- github/codeql-action 4.31.2 → 4.31.4
- actions/checkout 5.0.0 → 6.0.0

---

## [1.3.4] - 2025-11-06

### Dependencies

- Updated Go dependencies (#98)
- github/codeql-action 3.30.5 → 4.31.2
- docker/login-action 3.5.0 → 3.6.0

---

## [1.3.3] - 2025-09-19

### Dependencies

- Updated Go version and dependencies (#71)
- actions/setup-go 5.5.0 → 6.0.0
- aquasecurity/trivy-action 0.32.0 → 0.33.1
- github/codeql-action 3.29.11 → 3.30.3

---

## [1.3.2] - 2025-08-29

### Dependencies

- Bumped golang module (#60)
- github.com/aws/aws-sdk-go-v2/service/sts
- actions/checkout 4.2.2 → 5.0.0
- goreleaser/goreleaser-action 6.3.0 → 6.4.0

---

## [1.3.1] - 2025-08-18

### Fixed

- Replaced deprecated `builds` with `ids` in goreleaser archives (#25)
- Fixed goreleaser configuration issues (#53)

### Dependencies

- Bumped golang modules (#53)
- docker/login-action 3.4.0 → 3.5.0
- aquasecurity/trivy-action 0.31.0 → 0.32.0
- github/codeql-action 3.29.0 → 3.29.8

---

## [1.3.0] - 2025-07-14

### Performance

- Optimized Lambda bootstrap initialization — moved AWS client construction out of the hot path; Lambda cold starts reduced (#24)

### Dependencies

- github/codeql-action 3.28.19 → 3.29.0

---

## [1.2.0] - 2025-06-10

### Added

- Multi-audience support for OIDC token validation — `audience` config field now accepts a list; all values are checked against the token's `aud` claim (#6)
- CodeQL security analysis workflow and badge

### Changed

- Improved example configuration with better security patterns
- Updated GoReleaser archive format to modern syntax

---

## [1.1.0] - 2025-06-07

### Added

- `make build` command and improved CI workflow (#5)

---

## [1.0.0] - 2025-06-07

### Added

- Initial release — modular architecture with Lambda (API Gateway, ALB, Lambda URL) and local HTTP server deployment targets
- OIDC JWT validation with JWKS signature verification
- AWS STS AssumeRole with ABAC session tagging from token claims
- Repository + constraint matching with anchored regex
- Multi-tier JWKS cache (memory / DynamoDB / S3)
- Container image published to GHCR and Docker Hub
- CodeQL, Trivy, and gosec security scanning in CI

[3.0.0]: https://github.com/boogy/aws-oidc-warden/compare/v2.4.1...v3.0.0
[2.4.1]: https://github.com/boogy/aws-oidc-warden/compare/v2.4.0...v2.4.1
[2.4.0]: https://github.com/boogy/aws-oidc-warden/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/boogy/aws-oidc-warden/compare/v2.2.2...v2.3.0
[2.2.2]: https://github.com/boogy/aws-oidc-warden/compare/v2.2.1...v2.2.2
[2.2.1]: https://github.com/boogy/aws-oidc-warden/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/boogy/aws-oidc-warden/compare/v2.1.1...v2.2.0
[2.1.1]: https://github.com/boogy/aws-oidc-warden/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/boogy/aws-oidc-warden/compare/v2.0.1...v2.1.0
[2.0.1]: https://github.com/boogy/aws-oidc-warden/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/boogy/aws-oidc-warden/compare/v1.3.6...v2.0.0
[1.3.6]: https://github.com/boogy/aws-oidc-warden/compare/v1.3.5...v1.3.6
[1.3.5]: https://github.com/boogy/aws-oidc-warden/compare/v1.3.4...v1.3.5
[1.3.4]: https://github.com/boogy/aws-oidc-warden/compare/v1.3.3...v1.3.4
[1.3.3]: https://github.com/boogy/aws-oidc-warden/compare/v1.3.2...v1.3.3
[1.3.2]: https://github.com/boogy/aws-oidc-warden/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/boogy/aws-oidc-warden/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/boogy/aws-oidc-warden/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/boogy/aws-oidc-warden/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/boogy/aws-oidc-warden/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/boogy/aws-oidc-warden/releases/tag/v1.0.0
