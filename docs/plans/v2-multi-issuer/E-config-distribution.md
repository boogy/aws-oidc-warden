# Group E — Config distribution: fragment merge & cheap reload

Prereqs: A, D. Files: new `internal/config/fragments.go`, `internal/config/provider.go`.
**Read `SHARED.md` first** — invariants 9, 12.

## Tasks

- **E1** `config_fragments` (base-only key): list of S3 URIs / paths. Loader fetches and merges each fragment's `role_mappings` / `role_groups` / `role_sets` / `default_issuer` into the combined set, then builds the index (Group D). Bounded reads (`io.LimitReader`); soft cap + `log()` on fragment/mapping counts (S6).
- **E2** Reload: per-fragment ETag (or manifest). Re-fetch only **changed** fragments, rebuild the immutable snapshot, atomic-swap (no torn reads). Unchanged ⇒ skip entirely. Reload failure/invalid → **retain last-good** (never empty/partial, never seed fallback — invariant #12).
- **E3** Enforce the fragment allowlist at merge: `{role_mappings, role_groups, role_sets, default_issuer}` only. Reject `issuers`, hardening knobs, `allow_insecure_issuers`, `tag_auth` in a fragment. `default_issuer` in a fragment must reference a **base-defined** issuer (S5).
- **S9 (optional integrity):** wire the checksum/ETag integrity hook from Group A — verify before applying a fetched fragment/config; mismatch → reject, keep last-good.

## Security review E

fragment cannot inject issuers/knobs/`tag_auth`/`allow_insecure_issuers`; `default_issuer` must reference a base issuer; reload race/atomicity (`-race` during a fragment swap); merge precedence deterministic; S3 fetch bounded; failed reload retains last-good.

## Verification slice

- Base + N fragments merge deterministically (golden); a fragment with `issuers`/`tag_auth`/knobs → rejected; `default_issuer` referencing an unknown issuer → rejected.
- Changed-only fragment triggers reload; unchanged skips; failed reload keeps serving last-good config.
- `-race` reload test. `make check` + `go test -race ./internal/config/...` green.

## Commit

`feat(config): fragment merge + ETag-gated safe reload` → update `PROGRESS.md`.
