# Group A — Config model & schema (foundation)

Prereqs: none (unblocks everything). Files: `internal/config/config.go` (+ `CLAUDE.md`).
**Read `SHARED.md` first.**

## Goal

Replace single-issuer config with the `issuers[]` list + hardening knobs, with strict fail-closed validation. No legacy `issuer`/`audiences`.

## New `IssuerConfig`

```go
type IssuerConfig struct {
    Issuer         string            `mapstructure:"issuer"`
    Provider       string            `mapstructure:"provider"`        // "github" => native unmarshal; default "generic" = mapped-only
    Audiences      []string          `mapstructure:"audiences"`
    JWKSURI        string            `mapstructure:"jwks_uri"`        // optional; skips discovery
    ClaimMappings  map[string]string `mapstructure:"claim_mappings"`  // canonicalField <- providerClaim (must include `subject` for non-github)
    RequiredClaims []string          `mapstructure:"required_claims"`
    SessionTags    map[string]string `mapstructure:"session_tags"`    // tagKey -> claimName
}
```

## Tasks

- **A1** Add `Issuers []IssuerConfig` (`mapstructure:"issuers"`). Remove `Issuer`, `Audience`, `Audiences` fields. Update `reapplyEnvOverrides` (config.go:~270) to drop `AOW_ISSUER`/`AOW_AUDIENCE(S)`.
- **A2** `Validate()` (replace the issuer/audience block at config.go:~427-444) — per entry: non-empty `issuer`, ≥1 audience; reject duplicate issuer URLs; exact-match policy (no trailing-slash normalization); validate `session_tags` keys against STS tag-key charset/length (`[A-Za-z0-9 _.:/=+@-]`, ≤128).
- **A3** Zero-config GitHub default seed **only when no config source is found** (sets `provider: github`, issuer `https://token.actions.githubusercontent.com`, audiences `[sts.amazonaws.com]`, `required_claims:[repository]`, default GitHub `session_tags`). If a config source IS present but `issuers:` empty/unparsable → **hard error** (never silently trust GitHub).
- **A4** Hardening knobs (top-level): `jwt_leeway` (default 30s, **reject >120s**), `max_token_lifetime`, `max_token_age`, `max_token_bytes` (default 8 KB), `jwks_refetch_cooldown` (default **60s**), `allow_insecure_issuers` (default false). Bind via `BindEnv` + handle in `reapplyEnvOverrides`.
- **A5** Validation guards:
  - **S1** reject `claim_mappings` targeting reserved claims `iss/aud/exp/nbf/iat/sub`.
  - **V10** `provider` ∈ {`github`,`generic`}; non-`github` issuers must define a subject source (`claim_mappings.subject`), else error.
  - **S9** refuse start on invalid config (fail fast/loud); leave a hook for optional checksum/ETag integrity (full impl in E); reload retains last-good (the `Provider` already atomic-swaps from pristine base — ensure a failed `Validate` does NOT swap).

## Security review A (gate)

config-injection; env-override precedence (env > S3 > file); default-seed cannot silently trust GitHub; leeway bound enforced; reserved-claim mapping rejected; provider/subject validation; fail-safe reload (bad config never swapped in).

## Verification slice

- Table tests: valid multi-issuer config; duplicate issuer → error; missing audience → error; `claim_mappings: {sub: ...}` → error; `provider: gitlab`-without-`claim_mappings.subject` → error; `jwt_leeway: 200s` → error; config-present-but-empty-issuers → error; truly-no-config → GitHub seed with `provider: github`.
- `make check` + `go test -race ./internal/config/...` green.

## Commit

`feat(config): v2 issuers[] model, hardening knobs, fail-closed validation` → update `PROGRESS.md`.
