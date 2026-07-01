# Group B — Validator multi-issuer core

Prereqs: A. Files: `internal/validator/validator.go`, claims normalization, `CLAUDE.md`.
**Read `SHARED.md` first** — especially the final `Validate` flow and the concurrency/cold-start standards.

## Goal

Single `Validate(token)` that routes by issuer via an immutable registry snapshot, fully verifies, and normalizes to a canonical `subject` + raw claims map. (Crypto/time hardening details are Group C; here build the structure + the non-hardening flow.)

## Structures

```go
type issuerSpec struct {
    Issuer, Provider, JWKSURI string
    Audiences      []string
    ClaimMappings  map[string]string
    RequiredClaims []string
}
type snapshot struct { registry map[string]*issuerSpec } // immutable
type TokenValidator struct {
    snap     atomic.Pointer[snapshot]
    cache    cache.Cache
    provider *config.Provider
    httpc    *http.Client          // built once at init (Group C hardens it)
    leeway, maxLifetime, maxAge time.Duration
    maxTokenBytes int
    // refetch limiter added in Group C
}
```

## Tasks

- **B1** Build `snapshot.registry` from `provider.Get().Issuers`; publish via `atomic.Pointer`. Rebuild + swap when the provider's config pointer changes (cheap identity check) — readers load the pointer once per call. Built **once at init** (cold-start); optional non-fatal JWKS warm-prefetch.
- **B2** `Validate` flow steps **0–4b** (length guard → unverified `iss` peek → registry lookup → per-call parser → signature verify → re-assert verified `iss`). Steps 5/6/7 (hardening) are stubbed/added in Group C — structure the code so C slots in cleanly.
- **B3** Per-issuer audience ANY-match against `spec.Audiences` (handle `aud` string|array via `jwt.ClaimStrings`; empty/missing → deny). `required_claims` checked on **raw verified claims** (replaces the hard-coded `repository` requirement).
- **B4** `normalizeClaims(raw, provider, mappings) (*types.Claims, error)`: derive canonical `subject` (github default `repository`; others from `claim_mappings.subject`); native struct unmarshal **only** for `provider: github`; everything else mapped-subject-only — **no blanket unmarshal** (invariant #4). Raw-claim access for authz uses the **verified** claims, not the unverified peek. Fail closed on any error/missing required claim/type mismatch.
- Rename `types.GithubClaims` → `types.Claims` (add `Subject` field); update references. Provide a `ProviderAdapter` seam (github + generic) so providers are open/closed.

## Security review B (ADVERSARIAL)

unverified-`iss` spoof (routing only; decisions on verified claims); cross-issuer routing; self-asserted canonical identity (non-github token with rogue `repository` claim cannot set subject); audience string-vs-array confusion; every error path fails closed; registry atomic-swap has no race/torn read (run `-race` with concurrent Validate during a swap).

## Verification slice

- Two-issuer table tests: A-token rejected for B's audience, accepted for A's; unknown issuer → deny + JWKS never fetched; gitlab token via `claim_mappings.subject: project_path` → subject set, rogue `repository` claim ignored; missing `required_claims` → deny.
- `-race` test: N goroutines `Validate` across a hot-swap — no race, no stale read.
- `make check` + `go test -race ./internal/validator/...` green.

## Commit

`feat(validator): multi-issuer registry routing + canonical subject normalization` → update `PROGRESS.md`.
