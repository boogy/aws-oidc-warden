# Validator

Extends [../../CLAUDE.md](../../CLAUDE.md). Multi-issuer JWT verification and the claims extractors.

This file is a map plus the rules code cannot state. Read `Validate()` in `validator.go` before changing verification; operator semantics are in `docs/TOKEN_VALIDATION.md` and `docs/MULTI_ISSUER.md`.

## Where things are

- `validator.go` — `TokenValidator.Validate`, issuer registry snapshot, `normalizeClaims`, `providerAdapter` (`github`, `generic`).
- `jwks_fetch.go`, `jwks_state.go`, `refetch_limiter.go`, `keymemo.go` — JWKS fetch, cache, rotation refetch.
- `ssrf.go` — outbound dial guard.
- `extractor.go`, `self_extractor.go`, `apigw_extractor.go`, `alb_extractor.go`, `delegated_claims.go` — `ClaimsExtractorInterface` per `jwt_validation.mode`.

## Rules

- The unverified `iss` routes only; an unknown issuer denies before any network fetch, and the verified issuer is re-asserted after the signature.
- Algorithms: ES256/384/512, RS256/384/512. Never `none`; key type, curve and `use` must match the algorithm.
- Audience is ANY-match against the matched issuer's set only.
- `claims.Subject` comes from the adapter and config (`claim_mappings.subject`), never straight from the token. Authorization reads `Subject` and `Raw`.
- A new provider is a new `providerAdapter`; do not branch in `Validate()`.
- Extractors use `ExtractionInput.Config`; they never call `provider.Get()`.
- Delegated extractors fail closed on missing claims or an unconfigured issuer; `alb` mode requires `ALBExpectedSigner` and one issuer.
- Remote documents are bound-read (`io.LimitReader`); a `kid` miss allows one rate-limited refetch, not a loop.
- Build the validator once at bootstrap.
