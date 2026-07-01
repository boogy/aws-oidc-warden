# Group G — Delegated modes (apigw / alb)

Prereqs: B, F. Files: `internal/validator/apigw_extractor.go`, `alb_extractor.go`, `bootstrap.go` (`newClaimsExtractor`).
**Read `SHARED.md` first** — invariant 6 (delegated paths are not weaker).

## Tasks

- **G1** `apigw`/`alb` extractors adopt the single configured issuer's spec + `claim_mappings`/`required_claims`/`session_tags` normalization (canonical `subject`, raw claims for conditions/tags). Re-validate issuer/audience/`exp` **and** apply `nbf`/`sub`-required, leeway, `max_token_age`/`max_token_lifetime` against the claims they receive. `apigw` trusts upstream signature; `alb` verifies the ALB signature (keep `ALBExpectedSigner` pinning). Multi-issuer is `self`-only; apigw/alb stay single-issuer.
- **G2 (cleanup)** Make `mapAPIGWClaims` a package-level func `mapAPIGWClaims(issuer string, audiences []string, raw map[string]string) (*types.Claims, error)`. `APIGWExtractor.Extract` and `ALBExtractor.mapALBClaims` (alb_extractor.go:~250) both call it directly — remove the per-ALB-request `&APIGWExtractor{...}` allocation. Re-validation semantics identical for both callers.

## Security review G

upstream-trust re-validation (issuer/aud/exp + time bounds); ALB signer pinning intact; mapped-claim parity with `self` mode; package-level `mapAPIGWClaims` preserves issuer/audience re-validation for **both** callers (no path now skips it).

## Verification slice

- apigw/alb: wrong issuer/audience → reject; expired/over-max-age → reject; ALB signer mismatch → reject.
- Parity: same token via `self` vs delegated → same canonical subject + tags.
- `make check` + `go test -race ./internal/validator/...` green.

## Commit

`feat(validator): delegated modes adopt normalization + time bounds; dedup mapping` → update `PROGRESS.md`.
