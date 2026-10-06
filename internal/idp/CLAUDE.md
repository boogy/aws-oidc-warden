Extends ../../CLAUDE.md

# internal/idp

Warden-as-IdP: signs short-lived OIDC tokens that STS AssumeRoleWithWebIdentity trusts.

## Files

- `signer*.go` — `Signer` interface; PEM (dev) and KMS (production) signers.
- `jwk.go` — JWK encoding and RFC 7638 thumbprint.
- `keyset.go` — immutable `KeySet`, JWKS and discovery documents.
- `minter*.go` — self-verifying token mint; subject template rendering.
- `service.go` — frozen config, singleflight lazy key load, `Warm`.

## Invariants

- kid is the RFC 7638 thumbprint.
- Self-verify every token before returning it.
- Never log `Token.Value` or key material.
- Only RS256 and ES256.
- The loader fails if any key fails.
- MRK keys sign via the local replica; primary and every replica must be in `kms_allowed_regions`.
- `KeySet` is immutable after build.
- After a successful `Warm`, no request path calls the loader.
