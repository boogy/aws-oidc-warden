# Validator — OIDC Token Validation

Extends [../../CLAUDE.md](../../CLAUDE.md). JWT parsing + JWKS verification (`validator.go`).

## Interface

```go
type TokenValidatorInterface interface {
    Validate(string) (*types.GithubClaims, error)
    ParseToken(tokenString string) (*types.GithubClaims, error)
    FetchJWKS(issuer string) (*types.JWKS, error)
    GenKeyFunc(jwks *types.JWKS) jwt.Keyfunc
}
```

Flow: parse header → fetch JWKS (cached) → verify signature → validate issuer/audience/expiration → require `repository` claim.

## Security

- Allowed algorithms only: ES256/384/512, RS256/384/512. Never `none`.
- Verify in order: signature, issuer, audience (any expected match — multi-audience), expiration (required), required claims.
- JWKS fetched from `<issuer>/.well-known/openid-configuration`; HTTP client has a short timeout. Cached per issuer with `config.Cache.TTL`.

## Gotchas

- `audience` (string, deprecated) and `audiences` ([]string) both supported; validation accepts any matching audience.
- The JWT library validates only the first audience; full multi-audience check is in `Validate()`.
- Token `kid` must match a JWKS key.

Tests: `validator_test.go`, `multi_audience_test.go`, `integration_test.go` (mock JWKS server + generated JWTs).

## Extractors

`ClaimsExtractorInterface` abstracts how GitHub OIDC claims enter the pipeline:

```go
type ClaimsExtractorInterface interface {
    Extract(ctx context.Context, input ExtractionInput) (*types.GithubClaims, error)
}
```

Populate only the `ExtractionInput` fields relevant to the configured mode:

| Field              | Used by        |
| ------------------ | -------------- |
| `Token`            | SelfExtractor  |
| `AuthorizerClaims` | APIGWExtractor |
| `ALBOIDCData`      | ALBExtractor   |
| `AWSRegion`        | ALBExtractor   |

**Implementations:**

- `SelfExtractor` — default; wraps `TokenValidatorInterface.Validate()`. Full JWKS signature + claims verification.
- `APIGWExtractor` — reads pre-validated `map[string]string` claims from API Gateway HTTP API v2 JWT Authorizer. Rejects if `AuthorizerClaims` is nil (bypass guard). No signature verification.
- `ALBExtractor` — fetches ALB EC public key via HTTPS, verifies ES256 JWT from `x-amzn-oidc-data`. Validates optional `ALBExpectedSigner` ARN. Use `WithALBKeyEndpoint` to override in tests. Caches keys for 5 minutes to avoid per-request latency.

The factory `newClaimsExtractor(mode, albExpectedSigner, validator)` in `bootstrap.go` selects the implementation from `cfg.JWTValidation.Mode`.
