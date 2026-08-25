# Validator — OIDC Token Validation

Extends [../../CLAUDE.md](../../CLAUDE.md). Multi-issuer JWT parsing + JWKS verification (`validator.go`).

## Interface

```go
type TokenValidatorInterface interface {
    Validate(string) (*types.Claims, error)
}
```

Deliberately scoped to `Validate` only. `FetchJWKS`/`GenKeyFunc` remain exported on the concrete `*TokenValidator` (used by tests and `WarmPrefetch`) but are not part of the interface — they're an unscoped, audience-less path, not a standalone validation entry point.

`NewTokenValidator(provider *config.Provider, jwksCache cache.Cache) *TokenValidator` builds the shared `http.Client` and the initial issuer registry once, at construction — call it once during bootstrap, never per request.

## Multi-issuer registry

Each configured `config.IssuerConfig` is projected into an immutable `issuerSpec` (issuer, provider, JWKS URI override, audiences, claim mappings, required claims); the full set is keyed by exact issuer string into a `snapshot`. `TokenValidator` holds the current snapshot behind `atomic.Pointer[snapshot]`, plus a `builtFrom atomic.Pointer[config.Config]` cheap-identity check — a hot config reload (new/removed issuer, audience, mapping) is picked up on the next `Validate()` call via a lock-free rebuild-on-pointer-change, no restart required. `leeway`/`maxLifetime`/`maxAge`/`maxTokenBytes` are read live from the provider on every `Validate()` call, so a hot-reloaded change to `jwt_leeway`/`max_token_lifetime`/`max_token_age`/`max_token_bytes` takes effect without a restart. (`allowInsecureIssuers` is the exception — it configures the shared HTTP client built once at construction, so changing it still requires a restart.)

## Flow (`Validate()`)

0. Length guard (`max_token_bytes`) before any parsing.
1. Unverified `iss` peek — routing only, never used for identity/authorization.
2. Registry lookup by exact issuer match. Unknown issuer denies **before any JWKS fetch is attempted**.
3. Per-call parser scoped to the matched issuer (algorithm allowlist, `WithExpirationRequired`, `WithIssuedAt`, `WithLeeway`).
4. Fetch JWKS (cached per issuer); verify signature. A `kid` miss (`ErrKeyNotFound`) triggers one cache-bypassing refetch (key-rotation recovery), then fails. 4b. Re-assert the verified issuer matches the spec used, guarding a hot-reload race between steps 2 and 4.
5. Audience ANY-match against the issuer's configured audiences (`audienceMatches`).
6. `required_claims` present and non-empty on the verified raw claims.
7. `normalizeClaims` — see below.

The hardening steps — key-pinning refinement (`kid` + `alg` + `use=sig` + key-type↔alg-family), `sub`/`nbf` enforcement, the optional lifetime/age caps, and per-`(issuer, kid)` refetch rate limiting — are not entries of their own in the list above. They layer onto the baseline the per-call parser and `GenKeyFunc` already provide, inside steps 3-7.

## `normalizeClaims` and the `providerAdapter` seam

`normalizeClaims(raw, provider, mappings)` converts verified raw claims into canonical `types.Claims`: populates the standard registered claims for every provider (`populateRegisteredClaims`), then dispatches to a `providerAdapter` (`providerAdapters["github"|"generic"]`) for provider-specific struct population, and **always** sets `claims.Subject` from `adapter.subject(raw, mappings)` — never from raw JSON directly (the no-self-asserted-canonical-identity invariant: the authorization subject comes from config, never from a field the token chose for itself).

```go
type providerAdapter interface {
    subject(raw jwt.MapClaims, mappings map[string]string) (string, error)
    populate(raw jwt.MapClaims, claims *types.Claims) error // must never set claims.Subject
}
```

- `githubAdapter` — native unmarshal of the full GitHub claim set; subject defaults to `repository`, overridable via `claim_mappings.subject`.
- `genericAdapter` — no native struct; subject _must_ come from `claim_mappings.subject` (also enforced at `config.Validate()`, re-checked here as defense in depth).

Adding a new OIDC provider = implement `providerAdapter` and register it in `providerAdapters`; no `Validate()`/`normalizeClaims` edits required (open/closed).

`types.Claims.Subject` is the field authz/session-tag code must read as the canonical identity. `types.Claims.Raw` (JSON-excluded) carries every verified raw claim, for generic-provider condition/session-tag mapping and `required_claims` checks against provider-native claim names with no struct field.

## Security

- Allowed algorithms only: ES256/384/512, RS256/384/512. Never `none`.
- Verify in order: signature, issuer (registry lookup + re-assert), audience (ANY-match against the matched issuer only — no cross-issuer leakage), expiration, required claims.
- JWKS fetched from `<issuer>/.well-known/openid-configuration` (or the issuer's `jwks_uri` override, skipping discovery); JWKS responses and discovery documents are bound-read (`io.LimitReader`, 1 MB) and capped at 20 keys. Cached per issuer with `config.Cache.TTL`.
- An issuer's audience set is isolated from every other issuer's — a token's `aud` is only ever checked against the spec resolved by its own verified `iss`.

## Gotchas

- `kid` must match a JWKS key; a miss forces one cache-bypassing refetch, not an automatic retry loop.
- `ParseToken` and the old single-issuer `Unmarshal` method were dropped — nothing in the pipeline called them; use `Validate()`.

Tests: `validator_test.go` (core `Validate()` cases, unknown-issuer denial, per-issuer audience isolation, required claims), `jwks_test.go` (key rotation, refetch limiter under flood, audience ANY-match, end-to-end mock JWKS server), `hardening_test.go` (`GenKeyFunc` alg confusion RS/ES, `use:enc` rejection, duplicate-kid selection, discovery issuer mismatch), `delegated_test.go` (self-vs-delegated parity single and multi-issuer, cross-issuer key confusion, `alg:none`, time bounds, and proof an unconfigured `iss` triggers zero network fetches), `extractor_test.go` (the three `ClaimsExtractorInterface` implementations), `internal_test.go` (SSRF guards: blocked IPs, secure-URL and redirect policy, refetch limiter), `alg_allowlist_test.go` (algorithms outside the allowlist).

## Extractors

`ClaimsExtractorInterface` abstracts how claims enter the pipeline:

```go
type ClaimsExtractorInterface interface {
    Extract(ctx context.Context, input ExtractionInput) (*types.Claims, error)
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

- `SelfExtractor` — default; wraps `TokenValidatorInterface.Validate()`. Full JWKS signature + claims verification, multi-issuer aware.
- `APIGWExtractor` — reads pre-validated `map[string]string` claims from API Gateway HTTP API v2 JWT Authorizer. Rejects if `AuthorizerClaims` is nil (bypass guard). No signature verification. Resolves the matching issuer spec per request by exact match against the authorizer-verified `iss` claim (`resolveIssuerSpec`); an issuer with no config entry fails closed with `ErrUnknownIssuer` rather than falling back to another issuer's spec.
- `ALBExtractor` — fetches ALB EC public key via HTTPS, verifies ES256 JWT from `x-amzn-oidc-data`. Validates the `ALBExpectedSigner` ARN (required in `alb` mode by `config.Validate()`). Use `WithALBKeyEndpoint` to override in tests. Caches keys for 5 minutes to avoid per-request latency.

The factory `newClaimsExtractor(provider, validator)` in `bootstrap.go` selects the implementation from `cfg.JWTValidation.Mode`. Only `alb` mode additionally requires exactly one configured issuer at cold start (`singleDelegatedIssuer`) — an ALB has exactly one OIDC IdP, so a multi-issuer config is genuinely ambiguous there. `apigw` mode has no such restriction: each route's JWT Authorizer pins its own issuer, so `APIGWExtractor` resolves the spec per request instead of at cold start.
