# Validator Package - OIDC Token Validation

**Technology**: Go, JWT-go v5, RSA cryptography
**Entry Point**: `validator.go`
**Parent Context**: This extends [../../CLAUDE.md](../../CLAUDE.md)

---

## Development Commands

### From Package Directory

```bash
go test ./...              # Run validator tests
go test -v ./...           # Verbose output
go test -run Integration   # Run integration tests only
```

### From Root

```bash
go test -v ./pkg/validator/  # Test this package
```

---

## Architecture

### Directory Structure

```
pkg/validator/
├── validator.go           # Core validation logic
├── validator_test.go      # Unit tests
├── multi_audience_test.go # Multi-audience validation tests
└── integration_test.go    # Integration tests with mock JWKS
```

### Validation Flow

```
JWT Token → Parse Header → Fetch JWKS (cached) → Verify Signature → Validate Claims → Extract GitHub Claims
```

---

## Code Organization Patterns

### Interface Definition

The validator implements `TokenValidatorInterface` for testability:

```go
// ✅ DO: Use the interface for dependency injection
type TokenValidatorInterface interface {
    Validate(string) (*types.GithubClaims, error)
    ParseToken(tokenString string) (*types.GithubClaims, error)
    FetchJWKS(issuer string) (*types.JWKS, error)
    GenKeyFunc(jwks *types.JWKS) jwt.Keyfunc
}

// Create with NewTokenValidator
validator := NewTokenValidator(cfg, cache)
```

### Validation Pattern

Full validation flow in `Validate()`:

```go
// ✅ DO: Follow the complete validation pipeline
func (t *TokenValidator) Validate(token string) (*types.GithubClaims, error) {
    // 1. Parse and verify signature
    claims, err := t.ParseToken(token)
    if err != nil {
        return nil, fmt.Errorf("%w", err)
    }

    // 2. Validate issuer
    if claims.Issuer != t.ExpectedIssuer {
        return nil, fmt.Errorf("issuer %s expected", t.ExpectedIssuer)
    }

    // 3. Validate audience (multi-audience support)
    var validAudience bool
    for _, tokenAudience := range claims.Audience {
        for _, expectedAudience := range t.ExpectedAudiences {
            if tokenAudience == expectedAudience {
                validAudience = true
                break
            }
        }
    }

    if !validAudience {
        return nil, fmt.Errorf("audience must be one of %v", t.ExpectedAudiences)
    }

    // 4. Validate required claims
    if claims.Repository == "" {
        return nil, errors.New("repository is required")
    }

    return claims, nil
}
```

### JWKS Caching Pattern

JWKS is cached to avoid rate limiting and improve performance:

```go
// ✅ DO: Check cache before fetching
func (t *TokenValidator) FetchJWKS(issuer string) (*types.JWKS, error) {
    // Check cache first
    if cachedJWKS, found := t.Cache.Get(issuer); found {
        if cachedJWKS != nil {
            return cachedJWKS, nil
        }
    }

    // Fetch from OIDC provider
    client := &http.Client{Timeout: 5 * time.Second}
    resp, err := client.Get(issuer + "/.well-known/openid-configuration")
    // ... fetch and parse JWKS

    // Cache with TTL
    t.Cache.Set(issuer, &jwks, time.Duration(t.Cfg.Cache.TTL))

    return &jwks, nil
}
```

### JWT Parser Configuration

Strict validation options:

```go
// ✅ DO: Use strict JWT parser options
parser := jwt.NewParser(
    jwt.WithAudience(audienceForParser),
    jwt.WithIssuer(t.ExpectedIssuer),
    jwt.WithIssuedAt(),
    jwt.WithExpirationRequired(),
    jwt.WithValidMethods([]string{
        jwt.SigningMethodES256.Name,
        jwt.SigningMethodES384.Name,
        jwt.SigningMethodES512.Name,
        jwt.SigningMethodRS256.Name,
        jwt.SigningMethodRS384.Name,
        jwt.SigningMethodRS512.Name,
    }),
)
```

---

## Key Files

### Core Files

- `validator.go` - Complete validation implementation
  - `NewTokenValidator()` - Constructor
  - `Validate()` - Full validation pipeline
  - `ParseToken()` - JWT parsing with signature verification
  - `FetchJWKS()` - JWKS retrieval with caching
  - `GenKeyFunc()` - RSA key generation from JWKS

### Test Files

- `validator_test.go` - Unit tests for validation logic
- `multi_audience_test.go` - Multi-audience validation tests
- `integration_test.go` - End-to-end tests with mock JWKS servers

---

## Quick Search Commands

### Find Validation Logic

```bash
# Find validation entry point
rg -n "func.*Validate\(" pkg/validator/

# Find JWKS handling
rg -n "FetchJWKS\|JWKS" pkg/validator/

# Find JWT parser options
rg -n "jwt.NewParser\|WithAudience\|WithIssuer" pkg/validator/
```

### Find Claims Handling

```bash
# Find claims structure
rg -n "type.*Claims.*struct" pkg/types/

# Find claims extraction
rg -n "claims\.\w+" pkg/validator/
```

---

## Security Considerations

### Token Validation Security

```go
// ✅ DO: Always verify these in order
// 1. Signature (done in ParseToken via GenKeyFunc)
// 2. Issuer match
// 3. Audience match (any of expected audiences)
// 4. Expiration (jwt.WithExpirationRequired)
// 5. Required claims (repository)
```

### Allowed Signing Methods

Only allow known secure algorithms:

```go
// ✅ DO: Restrict to known algorithms
jwt.WithValidMethods([]string{
    "ES256", "ES384", "ES512",  // ECDSA
    "RS256", "RS384", "RS512",  // RSA
})
// ❌ DON'T: Allow "none" or weak algorithms
```

### JWKS Fetching Security

```go
// ✅ DO: Use timeout for HTTP requests
client := &http.Client{Timeout: 5 * time.Second}

// ✅ DO: Verify OIDC configuration endpoint
resp, err := client.Get(issuer + "/.well-known/openid-configuration")
if resp.StatusCode != http.StatusOK {
    return nil, fmt.Errorf("non-200 status: %d", resp.StatusCode)
}
```

---

## Multi-Audience Support

The validator supports multiple audiences for backward compatibility:

```go
// Configuration supports both:
// Legacy: single audience
audience: "sts.amazonaws.com"

// New: multiple audiences
audiences:
  - "sts.amazonaws.com"
  - "https://api.company.com"

// Validation accepts ANY matching audience
for _, tokenAudience := range claims.Audience {
    for _, expectedAudience := range t.ExpectedAudiences {
        if tokenAudience == expectedAudience {
            validAudience = true
            break
        }
    }
}
```

---

## Common Gotchas

- **JWKS URI**: Fetched from `.well-known/openid-configuration`, not hardcoded
- **Key ID (kid)**: Must match between token header and JWKS keys
- **Cache TTL**: Configured in `config.Cache.TTL`, typically 1-4 hours
- **Audience Validation**: JWT library only validates first audience; full validation in `Validate()`
- **HTTP Timeout**: 5 seconds for JWKS fetching to prevent hanging

---

## Testing Guidelines

### Unit Tests

```go
// Test token validation with mock JWKS
func TestValidate_ValidToken(t *testing.T) {
    // Create mock cache with pre-loaded JWKS
    mockCache := &MockCache{...}
    validator := NewTokenValidator(cfg, mockCache)

    claims, err := validator.Validate(validToken)

    assert.NoError(t, err)
    assert.Equal(t, "myorg/myrepo", claims.Repository)
}
```

### Integration Tests

```go
// Test with real JWKS server (mock)
func TestIntegration_ValidateWithMockJWKS(t *testing.T) {
    // Start mock JWKS server
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path == "/.well-known/openid-configuration" {
            json.NewEncoder(w).Encode(map[string]string{"jwks_uri": server.URL + "/jwks"})
        } else if r.URL.Path == "/jwks" {
            json.NewEncoder(w).Encode(testJWKS)
        }
    }))

    // Generate test JWT signed with test key
    token := generateTestJWT(testPrivateKey, claims)

    // Validate
    validator := NewTokenValidator(cfg, cache)
    result, err := validator.Validate(token)

    assert.NoError(t, err)
}
```
