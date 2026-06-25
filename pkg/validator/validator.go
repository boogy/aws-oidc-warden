package validator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"time"

	"github.com/boogy/aws-oidc-warden/pkg/cache"
	"github.com/boogy/aws-oidc-warden/pkg/config"
	"github.com/boogy/aws-oidc-warden/pkg/types"
	"github.com/golang-jwt/jwt/v5"
)

// ErrKeyNotFound is returned by the key function when no JWKS key matches the
// token's "kid". It is a sentinel so callers can detect a key miss (e.g. after
// signing-key rotation) and force a cache-bypassing JWKS refetch.
var ErrKeyNotFound = errors.New("key not found")

type TokenValidatorInterface interface {
	Validate(string) (*types.GithubClaims, error)
	ParseToken(tokenString string) (*types.GithubClaims, error)
	FetchJWKS(issuer string) (*types.JWKS, error)
	GenKeyFunc(jwks *types.JWKS) jwt.Keyfunc
}

type TokenValidator struct {
	Token             string
	ExpectedIssuer    string
	ExpectedAudience  string   // Deprecated: use ExpectedAudiences instead (kept for backward compatibility)
	ExpectedAudiences []string // List of expected audiences
	Cache             cache.Cache
	Cfg               *config.Config
}

func NewTokenValidator(cfg *config.Config, cache cache.Cache) *TokenValidator {
	return &TokenValidator{
		ExpectedIssuer:    cfg.Issuer,
		ExpectedAudience:  cfg.Audience,  // Keep for backward compatibility
		ExpectedAudiences: cfg.Audiences, // Use multiple audiences
		Cache:             cache,
		Cfg:               cfg,
	}
}

func (t *TokenValidator) Validate(token string) (*types.GithubClaims, error) {
	claims, err := t.ParseToken(token)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	if claims.Issuer != t.ExpectedIssuer {
		return nil, fmt.Errorf("issuer %s expected", t.ExpectedIssuer)
	}

	// Check if any of the token's audiences match any of the expected audiences
	var validAudience bool
	for _, tokenAudience := range claims.Audience {
		for _, expectedAudience := range t.ExpectedAudiences {
			if tokenAudience == expectedAudience {
				validAudience = true
				break
			}
		}
		if validAudience {
			break
		}
	}

	if !validAudience {
		return nil, fmt.Errorf("audience must be one of %v, got %v", t.ExpectedAudiences, claims.Audience)
	}

	if claims.Repository == "" {
		return nil, errors.New("repository is required")
	}

	return claims, nil
}

func (t *TokenValidator) Unmarshal(data []byte) (*types.GithubClaims, error) {
	var claims types.GithubClaims
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil, err
	}

	return &claims, nil
}

func (t *TokenValidator) ParseToken(tokenString string) (*types.GithubClaims, error) {
	jwks, err := t.FetchJWKS(t.ExpectedIssuer)
	if err != nil {
		return nil, err
	}

	if jwks == nil || len(jwks.Keys) == 0 {
		return nil, errors.New("jwks is nil")
	}

	// Create token parser with strict validation.
	//
	// Audience is intentionally NOT enforced here: jwt/v5's WithAudience only
	// matches a single expected value, which silently breaks multi-audience
	// support. The full multi-audience check is done in Validate().
	parser := jwt.NewParser(
		jwt.WithIssuer(t.ExpectedIssuer),
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(),
		jwt.WithValidMethods([]string{
			jwt.SigningMethodRS256.Name,
			jwt.SigningMethodRS384.Name,
			jwt.SigningMethodRS512.Name,
			jwt.SigningMethodES256.Name,
			jwt.SigningMethodES384.Name,
			jwt.SigningMethodES512.Name,
		}),
	)

	var claims types.GithubClaims
	token, err := parser.ParseWithClaims(tokenString, &claims, t.GenKeyFunc(jwks))

	// If the signing key was not found, the issuer may have rotated its keys.
	// Force a single cache-bypassing JWKS refetch and retry once.
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		slog.Info("Signing key not found in cached JWKS; refetching", slog.String("issuer", t.ExpectedIssuer))
		if jwks, err = t.fetchJWKS(t.ExpectedIssuer, true); err != nil {
			return nil, err
		}
		if jwks == nil || len(jwks.Keys) == 0 {
			return nil, errors.New("jwks is nil")
		}
		claims = types.GithubClaims{}
		token, err = parser.ParseWithClaims(tokenString, &claims, t.GenKeyFunc(jwks))
	}

	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("token is invalid")
	}

	return &claims, nil
}

// FetchJWKS fetches the JWKS for the given issuer, using the cache when available.
func (t *TokenValidator) FetchJWKS(issuer string) (*types.JWKS, error) {
	return t.fetchJWKS(issuer, false)
}

// fetchJWKS fetches the JWKS from the issuer's OIDC discovery endpoint
// (issuer + /.well-known/openid-configuration). When force is true the cache is
// bypassed and the freshly fetched JWKS replaces any cached entry — used to
// recover from signing-key rotation.
func (t *TokenValidator) fetchJWKS(issuer string, force bool) (*types.JWKS, error) {
	// Check the cache unless a forced refresh was requested
	if !force {
		if cachedJWKS, found := t.Cache.Get(issuer); found {
			if cachedJWKS != nil {
				return cachedJWKS, nil
			}
		}
	}

	// Enforce a secure transport for the issuer (loopback hosts excepted for tests/local).
	if err := requireSecureURL(issuer); err != nil {
		return nil, fmt.Errorf("invalid issuer URL: %w", err)
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(issuer + "/.well-known/openid-configuration")
	if err != nil {
		slog.Error("Failed to fetch OIDC configuration", "error", err)
		return nil, fmt.Errorf("failed to fetch OIDC configuration: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("Failed to close OIDC configuration response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		slog.Error("Received non-200 status code when fetching OIDC configuration", "status", resp.StatusCode)
		return nil, fmt.Errorf("received non-200 status code when fetching OIDC configuration: %d", resp.StatusCode)
	}

	var config struct {
		JwksURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		slog.Error("Failed to parse OIDC configuration", "error", err)
		return nil, fmt.Errorf("failed to parse OIDC configuration: %w", err)
	}

	// The discovered JWKS URI must also use a secure transport.
	if err := requireSecureURL(config.JwksURI); err != nil {
		return nil, fmt.Errorf("invalid jwks_uri: %w", err)
	}

	jwksResp, err := client.Get(config.JwksURI)
	if err != nil {
		slog.Error("Failed to fetch JWKS", "error", err)
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer func() {
		if err := jwksResp.Body.Close(); err != nil {
			slog.Error("Failed to close JWKS response body", "error", err)
		}
	}()

	if jwksResp.StatusCode != http.StatusOK {
		slog.Error("Received non-200 status code when fetching JWKS", "status", jwksResp.StatusCode)
		return nil, fmt.Errorf("received non-200 status code when fetching JWKS: %d", jwksResp.StatusCode)
	}

	var jwks types.JWKS
	if err := json.NewDecoder(jwksResp.Body).Decode(&jwks); err != nil {
		slog.Error("Failed to parse JWKS", "error", err)
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	// Cache the JWKS with TTL
	t.Cache.Set(issuer, &jwks, time.Duration(t.Cfg.Cache.TTL))

	return &jwks, nil
}

// GenKeyFunc generates a jwt.Keyfunc that validates JWT tokens using JWKS keys.
// Supports RSA (RS256/384/512) and ECDSA (ES256/384/512) key types.
func (t *TokenValidator) GenKeyFunc(jwks *types.JWKS) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("missing or invalid kid in token header")
		}

		for _, key := range jwks.Keys {
			if key.KeyID != kid {
				continue
			}
			switch key.KeyType {
			case "RSA":
				return parseRSAKey(key)
			case "EC":
				return parseECKey(key)
			default:
				return nil, fmt.Errorf("unsupported key type %q for kid %q", key.KeyType, kid)
			}
		}
		return nil, ErrKeyNotFound
	}
}

func parseRSAKey(key types.JSONWebKey) (*rsa.PublicKey, error) {
	if key.N == "" || key.E == "" {
		return nil, errors.New("RSA key missing modulus or exponent")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA exponent: %w", err)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}

func parseECKey(key types.JSONWebKey) (*ecdsa.PublicKey, error) {
	if key.X == "" || key.Y == "" || key.Crv == "" {
		return nil, errors.New("EC key missing x, y, or crv field")
	}
	curve, err := ecCurve(key.Crv)
	if err != nil {
		return nil, err
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EC x coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EC y coordinate: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

func ecCurve(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	}
	return nil, fmt.Errorf("unsupported EC curve %q", crv)
}

// requireSecureURL ensures u uses HTTPS. Plain HTTP is permitted only for
// loopback hosts (127.0.0.1, ::1, localhost) to support local servers and tests.
func requireSecureURL(u string) error {
	parsed, err := url.Parse(u)
	if err != nil {
		return fmt.Errorf("malformed URL %q: %w", u, err)
	}

	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		switch parsed.Hostname() {
		case "127.0.0.1", "::1", "localhost":
			return nil
		}
	}

	return fmt.Errorf("insecure scheme %q for host %q (https required)", parsed.Scheme, parsed.Hostname())
}
