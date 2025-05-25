package validator

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"time"

	"github.com/boogy/aws-oidc-warden/cache"
	"github.com/boogy/aws-oidc-warden/config"
	"github.com/boogy/aws-oidc-warden/types"
	"github.com/golang-jwt/jwt/v5"
)

type TokenValidatorInterface interface {
	Validate(string) (*types.GithubClaims, error)
	ParseToken(tokenString string) (*types.GithubClaims, error)
	FetchJWKS(issuer string) (*types.JWKS, error)
	GenKeyFunc(jwks *types.JWKS) jwt.Keyfunc
}

type TokenValidator struct {
	Token            string
	ExpectedIssuer   string
	ExpectedAudience string
	Cache            cache.Cache
	Cfg              *config.Config
}

func NewTokenValidator(cfg *config.Config, cache cache.Cache) *TokenValidator {
	return &TokenValidator{
		ExpectedIssuer:   cfg.Issuer,
		ExpectedAudience: cfg.Audience,
		Cache:            cache,
		Cfg:              cfg,
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

	if claims.Audience[0] != t.ExpectedAudience {
		return nil, fmt.Errorf("audience %s expected", t.ExpectedAudience)
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
		return nil, fmt.Errorf("%w", err)
	}

	if jwks == nil || len(jwks.Keys) == 0 {
		return nil, errors.New("jwks is nil")
	}

	// Generate key function for JWKS
	keyFunc := t.GenKeyFunc(jwks)

	// Create token parser with strict validation
	parser := jwt.NewParser(
		jwt.WithAudience(t.ExpectedAudience),
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

	var claims types.GithubClaims
	token, err := parser.ParseWithClaims(tokenString, &claims, keyFunc)

	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("token is invalid")
	}

	return &claims, nil
}

// fetchJwKS fetches the JWKS from the GitHub OIDC JWKS endpoint (issuer + /.well-known/openid-configuration)
// TODO: Add caching for the JWKS to avoid fetching it on every request
func (t *TokenValidator) FetchJWKS(issuer string) (*types.JWKS, error) {
	// Check the cache
	if cachedJWKS, found := t.Cache.Get(issuer); found {
		if cachedJWKS != nil {
			return cachedJWKS, nil
		}
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

// GenKeyFunc generates a jwt.Keyfunc that can be used to validate JWT tokens using the keys provided in the JWKS.
func (t *TokenValidator) GenKeyFunc(jwks *types.JWKS) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("missing or invalid kid in token header")
		}

		for _, key := range jwks.Keys {
			if key.KeyID == kid {
				nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
				if err != nil {
					slog.Error("Failed to decode modulus", slog.String("error", err.Error()))
					return nil, fmt.Errorf("failed to decode modulus: %w", err)
				}

				eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
				if err != nil {
					slog.Error("Failed to decode exponent", slog.String("error", err.Error()))
					return nil, fmt.Errorf("failed to decode exponent: %w", err)
				}

				// Construct the RSA public key
				pub := &rsa.PublicKey{
					N: new(big.Int).SetBytes(nBytes),
					E: int(new(big.Int).SetBytes(eBytes).Int64()),
				}
				return pub, nil
			}
		}
		return nil, errors.New("key not found")
	}
}
