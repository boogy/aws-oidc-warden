package validator_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/boogy/aws-oidc-warden/cache"
	"github.com/boogy/aws-oidc-warden/config"
	"github.com/boogy/aws-oidc-warden/types"
	"github.com/boogy/aws-oidc-warden/validator"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

// This is an integration test to ensure our refactoring of JWKS and JSONWebKey types
// doesn't break the actual OIDC token validation flow
func TestTokenValidationFlow(t *testing.T) {
	// Generate a test key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	publicKey := &privateKey.PublicKey

	// Create a key ID
	keyID := "test-key-id"

	// Create a JWKS with our test key
	jwks := &types.JWKS{
		Keys: []types.JSONWebKey{
			{
				KeyID:     keyID,
				KeyType:   "RSA",
				Algorithm: "RS256",
				Use:       "sig",
				N:         base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
				E:         base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
			},
		},
	}

	// Create a mock OIDC server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			config := struct {
				JwksURI string `json:"jwks_uri"`
			}{
				JwksURI: fmt.Sprintf("http://%s/jwks", r.Host),
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(config); err != nil {
				t.Logf("Failed to encode config: %v", err)
			}
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(jwks); err != nil {
				t.Logf("Failed to encode jwks: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Create a valid GitHub token
	issuer := server.URL
	audience := "test-audience"
	repository := "owner/repo"

	// Create claims
	claims := &types.GithubClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "repo:" + repository + ":ref:refs/heads/main",
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Actor:                "testuser",
		ActorID:              "12345",
		Repository:           repository,
		RepositoryOwner:      "owner",
		RepositoryID:         "67890",
		RepositoryOwnerID:    "54321",
		RepositoryVisibility: "public",
		Workflow:             "Test Workflow",
		Ref:                  "refs/heads/main",
		RefType:              "branch",
		EventName:            "push",
	}

	// Create and sign token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID
	tokenString, err := token.SignedString(privateKey)
	assert.NoError(t, err)

	// Create config and validator
	cfg := &config.Config{
		Issuer:   issuer,
		Audience: audience,
		Cache: &config.Cache{
			TTL: 10 * time.Minute,
		},
	}

	memoryCache := cache.NewMemoryCache()
	tokenValidator := validator.NewTokenValidator(cfg, memoryCache)

	// Validate the token
	resultClaims, err := tokenValidator.Validate(tokenString)
	assert.NoError(t, err)
	assert.NotNil(t, resultClaims)
	assert.Equal(t, repository, resultClaims.Repository)
	assert.Equal(t, issuer, resultClaims.Issuer)
	assert.Equal(t, audience, resultClaims.Audience[0])
}
