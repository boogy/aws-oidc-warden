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

	"github.com/boogy/aws-oidc-warden/config"
	"github.com/boogy/aws-oidc-warden/types"
	"github.com/boogy/aws-oidc-warden/validator"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockCache is a mock implementation of the Cache interface
type MockCache struct {
	mock.Mock
}

func (m *MockCache) Get(key string) (*types.JWKS, bool) {
	args := m.Called(key)
	if args.Get(0) == nil {
		return nil, args.Bool(1)
	}
	return args.Get(0).(*types.JWKS), args.Bool(1)
}

func (m *MockCache) Set(key string, value *types.JWKS, ttl time.Duration) {
	m.Called(key, value, ttl)
}

// generateRSAKey creates an RSA key pair for testing
func generateRSAKey() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// createJWKS generates a test JWKS with a single key
func createJWKS(keyID string, publicKey *rsa.PublicKey) *types.JWKS {
	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

	return &types.JWKS{
		Keys: []types.JSONWebKey{
			{
				KeyID:     keyID,
				KeyType:   "RSA",
				Algorithm: "RS256",
				Use:       "sig",
				N:         n,
				E:         e,
			},
		},
	}
}

// createGithubToken creates a test token signed with the given private key
func createGithubToken(privateKey *rsa.PrivateKey, keyID, issuer, audience, repository string) (string, error) {
	claims := &types.GithubClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "repo:" + repository + ":refs/heads/main",
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

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func TestNewTokenValidator(t *testing.T) {
	cfg := &config.Config{
		Issuer:   "https://example.com",
		Audience: "test-audience",
		Cache: &config.Cache{
			TTL: 10 * time.Minute,
		},
	}

	mockCache := new(MockCache)
	validator := validator.NewTokenValidator(cfg, mockCache)

	assert.Equal(t, cfg.Issuer, validator.ExpectedIssuer)
	assert.Equal(t, cfg.Audience, validator.ExpectedAudience)
	assert.Equal(t, mockCache, validator.Cache)
	assert.Equal(t, cfg, validator.Cfg)
}

func TestValidate_Success(t *testing.T) {
	keyID := "test-key-id"
	issuer := "https://example.com"
	audience := "test-audience"
	repository := "owner/repo"

	// Generate RSA keys for signing
	privateKey, publicKey, err := generateRSAKey()
	assert.NoError(t, err)

	// Create JWKS with the public key
	jwks := createJWKS(keyID, publicKey)

	// Create a valid GitHub token
	token, err := createGithubToken(privateKey, keyID, issuer, audience, repository)
	assert.NoError(t, err)

	// Setup mock cache
	mockCache := new(MockCache)
	mockCache.On("Get", issuer).Return(jwks, true)

	// Create config and validator
	cfg := &config.Config{
		Issuer:   issuer,
		Audience: audience,
		Cache: &config.Cache{
			TTL: 10 * time.Minute,
		},
	}

	validator := validator.NewTokenValidator(cfg, mockCache)

	// Test the Validate function
	claims, err := validator.Validate(token)
	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, repository, claims.Repository)
	assert.Equal(t, issuer, claims.Issuer)
	assert.Equal(t, audience, claims.Audience[0])

	mockCache.AssertExpectations(t)
}

func TestValidate_InvalidIssuer(t *testing.T) {
	keyID := "test-key-id"
	issuer := "https://example.com"
	wrongIssuer := "https://wrong-issuer.com"
	audience := "test-audience"
	repository := "owner/repo"

	// Generate RSA keys for signing
	privateKey, publicKey, err := generateRSAKey()
	assert.NoError(t, err)

	// Create JWKS with the public key
	jwks := createJWKS(keyID, publicKey)

	// Create a token with an invalid issuer
	token, err := createGithubToken(privateKey, keyID, wrongIssuer, audience, repository)
	assert.NoError(t, err)

	// Setup mock cache
	mockCache := new(MockCache)
	mockCache.On("Get", issuer).Return(jwks, true)

	// Create config and validator
	cfg := &config.Config{
		Issuer:   issuer,
		Audience: audience,
		Cache: &config.Cache{
			TTL: 10 * time.Minute,
		},
	}

	validator := validator.NewTokenValidator(cfg, mockCache)

	// Test the Validate function with invalid issuer
	claims, err := validator.Validate(token)
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "issuer")

	mockCache.AssertExpectations(t)
}

func TestValidate_InvalidAudience(t *testing.T) {
	keyID := "test-key-id"
	issuer := "https://example.com"
	audience := "test-audience"
	wrongAudience := "wrong-audience"
	repository := "owner/repo"

	// Generate RSA keys for signing
	privateKey, publicKey, err := generateRSAKey()
	assert.NoError(t, err)

	// Create JWKS with the public key
	jwks := createJWKS(keyID, publicKey)

	// Create a token with an invalid audience
	token, err := createGithubToken(privateKey, keyID, issuer, wrongAudience, repository)
	assert.NoError(t, err)

	// Setup mock cache
	mockCache := new(MockCache)
	mockCache.On("Get", issuer).Return(jwks, true)

	// Create config and validator
	cfg := &config.Config{
		Issuer:   issuer,
		Audience: audience,
		Cache: &config.Cache{
			TTL: 10 * time.Minute,
		},
	}

	validator := validator.NewTokenValidator(cfg, mockCache)

	// Test the Validate function with invalid audience
	claims, err := validator.Validate(token)
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "audience")

	mockCache.AssertExpectations(t)
}

func TestValidate_MissingRepository(t *testing.T) {
	keyID := "test-key-id"
	issuer := "https://example.com"
	audience := "test-audience"
	emptyRepository := ""

	// Generate RSA keys for signing
	privateKey, publicKey, err := generateRSAKey()
	assert.NoError(t, err)

	// Create JWKS with the public key
	jwks := createJWKS(keyID, publicKey)

	// Create a token with an empty repository
	token, err := createGithubToken(privateKey, keyID, issuer, audience, emptyRepository)
	assert.NoError(t, err)

	// Setup mock cache
	mockCache := new(MockCache)
	mockCache.On("Get", issuer).Return(jwks, true)

	// Create config and validator
	cfg := &config.Config{
		Issuer:   issuer,
		Audience: audience,
		Cache: &config.Cache{
			TTL: 10 * time.Minute,
		},
	}

	validator := validator.NewTokenValidator(cfg, mockCache)

	// Test the Validate function with missing repository
	claims, err := validator.Validate(token)
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "repository is required")

	mockCache.AssertExpectations(t)
}

func TestFetchJWKS_CacheHit(t *testing.T) {
	issuer := "https://example.com"

	// Create a test JWKS
	_, publicKey, err := generateRSAKey()
	assert.NoError(t, err)
	jwks := createJWKS("test-key-id", publicKey)

	// Setup mock cache with a cache hit
	mockCache := new(MockCache)
	mockCache.On("Get", issuer).Return(jwks, true)

	// Create config and validator
	cfg := &config.Config{
		Issuer: issuer,
		Cache: &config.Cache{
			TTL: 10 * time.Minute,
		},
	}

	validator := validator.NewTokenValidator(cfg, mockCache)

	// Test FetchJWKS with a cache hit
	result, err := validator.FetchJWKS(issuer)
	assert.NoError(t, err)
	assert.Equal(t, jwks, result)

	mockCache.AssertExpectations(t)
}

func TestFetchJWKS_CacheMiss(t *testing.T) {
	// Generate RSA keys for signing
	_, publicKey, err := generateRSAKey()
	assert.NoError(t, err)

	// Create a test JWKS
	jwks := createJWKS("test-key-id", publicKey)

	// Setup a direct test server with fixed responses
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			// Return a fixed JWKS URI pointing to our test server
			config := struct {
				JwksURI string `json:"jwks_uri"`
			}{
				// Important: Use the full URL including http:// and hostname
				JwksURI: fmt.Sprintf("http://%s/jwks", r.Host),
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(config); err != nil {
				http.Error(w, fmt.Sprintf("Failed to encode config: %v", err), http.StatusInternalServerError)
				return
			}
			return
		}

		if r.URL.Path == "/jwks" {
			// Return our test JWKS
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(jwks); err != nil {
				http.Error(w, fmt.Sprintf("Failed to encode JWKS: %v", err), http.StatusInternalServerError)
				return
			}
			return
		}

		// Default response for any other path
		http.NotFound(w, r)
	}))
	defer server.Close()

	// Setup mock cache with a cache miss
	mockCache := new(MockCache)
	mockCache.On("Get", server.URL).Return(nil, false)
	mockCache.On("Set", server.URL, mock.AnythingOfType("*types.JWKS"), mock.AnythingOfType("time.Duration")).Return()

	// Create config and validator with the test server URL as issuer
	cfg := &config.Config{
		Issuer: server.URL,
		Cache: &config.Cache{
			TTL: 10 * time.Minute,
		},
	}

	validator := validator.NewTokenValidator(cfg, mockCache)

	// Test FetchJWKS with a cache miss
	result, err := validator.FetchJWKS(server.URL)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Keys, 1)

	mockCache.AssertExpectations(t)
}

func TestGenKeyFunc(t *testing.T) {
	// Generate RSA keys for signing
	privateKey, publicKey, err := generateRSAKey()
	assert.NoError(t, err)

	// Create a test JWKS
	keyID := "test-key-id"
	jwks := createJWKS(keyID, publicKey)

	// Create validator
	validator := validator.NewTokenValidator(&config.Config{}, nil)

	// Create a token with the key ID
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = keyID

	// Test GenKeyFunc
	keyFunc := validator.GenKeyFunc(jwks)
	key, err := keyFunc(token)
	assert.NoError(t, err)
	assert.NotNil(t, key)

	// Test that the key can verify a signature
	testToken := jwt.New(jwt.SigningMethodRS256)
	testToken.Header["kid"] = keyID
	claims := jwt.RegisteredClaims{
		Subject: "test",
	}
	testToken = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	testToken.Header["kid"] = keyID

	signedString, err := testToken.SignedString(privateKey)
	assert.NoError(t, err)

	parsedToken, err := jwt.Parse(signedString, func(t *jwt.Token) (interface{}, error) {
		return key, nil
	})

	assert.NoError(t, err)
	assert.True(t, parsedToken.Valid)
}

func TestGenKeyFunc_MissingKID(t *testing.T) {
	// Create a test JWKS
	_, publicKey, err := generateRSAKey()
	assert.NoError(t, err)
	jwks := createJWKS("test-key-id", publicKey)

	// Create validator
	validator := validator.NewTokenValidator(&config.Config{}, nil)

	// Create a token without a key ID
	token := jwt.New(jwt.SigningMethodRS256)

	// Test GenKeyFunc with a missing KID
	keyFunc := validator.GenKeyFunc(jwks)
	key, err := keyFunc(token)
	assert.Error(t, err)
	assert.Nil(t, key)
	assert.Contains(t, err.Error(), "missing or invalid kid")
}

func TestGenKeyFunc_KeyNotFound(t *testing.T) {
	// Create a test JWKS
	_, publicKey, err := generateRSAKey()
	assert.NoError(t, err)
	jwks := createJWKS("test-key-id", publicKey)

	// Create validator
	validator := validator.NewTokenValidator(&config.Config{}, nil)

	// Create a token with a different key ID
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = "wrong-key-id"

	// Test GenKeyFunc with a key that doesn't exist in the JWKS
	keyFunc := validator.GenKeyFunc(jwks)
	key, err := keyFunc(token)
	assert.Error(t, err)
	assert.Nil(t, key)
	assert.Contains(t, err.Error(), "key not found")
}

func TestUnmarshal_SimpleFields(t *testing.T) {
	// Create simple JSON data with basic fields
	jsonData := []byte(`{
		"actor": "testuser",
		"repository": "owner/repo",
		"repository_owner": "owner"
	}`)

	// Create validator
	validator := validator.NewTokenValidator(&config.Config{}, nil)

	// Test Unmarshal with simple fields
	parsedClaims, err := validator.Unmarshal(jsonData)
	assert.NoError(t, err)
	assert.NotNil(t, parsedClaims)

	// Verify only the simple fields we provided
	assert.Equal(t, "testuser", parsedClaims.Actor)
	assert.Equal(t, "owner/repo", parsedClaims.Repository)
	assert.Equal(t, "owner", parsedClaims.RepositoryOwner)
}

func TestUnmarshal_InvalidJSON(t *testing.T) {
	// Create invalid JSON
	invalidJSON := []byte(`{invalid json}`)

	// Create validator
	validator := validator.NewTokenValidator(&config.Config{}, nil)

	// Test Unmarshal with invalid JSON
	parsedClaims, err := validator.Unmarshal(invalidJSON)
	assert.Error(t, err)
	assert.Nil(t, parsedClaims)
}

func TestParseToken_JWKSError(t *testing.T) {
	// Setup mock cache
	mockCache := new(MockCache)
	mockCache.On("Get", "https://example.com").Return(nil, false)

	// Create a test server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	// Create config and validator
	cfg := &config.Config{
		Issuer: "https://example.com",
		Cache: &config.Cache{
			TTL: 10 * time.Minute,
		},
	}

	validator := validator.NewTokenValidator(cfg, mockCache)

	// Test ParseToken with a JWKS fetch error
	claims, err := validator.ParseToken("invalid.token.string")
	assert.Error(t, err)
	assert.Nil(t, claims)

	mockCache.AssertExpectations(t)
}

func TestParseToken_EmptyJWKS(t *testing.T) {
	// Setup mock cache with an empty JWKS
	emptyJWKS := &types.JWKS{
		Keys: []types.JSONWebKey{},
	}

	mockCache := new(MockCache)
	mockCache.On("Get", "https://example.com").Return(emptyJWKS, true)

	// Create config and validator
	cfg := &config.Config{
		Issuer: "https://example.com",
		Cache: &config.Cache{
			TTL: 10 * time.Minute,
		},
	}

	validator := validator.NewTokenValidator(cfg, mockCache)

	// Test ParseToken with an empty JWKS
	claims, err := validator.ParseToken("invalid.token.string")
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "jwks is nil")

	mockCache.AssertExpectations(t)
}

func TestParseToken_InvalidToken(t *testing.T) {
	// Generate RSA keys for signing
	_, publicKey, err := generateRSAKey()
	assert.NoError(t, err)

	// Create JWKS with the public key
	jwks := createJWKS("test-key-id", publicKey)

	// Setup mock cache
	mockCache := new(MockCache)
	mockCache.On("Get", "https://example.com").Return(jwks, true)

	// Create config and validator
	cfg := &config.Config{
		Issuer:   "https://example.com",
		Audience: "test-audience",
		Cache: &config.Cache{
			TTL: 10 * time.Minute,
		},
	}

	validator := validator.NewTokenValidator(cfg, mockCache)

	// Test ParseToken with an invalid token
	claims, err := validator.ParseToken("invalid.token.string")
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "token validation failed")

	mockCache.AssertExpectations(t)
}
