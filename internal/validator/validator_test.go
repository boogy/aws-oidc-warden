package validator_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/cache"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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

// staticValidator builds a TokenValidator from a config that never hot-reloads,
// mirroring how most tests only care about a single fixed configuration.
func staticValidator(cfg *config.Config, c cache.Cache) *validator.TokenValidator {
	return validator.NewTokenValidator(config.NewStaticProvider(cfg), c)
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
	claims := &types.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
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

// signRawToken signs an arbitrary raw claim set, used to exercise non-github
// (generic) providers whose claims have no dedicated Go struct.
func signRawToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

func TestNewTokenValidator_UnknownIssuerDenied(t *testing.T) {
	// A validator built from a config with no registered issuers must deny
	// every token — fail closed, not fail open.
	cfg := &config.Config{Cache: &config.Cache{TTL: time.Minute}}
	v := staticValidator(cfg, new(MockCache))
	require.NotNil(t, v)

	privateKey, _, err := generateRSAKey()
	require.NoError(t, err)
	token, err := createGithubToken(privateKey, "kid", "https://untrusted.example.com", "aud", "owner/repo")
	require.NoError(t, err)

	_, err = v.Validate(token)
	require.Error(t, err)
	assert.True(t, errors.Is(err, validator.ErrUnknownIssuer))
}

func TestValidate_Success(t *testing.T) {
	keyID := "test-key-id"
	issuer := "https://example.com"
	audience := "test-audience"
	repository := "owner/repo"

	privateKey, publicKey, err := generateRSAKey()
	require.NoError(t, err)

	jwks := createJWKS(keyID, publicKey)

	token, err := createGithubToken(privateKey, keyID, issuer, audience, repository)
	require.NoError(t, err)

	mockCache := new(MockCache)
	mockCache.On("Get", issuer).Return(jwks, true)

	cfg := &config.Config{
		Issuers: []config.IssuerConfig{
			{Issuer: issuer, Provider: "github", Audiences: []string{audience}, RequiredClaims: []string{"repository"}},
		},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 10 * time.Minute},
	}
	require.NoError(t, cfg.Validate())

	v := staticValidator(cfg, mockCache)

	claims, err := v.Validate(token)
	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.Equal(t, repository, claims.Repository)
	assert.Equal(t, repository, claims.Subject, "canonical subject defaults to the repository claim for provider github")
	assert.Equal(t, issuer, claims.Issuer)
	assert.Equal(t, audience, claims.Audience[0])

	mockCache.AssertExpectations(t)
}

func TestValidate_UnknownIssuer_JWKSNeverFetched(t *testing.T) {
	var fetchCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fetchCount, 1)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	// The registry trusts a different issuer entirely; srv.URL is never
	// registered, so no discovery/JWKS request should ever reach it.
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{
			{Issuer: "https://trusted.example.com", Provider: "github", Audiences: []string{"aud"}, RequiredClaims: []string{"repository"}},
		},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 10 * time.Minute},
	}
	require.NoError(t, cfg.Validate())
	v := staticValidator(cfg, cache.NewMemoryCache())

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	token := signToken(t, key, "k1", srv.URL, "aud")

	_, err = v.Validate(token)
	require.Error(t, err)
	assert.True(t, errors.Is(err, validator.ErrUnknownIssuer))
	assert.Equal(t, int32(0), atomic.LoadInt32(&fetchCount), "discovery/JWKS endpoint must never be hit for an unknown issuer")
}

func TestValidate_InvalidAudience(t *testing.T) {
	keyID := "test-key-id"
	issuer := "https://example.com"
	audience := "test-audience"
	wrongAudience := "wrong-audience"
	repository := "owner/repo"

	privateKey, publicKey, err := generateRSAKey()
	require.NoError(t, err)

	jwks := createJWKS(keyID, publicKey)

	token, err := createGithubToken(privateKey, keyID, issuer, wrongAudience, repository)
	require.NoError(t, err)

	mockCache := new(MockCache)
	mockCache.On("Get", issuer).Return(jwks, true)

	cfg := &config.Config{
		Issuers: []config.IssuerConfig{
			{Issuer: issuer, Provider: "github", Audiences: []string{audience}, RequiredClaims: []string{"repository"}},
		},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 10 * time.Minute},
	}
	require.NoError(t, cfg.Validate())

	v := staticValidator(cfg, mockCache)

	claims, err := v.Validate(token)
	require.Error(t, err)
	assert.Nil(t, claims)
	assert.True(t, errors.Is(err, validator.ErrInvalidAudience))

	mockCache.AssertExpectations(t)
}

func TestValidate_TwoIssuerAudienceIsolation(t *testing.T) {
	keyA, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwksA := &types.JWKS{Keys: []types.JSONWebKey{jwkFromKey("ka", &keyA.PublicKey)}}
	srvA := oidcServer(t, func() *types.JWKS { return jwksA })

	keyB, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwksB := &types.JWKS{Keys: []types.JSONWebKey{jwkFromKey("kb", &keyB.PublicKey)}}
	srvB := oidcServer(t, func() *types.JWKS { return jwksB })

	cfg := &config.Config{
		Issuers: []config.IssuerConfig{
			{Issuer: srvA.URL, Provider: "github", Audiences: []string{"aud-a"}, RequiredClaims: []string{"repository"}},
			{Issuer: srvB.URL, Provider: "github", Audiences: []string{"aud-b"}, RequiredClaims: []string{"repository"}},
		},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 10 * time.Minute},
	}
	require.NoError(t, cfg.Validate())
	v := staticValidator(cfg, cache.NewMemoryCache())

	// Issuer A accepts its own audience.
	tokenAOK := signToken(t, keyA, "ka", srvA.URL, "aud-a")
	claims, err := v.Validate(tokenAOK)
	require.NoError(t, err)
	assert.Equal(t, "owner/repo", claims.Repository)

	// "aud-b" is valid for issuer B, but must NOT leak into issuer A's
	// acceptance just because the string matches — each issuer's audience
	// set is isolated.
	tokenAWrongAud := signToken(t, keyA, "ka", srvA.URL, "aud-b")
	_, err = v.Validate(tokenAWrongAud)
	require.Error(t, err)
	assert.True(t, errors.Is(err, validator.ErrInvalidAudience))

	// Issuer B accepts its own audience via its own JWKS/key.
	tokenBOK := signToken(t, keyB, "kb", srvB.URL, "aud-b")
	claims, err = v.Validate(tokenBOK)
	require.NoError(t, err)
	assert.Equal(t, "owner/repo", claims.Repository)
}

func TestValidate_MissingRequiredClaims(t *testing.T) {
	keyID := "test-key-id"
	issuer := "https://example.com"
	audience := "test-audience"
	emptyRepository := ""

	privateKey, publicKey, err := generateRSAKey()
	require.NoError(t, err)

	jwks := createJWKS(keyID, publicKey)

	token, err := createGithubToken(privateKey, keyID, issuer, audience, emptyRepository)
	require.NoError(t, err)

	mockCache := new(MockCache)
	mockCache.On("Get", issuer).Return(jwks, true)

	cfg := &config.Config{
		Issuers: []config.IssuerConfig{
			{Issuer: issuer, Provider: "github", Audiences: []string{audience}, RequiredClaims: []string{"repository"}},
		},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 10 * time.Minute},
	}
	require.NoError(t, cfg.Validate())

	v := staticValidator(cfg, mockCache)

	claims, err := v.Validate(token)
	require.Error(t, err)
	assert.Nil(t, claims)
	assert.True(t, errors.Is(err, validator.ErrMissingRequiredClaim))

	mockCache.AssertExpectations(t)
}

func TestValidate_GenericProvider_SubjectMappingIgnoresRogueClaim(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwks := &types.JWKS{Keys: []types.JSONWebKey{jwkFromKey("k1", &key.PublicKey)}}
	srv := oidcServer(t, func() *types.JWKS { return jwks })

	cfg := &config.Config{
		Issuers: []config.IssuerConfig{
			{
				Issuer:         srv.URL,
				Provider:       "generic",
				Audiences:      []string{"aud"},
				ClaimMappings:  map[string]string{"subject": "project_path"},
				RequiredClaims: []string{"project_path"},
			},
		},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 10 * time.Minute},
	}
	require.NoError(t, cfg.Validate())
	v := staticValidator(cfg, cache.NewMemoryCache())

	token := signRawToken(t, key, "k1", jwt.MapClaims{
		"iss":          srv.URL,
		"aud":          "aud",
		"exp":          time.Now().Add(10 * time.Minute).Unix(),
		"iat":          time.Now().Unix(),
		"project_path": "group/project",
		"repository":   "attacker/repo", // rogue claim; must never become the canonical subject
	})

	claims, err := v.Validate(token)
	require.NoError(t, err)
	assert.Equal(t, "group/project", claims.Subject, "canonical subject must come from claim_mappings.subject, not a same-named GitHub claim")
	assert.Empty(t, claims.Repository, "generic provider must not populate GitHub-specific struct fields")
	assert.Equal(t, "attacker/repo", claims.Raw["repository"], "raw claim is preserved for inspection but never trusted as canonical identity")
}

func TestValidate_TokenTooLarge(t *testing.T) {
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{
			{Issuer: "https://example.com", Provider: "github", Audiences: []string{"aud"}, RequiredClaims: []string{"repository"}},
		},
		RoleSessionName: "test",
		MaxTokenBytes:   10,
		Cache:           &config.Cache{TTL: time.Minute},
	}
	require.NoError(t, cfg.Validate())

	v := staticValidator(cfg, new(MockCache))

	_, err := v.Validate(strings.Repeat("a", 100))
	require.Error(t, err)
	assert.True(t, errors.Is(err, validator.ErrTokenTooLarge))
}

func TestValidate_SignatureInvalid(t *testing.T) {
	keyID := "test-key-id"
	issuer := "https://example.com"
	audience := "test-audience"

	// The JWKS advertises signingKey's public key...
	signingKey, publicKey, err := generateRSAKey()
	require.NoError(t, err)
	jwks := createJWKS(keyID, publicKey)

	// ...but the token is actually signed with a different key under the same
	// kid, so the kid lookup succeeds yet signature verification must fail.
	wrongKey, _, err := generateRSAKey()
	require.NoError(t, err)
	token, err := createGithubToken(wrongKey, keyID, issuer, audience, "owner/repo")
	require.NoError(t, err)
	_ = signingKey

	mockCache := new(MockCache)
	mockCache.On("Get", issuer).Return(jwks, true)

	cfg := &config.Config{
		Issuers: []config.IssuerConfig{
			{Issuer: issuer, Provider: "github", Audiences: []string{audience}, RequiredClaims: []string{"repository"}},
		},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 10 * time.Minute},
	}
	require.NoError(t, cfg.Validate())

	v := staticValidator(cfg, mockCache)

	claims, err := v.Validate(token)
	require.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "jwt parse error")

	mockCache.AssertExpectations(t)
}

func TestFetchJWKS_CacheHit(t *testing.T) {
	issuer := "https://example.com"

	_, publicKey, err := generateRSAKey()
	require.NoError(t, err)
	jwks := createJWKS("test-key-id", publicKey)

	mockCache := new(MockCache)
	mockCache.On("Get", issuer).Return(jwks, true)

	cfg := &config.Config{Cache: &config.Cache{TTL: 10 * time.Minute}}
	v := staticValidator(cfg, mockCache)

	result, err := v.FetchJWKS(issuer)
	require.NoError(t, err)
	assert.Equal(t, jwks, result)

	mockCache.AssertExpectations(t)
}

func TestFetchJWKS_CacheMiss(t *testing.T) {
	_, publicKey, err := generateRSAKey()
	require.NoError(t, err)
	jwks := createJWKS("test-key-id", publicKey)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			config := struct {
				JwksURI string `json:"jwks_uri"`
			}{
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
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(jwks); err != nil {
				http.Error(w, fmt.Sprintf("Failed to encode JWKS: %v", err), http.StatusInternalServerError)
				return
			}
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	mockCache := new(MockCache)
	mockCache.On("Get", server.URL).Return(nil, false)
	mockCache.On("Set", server.URL, mock.AnythingOfType("*types.JWKS"), mock.AnythingOfType("time.Duration")).Return()

	cfg := &config.Config{Cache: &config.Cache{TTL: 10 * time.Minute}}
	v := staticValidator(cfg, mockCache)

	result, err := v.FetchJWKS(server.URL)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result.Keys, 1)

	mockCache.AssertExpectations(t)
}

func TestFetchJWKS_EmptyJWKSRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/openid-configuration" {
			json.NewEncoder(w).Encode(struct { //nolint:errcheck
				JwksURI string `json:"jwks_uri"`
			}{JwksURI: fmt.Sprintf("http://%s/jwks", r.Host)})
			return
		}
		json.NewEncoder(w).Encode(&types.JWKS{Keys: []types.JSONWebKey{}}) //nolint:errcheck
	}))
	defer server.Close()

	mockCache := new(MockCache)
	mockCache.On("Get", server.URL).Return(nil, false)

	cfg := &config.Config{Cache: &config.Cache{TTL: 10 * time.Minute}}
	v := staticValidator(cfg, mockCache)

	_, err := v.FetchJWKS(server.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no keys")

	mockCache.AssertExpectations(t)
}

func TestFetchJWKS_TooManyKeysRejected(t *testing.T) {
	_, publicKey, err := generateRSAKey()
	require.NoError(t, err)
	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

	keys := make([]types.JSONWebKey, 21)
	for i := range keys {
		keys[i] = types.JSONWebKey{KeyID: fmt.Sprintf("key-%d", i), KeyType: "RSA", Algorithm: "RS256", Use: "sig", N: n, E: e}
	}
	oversizedJWKS := &types.JWKS{Keys: keys}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/openid-configuration" {
			json.NewEncoder(w).Encode(struct { //nolint:errcheck
				JwksURI string `json:"jwks_uri"`
			}{JwksURI: fmt.Sprintf("http://%s/jwks", r.Host)})
			return
		}
		json.NewEncoder(w).Encode(oversizedJWKS) //nolint:errcheck
	}))
	defer server.Close()

	mockCache := new(MockCache)
	mockCache.On("Get", server.URL).Return(nil, false)

	cfg := &config.Config{Cache: &config.Cache{TTL: 10 * time.Minute}}
	v := staticValidator(cfg, mockCache)

	_, err = v.FetchJWKS(server.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too many keys")

	mockCache.AssertExpectations(t)
}

func TestFetchJWKS_LargeOIDCDiscoveryRejected(t *testing.T) {
	// A discovery document larger than 1 MB must be rejected cleanly (not OOM).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Write a syntactically valid JSON object padded well past 1 MB.
		w.Write([]byte(`{"jwks_uri":"` + "https://example.com/jwks" + `","padding":"`)) //nolint:errcheck
		padding := make([]byte, 2<<20)                                                  // 2 MB of zeros
		for i := range padding {
			padding[i] = 'x'
		}
		w.Write(padding)       //nolint:errcheck
		w.Write([]byte(`"}}`)) //nolint:errcheck
	}))
	defer server.Close()

	mockCache := new(MockCache)
	mockCache.On("Get", server.URL).Return(nil, false)

	cfg := &config.Config{Cache: &config.Cache{TTL: 10 * time.Minute}}
	v := staticValidator(cfg, mockCache)

	_, err := v.FetchJWKS(server.URL)
	assert.Error(t, err)
}

func TestFetchJWKS_LargeJWKSRejected(t *testing.T) {
	// A JWKS payload larger than 1 MB must be rejected cleanly.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/openid-configuration" {
			cfg := struct {
				JwksURI string `json:"jwks_uri"`
			}{JwksURI: fmt.Sprintf("http://%s/jwks", r.Host)}
			json.NewEncoder(w).Encode(cfg) //nolint:errcheck
			return
		}
		// Return a JWKS body padded well past 1 MB.
		w.Write([]byte(`{"keys":[{"kty":"RSA","padding":"`)) //nolint:errcheck
		padding := make([]byte, 2<<20)
		for i := range padding {
			padding[i] = 'x'
		}
		w.Write(padding)        //nolint:errcheck
		w.Write([]byte(`"}]}`)) //nolint:errcheck
	}))
	defer server.Close()

	mockCache := new(MockCache)
	mockCache.On("Get", server.URL).Return(nil, false)

	cfg := &config.Config{Cache: &config.Cache{TTL: 10 * time.Minute}}
	v := staticValidator(cfg, mockCache)

	_, err := v.FetchJWKS(server.URL)
	assert.Error(t, err)
}

func TestGenKeyFunc(t *testing.T) {
	privateKey, publicKey, err := generateRSAKey()
	require.NoError(t, err)

	keyID := "test-key-id"
	jwks := createJWKS(keyID, publicKey)

	v := staticValidator(&config.Config{}, nil)

	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = keyID

	keyFunc := v.GenKeyFunc(jwks)
	key, err := keyFunc(token)
	require.NoError(t, err)
	assert.NotNil(t, key)

	testToken := jwt.New(jwt.SigningMethodRS256)
	testToken.Header["kid"] = keyID
	claims := jwt.RegisteredClaims{
		Subject: "test",
	}
	testToken = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	testToken.Header["kid"] = keyID

	signedString, err := testToken.SignedString(privateKey)
	require.NoError(t, err)

	parsedToken, err := jwt.Parse(signedString, func(t *jwt.Token) (interface{}, error) {
		return key, nil
	})

	require.NoError(t, err)
	assert.True(t, parsedToken.Valid)
}

func TestGenKeyFunc_RejectsShortRSAKey(t *testing.T) {
	// A 1024-bit RSA key must be rejected by the minimum-key-size guard.
	shortKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	keyID := "short-rsa-key"
	jwks := createJWKS(keyID, &shortKey.PublicKey)

	v := staticValidator(&config.Config{}, nil)
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = keyID

	_, err = v.GenKeyFunc(jwks)(token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RSA key too short")
}

func TestGenKeyFunc_MissingKID(t *testing.T) {
	_, publicKey, err := generateRSAKey()
	require.NoError(t, err)
	jwks := createJWKS("test-key-id", publicKey)

	v := staticValidator(&config.Config{}, nil)

	token := jwt.New(jwt.SigningMethodRS256)

	keyFunc := v.GenKeyFunc(jwks)
	key, err := keyFunc(token)
	require.Error(t, err)
	assert.Nil(t, key)
	assert.Contains(t, err.Error(), "missing or invalid kid")
}

func TestGenKeyFunc_KeyNotFound(t *testing.T) {
	_, publicKey, err := generateRSAKey()
	require.NoError(t, err)
	jwks := createJWKS("test-key-id", publicKey)

	v := staticValidator(&config.Config{}, nil)

	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = "wrong-key-id"

	keyFunc := v.GenKeyFunc(jwks)
	key, err := keyFunc(token)
	require.Error(t, err)
	assert.Nil(t, key)
	assert.Contains(t, err.Error(), "key not found")
}
