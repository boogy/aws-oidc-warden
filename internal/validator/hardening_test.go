package validator_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/cache"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenKeyFunc_AlgConfusion_RSTokenRejectsECKeyUnderSameKid guards against a
// classic alg-confusion attack: an attacker can't have an RS256-alg token
// header pick an EC key just because it shares a kid with a legitimate EC
// key. The kid is present, so the error must NOT be ErrKeyNotFound -- that
// sentinel triggers a cache-bypassing refetch, which an attacker could abuse
// to hammer the upstream JWKS endpoint.
func TestGenKeyFunc_AlgConfusion_RSTokenRejectsECKeyUnderSameKid(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwks := &types.JWKS{Keys: []types.JSONWebKey{ecJwkFromKey("shared-kid", &ecKey.PublicKey)}}

	v := staticValidator(&config.Config{}, nil)
	keyFunc := v.GenKeyFunc(jwks)

	token := &jwt.Token{Header: map[string]any{"kid": "shared-kid", "alg": "RS256"}}
	_, err = keyFunc(token)
	require.Error(t, err)
	assert.False(t, errors.Is(err, validator.ErrKeyNotFound),
		"kid is present but wrong key type; must not look like an unknown-kid miss")
}

// TestGenKeyFunc_AlgConfusion_ESTokenRejectsRSAKeyUnderSameKid is the mirror
// case: an ES256 token must not have an RSA key selected for it.
func TestGenKeyFunc_AlgConfusion_ESTokenRejectsRSAKeyUnderSameKid(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwks := &types.JWKS{Keys: []types.JSONWebKey{jwkFromKey("shared-kid", &rsaKey.PublicKey)}}

	v := staticValidator(&config.Config{}, nil)
	keyFunc := v.GenKeyFunc(jwks)

	token := &jwt.Token{Header: map[string]any{"kid": "shared-kid", "alg": "ES256"}}
	_, err = keyFunc(token)
	require.Error(t, err)
	assert.False(t, errors.Is(err, validator.ErrKeyNotFound))
}

// TestGenKeyFunc_UseEncRejected ensures a JWKS key explicitly marked for
// encryption (use != "sig") is never selected for signature verification.
func TestGenKeyFunc_UseEncRejected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk := jwkFromKey("enc-kid", &key.PublicKey)
	jwk.Use = "enc"
	jwks := &types.JWKS{Keys: []types.JSONWebKey{jwk}}

	v := staticValidator(&config.Config{}, nil)
	keyFunc := v.GenKeyFunc(jwks)

	token := &jwt.Token{Header: map[string]any{"kid": "enc-kid", "alg": "RS256"}}
	_, err = keyFunc(token)
	require.Error(t, err)
	assert.False(t, errors.Is(err, validator.ErrKeyNotFound))
}

// TestGenKeyFunc_AlgMismatchRejected ensures a JWKS entry that declares an alg
// is only usable for tokens asserting that exact alg.
func TestGenKeyFunc_AlgMismatchRejected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk := jwkFromKey("k1", &key.PublicKey)
	jwk.Algorithm = "RS384"
	jwks := &types.JWKS{Keys: []types.JSONWebKey{jwk}}

	v := staticValidator(&config.Config{}, nil)
	keyFunc := v.GenKeyFunc(jwks)

	token := &jwt.Token{Header: map[string]any{"kid": "k1", "alg": "RS256"}}
	_, err = keyFunc(token)
	require.Error(t, err)
	assert.False(t, errors.Is(err, validator.ErrKeyNotFound))
}

// TestGenKeyFunc_DuplicateKidDifferentType_SelectsCorrectKey verifies that
// when two JWKS entries happen to share a kid but differ in key type, the
// scan continues past the mismatching one and resolves the correct key
// rather than failing or non-deterministically picking the wrong type.
func TestGenKeyFunc_DuplicateKidDifferentType_SelectsCorrectKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwks := &types.JWKS{Keys: []types.JSONWebKey{
		ecJwkFromKey("dup", &ecKey.PublicKey),
		jwkFromKey("dup", &rsaKey.PublicKey),
	}}

	v := staticValidator(&config.Config{}, nil)
	keyFunc := v.GenKeyFunc(jwks)

	rsaToken := &jwt.Token{Header: map[string]any{"kid": "dup", "alg": "RS256"}}
	key, err := keyFunc(rsaToken)
	require.NoError(t, err)
	rsaPub, ok := key.(*rsa.PublicKey)
	require.True(t, ok, "must select the RSA key, not the EC key sharing the kid")
	assert.Equal(t, rsaKey.N, rsaPub.N)

	esToken := &jwt.Token{Header: map[string]any{"kid": "dup", "alg": "ES256"}}
	key, err = keyFunc(esToken)
	require.NoError(t, err)
	ecPub, ok := key.(*ecdsa.PublicKey)
	require.True(t, ok, "must select the EC key, not the RSA key sharing the kid")
	assert.True(t, ecKey.PublicKey.Equal(ecPub))
}

// discoveryDoc is the minimal RFC 8414 discovery document shape used across
// these tests.
type discoveryDoc struct {
	Issuer  string `json:"issuer"`
	JwksURI string `json:"jwks_uri"`
}

// TestFetchJWKS_DiscoveryIssuerMismatchRejected guards against a spoofed or
// misconfigured discovery document: if the document's "issuer" doesn't match
// the issuer we asked for, the fetch must fail rather than silently trusting
// whatever jwks_uri the document supplied.
func TestFetchJWKS_DiscoveryIssuerMismatchRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/openid-configuration" {
			json.NewEncoder(w).Encode(discoveryDoc{ //nolint:errcheck
				Issuer:  "https://attacker.example.com",
				JwksURI: fmt.Sprintf("http://%s/jwks", r.Host),
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	cfg := &config.Config{Cache: &config.Cache{TTL: time.Minute}, AllowInsecureIssuers: true}
	v := staticValidator(cfg, cache.NewMemoryCache())

	_, err := v.FetchJWKS(server.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match configured issuer")
}

// TestFetchJWKS_ZeroKeyJWKSNeverCached verifies that an empty-key JWKS is
// both rejected and never handed to cache.Set -- an empty JWKS must not
// poison the cache for the remainder of the TTL.
func TestFetchJWKS_ZeroKeyJWKSNeverCached(t *testing.T) {
	var srvURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/openid-configuration" {
			json.NewEncoder(w).Encode(discoveryDoc{ //nolint:errcheck
				Issuer:  srvURL,
				JwksURI: fmt.Sprintf("http://%s/jwks", r.Host),
			})
			return
		}
		json.NewEncoder(w).Encode(&types.JWKS{Keys: []types.JSONWebKey{}}) //nolint:errcheck
	}))
	defer server.Close()
	srvURL = server.URL

	realCache := cache.NewMemoryCache()
	cfg := &config.Config{Cache: &config.Cache{TTL: time.Minute}, AllowInsecureIssuers: true}
	v := staticValidator(cfg, realCache)

	_, err := v.FetchJWKS(server.URL)
	require.Error(t, err)

	_, found := realCache.Get(server.URL)
	assert.False(t, found, "an empty JWKS must never be cached")
}

// TestFetchJWKS_SingleflightCollapsesConcurrentFetches sends many concurrent
// Validate calls against a cold cache for the same issuer and asserts the
// upstream JWKS endpoint is hit exactly once -- singleflight must
// deduplicate concurrent cold fetches for one issuer rather than each
// goroutine independently hammering it.
func TestFetchJWKS_SingleflightCollapsesConcurrentFetches(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwks := &types.JWKS{Keys: []types.JSONWebKey{jwkFromKey("k1", &key.PublicKey)}}

	var jwksHits atomic.Int64
	var srvURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(discoveryDoc{ //nolint:errcheck
				Issuer:  srvURL,
				JwksURI: fmt.Sprintf("http://%s/jwks", r.Host),
			})
		case "/jwks":
			jwksHits.Add(1)
			// Give concurrent callers a real window to overlap the fetch.
			time.Sleep(50 * time.Millisecond)
			json.NewEncoder(w).Encode(jwks) //nolint:errcheck
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	srvURL = server.URL

	cfg := githubIssuer(server.URL, "aud")
	require.NoError(t, cfg.Validate())
	v := staticValidator(cfg, cache.NewMemoryCache())

	token := signToken(t, key, "k1", server.URL, "aud")

	const workers = 20
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			_, err := v.Validate(token)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(1), jwksHits.Load(), "concurrent cold fetches for the same issuer must collapse to one upstream call")
}

// ---------- integration ----------

// This is an integration test to ensure our refactoring of JWKS and JSONWebKey types
// doesn't break the actual OIDC token validation flow
func TestTokenValidationFlow(t *testing.T) {
	// Generate a test key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
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
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			config := struct {
				Issuer  string `json:"issuer"`
				JwksURI string `json:"jwks_uri"`
			}{
				Issuer:  serverURL,
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
	serverURL = server.URL

	// Create a valid GitHub token
	issuer := server.URL
	audience := "test-audience"
	repository := "owner/repo"

	// Create claims
	claims := &types.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   repository,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		// Sub (depth-0) is what actually marshals to "sub" -- it shadows
		// RegisteredClaims.Subject above for JSON purposes.
		Sub:                  repository,
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
	require.NoError(t, err)

	// Create config and validator
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{
			{Issuer: issuer, Provider: "github", Audiences: []string{audience}, RequiredClaims: []string{"repository"}},
		},
		RoleSessionName:      "aws-oidc-warden",
		Cache:                &config.Cache{TTL: 10 * time.Minute},
		AllowInsecureIssuers: true,
	}
	require.NoError(t, cfg.Validate())

	tokenValidator := validator.NewTokenValidator(config.NewStaticProvider(cfg), cache.NewMemoryCache())

	// Validate the token
	resultClaims, err := tokenValidator.Validate(tokenString)
	require.NoError(t, err)
	require.NotNil(t, resultClaims)
	assert.Equal(t, repository, resultClaims.Repository)
	assert.Equal(t, repository, resultClaims.Subject)
	assert.Equal(t, issuer, resultClaims.Issuer)
	assert.Equal(t, audience, resultClaims.Audience[0])
}

// Signing-algorithm restriction: only RS/ES 256-384-512 may ever verify.
//
// Three independent guards enforce this, and none of them was pinned by a test
// that could fail — deleting jwt.WithValidMethods left the entire suite green:
//
//  1. the parser's allowlist (jwt.WithValidMethods in validator.go);
//  2. the keyfunc's key-type/alg-family check (RSA+"RS*", EC+"ES*");
//  3. the JWKS key's own declared `alg`, when the issuer publishes one.
//
// They overlap, so removing any single one changes no observable behavior.
// This test therefore pins the *property* rather than one mechanism, and the
// fixture deliberately publishes a JWKS with NO declared `alg` — permitted by
// RFC 7517 and common in the wild — so guard 3 is out of the picture and the
// test exercises the two guards that are always present. It fails when guards
// 1 and 2 are both removed; that pair is what actually holds the line.
//
// PS256 is the interesting probe: jwt-go verifies RSA-PSS against the very same
// *rsa.PublicKey the keyfunc returns, and the token below is signed with the
// issuer's real private key, so nothing about the key stops it. `none` and
// HS256 additionally die on key type (the keyfunc returns only *rsa.PublicKey /
// *ecdsa.PublicKey, and HMAC demands []byte), but are pinned here so a future
// keyfunc change cannot open them silently.

func TestValidate_RejectsAlgorithmsOutsideTheAllowlist(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub := &privateKey.PublicKey
	const keyID = "alg-allowlist-key"
	const audience = "test-audience"

	jwks := &types.JWKS{Keys: []types.JSONWebKey{{
		KeyID:     keyID,
		KeyType:   "RSA",
		Algorithm: "", // no declared alg: the weakest realistic JWKS (see above)
		Use:       "sig",
		N:         base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:         base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}}

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(struct {
				Issuer  string `json:"issuer"`
				JwksURI string `json:"jwks_uri"`
			}{serverURL, fmt.Sprintf("http://%s/jwks", r.Host)}))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(jwks))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL
	issuer := server.URL

	newClaims := func() *types.Claims {
		return &types.Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    issuer,
				Subject:   "owner/repo",
				Audience:  jwt.ClaimStrings{audience},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
			Sub:             "owner/repo",
			Repository:      "owner/repo",
			RepositoryOwner: "owner",
		}
	}

	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer: issuer, Provider: "github",
			Audiences: []string{audience}, RequiredClaims: []string{"repository"},
		}},
		RoleSessionName:      "aws-oidc-warden",
		Cache:                &config.Cache{TTL: 10 * time.Minute},
		AllowInsecureIssuers: true,
	}
	require.NoError(t, cfg.Validate())
	v := validator.NewTokenValidator(config.NewStaticProvider(cfg), cache.NewMemoryCache())

	// Control: RS256 is on the allowlist and must verify, so a rejection below
	// is attributable to the algorithm and not to the fixture.
	t.Run("RS256 is accepted", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, newClaims())
		tok.Header["kid"] = keyID
		signed, err := tok.SignedString(privateKey)
		require.NoError(t, err)

		claims, err := v.Validate(signed)
		require.NoError(t, err)
		require.NotNil(t, claims)
		assert.Equal(t, "owner/repo", claims.Repository)
	})

	// PS256: verifies against the same *rsa.PublicKey the keyfunc returns, and
	// is signed here with the issuer's real private key. With no declared
	// `alg` in the JWKS, only the parser allowlist and the keyfunc's RS/ES
	// family check stand between this token and a successful validation.
	t.Run("PS256 signed with the real issuer key is rejected", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodPS256, newClaims())
		tok.Header["kid"] = keyID
		signed, err := tok.SignedString(privateKey)
		require.NoError(t, err)

		claims, err := v.Validate(signed)
		require.Error(t, err, "PS256 is not on the allowlist and must be refused")
		assert.Nil(t, claims)
	})

	// These also die on key type, but pin them so a future keyfunc change
	// cannot open them silently.
	t.Run("alg none is rejected", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodNone, newClaims())
		tok.Header["kid"] = keyID
		signed, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
		require.NoError(t, err)

		claims, err := v.Validate(signed)
		require.Error(t, err)
		assert.Nil(t, claims)
	})

	t.Run("HS256 signed with the RSA public key is rejected", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, newClaims())
		tok.Header["kid"] = keyID
		signed, err := tok.SignedString(pub.N.Bytes())
		require.NoError(t, err)

		claims, err := v.Validate(signed)
		require.Error(t, err)
		assert.Nil(t, claims)
	})
}
