package validator_test

// Adversarial coverage for Group C's crypto/time hardening: alg-confusion and
// duplicate-kid-different-type key selection (genKeyFuncForIssuer), OIDC
// discovery issuer mismatch (RFC 8414), zero-key JWKS never cached, and
// singleflight collapsing concurrent cold fetches for one issuer into a
// single upstream call.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
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
