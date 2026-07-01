package validator_test

import (
	"context"
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

// jwkFromKey builds a JWKS JSON web key for an RSA public key.
func jwkFromKey(kid string, pub *rsa.PublicKey) types.JSONWebKey {
	return types.JSONWebKey{
		KeyID:     kid,
		KeyType:   "RSA",
		Algorithm: "RS256",
		Use:       "sig",
		N:         base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:         base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// signToken signs a minimal valid GitHub claims set with the given key/kid.
func signToken(t *testing.T, key *rsa.PrivateKey, kid, issuer, audience string) string {
	t.Helper()
	claims := &types.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "owner/repo",
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		// Sub (depth-0) is what actually marshals to the "sub" JWT claim --
		// it shadows RegisteredClaims.Subject for JSON purposes (see
		// types.Claims doc comment). Set both so intent is clear even though
		// only Sub round-trips.
		Sub:        "owner/repo",
		Repository: "owner/repo",
		Ref:        "refs/heads/main",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

// oidcServer starts a mock OIDC server whose JWKS is supplied by getJWKS on
// each request (so the served keys can change between calls).
func oidcServer(t *testing.T, getJWKS func() *types.JWKS) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(struct {
				Issuer  string `json:"issuer"`
				JwksURI string `json:"jwks_uri"`
			}{Issuer: "http://" + r.Host, JwksURI: fmt.Sprintf("http://%s/jwks", r.Host)})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(getJWKS())
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// githubIssuer builds a single-issuer config trusting issuer for the given
// audiences with provider "github" and the "repository" claim required.
// AllowInsecureIssuers is set so the loopback httptest servers used
// throughout this package's tests aren't rejected by the HTTPS-only default.
func githubIssuer(issuer string, audiences ...string) *config.Config {
	return &config.Config{
		Issuers: []config.IssuerConfig{
			{Issuer: issuer, Provider: "github", Audiences: audiences, RequiredClaims: []string{"repository"}},
		},
		RoleSessionName:      "aws-oidc-warden",
		Cache:                &config.Cache{TTL: 10 * time.Minute},
		AllowInsecureIssuers: true,
	}
}

// TestValidate_NonFirstAudience verifies multi-audience support: a token whose
// audience matches a configured audience other than the first must validate.
// (Regression for the WithAudience-pins-first-audience bug.)
func TestValidate_NonFirstAudience(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwks := &types.JWKS{Keys: []types.JSONWebKey{jwkFromKey("k1", &key.PublicKey)}}
	srv := oidcServer(t, func() *types.JWKS { return jwks })

	cfg := githubIssuer(srv.URL, "first-aud", "second-aud", "third-aud")
	require.NoError(t, cfg.Validate())

	v := staticValidator(cfg, cache.NewMemoryCache())

	// Token carries only the THIRD configured audience.
	token := signToken(t, key, "k1", srv.URL, "third-aud")
	claims, err := v.Validate(token)
	require.NoError(t, err)
	assert.Equal(t, "owner/repo", claims.Repository)
}

// TestValidate_WrongAudienceRejected ensures an audience not in the configured
// list is still rejected after removing the parser-level audience pin.
func TestValidate_WrongAudienceRejected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwks := &types.JWKS{Keys: []types.JSONWebKey{jwkFromKey("k1", &key.PublicKey)}}
	srv := oidcServer(t, func() *types.JWKS { return jwks })

	cfg := githubIssuer(srv.URL, "expected-aud")
	require.NoError(t, cfg.Validate())

	v := staticValidator(cfg, cache.NewMemoryCache())

	token := signToken(t, key, "k1", srv.URL, "attacker-aud")
	_, err = v.Validate(token)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, validator.ErrInvalidAudience))
}

// TestValidate_KeyRotationRefetch verifies that a token signed with a freshly
// rotated key (kid absent from the cached JWKS) succeeds via a cache-bypassing
// refetch instead of failing for the duration of the cache TTL.
func TestValidate_KeyRotationRefetch(t *testing.T) {
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	var mu sync.Mutex
	served := &types.JWKS{Keys: []types.JSONWebKey{jwkFromKey("old-kid", &oldKey.PublicKey)}}
	srv := oidcServer(t, func() *types.JWKS {
		mu.Lock()
		defer mu.Unlock()
		return served
	})

	cfg := githubIssuer(srv.URL, "aud")
	cfg.Cache = &config.Cache{TTL: time.Hour} // long TTL: stale cache must not block rotation
	require.NoError(t, cfg.Validate())

	v := staticValidator(cfg, cache.NewMemoryCache())

	// Prime the cache with the old JWKS.
	_, err = v.Validate(signToken(t, oldKey, "old-kid", srv.URL, "aud"))
	require.NoError(t, err)

	// Rotate: server now serves only the new key.
	mu.Lock()
	served = &types.JWKS{Keys: []types.JSONWebKey{jwkFromKey("new-kid", &newKey.PublicKey)}}
	mu.Unlock()

	// A token signed with the new key has a kid absent from the cached JWKS;
	// it must still validate after a forced refetch.
	claims, err := v.Validate(signToken(t, newKey, "new-kid", srv.URL, "aud"))
	require.NoError(t, err)
	assert.Equal(t, "owner/repo", claims.Repository)
}

// TestFetchJWKS_RejectsInsecureIssuer ensures a non-HTTPS, non-loopback issuer
// is rejected.
func TestFetchJWKS_RejectsInsecureIssuer(t *testing.T) {
	cfg := githubIssuer("http://token.example.com", "aud")
	cfg.Cache = &config.Cache{TTL: time.Minute}
	require.NoError(t, cfg.Validate())

	v := staticValidator(cfg, cache.NewMemoryCache())

	_, err := v.FetchJWKS("http://token.example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer")
}

// ecJwkFromKey builds a JWKS JSON web key for an ECDSA public key (P-256).
// Uses ECDH() to extract X/Y coordinates without the deprecated big.Int fields.
func ecJwkFromKey(kid string, pub *ecdsa.PublicKey) types.JSONWebKey {
	ecdhKey, err := pub.ECDH()
	if err != nil {
		panic(fmt.Sprintf("ecJwkFromKey: %v", err))
	}
	// Uncompressed form: 0x04 || X || Y, each coordinate coordLen bytes.
	raw := ecdhKey.Bytes()
	coordLen := (len(raw) - 1) / 2
	return types.JSONWebKey{
		KeyID:     kid,
		KeyType:   "EC",
		Algorithm: "ES256",
		Use:       "sig",
		Crv:       "P-256",
		X:         base64.RawURLEncoding.EncodeToString(raw[1 : 1+coordLen]),
		Y:         base64.RawURLEncoding.EncodeToString(raw[1+coordLen:]),
	}
}

// signTokenEC signs a minimal valid GitHub claims set with the given EC key.
func signTokenEC(t *testing.T, key *ecdsa.PrivateKey, kid, issuer, audience string) string {
	t.Helper()
	claims := &types.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "owner/repo",
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		// Sub (depth-0) is what actually marshals to "sub" -- see signToken.
		Sub:        "owner/repo",
		Repository: "owner/repo",
		Ref:        "refs/heads/main",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

// TestValidate_ECKey_ES256 verifies that ES256-signed tokens are accepted.
func TestValidate_ECKey_ES256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwks := &types.JWKS{Keys: []types.JSONWebKey{ecJwkFromKey("ec-k1", &key.PublicKey)}}
	srv := oidcServer(t, func() *types.JWKS { return jwks })

	cfg := githubIssuer(srv.URL, "aud")
	require.NoError(t, cfg.Validate())

	v := staticValidator(cfg, cache.NewMemoryCache())
	token := signTokenEC(t, key, "ec-k1", srv.URL, "aud")
	claims, err := v.Validate(token)
	require.NoError(t, err)
	assert.Equal(t, "owner/repo", claims.Repository)
}

// TestGenKeyFunc_UnknownKtyReturnsError ensures an unknown or empty kty returns
// an error (not ErrKeyNotFound) so no spurious JWKS refetch is triggered.
func TestGenKeyFunc_UnknownKtyReturnsError(t *testing.T) {
	v := staticValidator(&config.Config{}, nil)

	for _, kty := range []string{"", "OKP", "oct"} {
		jwks := &types.JWKS{Keys: []types.JSONWebKey{{KeyID: "k1", KeyType: kty}}}
		keyFunc := v.GenKeyFunc(jwks)
		token := &jwt.Token{Header: map[string]any{"kid": "k1"}}
		_, err := keyFunc(token)
		require.Error(t, err, "kty=%q", kty)
		assert.False(t, errors.Is(err, validator.ErrKeyNotFound), "kty=%q should not trigger refetch", kty)
	}
}

// TestValidate_ConcurrentHotSwap_Race runs many goroutines calling Validate
// while a config hot-reload swaps the issuer's audience out from under them.
// Run with -race: the atomic snapshot swap in TokenValidator must never race,
// and once the swap has completed every subsequent Validate call must observe
// the new configuration (no stale reads).
func TestValidate_ConcurrentHotSwap_Race(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwks := &types.JWKS{Keys: []types.JSONWebKey{jwkFromKey("k1", &key.PublicKey)}}
	srv := oidcServer(t, func() *types.JWKS { return jwks })

	cfgV1 := githubIssuer(srv.URL, "aud-v1")
	require.NoError(t, cfgV1.Validate())

	// fetch supplies the v2 configuration bytes; MergeBytes overlays them onto
	// a clone of base (cfgV1) and re-validates, matching how a real remote
	// config reload behaves.
	v2JSON := fmt.Sprintf(`{"issuers":[{"issuer":%q,"provider":"github","audiences":["aud-v2"],"required_claims":["repository"]}]}`, srv.URL)
	provider := config.NewProvider(cfgV1, 0, "json", func(context.Context) ([]byte, error) {
		return []byte(v2JSON), nil
	})
	v := validator.NewTokenValidator(provider, cache.NewMemoryCache())

	tokenV1 := signToken(t, key, "k1", srv.URL, "aud-v1")
	tokenV2 := signToken(t, key, "k1", srv.URL, "aud-v2")

	const workers = 16
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				// Results are intentionally not asserted per-iteration: which
				// config a given call observes is a race by construction.
				// -race is what proves the swap itself is safe.
				_, _ = v.Validate(tokenV1)
				_, _ = v.Validate(tokenV2)
			}
		}()
	}

	// Swap the config while the workers are mid-flight.
	require.NoError(t, provider.Refresh(context.Background()))

	wg.Wait()

	// No-stale-read check: once Refresh has returned, every subsequent call
	// must observe the new configuration deterministically.
	_, err = v.Validate(tokenV1)
	assert.Error(t, err, "aud-v1 must be rejected after hot-reload removed it")
	assert.True(t, errors.Is(err, validator.ErrInvalidAudience))

	claims, err := v.Validate(tokenV2)
	require.NoError(t, err, "aud-v2 must be accepted after hot-reload")
	assert.Equal(t, "owner/repo", claims.Repository)
}

// TestGenKeyFunc_ECKey_MissingCoords ensures an EC key without x/y/crv returns
// an error rather than constructing a key with zero coordinates.
func TestGenKeyFunc_ECKey_MissingCoords(t *testing.T) {
	v := staticValidator(&config.Config{}, nil)

	jwks := &types.JWKS{Keys: []types.JSONWebKey{{
		KeyID:   "ec-kid",
		KeyType: "EC",
		Crv:     "P-256",
		// X and Y intentionally absent
	}}}

	keyFunc := v.GenKeyFunc(jwks)
	token := &jwt.Token{Header: map[string]any{"kid": "ec-kid"}}

	_, err := keyFunc(token)
	require.Error(t, err)
	assert.False(t, errors.Is(err, validator.ErrKeyNotFound))
}
