package validator

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/cache"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const stateTestTTL = time.Minute

// countingCache counts Set calls on top of a real in-memory cache.
type countingCache struct {
	cache.Cache
	sets atomic.Int64
}

func (c *countingCache) Set(ctx context.Context, key string, v *types.JWKS, ttl time.Duration) {
	c.sets.Add(1)
	c.Cache.Set(ctx, key, v, ttl)
}

// jwksTestServer serves discovery and a JWKS whose body and status the test
// controls, counting hits to each endpoint.
type jwksTestServer struct {
	*httptest.Server
	discoveryHits, jwksHits atomic.Int64
	mu                      sync.Mutex
	status                  int
	kid                     string
}

func (s *jwksTestServer) set(status int, kid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status, s.kid = status, kid
}

func newJWKSTestServer(t *testing.T) *jwksTestServer {
	t.Helper()
	s := &jwksTestServer{status: http.StatusOK, kid: "k1"}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			s.discoveryHits.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": s.URL, "jwks_uri": s.URL + "/jwks"})
		case "/jwks":
			s.jwksHits.Add(1)
			s.mu.Lock()
			status, kid := s.status, s.kid
			s.mu.Unlock()
			if status != http.StatusOK {
				w.WriteHeader(status)
				return
			}
			_, _ = fmt.Fprintf(w, `{"keys":[{"kid":%q,"kty":"RSA","n":"AQAB","e":"AQAB"}]}`, kid)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

// clockValidator builds a validator whose clock is the returned *time.Time.
func clockValidator(c cache.Cache) (*TokenValidator, *time.Time) {
	now := time.Now()
	cfg := &config.Config{Cache: &config.Cache{TTL: stateTestTTL}, AllowInsecureIssuers: true}
	return NewTokenValidator(config.NewStaticProvider(cfg), c, WithTimeNow(func() time.Time { return now })), &now
}

func TestJWKSCacheKey(t *testing.T) {
	const iss = "https://issuer.example.com"
	plain := newIssuerSpec(&config.IssuerConfig{Issuer: iss})
	a := newIssuerSpec(&config.IssuerConfig{Issuer: iss, JWKSURI: "https://staging.example.com/jwks"})
	b := newIssuerSpec(&config.IssuerConfig{Issuer: iss, JWKSURI: "https://prod.example.com/jwks"})
	a2 := newIssuerSpec(&config.IssuerConfig{Issuer: iss, JWKSURI: "https://staging.example.com/jwks"})

	assert.Equal(t, iss, jwksCacheKey(plain), "no override keeps the plain issuer key")
	assert.Equal(t, iss, jwksCacheKey(&issuerSpec{Issuer: iss}))
	assert.NotEqual(t, jwksCacheKey(a), jwksCacheKey(b), "specs differing only by override must not share a key")
	assert.NotEqual(t, iss, jwksCacheKey(a))
	assert.Equal(t, jwksCacheKey(a), jwksCacheKey(a2))
	assert.Equal(t, jwksCacheKey(a), jwksCacheKey(&issuerSpec{Issuer: iss, JWKSURI: a.JWKSURI}), "hand-built spec derives the same key")

	key := jwksCacheKey(a)
	require.True(t, strings.HasPrefix(key, iss+"|jwks_uri="))
	assert.Len(t, strings.TrimPrefix(key, iss+"|jwks_uri="), 16)
}

func TestFetchJWKS_OverrideChangeDoesNotReadOtherOverridesCache(t *testing.T) {
	srvA, srvB := newJWKSTestServer(t), newJWKSTestServer(t)
	srvB.set(http.StatusOK, "from-b")
	shared := cache.NewMemoryCache()
	v, _ := clockValidator(shared)
	const iss = "https://issuer.example.com"

	specA := newIssuerSpec(&config.IssuerConfig{Issuer: iss, JWKSURI: srvA.URL + "/jwks"})
	specB := newIssuerSpec(&config.IssuerConfig{Issuer: iss, JWKSURI: srvB.URL + "/jwks"})
	got, err := v.fetchJWKS(context.Background(), specA, false)
	require.NoError(t, err)
	assert.Equal(t, "k1", got.Keys[0].KeyID)
	_, planted := shared.Get(context.Background(), iss)
	assert.False(t, planted, "an override-sourced set must not land under the plain issuer key")

	got, err = v.fetchJWKS(context.Background(), specB, false)
	require.NoError(t, err)
	assert.Equal(t, "from-b", got.Keys[0].KeyID, "a changed override must fetch, not serve the old override's cache")
	assert.EqualValues(t, 1, srvB.jwksHits.Load())
}

func TestFetchJWKS_FailureMemo(t *testing.T) {
	for _, force := range []bool{false, true} {
		t.Run(fmt.Sprintf("force=%v", force), func(t *testing.T) {
			srv := newJWKSTestServer(t)
			srv.set(http.StatusInternalServerError, "")
			v, now := clockValidator(cache.NewMemoryCache())
			spec := newIssuerSpec(&config.IssuerConfig{Issuer: srv.URL})
			ctx := context.Background()

			_, err := v.fetchJWKS(ctx, spec, force)
			require.Error(t, err)
			require.EqualValues(t, 1, srv.jwksHits.Load())

			*now = now.Add(jwksFailureMemoTTL - time.Second)
			_, err2 := v.fetchJWKS(ctx, spec, force)
			require.Error(t, err2)
			assert.ErrorContains(t, err2, "skipped after recent failure")
			assert.ErrorContains(t, err2, "500", "wrapped error keeps the original cause")
			assert.EqualValues(t, 1, srv.jwksHits.Load(), "a fetch within the window must not reach the server")

			*now = now.Add(2 * time.Second)
			srv.set(http.StatusOK, "k1")
			_, err = v.fetchJWKS(ctx, spec, force)
			require.NoError(t, err)
			assert.EqualValues(t, 2, srv.jwksHits.Load(), "the fetch retries once the window passes")

			// Success clears the memo.
			srv.set(http.StatusInternalServerError, "")
			_, err = v.fetchJWKS(ctx, spec, true)
			require.Error(t, err)
			srv.set(http.StatusOK, "k1")
			*now = now.Add(jwksFailureMemoTTL)
			_, err = v.fetchJWKS(ctx, spec, true)
			require.NoError(t, err)
			_, err = v.fetchJWKS(ctx, spec, true)
			require.NoError(t, err, "a success leaves no failure behind")
		})
	}
}

func TestFetchJWKS_FailureMemoLeavesCachedKeysUnaffected(t *testing.T) {
	srv := newJWKSTestServer(t)
	c := cache.NewMemoryCache()
	v, _ := clockValidator(c)
	spec := newIssuerSpec(&config.IssuerConfig{Issuer: srv.URL})
	ctx := context.Background()

	_, err := v.fetchJWKS(ctx, spec, false)
	require.NoError(t, err)
	srv.set(http.StatusInternalServerError, "")
	_, err = v.fetchJWKS(ctx, spec, true)
	require.Error(t, err)

	got, err := v.fetchJWKS(ctx, spec, false)
	require.NoError(t, err, "a cache hit is served even during the failure window")
	assert.Equal(t, "k1", got.Keys[0].KeyID)
}

func TestFetchJWKS_FailureMemoIsPerCacheKey(t *testing.T) {
	srv := newJWKSTestServer(t)
	srv.set(http.StatusInternalServerError, "")
	other := newJWKSTestServer(t)
	v, _ := clockValidator(cache.NewMemoryCache())
	ctx := context.Background()

	_, err := v.fetchJWKS(ctx, newIssuerSpec(&config.IssuerConfig{Issuer: srv.URL}), false)
	require.Error(t, err)
	_, err = v.fetchJWKS(ctx, newIssuerSpec(&config.IssuerConfig{Issuer: other.URL}), false)
	require.NoError(t, err)
}

func TestFetchJWKS_DiscoveredURIMemoExpiresAfterCacheTTL(t *testing.T) {
	srv := newJWKSTestServer(t)
	v, now := clockValidator(cache.NewMemoryCache())
	spec := newIssuerSpec(&config.IssuerConfig{Issuer: srv.URL})
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		_, err := v.fetchJWKS(ctx, spec, true)
		require.NoError(t, err)
	}
	assert.EqualValues(t, 1, srv.discoveryHits.Load(), "forced refetches reuse the memoized jwks_uri")

	*now = now.Add(stateTestTTL - time.Second)
	_, err := v.fetchJWKS(ctx, spec, true)
	require.NoError(t, err)
	assert.EqualValues(t, 1, srv.discoveryHits.Load())

	*now = now.Add(2 * time.Second)
	_, err = v.fetchJWKS(ctx, spec, true)
	require.NoError(t, err)
	assert.EqualValues(t, 2, srv.discoveryHits.Load(), "discovery re-runs once the memo is older than the cache TTL")
	assert.EqualValues(t, 5, srv.jwksHits.Load())
}

func TestFetchJWKS_ForcedRefetchSkipsUnchangedWrite(t *testing.T) {
	srv := newJWKSTestServer(t)
	cc := &countingCache{Cache: cache.NewMemoryCache()}
	v, now := clockValidator(cc)
	spec := newIssuerSpec(&config.IssuerConfig{Issuer: srv.URL})
	ctx := context.Background()
	fetch := func(force bool) {
		t.Helper()
		_, err := v.fetchJWKS(ctx, spec, force)
		require.NoError(t, err)
	}

	fetch(false)
	require.EqualValues(t, 1, cc.sets.Load(), "a cold fetch always writes")

	fetch(true)
	fetch(true)
	assert.EqualValues(t, 1, cc.sets.Load(), "forced refetches of an unchanged key set skip the write")

	srv.set(http.StatusOK, "k2")
	fetch(true)
	assert.EqualValues(t, 2, cc.sets.Load(), "a changed key set is written")
	got, ok := cc.Get(ctx, srv.URL)
	require.True(t, ok)
	assert.Equal(t, "k2", got.Keys[0].KeyID)

	fetch(true)
	assert.EqualValues(t, 2, cc.sets.Load())

	*now = now.Add(stateTestTTL/2 + time.Second)
	fetch(true)
	assert.EqualValues(t, 3, cc.sets.Load(), "past half the TTL an unchanged set is rewritten to extend its expiry")
	fetch(true)
	assert.EqualValues(t, 3, cc.sets.Load())
}

func TestFetchJWKS_UnchangedWriteStillRepopulatesAnEvictedCache(t *testing.T) {
	srv := newJWKSTestServer(t)
	mem := cache.NewMemoryCache(cache.WithMemoryMaxSize(1))
	cc := &countingCache{Cache: mem}
	v, _ := clockValidator(cc)
	spec := newIssuerSpec(&config.IssuerConfig{Issuer: srv.URL})
	ctx := context.Background()

	_, err := v.fetchJWKS(ctx, spec, false)
	require.NoError(t, err)
	mem.Set(ctx, "evictor", &types.JWKS{Keys: []types.JSONWebKey{{KeyID: "x"}}}, time.Minute) // evicts the entry (size 1)
	before := cc.sets.Load()

	_, err = v.fetchJWKS(ctx, spec, true)
	require.NoError(t, err)
	assert.Equal(t, before+1, cc.sets.Load(), "an entry no longer cached is written even if the hash matches")
}
