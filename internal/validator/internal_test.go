package validator

// Unit tests for unexported hardening internals: SSRF dial-time IP blocking
// and redirect re-validation (ssrf.go), the per-(issuer,kid) forced-refetch
// limiter (refetch_limiter.go), and the in-process key memo (keymemo.go).
// These live in-package (not validator_test) because they exercise
// unexported helpers directly rather than through the public
// TokenValidatorInterface.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsBlockedIP(t *testing.T) {
	tests := []struct {
		name          string
		ip            string
		allowLoopback bool
		wantBlocked   bool
	}{
		{"public IP allowed", "8.8.8.8", false, false},
		{"metadata address blocked", "169.254.169.254", false, true},
		{"metadata address blocked even with allowLoopback", "169.254.169.254", true, true},
		{"private 10.x blocked", "10.0.0.1", false, true},
		{"private 192.168.x blocked", "192.168.1.1", false, true},
		{"loopback blocked by default", "127.0.0.1", false, true},
		{"loopback allowed under allowLoopback", "127.0.0.1", true, false},
		{"IPv6 loopback blocked by default", "::1", false, true},
		{"IPv6 loopback allowed under allowLoopback", "::1", true, false},
		{"unspecified blocked", "0.0.0.0", false, true},
		{"multicast blocked", "224.0.0.1", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			require.NotNil(t, ip)
			assert.Equal(t, tt.wantBlocked, isBlockedIP(ip, tt.allowLoopback))
		})
	}
}

func TestIsBlockedIP_NilRejected(t *testing.T) {
	assert.True(t, isBlockedIP(nil, true))
}

func TestRequireSecureURL(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		allowInsecure bool
		wantErr       bool
	}{
		{"https always allowed", "https://issuer.example.com", false, false},
		{"https allowed even without allowInsecure", "https://issuer.example.com", true, false},
		{"http rejected by default", "http://127.0.0.1:8080", false, true},
		{"http loopback allowed under allowInsecure", "http://127.0.0.1:8080", true, false},
		{"http localhost allowed under allowInsecure", "http://localhost:8080", true, false},
		{"http non-loopback rejected even under allowInsecure", "http://token.example.com", true, true},
		{"http non-loopback rejected by default", "http://token.example.com", false, true},
		{"malformed URL rejected", "://not-a-url", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := requireSecureURL(tt.url, tt.allowInsecure)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestSecureHTTPClient_RedirectToNonLoopbackHTTPRejected verifies the
// CheckRedirect hook re-validates each redirect hop: a loopback server (which
// itself passes requireSecureURL under allowInsecureIssuers) redirecting to a
// plain-HTTP, non-loopback host must be rejected rather than followed.
func TestSecureHTTPClient_RedirectToNonLoopbackHTTPRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer server.Close()

	client := newSecureHTTPClient(true, 2*time.Second)
	resp, err := client.Get(server.URL)
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirect target rejected")
}

// TestSecureHTTPClient_RedirectCapEnforced verifies a redirect chain longer
// than maxJWKSRedirects is stopped, even when every hop individually passes
// requireSecureURL (all loopback, under allowInsecureIssuers).
func TestSecureHTTPClient_RedirectCapEnforced(t *testing.T) {
	var handler http.HandlerFunc
	mux := http.NewServeMux()
	hops := 0
	handler = func(w http.ResponseWriter, r *http.Request) {
		hops++
		http.Redirect(w, r, r.URL.Path+"x", http.StatusFound)
	}
	mux.HandleFunc("/", handler)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newSecureHTTPClient(true, 2*time.Second)
	resp, err := client.Get(server.URL + "/start")
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stopped after")
	assert.GreaterOrEqual(t, hops, maxJWKSRedirects)
}

func TestRefetchLimiter_NewKidAlwaysAllowedOnce(t *testing.T) {
	now := time.Now()
	l := newRefetchLimiter(func() time.Time { return now }, time.Minute)

	assert.True(t, l.allow("issuer-a", "kid-1"), "a never-seen kid must be allowed on its first refetch")
}

func TestRefetchLimiter_SameKidThrottledWithinCooldown(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	l := newRefetchLimiter(clock, time.Minute)

	require.True(t, l.allow("issuer-a", "kid-1"))
	assert.False(t, l.allow("issuer-a", "kid-1"), "repeated refetch for the same kid within the cooldown must be denied")

	now = now.Add(2 * time.Minute)
	assert.True(t, l.allow("issuer-a", "kid-1"), "refetch must be allowed again once the cooldown has elapsed")
}

func TestRefetchLimiter_FloodOfDistinctBogusKidsBoundedByIssuerBackstop(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	l := newRefetchLimiter(clock, time.Minute)

	allowed := 0
	for i := 0; i < 50; i++ {
		if l.allow("issuer-a", fmt.Sprintf("bogus-kid-%d", i)) {
			allowed++
		}
	}
	// Every kid is distinct (never seen before), so the per-kid cooldown
	// never fires; only the per-issuer backstop can bound the flood.
	assert.Equal(t, 1, allowed, "a flood of distinct bogus kids for one issuer must be bounded by the per-issuer backstop")
}

func TestRefetchLimiter_RotationAcrossDifferentIssuersIndependent(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	l := newRefetchLimiter(clock, time.Minute)

	require.True(t, l.allow("issuer-a", "kid-1"))
	assert.True(t, l.allow("issuer-b", "kid-1"), "the same kid string under a different issuer must not be throttled by issuer-a's state")
}

func TestRefetchLimiter_NonPositiveCooldownFallsBackToDefault(t *testing.T) {
	l := newRefetchLimiter(time.Now, 0)
	assert.Equal(t, defaultRefetchKeyCooldown, l.keyCooldown)

	l = newRefetchLimiter(time.Now, -5*time.Second)
	assert.Equal(t, defaultRefetchKeyCooldown, l.keyCooldown)
}

func TestKeyMemo_StoreAndLoadRoundTrip(t *testing.T) {
	m := newKeyMemo()
	_, ok := m.load("fp-1")
	assert.False(t, ok)

	m.store("fp-1", "some-key")
	got, ok := m.load("fp-1")
	require.True(t, ok)
	assert.Equal(t, "some-key", got)
}

// TestALBKeyCache_OverflowClearsMap verifies the ALB public-key success
// cache is bounded: once it holds maxALBKeyCacheEntries distinct kids, adding
// one more clears the map first (mirroring keyMemo's overflow-clear pattern)
// rather than growing unboundedly, so a flood of distinct kids can only cost
// re-fetches, never unbounded memory.
func TestALBKeyCache_OverflowClearsMap(t *testing.T) {
	var c albKeyCache
	key := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(2)}

	for i := 0; i < maxALBKeyCacheEntries; i++ {
		c.set(fmt.Sprintf("kid-%d", i), key)
	}
	assert.Equal(t, maxALBKeyCacheEntries, len(c.entries), "cache should be exactly at capacity")

	// First kid must still be present before the overflow insert.
	_, ok := c.get("kid-0")
	assert.True(t, ok)

	c.set("kid-overflow", key)
	assert.Equal(t, 1, len(c.entries), "hitting the cap must clear the map before inserting the new entry")
	_, ok = c.get("kid-0")
	assert.False(t, ok, "the overflow clear must have evicted the earlier entries")
	_, ok = c.get("kid-overflow")
	assert.True(t, ok, "the entry that triggered the overflow must still be cached")
}

func rsaJWK(kid, n, e string) types.JSONWebKey {
	return types.JSONWebKey{KeyID: kid, KeyType: "RSA", N: n, E: e}
}

func TestKeyFingerprint_DiffersOnRotatedKeyMaterialUnderReusedKid(t *testing.T) {
	oldFP := keyFingerprint("issuer-a", rsaJWK("reused-kid", "old-n", "AQAB"))
	newFP := keyFingerprint("issuer-a", rsaJWK("reused-kid", "new-n", "AQAB"))
	assert.NotEqual(t, oldFP, newFP, "rotating the key material under a reused kid must produce a different fingerprint")
}

func TestKeyFingerprint_DiffersAcrossIssuers(t *testing.T) {
	fpA := keyFingerprint("issuer-a", rsaJWK("k1", "same-n", "AQAB"))
	fpB := keyFingerprint("issuer-b", rsaJWK("k1", "same-n", "AQAB"))
	assert.NotEqual(t, fpA, fpB, "the same kid/material from a different issuer must not collide")
}

// TestParseRSAKey_ExponentValidation guards against a malformed/oversized "e"
// silently truncating through big.Int.Int64()->int (e.g. a 9-byte exponent
// yields a negative int, which crypto/rsa would otherwise accept as a public
// exponent). A real RSA public exponent is tiny (65537 is 3 bytes), so a sane
// exponent must decode to <= 4 bytes, be >= 3, and be odd.
func TestParseRSAKey_ExponentValidation(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	n := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())

	encodeE := func(b ...byte) string {
		return base64.RawURLEncoding.EncodeToString(b)
	}

	tests := []struct {
		name    string
		e       string
		wantErr bool
	}{
		{"E=1 rejected (below minimum)", encodeE(1), true},
		{"E=2 rejected (even)", encodeE(2), true},
		{"oversized 9-byte exponent rejected", encodeE(1, 2, 3, 4, 5, 6, 7, 8, 9), true},
		{"E=65537 accepted", encodeE(1, 0, 1), false},
		{"E=3 accepted", encodeE(3), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := types.JSONWebKey{KeyID: "k", KeyType: "RSA", N: n, E: tt.e}
			_, err := parseRSAKey(key)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
