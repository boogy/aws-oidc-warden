package validator

// Unexported internals: claim normalization shared by the delegated
// extractors, and the SSRF guard's redirect/depth limits.
import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/cache"
	"github.com/boogy/aws-oidc-warden/internal/config"
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
	jwk := rsaJWK("k1", "n", "AQAB")
	_, ok := m.load("iss", jwk)
	assert.False(t, ok)

	m.store("iss", jwk, "some-key")
	got, ok := m.load("iss", jwk)
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
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key := &priv.PublicKey

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

func TestKeyMemo_MissesOnAnyChangedKeyMaterial(t *testing.T) {
	base := types.JSONWebKey{KeyID: "k", KeyType: "EC", Crv: "P-256", X: "x", Y: "y"}
	rsa := rsaJWK("k", "n", "AQAB")
	tests := []struct {
		name   string
		stored types.JSONWebKey
		probe  types.JSONWebKey
		want   bool
	}{
		{"identical EC", base, base, true},
		{"identical RSA", rsa, rsa, true},
		{"rotated RSA modulus under reused kid", rsa, rsaJWK("k", "n2", "AQAB"), false},
		{"changed RSA exponent", rsa, rsaJWK("k", "n", "Aw"), false},
		{"changed EC x", base, types.JSONWebKey{KeyID: "k", KeyType: "EC", Crv: "P-256", X: "x2", Y: "y"}, false},
		{"changed EC y", base, types.JSONWebKey{KeyID: "k", KeyType: "EC", Crv: "P-256", X: "x", Y: "y2"}, false},
		{"changed EC curve", base, types.JSONWebKey{KeyID: "k", KeyType: "EC", Crv: "P-384", X: "x", Y: "y"}, false},
		{"changed key type", base, types.JSONWebKey{KeyID: "k", KeyType: "RSA", Crv: "P-256", X: "x", Y: "y"}, false},
		{"different kid", base, types.JSONWebKey{KeyID: "other", KeyType: "EC", Crv: "P-256", X: "x", Y: "y"}, false},
		{"use/alg do not affect the parsed key", base, types.JSONWebKey{KeyID: "k", KeyType: "EC", Crv: "P-256", X: "x", Y: "y", Use: "sig", Algorithm: "ES256"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newKeyMemo()
			m.store("iss", tt.stored, "stored-key")
			_, ok := m.load("iss", tt.probe)
			assert.Equal(t, tt.want, ok)
		})
	}
}

func TestKeyMemo_IsolatedAcrossIssuers(t *testing.T) {
	m := newKeyMemo()
	jwk := rsaJWK("k1", "same-n", "AQAB")
	m.store("issuer-a", jwk, "key-a")
	_, ok := m.load("issuer-b", jwk)
	assert.False(t, ok, "the same kid/material from a different issuer must not collide")
}

func TestKeyMemo_RestoreUnderReusedKidReplacesEntryWithoutGrowing(t *testing.T) {
	m := newKeyMemo()
	m.store("iss", rsaJWK("k", "old", "AQAB"), "old-key")
	m.store("iss", rsaJWK("k", "new", "AQAB"), "new-key")
	assert.EqualValues(t, 1, m.size.Load())
	_, ok := m.load("iss", rsaJWK("k", "old", "AQAB"))
	assert.False(t, ok)
	got, ok := m.load("iss", rsaJWK("k", "new", "AQAB"))
	require.True(t, ok)
	assert.Equal(t, "new-key", got)
}

func TestKeyMemo_SizeBoundClearsOnOverflow(t *testing.T) {
	m := newKeyMemo()
	for i := 0; i < maxKeyMemoEntries; i++ {
		m.store("iss", rsaJWK(fmt.Sprintf("k%d", i), "n", "AQAB"), i)
	}
	assert.EqualValues(t, maxKeyMemoEntries, m.size.Load())
	m.store("iss", rsaJWK("overflow", "n", "AQAB"), "x")
	assert.EqualValues(t, 1, m.size.Load())
	_, ok := m.load("iss", rsaJWK("k0", "n", "AQAB"))
	assert.False(t, ok)
	_, ok = m.load("iss", rsaJWK("overflow", "n", "AQAB"))
	assert.True(t, ok)
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

// ---------- delegated claim normalization ----------

func twoIssuerConfig() *config.Config {
	leeway := 30 * time.Second
	return &config.Config{
		RoleSessionName: "test",
		JWTLeeway:       &leeway,
		Issuers: []config.IssuerConfig{
			{
				Issuer:         "https://token.actions.githubusercontent.com",
				Provider:       "github",
				Audiences:      []string{"sts.amazonaws.com"},
				RequiredClaims: []string{"repository"},
			},
			{
				Issuer:         "https://gitlab.com",
				Provider:       "generic",
				Audiences:      []string{"aws-oidc-warden"},
				ClaimMappings:  map[string]string{"subject": "project_path"},
				RequiredClaims: []string{"project_path"},
			},
		},
	}
}

// resolveIssuerSpec must return the spec belonging to the requested issuer —
// never the first entry, and never a merged view of both.
func TestResolveIssuerSpec_SelectsMatchingIssuer(t *testing.T) {
	cfg := twoIssuerConfig()

	spec, bounds, err := resolveIssuerSpec(cfg, "https://gitlab.com")
	require.NoError(t, err)
	assert.Equal(t, "generic", spec.Provider)
	assert.Equal(t, []string{"aws-oidc-warden"}, spec.Audiences)
	assert.Equal(t, map[string]string{"subject": "project_path"}, spec.ClaimMappings)
	assert.Equal(t, 30*time.Second, bounds.leeway)

	spec, _, err = resolveIssuerSpec(cfg, "https://token.actions.githubusercontent.com")
	require.NoError(t, err)
	assert.Equal(t, "github", spec.Provider)
	assert.Equal(t, []string{"sts.amazonaws.com"}, spec.Audiences)
}

// An issuer with no config entry must fail closed with ErrUnknownIssuer — the
// same sentinel self mode uses (validator.go:288) — and must not fall back to
// any other issuer's spec.
func TestResolveIssuerSpec_UnknownIssuerFailsClosed(t *testing.T) {
	cfg := twoIssuerConfig()

	spec, _, err := resolveIssuerSpec(cfg, "https://evil.example.com")
	require.ErrorIs(t, err, ErrUnknownIssuer)
	assert.Nil(t, spec)
}

// Exact matching only: no normalization of trailing slashes or case, matching
// config.Validate's duplicate-issuer semantics.
func TestResolveIssuerSpec_ExactMatchOnly(t *testing.T) {
	cfg := twoIssuerConfig()

	_, _, err := resolveIssuerSpec(cfg, "https://gitlab.com/")
	require.ErrorIs(t, err, ErrUnknownIssuer)

	_, _, err = resolveIssuerSpec(cfg, "https://GitLab.com")
	require.ErrorIs(t, err, ErrUnknownIssuer)
}

// ---------- SSRF guard ----------

// A redirect to https://169.254.169.254/ passes the scheme check (it IS https),
// so if it is refused at all the refusal must come from the dialer. That is
// what makes the guard rebinding-proof rather than name-based.
func TestSSRFGuard_RedirectToHTTPSMetadataBlockedAtDial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://169.254.169.254/latest/meta-data/iam/security-credentials/", http.StatusFound)
	}))
	defer server.Close()

	client := newSecureHTTPClient(true, 2*time.Second)
	resp, err := client.Get(server.URL)
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	if err == nil {
		t.Fatalf("https redirect to IMDS was FOLLOWED, status=%d", resp.StatusCode)
	}
	if got := err.Error(); !contains(got, "blocked") {
		t.Fatalf("expected a dial-time block, got: %s", got)
	}
}

// Same question for RFC1918, loopback, IPv6 ULA and IPv6 link-local reached via
// redirect. allowInsecure=true here ONLY so the httptest server on 127.0.0.1 is
// itself dialable — the block on these targets must not depend on that flag.
func TestSSRFGuard_RedirectToPrivateAndLinkLocalBlocked(t *testing.T) {
	for _, target := range []string{
		"https://10.0.0.1/",
		"https://192.168.1.1/",
		"https://127.0.0.1/",
		"https://[::1]/",
		"https://[fd00:ec2::254]/", // EC2 IMDS over IPv6
	} {
		t.Run(target, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target, http.StatusFound)
			}))
			defer server.Close()

			client := newSecureHTTPClient(true, 2*time.Second)
			resp, err := client.Get(server.URL)
			if resp != nil {
				defer func() { _ = resp.Body.Close() }()
			}
			if err == nil {
				t.Fatalf("redirect to %s was followed", target)
			}
		})
	}
}

// isBlockedIP must reject the IPv4-mapped IPv6 encodings of blocked ranges —
// ::ffff:127.0.0.1 is the classic bypass for a guard that only compares the
// 4-byte form.
func TestSSRFGuard_IsBlockedIP_V4MappedFormsBlocked(t *testing.T) {
	for _, s := range []string{
		"::ffff:127.0.0.1",
		"::ffff:169.254.169.254",
		"::ffff:10.0.0.1",
		"::ffff:192.168.1.1",
		"::ffff:0.0.0.0",
		"fd00:ec2::254",
		"fe80::1",
	} {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("unparseable: %s", s)
		}
		// allowLoopback=false is the production posture.
		if !isBlockedIP(ip, false) {
			t.Errorf("%s must be blocked in production posture", s)
		}
	}
}

// Ranges the guard previously did not classify: IPv6 forms that carry an IPv4
// destination the stdlib helpers see through only for ::ffff:, plus the two
// private-by-definition IPv4 ranges outside RFC1918. None was exploitable
// (reaching any required controlling DNS for an already-trusted issuer, and the
// IPv4-compatible forms are unroutable), but the guard already blocks RFC1918,
// so leaving these open was an inconsistency rather than a considered exception.
func TestSSRFGuard_IsBlockedIP_CarrierAndReservedRangesBlocked(t *testing.T) {
	for _, s := range []string{
		"::169.254.169.254",  // IPv4-compatible IPv6 carrying the metadata address
		"64:ff9b::a9fe:a9fe", // NAT64 prefix carrying 169.254.169.254
		"64:ff9b::a00:1",     // NAT64 prefix carrying 10.0.0.1
		"100.64.0.1",         // CGNAT / RFC6598 shared address space
		"100.127.255.255",    // CGNAT upper bound
		"0.0.0.1",            // 0.0.0.0/8 "this network"
	} {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("unparseable: %s", s)
		}
		if !isBlockedIP(ip, false) {
			t.Errorf("%s must be blocked in production posture", s)
		}
	}
}

// The carrier-form handling must not over-block: an address that merely
// resembles a carrier prefix, and ordinary public addresses, stay reachable.
// 100.128.0.1 and 99.255.255.255 sit just outside 100.64.0.0/10 in both
// directions — the classic off-by-one on a /10 mask.
func TestSSRFGuard_IsBlockedIP_PublicAddressesNotOverBlocked(t *testing.T) {
	for _, s := range []string{
		"140.82.121.4",    // github.com
		"8.8.8.8",         // public resolver
		"100.128.0.1",     // just above 100.64.0.0/10
		"99.255.255.255",  // just below 100.64.0.0/10
		"2606:4700::1111", // public IPv6
		"64:ff9c::1",      // NOT the NAT64 well-known prefix (64:ff9b)
	} {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("unparseable: %s", s)
		}
		if isBlockedIP(ip, false) {
			t.Errorf("%s must NOT be blocked — over-blocking breaks legitimate issuers", s)
		}
	}
}

// An OIDC discovery document may legitimately host its JWKS on a different
// domain (Google and others do), so a cross-host jwks_uri is fetched by design.
// This pins that: the containment property is the dial-time IP guard above,
// which still applies to the second host — NOT a same-host restriction.
func TestSSRFGuard_DiscoveryJWKSURIMayHostSwap(t *testing.T) {
	hit := make(chan string, 4)

	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit <- r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[{"kty":"RSA","kid":"k","n":"AQAB","e":"AQAB"}]}`))
	}))
	defer jwksSrv.Close()

	var issuerURL string
	issuerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, issuerURL, jwksSrv.URL+"/other-host-jwks")
	}))
	defer issuerSrv.Close()
	issuerURL = issuerSrv.URL

	v := ssrfTestValidator(true)
	if _, err := v.FetchJWKS(context.Background(), issuerURL); err != nil {
		t.Fatalf("FetchJWKS: %v", err)
	}
	select {
	case p := <-hit:
		if p != "/other-host-jwks" {
			t.Fatalf("unexpected jwks path %q", p)
		}
	default:
		t.Fatal("cross-host jwks_uri was not fetched; discovery host-swap behavior changed")
	}
}

func ssrfTestValidator(allowInsecure bool) *TokenValidator {
	cfg := &config.Config{
		Cache:                &config.Cache{TTL: time.Minute},
		AllowInsecureIssuers: allowInsecure,
	}
	return NewTokenValidator(config.NewStaticProvider(cfg), cache.NewMemoryCache())
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestSnapshotForNeverServesAnotherConfigsRegistry guards the atomicity of the
// snapshot/config-identity pair.
//
// The registry and the identity of the config it was built from must be
// published by ONE atomic store. When they were two — snap.Store(snap) then
// builtFrom.Store(cfg) — a goroutine preempted between them let a second
// goroutine publish its own pair in between, leaving the registry built from
// config B labelled as built from config A. The fast path then handed B's
// issuer specs to any caller holding A: the wrong audience set and the wrong
// claim_mappings, so a token could be checked against an audience the operator
// had just removed, or its canonical subject derived by the wrong mapping.
// In-flight requests hold the previous config pointer across a hot reload, so
// that state is reachable in production, not only in a stress test.
//
// Alternating two config pointers under concurrency is the cheapest way to
// keep the publish path contended. Every caller must get back a registry built
// from the exact config it passed.
func TestSnapshotForNeverServesAnotherConfigsRegistry(t *testing.T) {
	cfgA := &config.Config{Issuers: []config.IssuerConfig{{Issuer: "https://a.example"}}}
	cfgB := &config.Config{Issuers: []config.IssuerConfig{{Issuer: "https://b.example"}}}
	want := map[*config.Config]string{cfgA: "https://a.example", cfgB: "https://b.example"}

	v := &TokenValidator{}
	var mu sync.Mutex
	var mismatched int

	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for n := range 1000 {
				cfg := cfgA
				if (i+n)%2 == 0 {
					cfg = cfgB
				}
				if _, ok := v.snapshotFor(cfg).registry[want[cfg]]; !ok {
					mu.Lock()
					mismatched++
					mu.Unlock()
				}
			}
		}(i)
	}
	wg.Wait()

	if mismatched > 0 {
		t.Errorf("%d callers were served a registry built from a different config", mismatched)
	}
}

// stubPinnedValidator records which config generation actually decided the
// token. It implements TokenValidatorInterface AND the unexported
// pinnedValidator seam, so it exercises the same dispatch *TokenValidator does.
type stubPinnedValidator struct {
	provider *config.Provider
	sawCfg   func(*config.Config)
}

func (s *stubPinnedValidator) Validate(context.Context, string) (*types.Claims, error) {
	// The unpinned path: a second, independent read of the provider — exactly
	// what every extractor did before ExtractionInput.Config existed.
	s.sawCfg(s.provider.Get())
	return &types.Claims{}, nil
}

func (s *stubPinnedValidator) validateWith(_ context.Context, cfg *config.Config, _ string) (*types.Claims, error) {
	s.sawCfg(cfg)
	return &types.Claims{}, nil
}

// TestSelfExtractorIsDecidedByThePinnedConfig is the cross-stage drift guard.
//
// A request captures one config generation for authorization and must have its
// token decided by that same generation. When extraction re-read the provider
// instead, a reload landing between the two reads split one request across two
// generations: validated by N+1's issuers/audiences/claim mappings, authorized
// by N's role mappings. A refresh that widens validation while narrowing
// authorization then authorizes a caller neither generation allows alone.
//
// The refresh here is driven directly rather than raced, so the test fails
// deterministically rather than by scheduling luck.
func TestSelfExtractorIsDecidedByThePinnedConfig(t *testing.T) {
	pinned := &config.Config{Issuers: []config.IssuerConfig{{Issuer: "https://pinned.example"}}}
	swapped := &config.Config{Issuers: []config.IssuerConfig{{Issuer: "https://swapped.example"}}}

	provider := config.NewProvider(swapped, 0, "yaml", nil)

	var got *config.Config
	ext := NewSelfExtractor(&stubPinnedValidator{
		provider: provider,
		sawCfg:   func(c *config.Config) { got = c },
	})

	// The provider has already moved on to `swapped`; the request pinned
	// `pinned` before that happened.
	if _, err := ext.Extract(context.Background(), ExtractionInput{
		Token:  "any.token.value",
		Config: pinned,
	}); err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if got != pinned {
		t.Errorf("token was decided by the provider's current config, not the config the request pinned; "+
			"got issuers %v, want %v", got.Issuers, pinned.Issuers)
	}
}

// TestSelfExtractorFallsBackWhenNoConfigPinned keeps the seam optional: a
// caller that builds an input by hand, and every external mock of
// TokenValidatorInterface, must still work through plain Validate.
func TestSelfExtractorFallsBackWhenNoConfigPinned(t *testing.T) {
	current := &config.Config{Issuers: []config.IssuerConfig{{Issuer: "https://current.example"}}}
	provider := config.NewProvider(current, 0, "yaml", nil)

	var got *config.Config
	ext := NewSelfExtractor(&stubPinnedValidator{
		provider: provider,
		sawCfg:   func(c *config.Config) { got = c },
	})

	if _, err := ext.Extract(context.Background(), ExtractionInput{Token: "any.token.value"}); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if got != current {
		t.Errorf("unpinned extraction should read the provider; got %v", got)
	}
}

func TestALBKeyCache_GetDropsExpiredEntry(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	c := albKeyCache{entries: map[string]albKeyCacheEntry{
		"live":    {key: &priv.PublicKey, expiresAt: time.Now().Add(time.Minute)},
		"expired": {key: &priv.PublicKey, expiresAt: time.Now().Add(-time.Second)},
	}}

	_, ok := c.get("live")
	assert.True(t, ok)
	_, ok = c.get("expired")
	assert.False(t, ok)
	assert.NotContains(t, c.entries, "expired")
	_, ok = c.get("absent")
	assert.False(t, ok)
}

func TestALBKeyCache_ConcurrentGetSet(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var c albKeyCache
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				c.set("k", &priv.PublicKey)
				c.get("k")
			}
		}()
	}
	wg.Wait()
}

func TestIsBlockedAddr_ReservedRanges(t *testing.T) {
	tests := []struct {
		addr        string
		wantBlocked bool
	}{
		// 0.0.0.0/8
		{"0.0.0.0", true}, {"0.255.255.255", true}, {"1.0.0.0", false},
		// 100.64.0.0/10
		{"100.63.255.255", false}, {"100.64.0.0", true}, {"100.127.255.255", true}, {"100.128.0.0", false},
		// 192.0.0.0/24, 192.0.2.0/24
		{"191.255.255.255", false}, {"192.0.0.0", true}, {"192.0.0.255", true}, {"192.0.1.0", false},
		{"192.0.2.0", true}, {"192.0.2.255", true}, {"192.0.3.0", false},
		// 198.18.0.0/15, 198.51.100.0/24
		{"198.17.255.255", false}, {"198.18.0.0", true}, {"198.19.255.255", true}, {"198.20.0.0", false},
		{"198.51.99.255", false}, {"198.51.100.0", true}, {"198.51.100.255", true}, {"198.51.101.0", false},
		// 203.0.113.0/24
		{"203.0.112.255", false}, {"203.0.113.0", true}, {"203.0.113.255", true}, {"203.0.114.0", false},
		// 240.0.0.0/4 and broadcast
		{"239.255.255.255", true}, // multicast
		{"240.0.0.0", true}, {"254.255.255.255", true}, {"255.255.255.255", true},
		// existing classes still blocked
		{"10.1.2.3", true}, {"172.16.0.1", true}, {"172.32.0.1", false}, {"192.168.0.1", true},
		{"169.254.169.254", true}, {"224.0.0.1", true},
		// public
		{"8.8.8.8", false}, {"140.82.121.4", false},
		// IPv6
		{"64:ff9b::1", true}, {"64:ff9b::808:808", true}, {"64:ff9b:1::1", false}, {"64:ff9c::1", false},
		{"2001:db8::1", true}, {"2001:db8:ffff::1", true}, {"2001:db9::1", false},
		{"fc00::1", true}, {"fd12:3456::1", true}, {"fe00::1", false},
		{"fe80::1", true}, {"ff02::1", true}, {"::", true},
		{"2606:4700::1111", false},
		// v4-mapped and v4-compatible carriers of reserved IPv4
		{"::ffff:100.64.0.1", true}, {"::ffff:198.18.0.1", true}, {"::ffff:8.8.8.8", false},
		{"::100.64.0.1", true}, {"::8.8.8.8", false}, {"::198.51.100.1", true},
		// zone is ignored
		{"fe80::1%eth0", true}, {"2606:4700::1111%eth0", false},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			addr, err := netip.ParseAddr(tt.addr)
			require.NoError(t, err)
			assert.Equal(t, tt.wantBlocked, isBlockedAddr(addr, false))
			// Loopback is the only thing allowLoopback may relax.
			assert.Equal(t, tt.wantBlocked, isBlockedAddr(addr, true))
		})
	}
}

func TestIsBlockedAddr_Loopback(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "127.255.255.254", "::1", "::ffff:127.0.0.1"} {
		addr := netip.MustParseAddr(s)
		assert.True(t, isBlockedAddr(addr, false), s)
		assert.False(t, isBlockedAddr(addr, true), s)
	}
	assert.True(t, isBlockedAddr(netip.Addr{}, true), "zero Addr must be blocked")
}

func TestBlockedDialControl(t *testing.T) {
	tests := []struct {
		name          string
		address       string
		allowLoopback bool
		wantErr       string
	}{
		{"public v4", "8.8.8.8:443", false, ""},
		{"public v6", "[2606:4700::1111]:443", false, ""},
		{"metadata", "169.254.169.254:80", false, "blocked"},
		{"metadata allowLoopback", "169.254.169.254:80", true, "blocked"},
		{"private", "10.0.0.1:443", false, "blocked"},
		{"cgnat", "100.64.0.1:443", false, "blocked"},
		{"v4-mapped private", "[::ffff:10.0.0.1]:443", false, "blocked"},
		{"ula", "[fd00:ec2::254]:443", false, "blocked"},
		{"loopback blocked", "127.0.0.1:8080", false, "blocked"},
		{"loopback allowed", "127.0.0.1:8080", true, ""},
		{"v6 loopback allowed", "[::1]:8080", true, ""},
		{"zoned link-local", "[fe80::1%eth0]:443", false, "blocked"},
		{"no port", "8.8.8.8", false, "invalid dial address"},
		{"hostname not an ip", "example.com:443", false, "invalid dial address"},
		{"empty", "", false, "invalid dial address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := blockedDialControl(tt.allowLoopback)("tcp", tt.address, nil)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestSecureHTTPClient_NeverUsesEnvironmentProxy(t *testing.T) {
	tr, ok := newSecureHTTPClient(false, time.Second).Transport.(*http.Transport)
	require.True(t, ok)
	assert.Nil(t, tr.Proxy)
}

// Hostname targets are vetted after resolution, not by name.
func TestSecureHTTPClient_HostnameResolvingToBlockedIPRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)

	resp, err := newSecureHTTPClient(false, 2*time.Second).Get("http://localhost:" + port + "/")
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blocked")
}

// The standard dialer tries every resolved address: localhost may list ::1
// first while the server listens on 127.0.0.1 only.
func TestSecureHTTPClient_HostnameFallsThroughToLaterAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)

	resp, err := newSecureHTTPClient(true, 2*time.Second).Get("http://localhost:" + port + "/")
	require.NoError(t, err)
	_ = resp.Body.Close()
}

func TestSecureHTTPClient_LiteralBlockedIPTargetsRefused(t *testing.T) {
	client := newSecureHTTPClient(false, time.Second)
	// IPv6 targets are covered via blockedDialControl: on a host without IPv6
	// the socket() call fails before the control hook runs.
	for _, target := range []string{
		"https://169.254.169.254/", "https://10.0.0.1/", "https://100.64.0.1/", "https://198.18.0.1/",
		"https://[::ffff:10.0.0.1]/",
	} {
		t.Run(target, func(t *testing.T) {
			resp, err := client.Get(target)
			if resp != nil {
				_ = resp.Body.Close()
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), "blocked")
		})
	}
	for _, target := range []string{"https://[::1]/", "https://[64:ff9b::a00:1]/", "https://[fd00:ec2::254]/"} {
		t.Run(target, func(t *testing.T) {
			resp, err := client.Get(target)
			if resp != nil {
				_ = resp.Body.Close()
			}
			require.Error(t, err)
		})
	}
}

func BenchmarkResolveKey_CacheHit(b *testing.B) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(b, err)
	jwk := types.JSONWebKey{
		KeyID: "kid-1", KeyType: "RSA", Use: "sig", Algorithm: "RS256",
		N: base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
	}
	v := ssrfTestValidator(false)
	const issuer = "https://token.actions.githubusercontent.com"
	_, err = v.resolveKey(issuer, jwk)
	require.NoError(b, err)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := v.resolveKey(issuer, jwk); err != nil {
			b.Fatal(err)
		}
	}
}

func TestResolveKey_RotationUnderReusedKidReparses(t *testing.T) {
	v := ssrfTestValidator(false)
	jwkOf := func(k *rsa.PrivateKey) types.JSONWebKey {
		return rsaJWK("reused", base64.RawURLEncoding.EncodeToString(k.N.Bytes()), "AQAB")
	}
	oldPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	newPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	got, err := v.resolveKey("iss", jwkOf(oldPriv))
	require.NoError(t, err)
	assert.True(t, oldPriv.PublicKey.Equal(got))
	got, err = v.resolveKey("iss", jwkOf(newPriv))
	require.NoError(t, err)
	assert.True(t, newPriv.PublicKey.Equal(got), "rotated material under a reused kid must not serve the stale key")
	got, err = v.resolveKey("iss", jwkOf(newPriv))
	require.NoError(t, err)
	assert.True(t, newPriv.PublicKey.Equal(got))
}
