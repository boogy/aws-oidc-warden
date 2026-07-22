package validator

// Guard-depth tests for ssrf.go. The question these answer is not "is there an
// SSRF check" but "is it enforced at DIAL time, on EVERY redirect hop" — a
// pre-flight hostname check alone is defeated by DNS rebinding and by a
// redirect, and reaching IMDS from Lambda/ECS would leak the warden's own
// execution-role credentials.

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/cache"
	"github.com/boogy/aws-oidc-warden/internal/config"
)

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
	if _, err := v.FetchJWKS(issuerURL); err != nil {
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
