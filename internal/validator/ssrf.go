package validator

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// maxJWKSRedirects bounds how many redirects the JWKS/discovery HTTP client
// will follow. Each hop is re-validated by CheckRedirect (scheme + host);
// dial-time IP blocking (below) covers every hop's connection too, since
// Transport.DialContext runs for each new connection the client makes,
// including ones opened while following a redirect.
const maxJWKSRedirects = 5

// newSecureHTTPClient builds the single shared http.Client used for every
// outbound JWKS/discovery fetch (built once at TokenValidator construction,
// never per call). It blocks connections to private/loopback/link-local/
// metadata addresses at dial time -- including on redirects -- enforces
// TLS 1.2+, and caps + re-validates redirects. allowInsecureIssuers permits
// dialing loopback (dev/test servers) only; it never relaxes the
// private/link-local/metadata block.
func newSecureHTTPClient(allowInsecureIssuers bool, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout}

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid dial address %q: %w", addr, err)
		}

		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve %q: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no addresses resolved for %q", host)
		}

		ip := ips[0].IP
		if isBlockedIP(ip, allowInsecureIssuers) {
			return nil, fmt.Errorf("connection to %s (%s) blocked: private/loopback/link-local/metadata address", host, ip)
		}

		// Dial the resolved-and-validated address directly, not the original
		// hostname, so a second DNS lookup inside the dialer can't return a
		// different, unvalidated address (DNS rebinding).
		return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}

	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:     dialContext,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxJWKSRedirects {
				return fmt.Errorf("stopped after %d redirects", maxJWKSRedirects)
			}
			if err := requireSecureURL(req.URL.String(), allowInsecureIssuers); err != nil {
				return fmt.Errorf("redirect target rejected: %w", err)
			}
			return nil
		},
	}
}

// isBlockedIP reports whether ip must never be dialed: private, link-local
// (which covers the 169.254.169.254 cloud metadata address), unspecified, or
// multicast. Loopback is blocked too unless allowLoopback (dev/test servers
// under allow_insecure_issuers) is set.
func isBlockedIP(ip net.IP, allowLoopback bool) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() {
		return !allowLoopback
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() || sharedOrReservedIPv4(ip) {
		return true
	}
	// An IPv6 literal can carry an IPv4 destination the stdlib helpers above do
	// not see through. Judge the address it actually designates.
	if embedded := embeddedIPv4(ip); embedded != nil {
		return isBlockedIP(embedded, allowLoopback)
	}
	return false
}

// sharedOrReservedIPv4 blocks IPv4 ranges that cannot host a legitimate public
// JWKS endpoint but that the net helpers do not classify: 100.64.0.0/10 (RFC
// 6598 shared address space — AWS uses it for ECS awsvpc and EKS pod
// networking) and 0.0.0.0/8 "this network" (net.IP.IsUnspecified matches only
// the exact 0.0.0.0). The guard already blocks RFC1918, which is far likelier
// to host an internal IdP, so blocking the remaining private-by-definition
// ranges is the consistent position rather than a new restriction in kind.
func sharedOrReservedIPv4(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	if v4[0] == 0 {
		return true // 0.0.0.0/8
	}
	return v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 // 100.64.0.0/10
}

// embeddedIPv4 returns the IPv4 address an IPv6 address carries, or nil.
//
// Two forms matter and neither is resolved by net.IP.To4 (which handles only
// the IPv4-mapped ::ffff:x.x.x.x form): the deprecated IPv4-compatible form
// ::x.x.x.x, and the well-known NAT64 translation prefix 64:ff9b::/96, which a
// NAT64 gateway rewrites to the embedded IPv4 — including loopback, RFC1918 and
// the metadata address. Callers must judge the embedded address, not the
// wrapper.
//
// ::1 and :: are IPv4-compatible-shaped but are handled by the IsLoopback and
// IsUnspecified checks before this is reached, so they never get here.
func embeddedIPv4(ip net.IP) net.IP {
	ip16 := ip.To16()
	if ip16 == nil || ip.To4() != nil {
		return nil // not IPv6, or already resolved as v4 / v4-mapped
	}

	// NAT64 well-known prefix 64:ff9b::/96.
	if ip16[0] == 0x00 && ip16[1] == 0x64 && ip16[2] == 0xff && ip16[3] == 0x9b {
		if allZero(ip16[4:12]) {
			return net.IPv4(ip16[12], ip16[13], ip16[14], ip16[15])
		}
	}

	// IPv4-compatible ::x.x.x.x — the entire 96-bit prefix is zero.
	if allZero(ip16[:12]) {
		return net.IPv4(ip16[12], ip16[13], ip16[14], ip16[15])
	}
	return nil
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// requireSecureURL ensures u uses HTTPS. Plain HTTP is permitted only for
// loopback hosts (127.0.0.1, ::1, localhost), and only when allowInsecure is
// set (dev/test only).
func requireSecureURL(u string, allowInsecure bool) error {
	parsed, err := url.Parse(u)
	if err != nil {
		return fmt.Errorf("malformed URL %q: %w", u, err)
	}

	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		if allowInsecure {
			switch parsed.Hostname() {
			case "127.0.0.1", "::1", "localhost":
				return nil
			}
		}
	}

	return fmt.Errorf("insecure scheme %q for host %q (https required)", parsed.Scheme, parsed.Hostname())
}
