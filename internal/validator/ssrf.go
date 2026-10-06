package validator

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"
)

// maxJWKSRedirects bounds how many redirects the JWKS/discovery HTTP client
// will follow. Each hop is re-validated by CheckRedirect; the dial-time IP
// check below also covers every hop's connection.
const maxJWKSRedirects = 5

// blockedPrefixes are ranges that must never be dialed, beyond what the
// netip.Addr classifiers (loopback, private, link-local, multicast,
// unspecified) already cover.
var blockedPrefixes = mustParsePrefixes(
	"0.0.0.0/8",       // "this network"
	"100.64.0.0/10",   // RFC 6598 shared address space (ECS awsvpc, EKS pods)
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"240.0.0.0/4",     // reserved, includes 255.255.255.255
	"64:ff9b::/96",    // NAT64 well-known prefix
	"2001:db8::/32",   // documentation
	"fc00::/7",        // unique local
)

func mustParsePrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(cidrs))
	for i, c := range cidrs {
		out[i] = netip.MustParsePrefix(c)
	}
	return out
}

// newSecureHTTPClient builds the single shared http.Client used for every
// outbound JWKS/discovery fetch (built once at TokenValidator construction,
// never per call). It blocks connections to private/loopback/link-local/
// metadata addresses at connect time — including on redirects — enforces TLS
// 1.2+, and caps + re-validates redirects. allowInsecureIssuers permits
// dialing loopback (dev/test servers) only; it never relaxes the
// private/link-local/metadata block.
func newSecureHTTPClient(allowInsecureIssuers bool, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout: timeout,
		Control: blockedDialControl(allowInsecureIssuers),
	}

	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:           nil, // never honor HTTP(S)_PROXY: a proxy would dial the target itself, unchecked
			DialContext:     dialer.DialContext,
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

// blockedDialControl returns a net.Dialer.Control hook that vets the address
// of every connect attempt, after resolution, so each candidate address of a
// multi-address host is checked and a second DNS lookup can't slip in an
// unvalidated one (DNS rebinding). Fails closed on an unparseable address.
func blockedDialControl(allowLoopback bool) func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("invalid dial address %q: %w", address, err)
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return fmt.Errorf("invalid dial address %q: %w", address, err)
		}
		if isBlockedAddr(addr, allowLoopback) {
			return fmt.Errorf("connection to %s blocked: private/loopback/link-local/metadata address", host)
		}
		return nil
	}
}

// isBlockedIP reports whether ip must never be dialed; see isBlockedAddr.
// A nil or malformed ip is blocked.
func isBlockedIP(ip net.IP, allowLoopback bool) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	return isBlockedAddr(addr, allowLoopback)
}

// isBlockedAddr reports whether addr must never be dialed: private,
// link-local (covers the 169.254.169.254 cloud metadata address),
// unspecified, multicast, or in blockedPrefixes. Loopback is blocked too
// unless allowLoopback is set.
func isBlockedAddr(addr netip.Addr, allowLoopback bool) bool {
	addr = addr.Unmap().WithZone("")
	if !addr.IsValid() {
		return true
	}
	if addr.IsLoopback() {
		return !allowLoopback
	}
	if addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsUnspecified() || addr.IsMulticast() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	// The deprecated IPv4-compatible form ::x.x.x.x carries an IPv4
	// destination the classifiers above don't see through.
	if addr.Is6() {
		b := addr.As16()
		if allZero(b[:12]) {
			return isBlockedAddr(netip.AddrFrom4([4]byte(b[12:])), allowLoopback)
		}
	}
	return false
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
// loopback hosts, and only when allowInsecure is set (dev/test only).
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
