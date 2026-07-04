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
	return ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast()
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
