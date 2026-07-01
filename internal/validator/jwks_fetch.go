package validator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/boogy/aws-oidc-warden/internal/cache"
	"github.com/boogy/aws-oidc-warden/internal/types"
)

// FetchJWKS fetches the JWKS for the given issuer, using the cache when
// available. Exposed standalone (no jwks_uri override) for testing and
// warm-prefetch of issuers outside the registry; Validate uses the issuer's
// registered spec instead, which may carry a jwks_uri override.
func (t *TokenValidator) FetchJWKS(issuer string) (*types.JWKS, error) {
	return t.fetchJWKS(&issuerSpec{Issuer: issuer}, false)
}

// fetchJWKS fetches (or serves from cache) the JWKS for spec.Issuer. When
// spec.JWKSURI is set, OIDC discovery is skipped and that URL is fetched
// directly (still required to be a secure URL). When force is true the cache
// is bypassed and the freshly fetched JWKS replaces any cached entry -- used
// to recover from signing-key rotation. Concurrent cold fetches for the same
// issuer are deduplicated via a per-issuer singleflight, so a thundering herd
// of requests during cold-start or rotation makes exactly one upstream call.
func (t *TokenValidator) fetchJWKS(spec *issuerSpec, force bool) (*types.JWKS, error) {
	if !force {
		if cachedJWKS, found := t.cache.Get(spec.Issuer); found && cachedJWKS != nil {
			return cachedJWKS, nil
		}
	}

	v, err, _ := t.sfGroup.Do(spec.Issuer, func() (any, error) {
		return t.fetchAndCacheJWKS(spec)
	})
	if err != nil {
		return nil, err
	}
	return v.(*types.JWKS), nil
}

// fetchAndCacheJWKS does the actual network work for fetchJWKS: resolve the
// JWKS URI (explicit override, memoized discovery, or a fresh discovery
// call), fetch + validate the JWKS, and cache it. Runs inside the
// singleflight group, so it executes at most once per issuer per in-flight
// fetch.
func (t *TokenValidator) fetchAndCacheJWKS(spec *issuerSpec) (*types.JWKS, error) {
	jwksURI := spec.JWKSURI
	// Only a discovery-resolved URI (no per-issuer override) is eligible for
	// the "re-discover once on 404" recovery below and gets memoized.
	discoveryDriven := jwksURI == ""
	if discoveryDriven {
		if cached, ok := t.jwksURICache.Load(spec.Issuer); ok {
			jwksURI = cached.(string)
		} else {
			var err error
			jwksURI, err = t.discoverJWKSURI(spec)
			if err != nil {
				return nil, err
			}
		}
	}

	if err := requireSecureURL(jwksURI, t.allowInsecureIssuers); err != nil {
		return nil, fmt.Errorf("invalid jwks_uri: %w", err)
	}

	jwks, status, err := t.getJWKS(jwksURI)
	if discoveryDriven && status == http.StatusNotFound {
		// The memoized/discovered jwks_uri may be stale (issuer rotated its
		// discovery doc); re-discover once and retry before giving up.
		t.jwksURICache.Delete(spec.Issuer)
		if newURI, derr := t.discoverJWKSURI(spec); derr == nil {
			if serr := requireSecureURL(newURI, t.allowInsecureIssuers); serr == nil {
				jwks, status, err = t.getJWKS(newURI)
				jwksURI = newURI
			}
		}
	}
	if err != nil {
		return nil, err
	}

	if discoveryDriven {
		t.jwksURICache.Store(spec.Issuer, jwksURI)
	}

	t.cache.Set(spec.Issuer, jwks, cache.GetConfiguredTTL(t.currentConfig()))
	return jwks, nil
}

// discoverJWKSURI fetches spec.Issuer's OIDC discovery document
// (issuer + /.well-known/openid-configuration), validates that the
// document's own "issuer" matches spec.Issuer (RFC 8414 -- S8, so a
// compromised or misconfigured discovery endpoint can't redirect trust to a
// different issuer), and returns its jwks_uri.
func (t *TokenValidator) discoverJWKSURI(spec *issuerSpec) (string, error) {
	if err := requireSecureURL(spec.Issuer, t.allowInsecureIssuers); err != nil {
		return "", fmt.Errorf("invalid issuer URL: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		spec.Issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return "", fmt.Errorf("failed to build discovery request: %w", err)
	}

	resp, err := t.httpc.Do(req)
	if err != nil {
		slog.Error("Failed to fetch OIDC configuration", "error", err)
		return "", fmt.Errorf("failed to fetch OIDC configuration: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("Failed to close OIDC configuration response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		slog.Error("Received non-200 status code when fetching OIDC configuration", "status", resp.StatusCode)
		return "", fmt.Errorf("received non-200 status code when fetching OIDC configuration: %d", resp.StatusCode)
	}

	var discovery struct {
		Issuer  string `json:"issuer"`
		JwksURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&discovery); err != nil {
		slog.Error("Failed to parse OIDC configuration", "error", err)
		return "", fmt.Errorf("failed to parse OIDC configuration: %w", err)
	}
	if discovery.Issuer != spec.Issuer {
		return "", fmt.Errorf("discovery document issuer %q does not match configured issuer %q", discovery.Issuer, spec.Issuer)
	}
	return discovery.JwksURI, nil
}

// getJWKS fetches and decodes the JWKS document at jwksURI. The returned
// status code lets callers distinguish a 404 (candidate for one
// re-discovery retry, see fetchAndCacheJWKS) from other failures. A zero-key
// or oversized JWKS is rejected and, since the caller only caches on a nil
// error, is never cached.
func (t *TokenValidator) getJWKS(jwksURI string) (*types.JWKS, int, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to build JWKS request: %w", err)
	}

	resp, err := t.httpc.Do(req)
	if err != nil {
		slog.Error("Failed to fetch JWKS", "error", err)
		return nil, 0, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("Failed to close JWKS response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		slog.Error("Received non-200 status code when fetching JWKS", "status", resp.StatusCode)
		return nil, resp.StatusCode, fmt.Errorf("received non-200 status code when fetching JWKS: %d", resp.StatusCode)
	}

	var jwks types.JWKS
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&jwks); err != nil {
		slog.Error("Failed to parse JWKS", "error", err)
		return nil, resp.StatusCode, fmt.Errorf("failed to parse JWKS: %w", err)
	}
	if len(jwks.Keys) == 0 {
		return nil, resp.StatusCode, errors.New("jwks contains no keys")
	}
	const maxJWKSKeys = 20
	if len(jwks.Keys) > maxJWKSKeys {
		return nil, resp.StatusCode, fmt.Errorf("jwks contains too many keys (%d > %d)", len(jwks.Keys), maxJWKSKeys)
	}
	return &jwks, resp.StatusCode, nil
}
