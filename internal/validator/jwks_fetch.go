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
	"github.com/boogy/aws-oidc-warden/internal/logevent"
	"github.com/boogy/aws-oidc-warden/internal/types"
)

// issuerAttrs returns the issuer attr, plus any extras, shared by every JWKS
// fetch/discovery log line.
func issuerAttrs(issuer string, extra ...slog.Attr) []slog.Attr {
	attrs := make([]slog.Attr, 0, len(extra)+1)
	attrs = append(attrs, slog.String("issuer", issuer))
	return append(attrs, extra...)
}

// FetchJWKS fetches the JWKS for the given issuer, using the cache when
// available. Exposed standalone (no jwks_uri override) for testing and
// warm-prefetch; Validate uses the issuer's registered spec instead, which
// may carry a jwks_uri override.
func (t *TokenValidator) FetchJWKS(ctx context.Context, issuer string) (*types.JWKS, error) {
	return t.fetchJWKS(ctx, &issuerSpec{Issuer: issuer}, false)
}

// fetchJWKS fetches (or serves from cache) the JWKS for spec.Issuer. When
// spec.JWKSURI is set, OIDC discovery is skipped and that URL is fetched
// directly (still required to be a secure URL). When force is true the cache
// is bypassed — used to recover from signing-key rotation. Concurrent cold
// fetches for the same issuer are deduplicated via a per-issuer singleflight.
func (t *TokenValidator) fetchJWKS(ctx context.Context, spec *issuerSpec, force bool) (*types.JWKS, error) {
	if !force {
		if cachedJWKS, found := t.cache.Get(ctx, spec.Issuer); found && cachedJWKS != nil {
			return cachedJWKS, nil
		}
	}

	// A cancelled initiator must not abort the fetch its singleflight waiters share.
	fetchCtx := context.WithoutCancel(ctx)
	v, err, _ := t.sfGroup.Do(spec.Issuer, func() (any, error) {
		return t.fetchAndCacheJWKS(fetchCtx, spec)
	})
	if err != nil {
		return nil, err
	}
	return v.(*types.JWKS), nil
}

// fetchAndCacheJWKS does the actual network work for fetchJWKS: resolve the
// JWKS URI (explicit override, memoized discovery, or a fresh discovery
// call), fetch + validate the JWKS, and cache it. Runs inside the
// singleflight group, so it executes at most once per issuer per in-flight fetch.
func (t *TokenValidator) fetchAndCacheJWKS(ctx context.Context, spec *issuerSpec) (*types.JWKS, error) {
	jwksURI := spec.JWKSURI
	// Only a discovery-resolved URI (no per-issuer override) is eligible for
	// the "re-discover once on 404" recovery below and gets memoized.
	discoveryDriven := jwksURI == ""
	if discoveryDriven {
		if cached, ok := t.jwksURICache.Load(spec.Issuer); ok {
			jwksURI = cached.(string)
		} else {
			var err error
			jwksURI, err = t.discoverJWKSURI(ctx, spec)
			if err != nil {
				return nil, err
			}
		}
	}

	if err := requireSecureURL(jwksURI, t.allowInsecureIssuers); err != nil {
		return nil, fmt.Errorf("invalid jwks_uri: %w", err)
	}

	jwks, status, err := t.getJWKS(ctx, spec.Issuer, jwksURI)
	if discoveryDriven && status == http.StatusNotFound {
		// The memoized/discovered jwks_uri may be stale; re-discover once and
		// retry before giving up.
		t.jwksURICache.Delete(spec.Issuer)
		if newURI, derr := t.discoverJWKSURI(ctx, spec); derr == nil {
			if serr := requireSecureURL(newURI, t.allowInsecureIssuers); serr == nil {
				jwks, _, err = t.getJWKS(ctx, spec.Issuer, newURI)
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

	t.cache.Set(ctx, spec.Issuer, jwks, cache.GetConfiguredTTL(t.currentConfig()))
	return jwks, nil
}

// discoverJWKSURI fetches spec.Issuer's OIDC discovery document
// (issuer + /.well-known/openid-configuration), validates that the
// document's own "issuer" matches spec.Issuer (RFC 8414 S8, so a compromised
// or misconfigured discovery endpoint can't redirect trust to a different
// issuer), and returns its jwks_uri.
func (t *TokenValidator) discoverJWKSURI(ctx context.Context, spec *issuerSpec) (string, error) {
	if err := requireSecureURL(spec.Issuer, t.allowInsecureIssuers); err != nil {
		return "", fmt.Errorf("invalid issuer URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		spec.Issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return "", fmt.Errorf("failed to build discovery request: %w", err)
	}

	resp, err := t.httpc.Do(req)
	if err != nil {
		logevent.Error(ctx, nil, logevent.JWKSDiscoveryFailure, "failed to fetch OIDC configuration",
			issuerAttrs(spec.Issuer, slog.String("error", err.Error()))...)
		return "", fmt.Errorf("failed to fetch OIDC configuration: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logevent.Error(ctx, nil, logevent.JWKSDiscoveryFailure, "failed to close OIDC configuration response body",
				issuerAttrs(spec.Issuer, slog.String("error", err.Error()))...)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		logevent.Error(ctx, nil, logevent.JWKSDiscoveryFailure, "received non-200 status code fetching OIDC configuration",
			issuerAttrs(spec.Issuer, slog.Int("status", resp.StatusCode))...)
		return "", fmt.Errorf("received non-200 status code when fetching OIDC configuration: %d", resp.StatusCode)
	}

	var discovery struct {
		Issuer  string `json:"issuer"`
		JwksURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&discovery); err != nil {
		logevent.Error(ctx, nil, logevent.JWKSDiscoveryFailure, "failed to parse OIDC configuration",
			issuerAttrs(spec.Issuer, slog.String("error", err.Error()))...)
		return "", fmt.Errorf("failed to parse OIDC configuration: %w", err)
	}
	if discovery.Issuer != spec.Issuer {
		return "", fmt.Errorf("discovery document issuer %q does not match configured issuer %q", discovery.Issuer, spec.Issuer)
	}
	return discovery.JwksURI, nil
}

// getJWKS fetches and decodes the JWKS document at jwksURI. The returned
// status code lets callers distinguish a 404 (candidate for one
// re-discovery retry) from other failures. A zero-key or oversized JWKS is
// rejected and, since the caller only caches on a nil error, is never cached.
func (t *TokenValidator) getJWKS(ctx context.Context, issuer, jwksURI string) (*types.JWKS, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to build JWKS request: %w", err)
	}

	resp, err := t.httpc.Do(req)
	if err != nil {
		logevent.Error(ctx, nil, logevent.JWKSFetchFailure, "failed to fetch JWKS",
			issuerAttrs(issuer, slog.String("error", err.Error()))...)
		return nil, 0, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logevent.Error(ctx, nil, logevent.JWKSFetchFailure, "failed to close JWKS response body",
				issuerAttrs(issuer, slog.String("error", err.Error()))...)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		logevent.Error(ctx, nil, logevent.JWKSFetchFailure, "received non-200 status code fetching JWKS",
			issuerAttrs(issuer, slog.Int("status", resp.StatusCode))...)
		return nil, resp.StatusCode, fmt.Errorf("received non-200 status code when fetching JWKS: %d", resp.StatusCode)
	}

	var jwks types.JWKS
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&jwks); err != nil {
		logevent.Error(ctx, nil, logevent.JWKSFetchFailure, "failed to parse JWKS",
			issuerAttrs(issuer, slog.String("error", err.Error()))...)
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
