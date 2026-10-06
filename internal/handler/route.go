package handler

import (
	"context"
	"log/slog"
	"maps"
	"net/http"
	"strings"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/logevent"
)

type routeKind int

const (
	routeAssume routeKind = iota
	routeDiscovery
	routeJWKS
	routeMethodNotAllowed
	routeNotFound
	routeIdPDisabled
)

// idpRoutes holds the frozen IdP paths and their lowercase forms, computed once.
type idpRoutes struct {
	discovery, jwks           string
	lowerDiscovery, lowerJWKS string
}

func newIdPRoutes(p config.IdPPaths) *idpRoutes {
	return &idpRoutes{
		discovery: p.Discovery, jwks: p.JWKS,
		lowerDiscovery: strings.ToLower(p.Discovery), lowerJWKS: strings.ToLower(p.JWKS),
	}
}

// route classifies a request by method and exact path; without an IdP service everything is routeAssume.
func (r *RequestProcessor) route(ctx context.Context, method, path string) routeKind {
	if r.idp == nil {
		return routeAssume
	}
	p := r.routes
	if path == p.discovery || path == p.jwks {
		if method != http.MethodGet && method != http.MethodHead {
			return routeMethodNotAllowed
		}
		r.provider.RefreshIfDue(ctx)
		if !r.idpEnabled(r.provider.Get()) {
			return routeIdPDisabled
		}
		if path == p.discovery {
			return routeDiscovery
		}
		return routeJWKS
	}
	if p.shaped(path) {
		return routeNotFound
	}
	return routeAssume
}

// shaped reports a near-miss of a configured IdP path: other case, trailing slash, or one extra leading segment.
func (p *idpRoutes) shaped(path string) bool {
	lower := strings.TrimSuffix(strings.ToLower(path), "/")
	if p.matches(lower) {
		return true
	}
	if strings.HasPrefix(lower, "/") {
		if i := strings.Index(lower[1:], "/"); i >= 0 {
			return p.matches(lower[i+1:])
		}
	}
	return false
}

func (p *idpRoutes) matches(lower string) bool {
	return lower == p.lowerDiscovery || lower == p.lowerJWKS
}

// mergeHeaders copies ResponseHeaders and overlays extra.
func mergeHeaders(extra map[string]string) map[string]string {
	h := make(map[string]string, len(ResponseHeaders)+len(extra))
	maps.Copy(h, ResponseHeaders)
	maps.Copy(h, extra)
	return h
}

// serveIdP answers the IdP document routes; ok is false for routeAssume.
func serveIdP[T any](ctx context.Context, r *RequestProcessor, kind routeKind, method, path string, log *slog.Logger,
	newResp func(int, string, map[string]string) T,
) (resp T, ok bool) {
	switch kind {
	case routeDiscovery, routeJWKS:
		r.warnFrozenDrift(ctx, log, r.provider.Get())
		status, body, headers := r.idpDocument(ctx, kind, method == http.MethodHead, log)
		return newResp(status, body, headers), true
	case routeMethodNotAllowed:
		status, body := errorBody(ctx, ErrMethodNotAllowed, http.StatusMethodNotAllowed)
		return newResp(status, body, map[string]string{"Allow": "GET, HEAD"}), true
	case routeNotFound:
		logevent.Debug(ctx, log, logevent.IdPPathNotFound, "idp path not found", slog.String("path", path))
		status, body := errorBody(ctx, ErrIdPPathNotFound, http.StatusNotFound)
		return newResp(status, body, nil), true
	case routeIdPDisabled:
		logevent.Debug(ctx, log, logevent.IdPPathDisabled, "idp path requested while idp is disabled", slog.String("path", path))
		status, body := errorBody(ctx, ErrIdPPathNotFound, http.StatusNotFound)
		return newResp(status, body, nil), true
	}
	return resp, false
}
