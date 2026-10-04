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

// route classifies a request by method and exact path; without an IdP service everything is routeAssume.
func (r *RequestProcessor) route(ctx context.Context, method, path string) routeKind {
	if r.idp == nil {
		return routeAssume
	}
	p := r.idp.Config().Paths
	if path == p.Discovery || path == p.JWKS {
		if method != http.MethodGet && method != http.MethodHead {
			return routeMethodNotAllowed
		}
		r.provider.RefreshIfDue(ctx)
		if !r.idpEnabled(r.provider.Get()) {
			return routeIdPDisabled
		}
		if path == p.Discovery {
			return routeDiscovery
		}
		return routeJWKS
	}
	if idpShaped(path, p) {
		return routeNotFound
	}
	return routeAssume
}

// idpShaped reports a near-miss of a configured IdP path: other case, trailing slash, or one extra leading segment.
func idpShaped(path string, p config.IdPPaths) bool {
	lower := strings.TrimSuffix(strings.ToLower(path), "/")
	candidates := []string{lower}
	if strings.HasPrefix(lower, "/") {
		if i := strings.Index(lower[1:], "/"); i >= 0 {
			candidates = append(candidates, lower[i+1:])
		}
	}
	for _, c := range candidates {
		for _, want := range []string{p.Discovery, p.JWKS} {
			if c == strings.ToLower(want) {
				return true
			}
		}
	}
	return false
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
	newResp func(int, string) T, newRespH func(int, string, map[string]string) T,
) (resp T, ok bool) {
	switch kind {
	case routeDiscovery, routeJWKS:
		status, body, headers := r.idpDocument(ctx, kind, method == http.MethodHead, log)
		return newRespH(status, body, headers), true
	case routeMethodNotAllowed:
		status, body := errorBody(ctx, ErrMethodNotAllowed, http.StatusMethodNotAllowed)
		return newRespH(status, body, map[string]string{"Allow": "GET, HEAD"}), true
	case routeNotFound:
		logevent.Warn(ctx, log, logevent.IdPPathNotFound, "idp path not found", slog.String("path", path))
		return errorResponse(ctx, ErrIdPPathNotFound, http.StatusNotFound, newResp), true
	case routeIdPDisabled:
		logevent.Debug(ctx, log, logevent.IdPPathDisabled, "idp path requested while idp is disabled", slog.String("path", path))
		return errorResponse(ctx, ErrIdPPathNotFound, http.StatusNotFound, newResp), true
	}
	return resp, false
}
