package handler

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/boogy/aws-oidc-warden/internal/logevent"
)

// errorBody renders the standard error envelope as JSON.
func errorBody(ctx context.Context, err error, statusCode int) (int, string) {
	response, status := buildErrorResponse(ctx, err, statusCode)
	body, jsonErr := json.Marshal(response)
	if jsonErr != nil {
		return http.StatusInternalServerError, fallbackErrorBody
	}
	return status, string(body)
}

// idpDocument serves the discovery or JWKS document; the 503 uses the standard error envelope.
func (r *RequestProcessor) idpDocument(ctx context.Context, kind routeKind, head bool, log *slog.Logger) (status int, body string, headers map[string]string) {
	ks, err := r.idp.KeySet(ctx)
	if err != nil {
		logevent.Warn(ctx, log, logevent.IdPUnavailable, "idp signing keys unavailable", slog.String("error", err.Error()))
		status, body = errorBody(ctx, ErrIdPUnavailable, http.StatusServiceUnavailable)
		return status, body, nil
	}
	cfg := r.idp.Config()
	doc, path := ks.JWKS(), cfg.Paths.JWKS
	if kind == routeDiscovery {
		doc, path = ks.Discovery(), cfg.Paths.Discovery
	}
	logevent.Debug(ctx, log, logevent.IdPDocumentServed, "idp document served", slog.String("path", path))
	headers = map[string]string{"Cache-Control": "public, max-age=" + strconv.Itoa(int(cfg.JWKSCacheMaxAge.Seconds()))}
	if head {
		return http.StatusOK, "", headers
	}
	return http.StatusOK, string(doc), headers
}
