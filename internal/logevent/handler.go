package logevent

import (
	"context"
	"log/slog"
)

// ctxHandler injects request fields from ctx; under an open group they nest inside it.
type ctxHandler struct {
	inner slog.Handler
}

// NewHandler wraps inner to add the ctx Request's fields to every record.
func NewHandler(inner slog.Handler) slog.Handler {
	return &ctxHandler{inner: inner}
}

func (h *ctxHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *ctxHandler) Handle(ctx context.Context, r slog.Record) error {
	if req, ok := RequestFrom(ctx); ok {
		r = r.Clone()
		if req.ID != "" {
			r.AddAttrs(slog.String(keyRequestID, req.ID))
		}
		if req.FrontendID != "" {
			r.AddAttrs(slog.String(keyFrontendRequestID, req.FrontendID))
		}
		if req.SourceIP != "" {
			r.AddAttrs(slog.String(keySourceIP, req.SourceIP))
		}
		if req.SourceIPFrom != "" && req.SourceIPFrom != sourceFromFrontend {
			r.AddAttrs(slog.String(keySourceIPFrom, req.SourceIPFrom))
		}
	}
	return h.inner.Handle(ctx, r)
}

func (h *ctxHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ctxHandler{inner: h.inner.WithAttrs(attrs)}
}

func (h *ctxHandler) WithGroup(name string) slog.Handler {
	return &ctxHandler{inner: h.inner.WithGroup(name)}
}
