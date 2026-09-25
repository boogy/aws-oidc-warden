package logevent

import "context"

// Request carries the per-request identifiers NewHandler attaches to every
// log line written with a context descending from WithRequest.
type Request struct {
	ID           string
	FrontendID   string
	SourceIP     string
	SourceIPFrom string
}

type requestContextKey struct{}

// WithRequest attaches r to ctx for NewHandler to read.
func WithRequest(ctx context.Context, r Request) context.Context {
	return context.WithValue(ctx, requestContextKey{}, r)
}

// RequestFrom returns the Request attached to ctx, if any.
func RequestFrom(ctx context.Context) (Request, bool) {
	r, ok := ctx.Value(requestContextKey{}).(Request)
	return r, ok
}
