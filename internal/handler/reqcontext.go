package handler

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/boogy/aws-oidc-warden/internal/logevent"
	"github.com/google/uuid"
)

// resolveRequestID returns the canonical UUID request ID and the frontend's own ID.
func resolveRequestID(ctx context.Context, frontendID string) (requestID, frontendRequestID string) {
	if lc, ok := lambdacontext.FromContext(ctx); ok && lc.AwsRequestID != "" {
		return lc.AwsRequestID, frontendID
	}
	return uuid.New().String(), frontendID
}

// ipSource tells an AWS-attested IP from a client-supplied one.
const (
	ipSourceFrontend     = "frontend"        // platform-attested
	ipSourceForwardedFor = "x-forwarded-for" // client-supplied, spoofable
)

// clientIP resolves the client IP and its provenance (audit only): rightmost XFF hop, no fallback; see docs/LOGGING.md "Source IP trust model".
func clientIP(directIP string, headers map[string]string) (ip, source string) {
	if parsed := net.ParseIP(strings.TrimSpace(directIP)); parsed != nil {
		return parsed.String(), ipSourceFrontend
	}
	value := headerValue(headers, "x-forwarded-for")
	if value == "" {
		return "", ""
	}
	hops := strings.Split(value, ",")
	if parsed := net.ParseIP(strings.TrimSpace(hops[len(hops)-1])); parsed != nil {
		return parsed.String(), ipSourceForwardedFor
	}
	return "", ""
}

// headerValue looks up a header case-insensitively; case-variant ties pick the smallest key so the result is deterministic.
func headerValue(headers map[string]string, name string) string {
	if v, ok := headers[name]; ok {
		return v
	}
	bestKey, bestValue := "", ""
	for k, v := range headers {
		if !strings.EqualFold(k, name) {
			continue
		}
		if bestKey == "" || k < bestKey {
			bestKey, bestValue = k, v
		}
	}
	return bestValue
}

// newRequestContext binds per-request tracking values under DefaultTimeout; the caller must defer cancel.
func newRequestContext(ctx context.Context, frontendID, directIP string, headers map[string]string) (context.Context, context.CancelFunc) {
	requestID, frontendRequestID := resolveRequestID(ctx, frontendID)
	sourceIP, sourceIPFrom := clientIP(directIP, headers)

	ctx = context.WithValue(ctx, RequestIDContextKey, requestID)
	ctx = context.WithValue(ctx, FrontendRequestIDContextKey, frontendRequestID)
	ctx = context.WithValue(ctx, StartTimeContextKey, time.Now())
	ctx = context.WithValue(ctx, SourceIPContextKey, sourceIP)
	ctx = context.WithValue(ctx, SourceIPSourceContextKey, sourceIPFrom)

	// Carries request identity for logevent's ctx handler to inject.
	ctx = logevent.WithRequest(ctx, logevent.Request{
		ID:           requestID,
		FrontendID:   frontendRequestID,
		SourceIP:     sourceIP,
		SourceIPFrom: sourceIPFrom,
	})

	return context.WithTimeout(ctx, DefaultTimeout)
}

// requestLogger binds adapter attrs; request identity comes from logevent's ctx handler.
func requestLogger(attrs ...any) *slog.Logger {
	return slog.With(attrs...)
}
