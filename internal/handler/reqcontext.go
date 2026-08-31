package handler

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/google/uuid"
)

// resolveRequestID returns the canonical (always-UUID) request ID plus the
// frontend's own, non-interchangeable ID, for cross-frontend log correlation.
func resolveRequestID(ctx context.Context, frontendID string) (requestID, frontendRequestID string) {
	if lc, ok := lambdacontext.FromContext(ctx); ok && lc.AwsRequestID != "" {
		return lc.AwsRequestID, frontendID
	}
	return uuid.New().String(), frontendID
}

// ipSource records where a logged IP came from, so a reader of the audit trail
// can tell an attested value from a client-supplied one.
const (
	ipSourceFrontend     = "frontend"        // platform-attested
	ipSourceForwardedFor = "x-forwarded-for" // client-supplied, spoofable
)

// clientIP resolves the requesting client's IP and reports its provenance.
//
// Prefers the frontend's own source-IP field (API Gateway, Lambda URLs); ALB
// has none, so falls back to X-Forwarded-For. Takes the RIGHTMOST XFF hop —
// ALB appends the TCP peer it observed to the end, so every earlier entry is
// attacker-controlled. No fallback to an earlier hop if the last one fails to
// parse: that would return the attacker-chosen value rightmost exists to
// reject. A trusted proxy in front of ALB needs a trusted-hop count this
// function doesn't have; see docs/LOGGING.md "Source IP trust model".
// IP is audit metadata only, never consulted for authorization.
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

// headerValue looks up a header case-insensitively and deterministically.
//
// Map iteration order is random, so ties between case variants (e.g. a caller
// sending both "X-Forwarded-For" and "x-forwarded-for") are broken by picking
// the lexicographically smallest key — otherwise the same event could log a
// different origin on different invocations.
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

// newRequestContext binds the per-request tracking values every frontend
// adapter carries and bounds the request with DefaultTimeout. The caller must
// invoke the returned cancel (via defer).
func newRequestContext(ctx context.Context, frontendID, directIP string, headers map[string]string, userAgent string) (context.Context, context.CancelFunc) {
	requestID, frontendRequestID := resolveRequestID(ctx, frontendID)
	sourceIP, sourceIPFrom := clientIP(directIP, headers)

	ctx = context.WithValue(ctx, RequestIDContextKey, requestID)
	ctx = context.WithValue(ctx, FrontendRequestIDContextKey, frontendRequestID)
	ctx = context.WithValue(ctx, StartTimeContextKey, time.Now())
	ctx = context.WithValue(ctx, SourceIPContextKey, sourceIP)
	ctx = context.WithValue(ctx, SourceIPSourceContextKey, sourceIPFrom)
	ctx = context.WithValue(ctx, UserAgentContextKey, userAgent)

	return context.WithTimeout(ctx, DefaultTimeout)
}

// requestLogger appends the request-tracking attrs shared by every adapter to
// the adapter's own event-specific attrs. Empty values are omitted rather than
// bound empty.
//
// slog.With, not a struct field: no adapter has a logger field; all four build
// from the default, which bootstrap points at the JSON handler.
func requestLogger(ctx context.Context, attrs ...any) *slog.Logger {
	if v, _ := ctx.Value(FrontendRequestIDContextKey).(string); v != "" {
		attrs = append(attrs, slog.String("frontendRequestId", v))
	}
	if v, _ := ctx.Value(SourceIPContextKey).(string); v != "" {
		attrs = append(attrs, slog.String("sourceIp", v))
	}
	// Only surfaced when not the platform-attested value, so an anomaly is
	// visible without a constant "sourceIpFrom=frontend" on every line.
	if v, _ := ctx.Value(SourceIPSourceContextKey).(string); v != "" && v != ipSourceFrontend {
		attrs = append(attrs, slog.String("sourceIpFrom", v))
	}
	return slog.With(attrs...)
}
