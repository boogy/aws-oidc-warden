package handler

import (
	"context"
	"net"
	"strings"

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
