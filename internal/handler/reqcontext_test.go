package handler

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/stretchr/testify/assert"
)

func TestResolveRequestID_PrefersLambdaUUID(t *testing.T) {
	const awsUUID = "8f7e6d5c-4b3a-2910-8f7e-6d5c4b3a2910"
	ctx := lambdacontext.NewContext(context.Background(),
		&lambdacontext.LambdaContext{AwsRequestID: awsUUID})

	// API Gateway v2 hands out non-UUID IDs like "CPyipjveDoEEPIA=".
	reqID, frontendID := resolveRequestID(ctx, "CPyipjveDoEEPIA=")

	assert.Equal(t, awsUUID, reqID, "requestId must be the Lambda invocation UUID")
	assert.Equal(t, "CPyipjveDoEEPIA=", frontendID, "frontend ID must be preserved for access-log correlation")
}

func TestResolveRequestID_FallsBackWhenNoLambdaContext(t *testing.T) {
	// cmd/local and unit tests run without a Lambda context.
	reqID, frontendID := resolveRequestID(context.Background(), "CPyipjveDoEEPIA=")

	assert.NotEmpty(t, reqID)
	assert.Len(t, reqID, 36, "fallback must still be a generated UUID")
	assert.NotEqual(t, "CPyipjveDoEEPIA=", reqID, "must not fall back to a non-UUID frontend ID")
	assert.Equal(t, "CPyipjveDoEEPIA=", frontendID)
}

func TestClientIP(t *testing.T) {
	for _, tc := range []struct {
		name     string
		directIP string
		headers  map[string]string
		want     string
	}{
		{"direct IP wins", "203.0.113.7", map[string]string{"x-forwarded-for": "198.51.100.1"}, "203.0.113.7"},
		// RIGHTMOST, not leftmost: ALB appends the real TCP peer to whatever
		// XFF the client sent, so the last entry is the load balancer's own
		// observation and every entry left of it is client-supplied.
		{"ALB: rightmost XFF hop is the attested one", "", map[string]string{"x-forwarded-for": "198.51.100.1, 10.0.0.5, 203.0.113.7"}, "203.0.113.7"},
		{"spoofed prefix ignored", "", map[string]string{"x-forwarded-for": "1.2.3.4, 203.0.113.7"}, "203.0.113.7"},
		{"XFF single value", "", map[string]string{"x-forwarded-for": "198.51.100.1"}, "198.51.100.1"},
		{"XFF whitespace trimmed", "", map[string]string{"x-forwarded-for": "10.0.0.5,  198.51.100.1  "}, "198.51.100.1"},
		{"header casing ignored", "", map[string]string{"X-Forwarded-For": "198.51.100.1"}, "198.51.100.1"},
		// No fallback: only the last field is ever examined. A trailing
		// unparseable/empty field means the header was not produced by a
		// well-behaved ALB append, so an earlier hop is never trusted.
		{"garbage last hop is not a fallback trigger", "", map[string]string{"x-forwarded-for": "198.51.100.1, not-an-ip"}, ""},
		{"garbage XFF rejected", "", map[string]string{"x-forwarded-for": "not-an-ip"}, ""},
		{"nothing available", "", nil, ""},
		{"never returns an ARN", "arn:aws:elasticloadbalancing:eu-west-1:1234:targetgroup/tg/abc", nil, ""},
		{"empty XFF", "", map[string]string{"x-forwarded-for": ""}, ""},
		{"whitespace-only XFF", "", map[string]string{"x-forwarded-for": "   "}, ""},
		{"commas-only XFF", "", map[string]string{"x-forwarded-for": ",,,"}, ""},
		{"bare IPv6 accepted", "", map[string]string{"x-forwarded-for": "2001:db8::1"}, "2001:db8::1"},
		{"bracketed IPv6 rejected", "", map[string]string{"x-forwarded-for": "[2001:db8::1]"}, ""},
		{"host:port rejected", "", map[string]string{"x-forwarded-for": "203.0.113.1:1234"}, ""},
		{"bracketed IPv6 with port rejected", "", map[string]string{"x-forwarded-for": "[2001:db8::1]:443"}, ""},
		{"trailing junk hops are not skipped", "", map[string]string{"x-forwarded-for": "1.2.3.4, junk, junk"}, ""},
		{"trailing empty hops are not skipped", "", map[string]string{"x-forwarded-for": "1.2.3.4, , "}, ""},
		{"trailing host:port hop is not skipped", "", map[string]string{"x-forwarded-for": "1.2.3.4, not-an-ip:99"}, ""},
		{"trailing unknown hop is not skipped", "", map[string]string{"x-forwarded-for": "1.2.3.4, unknown"}, ""},
		{"tab-padded XFF trimmed", "", map[string]string{"x-forwarded-for": "10.0.0.5,\t198.51.100.1\t"}, "198.51.100.1"},
		{"CRLF-separated XFF trimmed", "", map[string]string{"x-forwarded-for": "10.0.0.5,\r\n198.51.100.1"}, "198.51.100.1"},
		{"1000-hop XFF still resolves the rightmost", "", map[string]string{"x-forwarded-for": strings.Repeat("10.0.0.1, ", 999) + "203.0.113.7"}, "203.0.113.7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ip, _ := clientIP(tc.directIP, tc.headers)
			assert.Equal(t, tc.want, ip)
		})
	}
}

// TestClientIP_ReportsProvenance pins that the caller can tell a
// platform-attested IP from a client-supplied one. Authorization never
// depends on this value, but the audit record does: a holder of a valid token
// could otherwise forge their apparent origin in the trail undetectably.
func TestClientIP_ReportsProvenance(t *testing.T) {
	ip, source := clientIP("203.0.113.7", map[string]string{"x-forwarded-for": "1.2.3.4"})
	assert.Equal(t, "203.0.113.7", ip)
	assert.Equal(t, ipSourceFrontend, source, "frontend-provided IP is platform-attested")

	ip, source = clientIP("", map[string]string{"x-forwarded-for": "1.2.3.4, 203.0.113.7"})
	assert.Equal(t, "203.0.113.7", ip)
	assert.Equal(t, ipSourceForwardedFor, source, "XFF-derived IP must be marked as such")

	ip, source = clientIP("", nil)
	assert.Empty(t, ip)
	assert.Empty(t, source, "no IP means no provenance claim")
}

// TestAuditRecord_CarriesSourceIPProvenance pins that the durable audit
// record — not just the CloudWatch log line — carries the resolved IP and its
// provenance, and that redact() (which suppresses claim VALUES) leaves this
// request metadata alone.
func TestAuditRecord_CarriesSourceIPProvenance(t *testing.T) {
	ctx := context.WithValue(context.Background(), SourceIPContextKey, "203.0.113.7")
	ctx = context.WithValue(ctx, SourceIPSourceContextKey, ipSourceForwardedFor)

	rec := auditRecord{}
	rec.SourceIP, _ = ctx.Value(SourceIPContextKey).(string)
	rec.SourceIPFrom, _ = ctx.Value(SourceIPSourceContextKey).(string)
	rec.redact(false)

	assert.Equal(t, "203.0.113.7", rec.SourceIP, "redact() must not drop request metadata")
	assert.Equal(t, ipSourceForwardedFor, rec.SourceIPFrom)
}
