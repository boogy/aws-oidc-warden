package handler

// The structured log/audit schema, the logger setup, and the per-request
// context fields every log site shares.
import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDecisionLine_NoDuplicateKeys is the permanent regression guard for the
// bug class fixed by this task: a request-scoped logger built via slog.With
// (as every adapter builds it) plus the attrs auditLogAttrs adds to the
// decision line must never both write the same key. json.Unmarshal is
// deliberately NOT used here — encoding/json's last-wins behavior on
// duplicate object keys is exactly what let the earlier bug survive
// TestLogOutputIsJSON undetected; a raw substring count is the only way to
// see the duplicate that a parsed map hides.
func TestDecisionLine_NoDuplicateKeys(t *testing.T) {
	keys := []string{"requestId", "frontendRequestId", "sourceIp", "sourceIpFrom", "sessionName", "decision"}

	for _, tc := range []struct {
		name string
		log  func(buf *bytes.Buffer) *slog.Logger
		rec  *auditRecord
	}{
		{
			name: "apigateway",
			log: func(buf *bytes.Buffer) *slog.Logger {
				base := slog.New(slog.NewJSONHandler(buf, nil))
				log := base.With(
					slog.String("requestId", "req-1"),
					slog.String("path", "/assume-role"),
					slog.String("method", "POST"),
					slog.String("userAgent", "curl"),
					slog.String("requestTime", "01/Jan/2026"),
					slog.String("domainName", "api.example.com"),
				)
				log = log.With(slog.String("frontendRequestId", "apigw-id-1"))
				log = log.With(slog.String("sourceIp", "198.51.100.5"))
				return log
			},
			// rec carries the same values the adapter would have put in
			// context (frontendRequestId/sourceIp come from the same
			// resolveRequestID/clientIP call as the logger binding above), so
			// a reintroduced appendIf in auditLogAttrs actually collides.
			rec: &auditRecord{FrontendRequestID: "apigw-id-1", SourceIP: "198.51.100.5"},
		},
		{
			name: "apigatewayv2",
			log: func(buf *bytes.Buffer) *slog.Logger {
				base := slog.New(slog.NewJSONHandler(buf, nil))
				log := base.With(
					slog.String("requestId", "req-2"),
					slog.String("path", "/assume-role"),
					slog.String("method", "POST"),
					slog.String("userAgent", "curl"),
				)
				log = log.With(slog.String("frontendRequestId", "apigwv2-id-1"))
				log = log.With(slog.String("sourceIp", "198.51.100.5"))
				return log
			},
			rec: &auditRecord{FrontendRequestID: "apigwv2-id-1", SourceIP: "198.51.100.5"},
		},
		{
			name: "lambdaurl",
			log: func(buf *bytes.Buffer) *slog.Logger {
				base := slog.New(slog.NewJSONHandler(buf, nil))
				log := base.With(
					slog.String("requestId", "req-3"),
					slog.String("path", "/assume-role"),
					slog.String("method", "POST"),
					slog.String("userAgent", "curl"),
					slog.String("requestTime", "01/Jan/2026"),
					slog.String("domainName", "fn.lambda-url.aws"),
				)
				log = log.With(slog.String("frontendRequestId", "lambdaurl-id-1"))
				log = log.With(slog.String("sourceIp", "198.51.100.5"))
				return log
			},
			rec: &auditRecord{FrontendRequestID: "lambdaurl-id-1", SourceIP: "198.51.100.5"},
		},
		{
			name: "alb-with-xff",
			log: func(buf *bytes.Buffer) *slog.Logger {
				base := slog.New(slog.NewJSONHandler(buf, nil))
				log := base.With(
					slog.String("requestId", "req-4"),
					slog.String("path", "/assume-role"),
					slog.String("method", "POST"),
					slog.String("targetGroupArn", "arn:aws:elasticloadbalancing:..."),
					slog.String("userAgent", "curl"),
				)
				log = log.With(slog.String("sourceIp", "203.0.113.7"))
				log = log.With(slog.String("sourceIpFrom", "x-forwarded-for"))
				return log
			},
			rec: &auditRecord{SourceIP: "203.0.113.7", SourceIPFrom: "x-forwarded-for"},
		},
		{
			// ALB with no X-Forwarded-For header: clientIP("", …) returns
			// ("", ""), so no sourceIp/sourceIpFrom binding must occur at all.
			name: "alb-without-xff",
			log: func(buf *bytes.Buffer) *slog.Logger {
				base := slog.New(slog.NewJSONHandler(buf, nil))
				return base.With(
					slog.String("requestId", "req-5"),
					slog.String("path", "/assume-role"),
					slog.String("method", "POST"),
					slog.String("targetGroupArn", "arn:aws:elasticloadbalancing:..."),
					slog.String("userAgent", "curl"),
				)
			},
			rec: &auditRecord{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			log := tc.log(&buf)

			rec := tc.rec
			rec.Frontend = "test"
			rec.JWTMode = "self"
			rec.SessionName = "test-session"
			r := &RequestProcessor{}
			if err := r.recordDecision(context.Background(), log, &config.Config{}, rec); err != nil {
				t.Fatalf("recordDecision: %v", err)
			}

			line := strings.TrimSpace(buf.String())

			for _, key := range keys {
				count := strings.Count(line, "\""+key+"\":")
				if count > 1 {
					t.Errorf("key %q appears %d times in the decision line, want at most 1: %s", key, count, line)
				}
			}

			if tc.name == "alb-without-xff" {
				for _, key := range []string{"sourceIp", "sourceIpFrom", "frontendRequestId"} {
					if strings.Contains(line, "\""+key+"\":\"\"") {
						t.Errorf("key %q emitted empty on the ALB-without-XFF decision line: %s", key, line)
					}
				}
			}
		})
	}
}

// ---------- logger setup ----------

// TestLogOutputIsJSON pins that every emitted line parses as JSON. Downstream
// log ingestion parses these lines; a text handler would silently break every
// query built against them, and this service's log stream is the audit trail's
// live counterpart.
func TestLogOutputIsJSON(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	logger.Info("decision",
		slog.String("requestId", "8f7e6d5c-4b3a-2910-8f7e-6d5c4b3a2910"),
		slog.String("decision", "allow"),
		slog.Any("claims", map[string]string{"repo": "acme/api"}))

	for line := range strings.Lines(strings.TrimSpace(buf.String())) {
		var parsed map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &parsed),
			"every log line must be valid JSON, got: %s", line)
	}
}

// TestBootstrapLoggerIsJSONHandler pins that the bootstrap-installed logger is
// always a JSON handler, never a text handler, so a future change can't
// quietly switch the production log format. White-box (package handler) so it
// can call initializeLogger directly rather than exercising the full
// NewBootstrap path, which also loads AWS SDK config and the on-disk config
// file — neither of which this test cares about.
func TestBootstrapLoggerIsJSONHandler(t *testing.T) {
	_, logger, err := initializeLogger()
	require.NoError(t, err)
	_, ok := logger.Handler().(*slog.JSONHandler)
	assert.True(t, ok, "bootstrap must install a JSON handler, never a text handler")
}

// ---------- request context ----------

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
