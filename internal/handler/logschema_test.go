package handler

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/config"
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
