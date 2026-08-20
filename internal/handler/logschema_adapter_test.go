package handler_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/boogy/aws-oidc-warden/internal/handler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestALBHandler_NoXFF_OmitsEmptySourceIPKeys drives the real ALB adapter
// (handler.AwsApplicationLoadBalancer.Handler) rather than hand-composing its
// slog.With bindings, because logschema_test.go's alb-without-xff sub-test
// only reproduces those bindings — it can't detect a regression in alb.go
// itself. If alb.go ever goes back to binding sourceIp/sourceIpFrom
// unconditionally, this is the only guard that would catch it.
//
// The stub extractor fails immediately, so this also exercises the "request
// dies before the decision" path the brief calls out: the standardized
// decision line is still emitted (via finalizeDeny), and it must still omit
// the empty IP keys.
func TestALBHandler_NoXFF_OmitsEmptySourceIPKeys(t *testing.T) {
	var buf bytes.Buffer
	prevDefault := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(prevDefault)

	ex := &stubExtractor{err: handler.ErrTokenValidationFailed}
	h := handler.NewAwsApplicationLoadBalancer(staticProvider(t), mockConsumer(t), ex, nil)

	event := events.ALBTargetGroupRequest{
		HTTPMethod: "POST",
		Path:       "/assume-role",
		Body:       `{"role":"arn:aws:iam::123456789012:role/MyRole"}`,
		Headers: map[string]string{
			// Deliberately no x-forwarded-for key: clientIP("", headers)
			// returns ("", "") for ALB in this case.
			"x-amzn-oidc-data": "dummy-oidc-data",
		},
		RequestContext: events.ALBTargetGroupRequestContext{
			ELB: events.ELBContext{TargetGroupArn: "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test/abc"},
		},
	}

	resp, err := h.Handler(context.Background(), event)
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode)

	lines := 0
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		lines++
		assert.NotContains(t, line, `"sourceIp":""`, "sourceIp must be omitted, not emitted empty, on the real ALB adapter: %s", line)
		assert.NotContains(t, line, `"sourceIpFrom":""`, "sourceIpFrom must be omitted, not emitted empty, on the real ALB adapter: %s", line)
	}
	require.NotZero(t, lines, "expected at least one captured log line")
}
