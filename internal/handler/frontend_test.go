package handler_test

// The per-frontend adapters: event parse and response serialization for API
// Gateway v2 and ALB (including multi-value headers), plus the log-schema
// adapter each one feeds.
import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/boogy/aws-oidc-warden/internal/handler"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAwsApiGatewayV2_Handler_ExtractsClaims(t *testing.T) {
	event := events.APIGatewayV2HTTPRequest{
		Body: `{"role":"arn:aws:iam::123456789012:role/MyRole"}`,
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			Authorizer: &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{
				JWT: &events.APIGatewayV2HTTPRequestContextAuthorizerJWTDescription{
					Claims: map[string]string{
						"iss":        "https://token.actions.githubusercontent.com",
						"repository": "org/repo",
						"ref":        "refs/heads/main",
						"ref_type":   "branch",
						"actor":      "octocat",
						"exp":        "9999999999",
						"iat":        "1000000000",
					},
				},
			},
		},
	}

	// Use a fixed extractor so claims are returned directly without token validation.
	// This isolates the adapter's routing logic from the extractor implementation.
	ex := &fixedExtractor{claims: &types.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Issuer: testIssuer, Subject: "org/repo"},
		Repository:       "org/repo",
		Ref:              "refs/heads/main",
		Actor:            "octocat",
	}}

	h := handler.NewAwsApiGatewayV2(staticProvider(t), mockConsumer(t), ex, nil)
	resp, err := h.Handler(context.Background(), event)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestAwsApiGatewayV2_Handler_MissingAuthorizer(t *testing.T) {
	// No authorizer claims → extractor should reject with ErrTokenValidationFailed → 401.
	event := events.APIGatewayV2HTTPRequest{
		Body: `{"role":"arn:aws:iam::123456789012:role/MyRole"}`,
	}

	// Use a stub extractor that always fails (simulates missing authorizer context).
	ex := &stubExtractor{err: handler.ErrTokenValidationFailed}

	h := handler.NewAwsApiGatewayV2(staticProvider(t), mockConsumer(t), ex, nil)
	resp, err := h.Handler(context.Background(), event)
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode)
}

// ---------- ALB multi-value headers ----------

// captureExtractor records the ExtractionInput the adapter built and then
// fails the request, so a test can assert on adapter behaviour alone.
type captureExtractor struct{ input validator.ExtractionInput }

func (c *captureExtractor) Extract(_ context.Context, in validator.ExtractionInput) (*types.Claims, error) {
	c.input = in
	return nil, handler.ErrTokenValidationFailed
}

// albEvent builds a minimal ALB event with the multi-value header map
// populated and headers left empty — exactly the shape ALB sends when the
// target group has lambda.multi_value_headers.enabled=true.
func albEvent(multi map[string][]string, body string) events.ALBTargetGroupRequest {
	return events.ALBTargetGroupRequest{
		HTTPMethod:        "POST",
		Path:              "/assume-role",
		Body:              body,
		MultiValueHeaders: multi,
		RequestContext: events.ALBTargetGroupRequestContext{
			ELB: events.ELBContext{TargetGroupArn: "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test/abc"},
		},
	}
}

// TestALBHandler_ReadsMultiValueHeaders proves the adapter sees the ALB OIDC
// header when the target group delivers headers in multiValueHeaders.
//
// With lambda.multi_value_headers.enabled=true, ALB populates
// multiValueHeaders and leaves headers EMPTY. Reading only event.Headers made
// x-amzn-oidc-data invisible, so ALB delegated mode silently fell back to
// token-in-body and rejected every request from a correctly configured target
// group.
func TestALBHandler_ReadsMultiValueHeaders(t *testing.T) {
	ex := &captureExtractor{}
	h := handler.NewAwsApplicationLoadBalancer(staticProvider(t), mockConsumer(t), ex, nil)

	event := albEvent(map[string][]string{
		"x-amzn-oidc-data": {"delegated-oidc-data"},
	}, `{"role":"arn:aws:iam::123456789012:role/MyRole"}`)

	_, err := h.Handler(context.Background(), event)
	require.NoError(t, err)

	assert.Equal(t, "delegated-oidc-data", ex.input.ALBOIDCData,
		"ALB delegated mode ignored x-amzn-oidc-data delivered in multiValueHeaders")
	assert.Empty(t, ex.input.Token, "must not fall back to token-in-body when the ALB header is present")
}

// A body carrying no token must still parse when the OIDC header arrives via
// multiValueHeaders: the role-only parser is selected from the same resolved
// header value the extraction input uses, so the two can never disagree.
func TestALBHandler_MultiValueHeaderSelectsRoleOnlyParser(t *testing.T) {
	ex := &captureExtractor{}
	h := handler.NewAwsApplicationLoadBalancer(staticProvider(t), mockConsumer(t), ex, nil)

	resp, err := h.Handler(context.Background(), albEvent(map[string][]string{
		"x-amzn-oidc-data": {"delegated-oidc-data"},
	}, `{"role":"arn:aws:iam::123456789012:role/MyRole"}`))
	require.NoError(t, err)

	// 401 (token validation) not 400 (body parse): the role-only parser ran.
	assert.Equal(t, 401, resp.StatusCode,
		"body was parsed with the token-requiring parser despite the ALB OIDC header")
}

// TestALBHandler_MultiValueXFFPopulatesSourceIP proves the audit/log sourceIp
// survives a multi-value target group, and that a per-hop repeated
// x-forwarded-for is folded into one list so the rightmost-hop rule still
// picks the hop ALB itself appended.
func TestALBHandler_MultiValueXFFPopulatesSourceIP(t *testing.T) {
	var buf bytes.Buffer
	prevDefault := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(prevDefault)

	ex := &captureExtractor{}
	h := handler.NewAwsApplicationLoadBalancer(staticProvider(t), mockConsumer(t), ex, nil)

	_, err := h.Handler(context.Background(), albEvent(map[string][]string{
		"x-amzn-oidc-data": {"delegated-oidc-data"},
		"x-forwarded-for":  {"10.0.0.1", "203.0.113.7"},
		"user-agent":       {"actions/oidc-client"},
	}, `{"role":"arn:aws:iam::123456789012:role/MyRole"}`))
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, `"sourceIp":"203.0.113.7"`,
		"sourceIp is blank or wrong when x-forwarded-for arrives in multiValueHeaders: %s", out)
	assert.Contains(t, out, `"userAgent":"actions/oidc-client"`,
		"user-agent is blank when it arrives in multiValueHeaders")
}

// Single-value target groups must keep working unchanged.
func TestALBHandler_SingleValueHeadersStillWork(t *testing.T) {
	ex := &captureExtractor{}
	h := handler.NewAwsApplicationLoadBalancer(staticProvider(t), mockConsumer(t), ex, nil)

	event := albEvent(nil, `{"role":"arn:aws:iam::123456789012:role/MyRole"}`)
	event.Headers = map[string]string{"x-amzn-oidc-data": "single-value-oidc"}

	_, err := h.Handler(context.Background(), event)
	require.NoError(t, err)
	assert.Equal(t, "single-value-oidc", ex.input.ALBOIDCData)
}

// When both maps carry the header (ALB never does this, but a proxy in front
// of the Lambda could), the multi-value map wins: it is the one ALB populates
// when multi-value is on, and the one that can carry every hop.
func TestALBHandler_MultiValueWinsOverSingleValue(t *testing.T) {
	ex := &captureExtractor{}
	h := handler.NewAwsApplicationLoadBalancer(staticProvider(t), mockConsumer(t), ex, nil)

	event := albEvent(map[string][]string{"x-amzn-oidc-data": {"multi-value-oidc"}},
		`{"role":"arn:aws:iam::123456789012:role/MyRole"}`)
	event.Headers = map[string]string{"x-amzn-oidc-data": "single-value-oidc"}

	_, err := h.Handler(context.Background(), event)
	require.NoError(t, err)
	assert.Equal(t, "multi-value-oidc", ex.input.ALBOIDCData)
}

// ---------- log-schema adapter ----------

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
