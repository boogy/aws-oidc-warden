package handler_test

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/boogy/aws-oidc-warden/internal/handler"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
