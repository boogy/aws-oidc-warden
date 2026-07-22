package handler_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/handler"
	"github.com/boogy/aws-oidc-warden/internal/s3logger"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// leakyConsumer wraps fakeConsumer so AssumeRole can fail with a realistic
// AWS SDK error string (which embeds ARNs / account IDs).
type leakyConsumer struct {
	*fakeConsumer
	assumeErr error
}

func (l *leakyConsumer) AssumeRole(roleARN, _ string, _ *string, _ *int32, _ *types.Claims, _ map[string]string) (*ststypes.Credentials, error) {
	if l.assumeErr != nil {
		return nil, l.assumeErr
	}
	return l.assumeOut, nil
}

// --- 1. audit_required fail-closed vs. the REAL s3logger sink ---

// The S3Logger captures *config.Config by pointer at bootstrap
// (bootstrap.go:120 `s3logger.NewS3Logger(provider.Get())`), while
// recordDecision reads the LIVE config from provider.Get() on every request.
// After a hot reload the two disagree. This models: boot config had
// log_to_s3=false / audit_required=false (both defaults), reloaded config
// turns audit_required=true + log_to_s3=true.
func TestAudit_RequiredAudit_StaleS3LoggerConfig_ReturnsCredentialsWithNoDurableWrite(t *testing.T) {
	bootCfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer: testIssuer, Provider: "github", Audiences: []string{"sts.amazonaws.com"},
		}},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 0},
		RoleMappings: []config.RoleMapping{{
			Subject: "org/repo",
			Roles:   []string{"arn:aws:iam::123456789012:role/MyRole"},
		}},
		LogToS3:       false, // default
		AuditRequired: false, // default
	}
	require.NoError(t, bootCfg.Validate())

	// The real sink, built from the boot config exactly as bootstrap does.
	sink := s3logger.NewS3Logger(bootCfg)

	// Hot-reloaded config: operator turns on required auditing without a redeploy.
	liveCfg := &config.Config{
		Issuers:         bootCfg.Issuers,
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 0},
		RoleMappings:    bootCfg.RoleMappings,
		LogToS3:         true,
		LogBucket:       "audit-bucket",
		AuditRequired:   true,
	}
	require.NoError(t, liveCfg.Validate())

	proc := handler.NewRequestProcessor(
		config.NewStaticProvider(liveCfg), mockConsumer(t),
		&fixedExtractor{claims: allowClaims("org/repo")}, sink, "test")

	creds, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"}, "req-stale", slog.Default())

	// audit_required=true promises: no credentials unless the record was
	// durably written. The sink has no S3 client at all here.
	t.Logf("err=%v creds!=nil=%v", err, creds != nil)
	require.Error(t, err, "FAIL-OPEN: credentials returned although audit_required=true and the sink wrote nothing")
	assert.Nil(t, creds)
}

// --- 2. error bodies from the untested apigateway Handler path ---

func TestAudit_APIGatewayHandler_AssumeRoleErrorBodyLeaksNothing(t *testing.T) {
	cfg := auditTestCfg(t, false, true)
	sdkErr := errors.New("operation error STS: AssumeRole, https response error StatusCode: 403, " +
		"api error AccessDenied: User: arn:aws:sts::999988887777:assumed-role/warden-hub/lambda is not authorized " +
		"to perform: sts:AssumeRole on resource: arn:aws:iam::123456789012:role/MyRole")

	consumer := &leakyConsumer{fakeConsumer: mockConsumer(t), assumeErr: sdkErr}
	h := handler.NewAwsApiGateway(config.NewStaticProvider(cfg), consumer,
		&fixedExtractor{claims: allowClaims("org/repo")}, nil)

	resp, err := h.Handler(context.Background(), events.APIGatewayProxyRequest{
		Path: "/", HTTPMethod: "POST",
		Body: `{"token":"eyJhbGciOiJSUzI1NiJ9.payload.sig","role":"arn:aws:iam::123456789012:role/MyRole"}`,
	})
	require.NoError(t, err)
	t.Logf("status=%d headers=%v body=%s", resp.StatusCode, resp.Headers, resp.Body)

	assert.NotContains(t, resp.Body, "999988887777")
	assert.NotContains(t, resp.Body, "arn:aws:iam::")
	assert.NotContains(t, resp.Body, "AccessDenied")
	assert.NotContains(t, resp.Body, "eyJhbGciOiJSUzI1NiJ9")
}

// Success path: confirm what headers a live-credential response actually
// carries, and that no request token is echoed.
func TestAudit_APIGatewayHandler_SuccessResponseHeadersAndBody(t *testing.T) {
	cfg := auditTestCfg(t, false, true)
	h := handler.NewAwsApiGateway(config.NewStaticProvider(cfg), mockConsumer(t),
		&fixedExtractor{claims: allowClaims("org/repo")}, nil)

	resp, err := h.Handler(context.Background(), events.APIGatewayProxyRequest{
		Path: "/", HTTPMethod: "GET", // NOTE: method is never checked by the handler
		Body: `{"token":"eyJhbGciOiJSUzI1NiJ9.payload.sig","role":"arn:aws:iam::123456789012:role/MyRole"}`,
	})
	require.NoError(t, err)
	t.Logf("status=%d headers=%#v", resp.StatusCode, resp.Headers)
	t.Logf("body=%s", resp.Body)

	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(resp.Body), &got))
	assert.Equal(t, float64(200), got["statusCode"])
	assert.NotContains(t, resp.Body, "eyJhbGciOiJSUzI1NiJ9")

	// Report which cache-relevant headers are present on a credential response.
	for _, hdr := range []string{"Cache-Control", "Pragma", "Access-Control-Allow-Origin"} {
		if v, ok := resp.Headers[hdr]; ok {
			t.Logf("header %s=%q", hdr, v)
		} else {
			t.Logf("header %s ABSENT", hdr)
		}
	}
	assert.Contains(t, strings.ToLower(resp.Headers["Content-Type"]), "json")
}
