package handler_test

// The per-frontend adapters: event parse and response serialization for API
// Gateway v2 and ALB (including multi-value headers), plus the log-schema
// adapter each one feeds.
import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/handler"
	"github.com/boogy/aws-oidc-warden/internal/idp"
	"github.com/boogy/aws-oidc-warden/internal/idp/idptest"
	"github.com/boogy/aws-oidc-warden/internal/logevent"
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
	slog.SetDefault(slog.New(logevent.NewHandler(slog.NewJSONHandler(&buf, nil))))
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

func TestALBHandler_OversizedOIDCHeaderIsInvalidRequest(t *testing.T) {
	h := handler.NewAwsApplicationLoadBalancer(staticProvider(t), mockConsumer(t), &captureExtractor{}, nil)

	resp, err := h.Handler(context.Background(), albEvent(map[string][]string{
		"x-amzn-oidc-data": {strings.Repeat("a", handler.MaxTokenLength+1)},
	}, `{"role":"arn:aws:iam::123456789012:role/MyRole"}`))
	require.NoError(t, err)

	assert.Equal(t, 400, resp.StatusCode)
	assert.Contains(t, resp.Body, `"errorCode":"invalid_request"`)
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
	slog.SetDefault(slog.New(logevent.NewHandler(slog.NewJSONHandler(&buf, nil))))
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

// idpFrontResp is a frontend response reduced to what the IdP routing tests assert on.
type idpFrontResp struct {
	status  int
	body    string
	headers map[string]string
	multi   map[string][]string
}

func (r idpFrontResp) code(t *testing.T) string {
	t.Helper()
	var env struct {
		ErrorCode string `json:"errorCode"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.body), &env))
	return env.ErrorCode
}

type idpFrontend struct {
	name  string
	build func(t *testing.T, p *config.Provider, c *fakeConsumer, ex validator.ClaimsExtractorInterface, svc *idp.Service) func(method, path, body string) idpFrontResp
}

func idpFrontends() []idpFrontend {
	return []idpFrontend{
		{"apigateway", func(t *testing.T, p *config.Provider, c *fakeConsumer, ex validator.ClaimsExtractorInterface, svc *idp.Service) func(string, string, string) idpFrontResp {
			h := handler.NewAwsApiGateway(p, c, ex, nil)
			if svc != nil {
				h.WithIdP(svc)
			}
			return func(m, path, body string) idpFrontResp {
				r, err := h.Handler(context.Background(), events.APIGatewayProxyRequest{HTTPMethod: m, Path: path, Body: body})
				require.NoError(t, err)
				return idpFrontResp{status: r.StatusCode, body: r.Body, headers: r.Headers}
			}
		}},
		{"apigatewayv2", func(t *testing.T, p *config.Provider, c *fakeConsumer, ex validator.ClaimsExtractorInterface, svc *idp.Service) func(string, string, string) idpFrontResp {
			h := handler.NewAwsApiGatewayV2(p, c, ex, nil)
			if svc != nil {
				h.WithIdP(svc)
			}
			return func(m, path, body string) idpFrontResp {
				ev := events.APIGatewayV2HTTPRequest{RawPath: path, Body: body}
				ev.RequestContext.HTTP.Method = m
				r, err := h.Handler(context.Background(), ev)
				require.NoError(t, err)
				return idpFrontResp{status: r.StatusCode, body: r.Body, headers: r.Headers}
			}
		}},
		{"alb", func(t *testing.T, p *config.Provider, c *fakeConsumer, ex validator.ClaimsExtractorInterface, svc *idp.Service) func(string, string, string) idpFrontResp {
			h := handler.NewAwsApplicationLoadBalancer(p, c, ex, nil)
			if svc != nil {
				h.WithIdP(svc)
			}
			return func(m, path, body string) idpFrontResp {
				ev := albEvent(nil, body)
				ev.HTTPMethod, ev.Path = m, path
				r, err := h.Handler(context.Background(), ev)
				require.NoError(t, err)
				return idpFrontResp{status: r.StatusCode, body: r.Body, headers: r.Headers, multi: r.MultiValueHeaders}
			}
		}},
		{"lambdaurl", func(t *testing.T, p *config.Provider, c *fakeConsumer, ex validator.ClaimsExtractorInterface, svc *idp.Service) func(string, string, string) idpFrontResp {
			h := handler.NewAwsLambdaUrl(p, c, ex, nil)
			if svc != nil {
				h.WithIdP(svc)
			}
			return func(m, path, body string) idpFrontResp {
				ev := events.LambdaFunctionURLRequest{RawPath: path, Body: body}
				ev.RequestContext.HTTP.Method = m
				r, err := h.Handler(context.Background(), ev)
				require.NoError(t, err)
				return idpFrontResp{status: r.StatusCode, body: r.Body, headers: r.Headers}
			}
		}},
	}
}

const (
	idpTokenPath = "/verify"
	idpDiscPath  = "/.well-known/openid-configuration"
	idpJWKSPath  = "/.well-known/jwks.json"
)

func TestIdPFrontends(t *testing.T) {
	mintBody := func(extra string) string {
		return `{"token":"x","role":"` + testRoleARN + `"` + extra + `}`
	}
	disabled := func(c *config.Config) { c.IdP.Enabled = false }

	tests := []struct {
		name         string
		mutate       []func(*config.Config)
		loadErr      error
		noIdP        bool
		denyExtract  bool
		method, path string
		body         string
		wantStatus   int
		wantCode     string
		wantHeaders  map[string]string
		wantEmpty    bool
		multi        bool
		check        func(t *testing.T, r idpFrontResp, cons *fakeConsumer, logs string)
	}{
		{
			name: "discovery", multi: true, method: "GET", path: idpDiscPath, wantStatus: 200,
			wantHeaders: map[string]string{"Content-Type": "application/json", "Cache-Control": "public, max-age=300"},
			check: func(t *testing.T, r idpFrontResp, _ *fakeConsumer, _ string) {
				assert.Contains(t, r.body, `"issuer"`)
			},
		},
		{
			name: "jwks", method: "GET", path: idpJWKSPath, wantStatus: 200,
			wantHeaders: map[string]string{"Content-Type": "application/json", "Cache-Control": "public, max-age=300"},
			check: func(t *testing.T, r idpFrontResp, _ *fakeConsumer, _ string) {
				var doc struct{ Keys []any }
				require.NoError(t, json.Unmarshal([]byte(r.body), &doc))
				assert.NotEmpty(t, doc.Keys)
			},
		},
		{
			name: "head jwks", multi: true, method: "HEAD", path: idpJWKSPath, wantStatus: 200, wantEmpty: true,
			wantHeaders: map[string]string{"Content-Type": "application/json", "Cache-Control": "public, max-age=300"},
		},
		{
			name: "mint", method: "POST", path: idpTokenPath, body: mintBody(""), wantStatus: 200,
			wantHeaders: map[string]string{"Cache-Control": "no-store"},
			check: func(t *testing.T, r idpFrontResp, cons *fakeConsumer, _ string) {
				var env struct {
					Success bool
					Data    struct{ AccessKeyId string }
				}
				require.NoError(t, json.Unmarshal([]byte(r.body), &env))
				assert.True(t, env.Success)
				assert.Equal(t, "AKIAEXAMPLE", env.Data.AccessKeyId)
				assert.NotContains(t, r.body, "eyJ")
				assert.Equal(t, 1, cons.wiCalls)
				assert.Zero(t, cons.assumeCalls)
			},
		},
		{
			name: "mint over cap", method: "POST", path: idpTokenPath, body: mintBody(`,"durationSeconds":7200`),
			wantStatus: 400, wantCode: "duration_exceeds_cap",
		},
		{
			name: "jwks wrong method", multi: true, method: "POST", path: idpJWKSPath, wantStatus: 405, wantCode: "method_not_allowed",
			wantHeaders: map[string]string{"Allow": "GET, HEAD"},
		},
		{
			name: "kill switch over 1h", mutate: []func(*config.Config){disabled}, method: "POST", path: idpTokenPath, body: mintBody(`,"durationSeconds":7200`),
			wantStatus: 503, wantCode: "idp_signing_unavailable",
			check: func(t *testing.T, _ idpFrontResp, cons *fakeConsumer, _ string) {
				assert.Zero(t, cons.wiCalls)
				assert.Zero(t, cons.assumeCalls)
			},
		},
		{name: "kill switch jwks", mutate: []func(*config.Config){disabled}, method: "GET", path: idpJWKSPath, wantStatus: 404, wantCode: "idp_path_not_found"},
		{
			name: "stage prefixed path", method: "GET", path: "/prod" + idpJWKSPath,
			wantStatus: 404, wantCode: "idp_path_not_found",
			check: func(t *testing.T, _ idpFrontResp, _ *fakeConsumer, logs string) {
				assert.Equal(t, 1, countEventLines(logs, "idp.path.not_found"))
			},
		},
		{name: "no idp jwks path", noIdP: true, denyExtract: true, method: "GET", path: idpJWKSPath, body: mintBody(""), wantStatus: 401, wantCode: "token_invalid"},
		{name: "no idp credential path", noIdP: true, denyExtract: true, method: "POST", path: idpTokenPath, body: mintBody(""), wantStatus: 401, wantCode: "token_invalid"},
		{
			name: "loader failure", loadErr: errBoom, method: "GET", path: idpJWKSPath, wantStatus: 503, wantCode: "idp_signing_unavailable",
			wantHeaders: map[string]string{"Content-Type": "application/json"},
		},
	}

	for _, fe := range idpFrontends() {
		for _, tt := range tests {
			t.Run(fe.name+"/"+tt.name, func(t *testing.T) {
				var buf bytes.Buffer
				prev := slog.Default()
				slog.SetDefault(slog.New(logevent.NewHandler(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))))
				defer slog.SetDefault(prev)

				cfg := idpConfig(t, true, "", tt.mutate...)
				cons := mockWI(t)
				var ex validator.ClaimsExtractorInterface = idpClaims(nil)
				if tt.denyExtract {
					ex = &stubExtractor{err: handler.ErrTokenValidationFailed}
				}
				var svc *idp.Service
				if !tt.noIdP {
					svc = idpService(t, cfg, &countingSigner{Signer: idptest.NewSigner(t)}, tt.loadErr)
				}
				r := fe.build(t, config.NewStaticProvider(cfg), cons, ex, svc)(tt.method, tt.path, tt.body)

				assert.Equal(t, tt.wantStatus, r.status, r.body)
				if tt.wantCode != "" {
					assert.Equal(t, tt.wantCode, r.code(t))
				}
				for k, v := range tt.wantHeaders {
					assert.Equal(t, v, r.headers[k], k)
					if fe.name == "alb" && tt.multi {
						assert.Equal(t, []string{v}, r.multi[k], "multi "+k)
					}
				}
				if tt.wantEmpty {
					assert.Empty(t, r.body)
				}
				if tt.check != nil {
					tt.check(t, r, cons, buf.String())
				}
			})
		}
	}
}

func TestIdPDocuments(t *testing.T) {
	cfg := idpConfig(t, true, "")
	svc := idpService(t, cfg, &countingSigner{Signer: idptest.NewSigner(t)}, nil)
	ks, err := svc.KeySet(context.Background())
	require.NoError(t, err)
	paths := svc.Config().Paths

	for _, fe := range idpFrontends() {
		t.Run(fe.name, func(t *testing.T) {
			call := fe.build(t, config.NewStaticProvider(cfg), mockWI(t), idpClaims(nil), svc)

			disc := call("GET", paths.Discovery, "")
			require.Equal(t, 200, disc.status)
			var d struct {
				Issuer  string `json:"issuer"`
				JWKSURI string `json:"jwks_uri"`
			}
			require.NoError(t, json.Unmarshal([]byte(disc.body), &d))
			assert.Equal(t, d.Issuer+paths.JWKS, d.JWKSURI)

			jwks := call("GET", paths.JWKS, "")
			require.Equal(t, 200, jwks.status)
			var want, got struct {
				Keys []struct {
					Kid string `json:"kid"`
				} `json:"keys"`
			}
			require.NoError(t, json.Unmarshal(ks.JWKS(), &want))
			require.NoError(t, json.Unmarshal([]byte(jwks.body), &got))
			assert.Equal(t, want, got)
			assert.NotEmpty(t, got.Keys)

			for _, b := range []string{disc.body, jwks.body} {
				assert.NotContains(t, b, `"d":`)
			}
		})
	}
}

func TestAPIGatewayRoutesIdPOnStageQualifiedPath(t *testing.T) {
	cfg := idpConfig(t, true, "", func(c *config.Config) { c.IdP.Issuer = "https://idp.example.com/prod" })
	svc := idpService(t, cfg, &countingSigner{Signer: idptest.NewSigner(t)}, nil)
	h := handler.NewAwsApiGateway(config.NewStaticProvider(cfg), mockWI(t), idpClaims(nil), nil).WithIdP(svc)

	ev := events.APIGatewayProxyRequest{HTTPMethod: "GET", Path: idpJWKSPath}
	ev.RequestContext.Path = "/prod" + idpJWKSPath
	r, err := h.Handler(context.Background(), ev)
	require.NoError(t, err)
	assert.Equal(t, 200, r.StatusCode, r.Body)
	assert.Contains(t, r.Body, `"keys"`)
}

func TestIdPDocumentRouteWarnsOnFrozenDrift(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(logevent.NewHandler(slog.NewJSONHandler(&buf, nil))))
	defer slog.SetDefault(prev)

	cfg := idpConfig(t, true, "")
	svc := idpService(t, cfg, &countingSigner{Signer: idptest.NewSigner(t)}, nil)
	cfg.IdP.Audience = "drifted.example.com"
	h := handler.NewAwsApiGateway(config.NewStaticProvider(cfg), mockWI(t), idpClaims(nil), nil).WithIdP(svc)

	r, err := h.Handler(context.Background(), events.APIGatewayProxyRequest{HTTPMethod: "GET", Path: idpJWKSPath})
	require.NoError(t, err)
	require.Equal(t, 200, r.StatusCode, r.Body)
	assert.Equal(t, 1, countEventLines(buf.String(), "config.idp.reload_ignored"))
}
