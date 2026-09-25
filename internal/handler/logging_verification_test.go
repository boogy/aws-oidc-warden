package handler_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/boogy/aws-oidc-warden/internal/handler"
	"github.com/boogy/aws-oidc-warden/internal/logevent"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validLoggingRole = "arn:aws:iam::123456789012:role/MyRole"

func countEventLines(out, eventType string) int {
	n := 0
	for line := range strings.SplitSeq(strings.TrimRight(out, "\n"), "\n") {
		if line != "" && strings.Contains(line, `"eventType":"`+eventType+`"`) {
			n++
		}
	}
	return n
}

func countErrorLevelLines(out string) int {
	n := 0
	for line := range strings.SplitSeq(strings.TrimRight(out, "\n"), "\n") {
		if line != "" && strings.Contains(line, `"level":"ERROR"`) {
			n++
		}
	}
	return n
}

// loggingAdapter drives one frontend's real Handler(); assertions read the log buffer.
type loggingAdapter struct {
	name          string
	validBody     string
	malformedBody string
	run           func(t *testing.T, ex validator.ClaimsExtractorInterface, fc *fakeConsumer, body string)
}

var loggingAdapters = []loggingAdapter{
	{
		name:          "apigateway",
		validBody:     `{"token":"tok","role":"` + validLoggingRole + `"}`,
		malformedBody: `not-json`,
		run: func(t *testing.T, ex validator.ClaimsExtractorInterface, fc *fakeConsumer, body string) {
			h := handler.NewAwsApiGateway(staticProvider(t), fc, ex, nil)
			_, err := h.Handler(context.Background(), events.APIGatewayProxyRequest{
				HTTPMethod: "POST", Path: "/assume-role", Body: body,
			})
			require.NoError(t, err)
		},
	},
	{
		name:          "apigatewayv2",
		validBody:     `{"role":"` + validLoggingRole + `"}`,
		malformedBody: `not-json`,
		run: func(t *testing.T, ex validator.ClaimsExtractorInterface, fc *fakeConsumer, body string) {
			h := handler.NewAwsApiGatewayV2(staticProvider(t), fc, ex, nil)
			_, err := h.Handler(context.Background(), events.APIGatewayV2HTTPRequest{Body: body})
			require.NoError(t, err)
		},
	},
	{
		name:          "alb",
		validBody:     `{"token":"tok","role":"` + validLoggingRole + `"}`,
		malformedBody: `not-json`,
		run: func(t *testing.T, ex validator.ClaimsExtractorInterface, fc *fakeConsumer, body string) {
			h := handler.NewAwsApplicationLoadBalancer(staticProvider(t), fc, ex, nil)
			_, err := h.Handler(context.Background(), events.ALBTargetGroupRequest{
				HTTPMethod: "POST", Path: "/assume-role", Body: body,
				RequestContext: events.ALBTargetGroupRequestContext{
					ELB: events.ELBContext{TargetGroupArn: "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test/abc"},
				},
			})
			require.NoError(t, err)
		},
	},
	{
		name:          "lambdaurl",
		validBody:     `{"token":"tok","role":"` + validLoggingRole + `"}`,
		malformedBody: `not-json`,
		run: func(t *testing.T, ex validator.ClaimsExtractorInterface, fc *fakeConsumer, body string) {
			h := handler.NewAwsLambdaUrl(staticProvider(t), fc, ex, nil)
			_, err := h.Handler(context.Background(), events.LambdaFunctionURLRequest{Body: body})
			require.NoError(t, err)
		},
	},
}

func TestHandlerLogging_TerminalLineInvariants(t *testing.T) {
	okClaims := &types.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Issuer: testIssuer, Subject: "org/repo"},
		Repository:       "org/repo",
	}

	type scenario struct {
		name       string
		malformed  bool  // pre-pipeline reject: body never reaches the extractor
		extractErr error // client-caused deny: extractor fails
		assumeErr  error // AssumeRole infra failure
	}
	scenarios := []scenario{
		{name: "client_deny", extractErr: errors.New("token is expired")},
		{name: "pre_pipeline_reject", malformed: true},
		{name: "assume_role_infra_failure", assumeErr: errors.New("sts unavailable")},
	}

	for _, ad := range loggingAdapters {
		for _, sc := range scenarios {
			t.Run(ad.name+"/"+sc.name, func(t *testing.T) {
				var buf bytes.Buffer
				prevDefault := slog.Default()
				slog.SetDefault(slog.New(logevent.NewHandler(slog.NewJSONHandler(&buf, nil))))
				defer slog.SetDefault(prevDefault)

				var ex validator.ClaimsExtractorInterface = &fixedExtractor{claims: okClaims}
				if sc.extractErr != nil {
					ex = &stubExtractor{err: sc.extractErr}
				}
				fc := &fakeConsumer{allowAccount: true, assumeErr: sc.assumeErr}

				body := ad.validBody
				if sc.malformed {
					body = ad.malformedBody
				}
				ad.run(t, ex, fc, body)
				out := buf.String()

				decisionLines := countEventLines(out, "authz.decision")
				rejectedLines := countEventLines(out, "request.rejected")
				errorLines := countErrorLevelLines(out)

				switch sc.name {
				case "client_deny":
					assert.Equal(t, 1, decisionLines, "want exactly one authz.decision line:\n%s", out)
					assert.Equal(t, 0, errorLines, "client-caused deny must never log at ERROR:\n%s", out)
				case "pre_pipeline_reject":
					assert.Equal(t, 1, rejectedLines, "want exactly one request.rejected line:\n%s", out)
					assert.Equal(t, 0, decisionLines, "a pre-pipeline reject must not reach authz.decision:\n%s", out)
				case "assume_role_infra_failure":
					assert.Equal(t, 1, decisionLines, "want exactly one authz.decision line:\n%s", out)
					// The handler side logs nothing at ERROR for a bare
					// AssumeRole failure (nil audit sink, audit not enforced):
					// STS-failure ERROR logging is internal/aws's (not
					// exercised through fakeConsumer). Asserting the observed
					// count rather than a fabricated "at least one".
					assert.Equal(t, 0, errorLines, "handler emits no ERROR line for a bare AssumeRole failure; see internal/aws for STS-side failure logging:\n%s", out)
				}
			})
		}
	}
}
