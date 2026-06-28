package handler_test

import (
	"context"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/boogy/aws-oidc-warden/internal/handler"
	"github.com/boogy/aws-oidc-warden/internal/types"
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
	ex := &fixedExtractor{claims: &types.GithubClaims{
		Repository: "org/repo",
		Ref:        "refs/heads/main",
		Actor:      "octocat",
	}}

	h := handler.NewAwsApiGatewayV2(staticProvider(t), mockConsumer(t), ex)
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

	h := handler.NewAwsApiGatewayV2(staticProvider(t), mockConsumer(t), ex)
	resp, err := h.Handler(context.Background(), event)
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode)
}
