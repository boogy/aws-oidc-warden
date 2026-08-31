package handler

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/boogy/aws-oidc-warden/internal/aws"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/validator"
)

// frontendAPIGatewayV2 identifies this adapter in audit records/logs.
const frontendAPIGatewayV2 = "apigatewayv2"

// AwsApiGatewayV2 handles AWS API Gateway HTTP API (v2) requests with a JWT Authorizer.
// Use this adapter when API Gateway validates the JWT and passes claims via
// event.requestContext.authorizer.jwt.claims. Set jwt_validation.mode: "apigw".
type AwsApiGatewayV2 struct {
	processor *RequestProcessor
}

// NewAwsApiGatewayV2 creates a new HTTP API v2 handler. audit may be nil (see AuditSink).
func NewAwsApiGatewayV2(provider *config.Provider, consumer aws.AwsConsumerInterface, extractor validator.ClaimsExtractorInterface, audit AuditSink) *AwsApiGatewayV2 {
	return &AwsApiGatewayV2{processor: NewRequestProcessor(provider, consumer, extractor, audit, frontendAPIGatewayV2)}
}

// Handler is the Lambda function interface for API Gateway HTTP API v2.
func (h *AwsApiGatewayV2) Handler(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	ctx, cancel := h.createRequestContext(ctx, event)
	defer cancel()
	requestID, _ := ctx.Value(RequestIDContextKey).(string)

	log := requestLogger(ctx,
		slog.String("requestId", requestID),
		slog.String("path", event.RawPath),
		slog.String("method", event.RequestContext.HTTP.Method),
		slog.String("userAgent", event.RequestContext.HTTP.UserAgent),
	)

	requestData, err := ParseRoleOnlyRequestBody(event.Body)
	if err != nil {
		return h.respondError(ctx, err, http.StatusBadRequest)
	}

	// Extract claims from API Gateway JWT Authorizer context.
	var authorizerClaims map[string]string
	if event.RequestContext.Authorizer != nil && event.RequestContext.Authorizer.JWT != nil {
		authorizerClaims = event.RequestContext.Authorizer.JWT.Claims
	}
	input := validator.ExtractionInput{AuthorizerClaims: authorizerClaims}

	credentials, err := h.processor.ProcessRequest(ctx, requestData, input, requestID, log)
	if err != nil {
		return h.respondError(ctx, err, http.StatusInternalServerError)
	}
	return h.respondJSON(ctx, credentials)
}

func (h *AwsApiGatewayV2) createRequestContext(ctx context.Context, event events.APIGatewayV2HTTPRequest) (context.Context, context.CancelFunc) {
	return newRequestContext(ctx,
		event.RequestContext.RequestID,
		event.RequestContext.HTTP.SourceIP,
		event.Headers,
		event.RequestContext.HTTP.UserAgent,
	)
}

// newResponse builds this frontend's response type from a status and body.
func (h *AwsApiGatewayV2) newResponse(statusCode int, body string) events.APIGatewayV2HTTPResponse {
	return events.APIGatewayV2HTTPResponse{StatusCode: statusCode, Headers: ResponseHeaders, Body: body}
}

func (h *AwsApiGatewayV2) respondError(ctx context.Context, err error, statusCode int) (events.APIGatewayV2HTTPResponse, error) {
	return errorResponse(ctx, err, statusCode, h.newResponse), nil
}

func (h *AwsApiGatewayV2) respondJSON(ctx context.Context, credentials *types.Credentials) (events.APIGatewayV2HTTPResponse, error) {
	return successResponse(ctx, credentials, h.newResponse), nil
}
