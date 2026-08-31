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

// frontendAPIGateway identifies this adapter in audit records/logs.
const frontendAPIGateway = "apigateway"

// AwsApiGateway handles AWS API Gateway proxy integration requests
type AwsApiGateway struct {
	processor *RequestProcessor
}

// NewAwsApiGateway creates a new API Gateway handler. audit may be nil (see AuditSink).
func NewAwsApiGateway(provider *config.Provider, consumer aws.AwsConsumerInterface, extractor validator.ClaimsExtractorInterface, audit AuditSink) *AwsApiGateway {
	return &AwsApiGateway{
		processor: NewRequestProcessor(provider, consumer, extractor, audit, frontendAPIGateway),
	}
}

// Handler is the Lambda function interface for API Gateway
func (h *AwsApiGateway) Handler(ctx context.Context, event events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	ctx, cancel := h.createRequestContext(ctx, event)
	defer cancel()
	requestID, _ := ctx.Value(RequestIDContextKey).(string)

	log := requestLogger(ctx,
		slog.String("requestId", requestID),
		slog.String("path", event.Path),
		slog.String("method", event.HTTPMethod),
		slog.String("userAgent", event.RequestContext.Identity.UserAgent),
		slog.String("requestTime", event.RequestContext.RequestTime),
		slog.String("domainName", event.RequestContext.DomainName),
	)

	requestData, err := h.unmarshalRequestData(event)
	if err != nil {
		return h.respondError(ctx, err, http.StatusBadRequest)
	}

	input := validator.ExtractionInput{Token: requestData.Token}

	credentials, err := h.processor.ProcessRequest(ctx, requestData, input, requestID, log)
	if err != nil {
		return h.respondError(ctx, err, http.StatusInternalServerError)
	}

	return h.respondJSON(ctx, credentials)
}

// createRequestContext creates an enhanced context with request tracking information
func (h *AwsApiGateway) createRequestContext(ctx context.Context, event events.APIGatewayProxyRequest) (context.Context, context.CancelFunc) {
	return newRequestContext(ctx,
		event.RequestContext.RequestID,
		event.RequestContext.Identity.SourceIP,
		event.Headers,
		event.RequestContext.Identity.UserAgent,
	)
}

func (h *AwsApiGateway) unmarshalRequestData(event events.APIGatewayProxyRequest) (*RequestData, error) {
	return ParseRequestBody(event.Body)
}

// newResponse builds this frontend's response type from a status and body.
func (h *AwsApiGateway) newResponse(statusCode int, body string) events.APIGatewayProxyResponse {
	return events.APIGatewayProxyResponse{
		StatusCode:      statusCode,
		Headers:         ResponseHeaders,
		Body:            body,
		IsBase64Encoded: false,
	}
}

// respondError formats a response with an error message.
func (h *AwsApiGateway) respondError(ctx context.Context, err error, statusCode int) (events.APIGatewayProxyResponse, error) {
	return errorResponse(ctx, err, statusCode, h.newResponse), nil
}

// respondJSON formats a successful response with credentials
func (h *AwsApiGateway) respondJSON(ctx context.Context, credentials *types.Credentials) (events.APIGatewayProxyResponse, error) {
	return successResponse(ctx, credentials, h.newResponse), nil
}
