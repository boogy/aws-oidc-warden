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

// frontendLambdaURL identifies this adapter in audit records/logs.
const frontendLambdaURL = "lambdaurl"

// AwsLambdaUrl handles AWS Lambda URL requests
type AwsLambdaUrl struct {
	processor *RequestProcessor
}

// NewAwsLambdaUrl creates a new Lambda URL handler. audit may be nil (see AuditSink).
func NewAwsLambdaUrl(provider *config.Provider, consumer aws.AwsConsumerInterface, extractor validator.ClaimsExtractorInterface, audit AuditSink) *AwsLambdaUrl {
	return &AwsLambdaUrl{
		processor: NewRequestProcessor(provider, consumer, extractor, audit, frontendLambdaURL),
	}
}

// Handler is the Lambda function interface for Lambda URLs
func (h *AwsLambdaUrl) Handler(ctx context.Context, event events.LambdaFunctionURLRequest) (events.LambdaFunctionURLResponse, error) {
	ctx, cancel := h.createRequestContext(ctx, event)
	defer cancel()
	requestID, _ := ctx.Value(RequestIDContextKey).(string)

	log := requestLogger(ctx,
		slog.String("requestId", requestID),
		slog.String("path", event.RawPath),
		slog.String("method", event.RequestContext.HTTP.Method),
		slog.String("userAgent", event.RequestContext.HTTP.UserAgent),
		slog.String("requestTime", event.RequestContext.Time),
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
func (h *AwsLambdaUrl) createRequestContext(ctx context.Context, event events.LambdaFunctionURLRequest) (context.Context, context.CancelFunc) {
	return newRequestContext(ctx,
		event.RequestContext.RequestID,
		event.RequestContext.HTTP.SourceIP,
		event.Headers,
		event.RequestContext.HTTP.UserAgent,
	)
}

// unmarshalRequestData parses and validates the request data from a Lambda URL event
func (h *AwsLambdaUrl) unmarshalRequestData(event events.LambdaFunctionURLRequest) (*RequestData, error) {
	return ParseRequestBody(event.Body)
}

// newResponse builds this frontend's response type from a status and body.
func (h *AwsLambdaUrl) newResponse(statusCode int, body string) events.LambdaFunctionURLResponse {
	return events.LambdaFunctionURLResponse{
		StatusCode: statusCode,
		Headers:    ResponseHeaders,
		Body:       body,
	}
}

// respondError formats a response with an error message
func (h *AwsLambdaUrl) respondError(ctx context.Context, err error, statusCode int) (events.LambdaFunctionURLResponse, error) {
	return errorResponse(ctx, err, statusCode, h.newResponse), nil
}

// respondJSON formats a successful response with credentials
func (h *AwsLambdaUrl) respondJSON(ctx context.Context, credentials *types.Credentials) (events.LambdaFunctionURLResponse, error) {
	return successResponse(ctx, credentials, h.newResponse), nil
}
