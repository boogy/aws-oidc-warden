package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/boogy/aws-oidc-warden/internal/aws"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/google/uuid"
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
	// Create a request context with tracking information and timeout
	ctx, cancel := h.createRequestContext(ctx, event)
	defer cancel()
	requestID, _ := ctx.Value(RequestIDContextKey).(string)

	// Add request ID and additional data to all logs for this request
	log := slog.With(
		slog.String("requestId", requestID),
		slog.String("rawPath", event.RawPath),
		slog.String("method", event.RequestContext.HTTP.Method),
		slog.String("sourceIp", event.RequestContext.HTTP.SourceIP),
		slog.String("userAgent", event.RequestContext.HTTP.UserAgent),
		slog.String("requestTime", event.RequestContext.Time),
		slog.String("domainName", event.RequestContext.DomainName),
	)

	// Parse request data
	requestData, err := h.unmarshalRequestData(event)
	if err != nil {
		return h.respondError(ctx, err, http.StatusBadRequest)
	}

	// Build extraction input from the parsed request token.
	input := validator.ExtractionInput{Token: requestData.Token}

	// Process the request using the request processor
	credentials, err := h.processor.ProcessRequest(ctx, requestData, input, requestID, log)
	if err != nil {
		return h.respondError(ctx, err, http.StatusInternalServerError)
	}

	return h.respondJSON(ctx, credentials)
}

// createRequestContext creates an enhanced context with request tracking information
func (h *AwsLambdaUrl) createRequestContext(ctx context.Context, event events.LambdaFunctionURLRequest) (context.Context, context.CancelFunc) {
	// Generate a request ID if not available from the event
	requestID := event.RequestContext.RequestID
	if requestID == "" {
		requestID = uuid.New().String()
	}

	// Start request timer
	startTime := time.Now()

	// Add request tracking information using context keys
	ctx = context.WithValue(ctx, RequestIDContextKey, requestID)
	ctx = context.WithValue(ctx, StartTimeContextKey, startTime)
	ctx = context.WithValue(ctx, SourceIPContextKey, event.RequestContext.HTTP.SourceIP)
	ctx = context.WithValue(ctx, UserAgentContextKey, event.RequestContext.HTTP.UserAgent)

	// Create a context with timeout. The caller must invoke the returned cancel
	// (via defer) to release the timer when the request completes.
	return context.WithTimeout(ctx, DefaultTimeout)
}

// unmarshalRequestData parses and validates the request data from a Lambda URL event
func (h *AwsLambdaUrl) unmarshalRequestData(event events.LambdaFunctionURLRequest) (*RequestData, error) {
	return ParseRequestBody(event.Body)
}

// respondError formats a response with an error message
func (h *AwsLambdaUrl) respondError(ctx context.Context, err error, statusCode int) (events.LambdaFunctionURLResponse, error) {
	response, statusCode := buildErrorResponse(ctx, err, statusCode)

	jsonResponse, jsonErr := json.Marshal(response)
	if jsonErr != nil {
		// Fallback to simple error response if JSON marshalling fails
		return events.LambdaFunctionURLResponse{
			StatusCode: http.StatusInternalServerError,
			Headers:    ResponseHeaders,
			Body:       fmt.Sprintf(`{"error": "%s"}`, err.Error()),
		}, nil
	}

	return events.LambdaFunctionURLResponse{
		StatusCode: statusCode,
		Headers:    ResponseHeaders,
		Body:       string(jsonResponse),
	}, nil
}

// respondJSON formats a successful response with credentials
func (h *AwsLambdaUrl) respondJSON(ctx context.Context, credentials *types.Credentials) (events.LambdaFunctionURLResponse, error) {
	response := buildSuccessResponse(ctx, credentials)

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		return h.respondError(ctx, fmt.Errorf("failed to marshal response: %w", err), http.StatusInternalServerError)
	}

	return events.LambdaFunctionURLResponse{
		StatusCode: http.StatusOK,
		Headers:    ResponseHeaders,
		Body:       string(jsonResponse),
	}, nil
}
