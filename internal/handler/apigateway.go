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

// AwsApiGateway handles AWS API Gateway proxy integration requests
type AwsApiGateway struct {
	processor *RequestProcessor
}

// NewAwsApiGateway creates a new API Gateway handler
func NewAwsApiGateway(provider *config.Provider, consumer aws.AwsConsumerInterface, extractor validator.ClaimsExtractorInterface) *AwsApiGateway {
	return &AwsApiGateway{
		processor: NewRequestProcessor(provider, consumer, extractor),
	}
}

// Handler is the Lambda function interface for API Gateway
func (h *AwsApiGateway) Handler(ctx context.Context, event events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Create a request context with tracking information and timeout
	ctx, cancel := h.createRequestContext(ctx, event)
	defer cancel()
	requestID, _ := ctx.Value(RequestIDContextKey).(string)

	// Add request ID and additional data to all logs for this request
	log := slog.With(
		slog.String("requestId", requestID),
		slog.String("path", event.Path),
		slog.String("method", event.HTTPMethod),
		slog.String("sourceIp", event.RequestContext.Identity.SourceIP),
		slog.String("userAgent", event.RequestContext.Identity.UserAgent),
		slog.String("requestTime", event.RequestContext.RequestTime),
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
func (h *AwsApiGateway) createRequestContext(ctx context.Context, event events.APIGatewayProxyRequest) (context.Context, context.CancelFunc) {
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
	ctx = context.WithValue(ctx, SourceIPContextKey, event.RequestContext.Identity.SourceIP)
	ctx = context.WithValue(ctx, UserAgentContextKey, event.RequestContext.Identity.UserAgent)

	// Create a context with timeout. The caller must invoke the returned cancel
	// (via defer) to release the timer when the request completes.
	return context.WithTimeout(ctx, DefaultTimeout)
}

// unmarshalRequestData parses and validates the request data from an API Gateway event
func (h *AwsApiGateway) unmarshalRequestData(event events.APIGatewayProxyRequest) (*RequestData, error) {
	return ParseRequestBody(event.Body)
}

// respondError formats a response with an error message
func (h *AwsApiGateway) respondError(ctx context.Context, err error, statusCode int) (events.APIGatewayProxyResponse, error) {
	response, statusCode := buildErrorResponse(ctx, err, statusCode)

	jsonResponse, jsonErr := json.Marshal(response)
	if jsonErr != nil {
		// Fallback to simple error response if JSON marshalling fails
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusInternalServerError,
			Headers:    ResponseHeaders,
			Body:       fmt.Sprintf(`{"error": "%s"}`, err.Error()),
		}, nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode:      statusCode,
		Headers:         ResponseHeaders,
		Body:            string(jsonResponse),
		IsBase64Encoded: false,
	}, nil
}

// respondJSON formats a successful response with credentials
func (h *AwsApiGateway) respondJSON(ctx context.Context, credentials *types.Credentials) (events.APIGatewayProxyResponse, error) {
	response := buildSuccessResponse(ctx, credentials)

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		return h.respondError(ctx, fmt.Errorf("failed to marshal response: %w", err), http.StatusInternalServerError)
	}

	return events.APIGatewayProxyResponse{
		StatusCode:      http.StatusOK,
		Headers:         ResponseHeaders,
		Body:            string(jsonResponse),
		IsBase64Encoded: false,
	}, nil
}
