package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/boogy/aws-oidc-warden/pkg/aws"
	"github.com/boogy/aws-oidc-warden/pkg/config"
	"github.com/boogy/aws-oidc-warden/pkg/validator"
	"github.com/google/uuid"
)

// AwsApiGateway handles AWS API Gateway proxy integration requests
type AwsApiGateway struct {
	processor *RequestProcessor
}

// NewAwsApiGateway creates a new API Gateway handler
func NewAwsApiGateway(cfg *config.Config, consumer aws.AwsConsumerInterface, validator validator.TokenValidatorInterface) *AwsApiGateway {
	return &AwsApiGateway{
		processor: NewRequestProcessor(cfg, consumer, validator),
	}
}

// Handler is the Lambda function interface for API Gateway
func (h *AwsApiGateway) Handler(ctx context.Context, event events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Create a request context with tracking information and timeout
	ctx = h.createRequestContext(ctx, event)
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

	// Process the request using the request processor
	credentials, err := h.processor.ProcessRequest(ctx, requestData, requestID, log)
	if err != nil {
		statusCode := http.StatusInternalServerError
		switch {
		case errors.Is(err, ErrRoleNotPermitted):
			statusCode = http.StatusForbidden
		case errors.Is(err, ErrSessionPolicyAccess), errors.Is(err, ErrAssumeRoleFailed):
			statusCode = http.StatusInternalServerError
		default:
			if err.Error() == "token validation failed" {
				statusCode = http.StatusUnauthorized
			}
		}
		return h.respondError(ctx, err, statusCode)
	}

	return h.respondJSON(ctx, credentials)
}

// createRequestContext creates an enhanced context with request tracking information
func (h *AwsApiGateway) createRequestContext(ctx context.Context, event events.APIGatewayProxyRequest) context.Context {
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

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)

	// Ensure the cancel function is called when the Lambda execution completes
	go func() {
		<-ctx.Done()
		cancel()
	}()

	return ctx
}

// unmarshalRequestData parses and validates the request data from an API Gateway event
func (h *AwsApiGateway) unmarshalRequestData(event events.APIGatewayProxyRequest) (*RequestData, error) {
	return ParseRequestBody(event.Body)
}

// respondError formats a response with an error message
func (h *AwsApiGateway) respondError(ctx context.Context, err error, statusCode int) (events.APIGatewayProxyResponse, error) {
	// Extract request ID from context if available
	requestID, _ := ctx.Value(RequestIDContextKey).(string)
	if requestID == "" {
		requestID = uuid.New().String()
	}

	// Get processing time if available
	var processingMS int64
	if startTime, ok := ctx.Value(StartTimeContextKey).(time.Time); ok {
		processingMS = time.Since(startTime).Milliseconds()
	}

	// Create structured error
	errCode := "internal_error"
	errMsg := "An internal error occurred"

	// Map common errors to specific error codes and messages
	switch {
	case errors.Is(err, ErrEmptyToken), errors.Is(err, ErrTokenTooLarge),
		errors.Is(err, ErrEmptyRole), errors.Is(err, ErrRoleTooLarge),
		errors.Is(err, ErrInvalidJSON):
		errCode = "invalid_request"
		errMsg = "Invalid request parameters"
		statusCode = http.StatusBadRequest
	case errors.Is(err, ErrRoleNotPermitted):
		errCode = "permission_denied"
		errMsg = "Permission denied for the requested operation"
		statusCode = http.StatusForbidden
	case errors.Is(err, ErrSessionPolicyAccess):
		errCode = "policy_error"
		errMsg = "Error accessing policy information"
		statusCode = http.StatusInternalServerError
	case errors.Is(err, ErrAssumeRoleFailed):
		errCode = "assume_role_failed"
		errMsg = "Failed to assume the requested role"
		statusCode = http.StatusInternalServerError
	}

	// Log the error with context
	slog.Error("Request error",
		slog.String("requestId", requestID),
		slog.String("errorCode", errCode),
		slog.String("error", err.Error()),
		slog.Int("status", statusCode),
		slog.Int64("processingMs", processingMS))

	// Create response object with non-redundant error information
	response := Response{
		Success:      false,
		StatusCode:   statusCode,
		ErrorCode:    errCode,
		Message:      errMsg,
		ErrorDetails: err.Error(),
		RequestID:    requestID,
		ProcessingMS: processingMS,
	}

	// Marshall response to JSON
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
	// Extract request ID from context if available
	requestID, _ := ctx.Value(RequestIDContextKey).(string)
	if requestID == "" {
		requestID = uuid.New().String()
	}

	// Get processing time if available
	var processingMS int64
	if startTime, ok := ctx.Value(StartTimeContextKey).(time.Time); ok {
		processingMS = time.Since(startTime).Milliseconds()
	}

	// Create response object
	response := Response{
		Success:      true,
		StatusCode:   http.StatusOK,
		Message:      "Token validation successful and role assumed",
		RequestID:    requestID,
		ProcessingMS: processingMS,
		Data:         credentials,
	}

	// Marshal the response
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		return h.respondError(ctx, fmt.Errorf("failed to marshal response: %w", err), http.StatusInternalServerError)
	}

	slog.Debug("Response successful",
		slog.String("requestId", requestID),
		slog.Int64("processingMs", processingMS))

	return events.APIGatewayProxyResponse{
		StatusCode:      http.StatusOK,
		Headers:         ResponseHeaders,
		Body:            string(jsonResponse),
		IsBase64Encoded: false,
	}, nil
}
