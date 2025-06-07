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

// AwsLambdaUrl handles AWS Lambda URL requests
type AwsLambdaUrl struct {
	processor *RequestProcessor
}

// NewAwsLambdaUrl creates a new Lambda URL handler
func NewAwsLambdaUrl(cfg *config.Config, consumer aws.AwsConsumerInterface, validator validator.TokenValidatorInterface) *AwsLambdaUrl {
	return &AwsLambdaUrl{
		processor: NewRequestProcessor(cfg, consumer, validator),
	}
}

// Handler is the Lambda function interface for Lambda URLs
func (h *AwsLambdaUrl) Handler(ctx context.Context, event events.LambdaFunctionURLRequest) (events.LambdaFunctionURLResponse, error) {
	// Create a request context with tracking information and timeout
	ctx = h.createRequestContext(ctx, event)
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
func (h *AwsLambdaUrl) createRequestContext(ctx context.Context, event events.LambdaFunctionURLRequest) context.Context {
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

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)

	// Ensure the cancel function is called when the Lambda execution completes
	go func() {
		<-ctx.Done()
		cancel()
	}()

	return ctx
}

// unmarshalRequestData parses and validates the request data from a Lambda URL event
func (h *AwsLambdaUrl) unmarshalRequestData(event events.LambdaFunctionURLRequest) (*RequestData, error) {
	return ParseRequestBody(event.Body)
}

// respondError formats a response with an error message
func (h *AwsLambdaUrl) respondError(ctx context.Context, err error, statusCode int) (events.LambdaFunctionURLResponse, error) {
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

	return events.LambdaFunctionURLResponse{
		StatusCode: http.StatusOK,
		Headers:    ResponseHeaders,
		Body:       string(jsonResponse),
	}, nil
}
