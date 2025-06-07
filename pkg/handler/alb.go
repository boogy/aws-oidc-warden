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

// AwsApplicationLoadBalancer handles AWS Application Load Balancer requests
type AwsApplicationLoadBalancer struct {
	processor *RequestProcessor
}

// NewAwsApplicationLoadBalancer creates a new Application Load Balancer handler
func NewAwsApplicationLoadBalancer(cfg *config.Config, consumer aws.AwsConsumerInterface, validator validator.TokenValidatorInterface) *AwsApplicationLoadBalancer {
	return &AwsApplicationLoadBalancer{
		processor: NewRequestProcessor(cfg, consumer, validator),
	}
}

// Handler is the Lambda function interface for Application Load Balancer
func (h *AwsApplicationLoadBalancer) Handler(ctx context.Context, event events.ALBTargetGroupRequest) (events.ALBTargetGroupResponse, error) {
	// Create a request context with tracking information and timeout
	ctx = h.createRequestContext(ctx, event)
	requestID, _ := ctx.Value(RequestIDContextKey).(string)

	// Add request ID and additional data to all logs for this request
	log := slog.With(
		slog.String("requestId", requestID),
		slog.String("path", event.Path),
		slog.String("method", event.HTTPMethod),
		slog.String("sourceIp", event.RequestContext.ELB.TargetGroupArn), // ALB doesn't provide direct source IP in the same way
		slog.String("userAgent", event.Headers["user-agent"]),
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
func (h *AwsApplicationLoadBalancer) createRequestContext(ctx context.Context, event events.ALBTargetGroupRequest) context.Context {
	// Generate a request ID (ALB doesn't provide one directly)
	requestID := uuid.New().String()

	// Start request timer
	startTime := time.Now()

	// Add request tracking information using context keys
	ctx = context.WithValue(ctx, RequestIDContextKey, requestID)
	ctx = context.WithValue(ctx, StartTimeContextKey, startTime)
	ctx = context.WithValue(ctx, SourceIPContextKey, event.Headers["x-forwarded-for"])
	ctx = context.WithValue(ctx, UserAgentContextKey, event.Headers["user-agent"])

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)

	// Ensure the cancel function is called when the Lambda execution completes
	go func() {
		<-ctx.Done()
		cancel()
	}()

	return ctx
}

// unmarshalRequestData parses and validates the request data from an ALB event
func (h *AwsApplicationLoadBalancer) unmarshalRequestData(event events.ALBTargetGroupRequest) (*RequestData, error) {
	return ParseRequestBody(event.Body)
}

// respondError formats a response with an error message
func (h *AwsApplicationLoadBalancer) respondError(ctx context.Context, err error, statusCode int) (events.ALBTargetGroupResponse, error) {
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
		return events.ALBTargetGroupResponse{
			StatusCode: http.StatusInternalServerError,
			Headers:    ResponseHeaders,
			Body:       fmt.Sprintf(`{"error": "%s"}`, err.Error()),
		}, nil
	}

	return events.ALBTargetGroupResponse{
		StatusCode: statusCode,
		Headers:    ResponseHeaders,
		Body:       string(jsonResponse),
	}, nil
}

// respondJSON formats a successful response with credentials
func (h *AwsApplicationLoadBalancer) respondJSON(ctx context.Context, credentials *types.Credentials) (events.ALBTargetGroupResponse, error) {
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

	return events.ALBTargetGroupResponse{
		StatusCode: http.StatusOK,
		Headers:    ResponseHeaders,
		Body:       string(jsonResponse),
	}, nil
}
