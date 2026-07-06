package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/boogy/aws-oidc-warden/internal/aws"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/google/uuid"
)

// frontendALB identifies this adapter in audit records/logs.
const frontendALB = "alb"

// AwsApplicationLoadBalancer handles AWS Application Load Balancer requests
type AwsApplicationLoadBalancer struct {
	processor *RequestProcessor
	region    string
}

// NewAwsApplicationLoadBalancer creates a new Application Load Balancer handler. audit may be nil (see AuditSink).
func NewAwsApplicationLoadBalancer(provider *config.Provider, consumer aws.AwsConsumerInterface, extractor validator.ClaimsExtractorInterface, audit AuditSink) *AwsApplicationLoadBalancer {
	return &AwsApplicationLoadBalancer{
		processor: NewRequestProcessor(provider, consumer, extractor, audit, frontendALB),
		region:    os.Getenv("AWS_REGION"),
	}
}

// Handler is the Lambda function interface for Application Load Balancer
func (h *AwsApplicationLoadBalancer) Handler(ctx context.Context, event events.ALBTargetGroupRequest) (events.ALBTargetGroupResponse, error) {
	// Create a request context with tracking information and timeout
	ctx, cancel := h.createRequestContext(ctx, event)
	defer cancel()
	requestID, _ := ctx.Value(RequestIDContextKey).(string)

	// Add request ID and additional data to all logs for this request
	log := slog.With(
		slog.String("requestId", requestID),
		slog.String("path", event.Path),
		slog.String("method", event.HTTPMethod),
		slog.String("sourceIp", event.RequestContext.ELB.TargetGroupArn), // ALB doesn't provide direct source IP in the same way
		slog.String("userAgent", event.Headers["user-agent"]),
	)

	// Build extraction input: prefer ALB OIDC data header when present.
	oidcData := event.Headers["x-amzn-oidc-data"]
	region := h.region

	// Bound before body parsing to reject oversized ALB OIDC headers early.
	if len(oidcData) > MaxTokenLength {
		return h.respondError(ctx, fmt.Errorf("x-amzn-oidc-data header exceeds maximum allowed size"), http.StatusBadRequest)
	}

	// Parse request data
	requestData, err := h.unmarshalRequestData(event)
	if err != nil {
		return h.respondError(ctx, err, http.StatusBadRequest)
	}

	var input validator.ExtractionInput
	if oidcData != "" {
		input = validator.ExtractionInput{
			ALBOIDCData: oidcData,
			AWSRegion:   region,
		}
	} else {
		input = validator.ExtractionInput{Token: requestData.Token}
	}

	// Process the request using the request processor.
	// respondError classifies the error and sets the final status code.
	credentials, err := h.processor.ProcessRequest(ctx, requestData, input, requestID, log)
	if err != nil {
		return h.respondError(ctx, err, http.StatusInternalServerError)
	}

	return h.respondJSON(ctx, credentials)
}

// createRequestContext creates an enhanced context with request tracking information
func (h *AwsApplicationLoadBalancer) createRequestContext(ctx context.Context, event events.ALBTargetGroupRequest) (context.Context, context.CancelFunc) {
	// Generate a request ID (ALB doesn't provide one directly)
	requestID := uuid.New().String()

	// Start request timer
	startTime := time.Now()

	// Add request tracking information using context keys
	ctx = context.WithValue(ctx, RequestIDContextKey, requestID)
	ctx = context.WithValue(ctx, StartTimeContextKey, startTime)
	ctx = context.WithValue(ctx, SourceIPContextKey, event.Headers["x-forwarded-for"])
	ctx = context.WithValue(ctx, UserAgentContextKey, event.Headers["user-agent"])

	// Create a context with timeout. The caller must invoke the returned cancel
	// (via defer) to release the timer when the request completes.
	return context.WithTimeout(ctx, DefaultTimeout)
}

// unmarshalRequestData parses and validates the request data from an ALB event.
// When x-amzn-oidc-data is present the body only needs to carry the role (token
// comes from the header), so we use the role-only parser in that case.
func (h *AwsApplicationLoadBalancer) unmarshalRequestData(event events.ALBTargetGroupRequest) (*RequestData, error) {
	if event.Headers["x-amzn-oidc-data"] != "" {
		return ParseRoleOnlyRequestBody(event.Body)
	}
	return ParseRequestBody(event.Body)
}

// respondError formats a response with an error message
func (h *AwsApplicationLoadBalancer) respondError(ctx context.Context, err error, statusCode int) (events.ALBTargetGroupResponse, error) {
	response, statusCode := buildErrorResponse(ctx, err, statusCode)

	jsonResponse, jsonErr := json.Marshal(response)
	if jsonErr != nil {
		// Fallback to simple error response if JSON marshalling fails
		return events.ALBTargetGroupResponse{
			StatusCode: http.StatusInternalServerError,
			Headers:    ResponseHeaders,
			Body:       fallbackErrorBody,
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
	response := buildSuccessResponse(ctx, credentials)

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		return h.respondError(ctx, fmt.Errorf("failed to marshal response: %w", err), http.StatusInternalServerError)
	}

	return events.ALBTargetGroupResponse{
		StatusCode: http.StatusOK,
		Headers:    ResponseHeaders,
		Body:       string(jsonResponse),
	}, nil
}
