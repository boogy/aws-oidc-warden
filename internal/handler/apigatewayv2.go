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

// AwsApiGatewayV2 handles AWS API Gateway HTTP API (v2) requests with a JWT Authorizer.
// Use this adapter when API Gateway validates the JWT and passes claims via
// event.requestContext.authorizer.jwt.claims. Set jwt_validation.mode: "apigw".
type AwsApiGatewayV2 struct {
	processor *RequestProcessor
}

// NewAwsApiGatewayV2 creates a new HTTP API v2 handler.
func NewAwsApiGatewayV2(provider *config.Provider, consumer aws.AwsConsumerInterface, extractor validator.ClaimsExtractorInterface) *AwsApiGatewayV2 {
	return &AwsApiGatewayV2{processor: NewRequestProcessor(provider, consumer, extractor)}
}

// Handler is the Lambda function interface for API Gateway HTTP API v2.
func (h *AwsApiGatewayV2) Handler(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	ctx, cancel := h.createRequestContext(ctx, event)
	defer cancel()
	requestID, _ := ctx.Value(RequestIDContextKey).(string)

	log := slog.With(
		slog.String("requestId", requestID),
		slog.String("path", event.RawPath),
		slog.String("method", event.RequestContext.HTTP.Method),
		slog.String("sourceIp", event.RequestContext.HTTP.SourceIP),
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
	requestID := event.RequestContext.RequestID
	if requestID == "" {
		requestID = uuid.New().String()
	}
	ctx = context.WithValue(ctx, RequestIDContextKey, requestID)
	ctx = context.WithValue(ctx, StartTimeContextKey, time.Now())
	ctx = context.WithValue(ctx, SourceIPContextKey, event.RequestContext.HTTP.SourceIP)
	ctx = context.WithValue(ctx, UserAgentContextKey, event.RequestContext.HTTP.UserAgent)
	return context.WithTimeout(ctx, DefaultTimeout)
}

func (h *AwsApiGatewayV2) respondError(ctx context.Context, err error, statusCode int) (events.APIGatewayV2HTTPResponse, error) {
	requestID, _ := ctx.Value(RequestIDContextKey).(string)
	if requestID == "" {
		requestID = uuid.New().String()
	}
	var processingMS int64
	if startTime, ok := ctx.Value(StartTimeContextKey).(time.Time); ok {
		processingMS = time.Since(startTime).Milliseconds()
	}
	errCode, errMsg := classifyError(err, &statusCode)
	slog.Error("Request error",
		slog.String("requestId", requestID),
		slog.String("errorCode", errCode),
		slog.String("error", err.Error()),
		slog.Int("status", statusCode),
		slog.Int64("processingMs", processingMS))
	response := Response{
		Success:      false,
		StatusCode:   statusCode,
		ErrorCode:    errCode,
		Message:      errMsg,
		ErrorDetails: err.Error(),
		RequestID:    requestID,
		ProcessingMS: processingMS,
	}
	body, jsonErr := json.Marshal(response)
	if jsonErr != nil {
		return events.APIGatewayV2HTTPResponse{
			StatusCode: http.StatusInternalServerError,
			Headers:    ResponseHeaders,
			Body:       fmt.Sprintf(`{"error":"%s"}`, err.Error()),
		}, nil
	}
	return events.APIGatewayV2HTTPResponse{StatusCode: statusCode, Headers: ResponseHeaders, Body: string(body)}, nil
}

func (h *AwsApiGatewayV2) respondJSON(ctx context.Context, credentials *types.Credentials) (events.APIGatewayV2HTTPResponse, error) {
	requestID, _ := ctx.Value(RequestIDContextKey).(string)
	if requestID == "" {
		requestID = uuid.New().String()
	}
	var processingMS int64
	if startTime, ok := ctx.Value(StartTimeContextKey).(time.Time); ok {
		processingMS = time.Since(startTime).Milliseconds()
	}
	response := Response{
		Success:      true,
		StatusCode:   http.StatusOK,
		Message:      "Claims extracted and role assumed",
		RequestID:    requestID,
		ProcessingMS: processingMS,
		Data:         credentials,
	}
	body, err := json.Marshal(response)
	if err != nil {
		return h.respondError(ctx, fmt.Errorf("failed to marshal response: %w", err), http.StatusInternalServerError)
	}
	slog.Debug("Response successful",
		slog.String("requestId", requestID),
		slog.Int64("processingMs", processingMS))
	return events.APIGatewayV2HTTPResponse{StatusCode: http.StatusOK, Headers: ResponseHeaders, Body: string(body)}, nil
}
