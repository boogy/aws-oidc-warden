package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/boogy/aws-oidc-warden/internal/aws"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/validator"
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
	ctx, cancel := h.createRequestContext(ctx, event)
	defer cancel()
	headers := albRequestHeaders(event)
	requestID, _ := ctx.Value(RequestIDContextKey).(string)
	sourceIP, _ := ctx.Value(SourceIPContextKey).(string)
	sourceIPFrom, _ := ctx.Value(SourceIPSourceContextKey).(string)

	// slog.With, not a struct field: no adapter has a logger field; all four
	// build from the default, which bootstrap points at the JSON handler.
	log := slog.With(
		slog.String("requestId", requestID),
		slog.String("path", event.Path),
		slog.String("method", event.HTTPMethod),
		slog.String("targetGroupArn", event.RequestContext.ELB.TargetGroupArn),
		slog.String("userAgent", headerValue(headers, "user-agent")),
	)
	if sourceIP != "" {
		log = log.With(slog.String("sourceIp", sourceIP))
	}
	if sourceIPFrom != "" {
		log = log.With(slog.String("sourceIpFrom", sourceIPFrom))
	}

	oidcData := headerValue(headers, "x-amzn-oidc-data")
	region := h.region

	// Bound before body parsing to reject oversized ALB OIDC headers early.
	if len(oidcData) > MaxTokenLength {
		return h.respondError(ctx, fmt.Errorf("x-amzn-oidc-data header exceeds maximum allowed size"), http.StatusBadRequest)
	}

	requestData, err := h.unmarshalRequestData(event.Body, oidcData)
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

	credentials, err := h.processor.ProcessRequest(ctx, requestData, input, requestID, log)
	if err != nil {
		return h.respondError(ctx, err, http.StatusInternalServerError)
	}

	return h.respondJSON(ctx, credentials)
}

// albRequestHeaders flattens the two header maps an ALB event can carry:
// with lambda.multi_value_headers.enabled=true only MultiValueHeaders is
// populated (Headers is empty), so reading Headers alone silently drops
// x-amzn-oidc-data/x-forwarded-for/user-agent on such a target group.
// Repeated values are folded with ", " per RFC 9110 §5.3, matching the form
// X-Forwarded-For already uses, so clientIP's rightmost-hop rule still works.
func albRequestHeaders(event events.ALBTargetGroupRequest) map[string]string {
	headers := make(map[string]string, len(event.Headers)+len(event.MultiValueHeaders))
	maps.Copy(headers, event.Headers)
	for name, values := range event.MultiValueHeaders {
		if len(values) == 0 {
			continue
		}
		headers[name] = strings.Join(values, ", ")
	}
	return headers
}

// createRequestContext creates an enhanced context with request tracking information
func (h *AwsApplicationLoadBalancer) createRequestContext(ctx context.Context, event events.ALBTargetGroupRequest) (context.Context, context.CancelFunc) {
	// ALB has neither a request ID nor a source-IP field, so both fall back
	// to their non-frontend paths (fresh UUID, rightmost XFF hop).
	requestID, frontendRequestID := resolveRequestID(ctx, "")
	headers := albRequestHeaders(event)
	sourceIP, sourceIPFrom := clientIP("", headers)

	startTime := time.Now()

	ctx = context.WithValue(ctx, RequestIDContextKey, requestID)
	ctx = context.WithValue(ctx, FrontendRequestIDContextKey, frontendRequestID)
	ctx = context.WithValue(ctx, StartTimeContextKey, startTime)
	ctx = context.WithValue(ctx, SourceIPContextKey, sourceIP)
	ctx = context.WithValue(ctx, SourceIPSourceContextKey, sourceIPFrom)
	ctx = context.WithValue(ctx, UserAgentContextKey, headerValue(headers, "user-agent"))

	// Caller must invoke the returned cancel (via defer).
	return context.WithTimeout(ctx, DefaultTimeout)
}

// unmarshalRequestData parses the ALB request body: role-only when
// x-amzn-oidc-data carries the token, full body otherwise.
func (h *AwsApplicationLoadBalancer) unmarshalRequestData(body, oidcData string) (*RequestData, error) {
	if oidcData != "" {
		return ParseRoleOnlyRequestBody(body)
	}
	return ParseRequestBody(body)
}

// respondError formats a response with an error message
func (h *AwsApplicationLoadBalancer) respondError(ctx context.Context, err error, statusCode int) (events.ALBTargetGroupResponse, error) {
	response, statusCode := buildErrorResponse(ctx, err, statusCode)

	jsonResponse, jsonErr := json.Marshal(response)
	if jsonErr != nil {
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
