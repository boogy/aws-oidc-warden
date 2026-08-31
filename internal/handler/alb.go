package handler

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"strings"

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
	headers := albRequestHeaders(event)
	ctx, cancel := h.createRequestContext(ctx, headers)
	defer cancel()
	requestID, _ := ctx.Value(RequestIDContextKey).(string)

	log := requestLogger(ctx,
		slog.String("requestId", requestID),
		slog.String("path", event.Path),
		slog.String("method", event.HTTPMethod),
		slog.String("targetGroupArn", event.RequestContext.ELB.TargetGroupArn),
		slog.String("userAgent", headerValue(headers, "user-agent")),
	)

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
func (h *AwsApplicationLoadBalancer) createRequestContext(ctx context.Context, headers map[string]string) (context.Context, context.CancelFunc) {
	// ALB has neither a request ID nor a source-IP field, so both fall back
	// to their non-frontend paths (fresh UUID, rightmost XFF hop).
	return newRequestContext(ctx, "", "", headers, headerValue(headers, "user-agent"))
}

// unmarshalRequestData parses the ALB request body: role-only when
// x-amzn-oidc-data carries the token, full body otherwise.
func (h *AwsApplicationLoadBalancer) unmarshalRequestData(body, oidcData string) (*RequestData, error) {
	if oidcData != "" {
		return ParseRoleOnlyRequestBody(body)
	}
	return ParseRequestBody(body)
}

// newResponse builds this frontend's response type from a status and body.
func (h *AwsApplicationLoadBalancer) newResponse(statusCode int, body string) events.ALBTargetGroupResponse {
	return events.ALBTargetGroupResponse{
		StatusCode: statusCode,
		Headers:    ResponseHeaders,
		Body:       body,
	}
}

// respondError formats a response with an error message
func (h *AwsApplicationLoadBalancer) respondError(ctx context.Context, err error, statusCode int) (events.ALBTargetGroupResponse, error) {
	return errorResponse(ctx, err, statusCode, h.newResponse), nil
}

// respondJSON formats a successful response with credentials
func (h *AwsApplicationLoadBalancer) respondJSON(ctx context.Context, credentials *types.Credentials) (events.ALBTargetGroupResponse, error) {
	return successResponse(ctx, credentials, h.newResponse), nil
}
