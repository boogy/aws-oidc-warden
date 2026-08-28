package handler

import (
	"errors"
	"time"
)

const (
	DefaultTimeout = 10 * time.Second
	MaxTokenLength = 16384 // 16KB
	MaxRoleLength  = 2048  // 2KB
)

// contextKey avoids string collisions among context values.
type contextKey string

const (
	RequestIDContextKey         contextKey = "requestId"
	StartTimeContextKey         contextKey = "startTime"
	SourceIPContextKey          contextKey = "sourceIp"
	UserAgentContextKey         contextKey = "userAgent"
	FrontendRequestIDContextKey contextKey = "frontendRequestId"
	// SourceIPSourceContextKey carries the provenance of SourceIPContextKey:
	// "frontend" (attested by AWS) or "x-forwarded-for" (client-supplied).
	SourceIPSourceContextKey contextKey = "sourceIpSource"
)

var (
	ErrEmptyToken            = errors.New("token is empty")
	ErrTokenTooLarge         = errors.New("token exceeds maximum allowed size")
	ErrEmptyRole             = errors.New("role is empty")
	ErrInvalidRoleFormat     = errors.New("role is not a valid AWS IAM role ARN")
	ErrRoleTooLarge          = errors.New("role exceeds maximum allowed size")
	ErrInvalidJSON           = errors.New("invalid JSON in request body")
	ErrTokenValidationFailed = errors.New("token validation failed")
	ErrSessionPolicyAccess   = errors.New("failed to access session policy")
	ErrRoleNotPermitted      = errors.New("role not allowed for this subject or its conditions are not met")
	ErrAccountNotAllowed     = errors.New("target account is not in the allowed_accounts list")
	ErrAssumeRoleFailed      = errors.New("failed to assume the requested role")
	ErrAuditWriteFailed      = errors.New("audit record could not be durably written")
)

var (
	// ValidPrefixes: AWS partitions a role ARN may belong to.
	ValidPrefixes = []string{
		"arn:aws:iam::",        // Standard AWS
		"arn:aws-us-gov:iam::", // AWS GovCloud
		"arn:aws-cn:iam::",     // AWS China
	}

	// ResponseHeaders: no-store is explicit because a 200 here carries live
	// AWS credentials and handlers don't vary caching by HTTP method.
	ResponseHeaders = map[string]string{
		"Content-Type":  "application/json",
		"Cache-Control": "no-store",
	}
)

// RequestData is the request format expected by the Lambda.
type RequestData struct {
	Token string `json:"token"`
	Role  string `json:"role"`
}

// Response represents a standardized API response
type Response struct {
	Success      bool   `json:"success"`
	StatusCode   int    `json:"statusCode,omitempty"`
	RequestID    string `json:"requestId"`
	ProcessingMS int64  `json:"processingMs,omitempty"`

	Message string `json:"message,omitempty"` // success
	Data    any    `json:"data,omitempty"`    // success

	// ErrorCode: classified only; raw error detail stays server-side (buildErrorResponse).
	ErrorCode string `json:"errorCode,omitempty"`
}
