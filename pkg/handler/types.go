package handler

import (
	"errors"
	"time"
)

// Constants for handler configuration
const (
	// DefaultTimeout is the maximum time to process a request
	DefaultTimeout = 10 * time.Second

	// MaxTokenLength is the maximum allowed length for a JWT token
	MaxTokenLength = 16384 // 16KB

	// MaxRoleLength is the maximum allowed length for role ARN
	MaxRoleLength = 2048 // 2KB
)

// Context key types to avoid string collision in context values
type contextKey string

const (
	RequestIDContextKey contextKey = "requestId"
	StartTimeContextKey contextKey = "startTime"
	SourceIPContextKey  contextKey = "sourceIp"
	UserAgentContextKey contextKey = "userAgent"
)

// Custom error types for more precise error reporting
var (
	ErrEmptyToken          = errors.New("token is empty")
	ErrTokenTooLarge       = errors.New("token exceeds maximum allowed size")
	ErrEmptyRole           = errors.New("role is empty")
	ErrRoleTooLarge        = errors.New("role exceeds maximum allowed size")
	ErrInvalidJSON         = errors.New("invalid JSON in request body")
	ErrSessionPolicyAccess = errors.New("failed to access session policy")
	ErrRoleNotPermitted    = errors.New("role not allowed for repository or doesn't meet constraints")
	ErrAssumeRoleFailed    = errors.New("failed to assume the requested role")
)

var (
	// Basic validation that the role looks like an ARN
	// Check if the role ARN has a valid AWS partition prefix
	ValidPrefixes = []string{
		"arn:aws:iam::",        // Standard AWS
		"arn:aws-us-gov:iam::", // AWS GovCloud
		"arn:aws-cn:iam::",     // AWS China
	}

	// ResponseHeaders common headers to include in all API responses
	ResponseHeaders = map[string]string{
		"Content-Type": "application/json",
	}
)

// RequestData is the request format expected by the Lambda
type RequestData struct {
	Token string `json:"token"` // The JWT token to be validated
	Role  string `json:"role"`  // The role to be assumed
}

// Response represents a standardized API response
type Response struct {
	Success      bool   `json:"success"`
	StatusCode   int    `json:"statusCode,omitempty"`
	RequestID    string `json:"requestId"`
	ProcessingMS int64  `json:"processingMs,omitempty"`

	// For successful responses
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`

	// For error responses
	ErrorCode    string `json:"errorCode,omitempty"`
	ErrorDetails string `json:"errorDetails,omitempty"`
}
