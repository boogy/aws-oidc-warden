package handler

import (
	"errors"
	"fmt"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/utils"
)

const (
	DefaultTimeout = 10 * time.Second
	MaxTokenLength = config.MaxTokenBytesCeiling
	MaxRoleLength  = 2048 // 2KB
)

// contextKey avoids string collisions among context values.
type contextKey string

const (
	RequestIDContextKey         contextKey = "requestId"
	StartTimeContextKey         contextKey = "startTime"
	SourceIPContextKey          contextKey = "sourceIp"
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
	ErrAssumeRoleDenied      = errors.New("aws denied the assume-role request for the requested role")
	ErrAuditWriteFailed      = errors.New("audit record could not be durably written")
	ErrConfigStale           = errors.New("configuration is stale")

	ErrIdPNotPermitted          = errors.New("IdP token not permitted for this role")
	ErrIdPUnavailable           = errors.New("IdP token signing temporarily unavailable")
	ErrMethodNotAllowed         = errors.New("method not allowed")
	ErrIdPPathNotFound          = errors.New("IdP path not found")
	ErrIdPTokenTooLarge         = errors.New("IdP token exceeds the STS size limit")
	ErrInvalidDuration          = fmt.Errorf("durationSeconds must be between %d and %d", utils.MinSTSSessionSecs, utils.MaxSTSSessionSecs)
	ErrDurationExceedsCap       = errors.New("durationSeconds exceeds the configured cap")
	ErrDurationExceedsRoleMax   = errors.New("durationSeconds exceeds the role's MaxSessionDuration")
	ErrInvalidSessionName       = errors.New("sessionName must match " + utils.STSNameRule)
	ErrIdPSourceIdentityInvalid = errors.New("source identity could not be derived for this request")
	ErrIdPSubjectInvalid        = errors.New("IdP subject could not be derived for this request")
	ErrIdPExchangeDenied        = errors.New("aws refused the web identity exchange")
	ErrIdPExchangeUnavailable   = errors.New("aws could not reach the idp")
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
	Token           string `json:"token"`
	Role            string `json:"role"`
	DurationSeconds int32  `json:"durationSeconds,omitempty"`
	SessionName     string `json:"sessionName,omitempty"`
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
