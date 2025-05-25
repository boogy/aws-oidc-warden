package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/boogy/aws-oidc-warden/aws"
	gtvcfg "github.com/boogy/aws-oidc-warden/config"
	"github.com/boogy/aws-oidc-warden/utils"
	"github.com/boogy/aws-oidc-warden/validator"
	"github.com/google/uuid"
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
	requestIDContextKey contextKey = "requestId"
	startTimeContextKey contextKey = "startTime"
	sourceIPContextKey  contextKey = "sourceIp"
	userAgentContextKey contextKey = "userAgent"
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
	validPrefixes = []string{
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

// RespondError formats a response with an error message
func RespondError(ctx context.Context, err error, statusCode int) (events.APIGatewayProxyResponse, error) {
	// Extract request ID from context if available
	requestID, _ := ctx.Value(requestIDContextKey).(string)
	if requestID == "" {
		requestID = uuid.New().String()
	}

	// Get processing time if available
	var processingMS int64
	if startTime, ok := ctx.Value(startTimeContextKey).(time.Time); ok {
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

// RespondJSON formats a successful response with credentials
func RespondJSON(ctx context.Context, credentials *types.Credentials) (events.APIGatewayProxyResponse, error) {
	// Extract request ID from context if available
	requestID, _ := ctx.Value(requestIDContextKey).(string)
	if requestID == "" {
		requestID = uuid.New().String()
	}

	// Get processing time if available
	var processingMS int64
	if startTime, ok := ctx.Value(startTimeContextKey).(time.Time); ok {
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
		return RespondError(ctx, fmt.Errorf("failed to marshal response: %w", err), http.StatusInternalServerError)
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

// UnmarshalRequestData parses and validates the request data from an API Gateway event
func UnmarshalRequestData(event events.APIGatewayProxyRequest) (*RequestData, error) {
	// Validate request body is not empty
	if strings.TrimSpace(event.Body) == "" {
		return nil, fmt.Errorf("request body is empty: %w", ErrInvalidJSON)
	}

	// Check if body exceeds maximum allowed size (sanity check)
	if len(event.Body) > 1024*1024 { // 1MB limit
		return nil, fmt.Errorf("request body too large: %w", ErrInvalidJSON)
	}

	var requestData RequestData
	if err := json.Unmarshal([]byte(event.Body), &requestData); err != nil {
		slog.Error("Failed to unmarshal request body",
			slog.String("error", err.Error()),
			slog.String("bodyPreview", utils.TruncateString(event.Body, 100)))
		return nil, fmt.Errorf("invalid JSON format: %w", ErrInvalidJSON)
	}

	// Validate token is not empty
	if strings.TrimSpace(requestData.Token) == "" {
		return nil, ErrEmptyToken
	}

	// Check token length for security (prevent DoS)
	if len(requestData.Token) > MaxTokenLength {
		return nil, ErrTokenTooLarge
	}

	// Validate role
	if strings.TrimSpace(requestData.Role) == "" {
		return nil, ErrEmptyRole
	}

	// Check role length for security
	if len(requestData.Role) > MaxRoleLength {
		return nil, ErrRoleTooLarge
	}

	isValidPrefix := false
	for _, prefix := range validPrefixes {
		if strings.HasPrefix(requestData.Role, prefix) {
			isValidPrefix = true
			break
		}
	}

	if !isValidPrefix {
		return nil, fmt.Errorf("role does not appear to be a valid AWS IAM role ARN: %w", ErrEmptyRole)
	}

	return &requestData, nil
}

// createRequestContext creates an enhanced context with request tracking information
func createRequestContext(ctx context.Context, event events.APIGatewayProxyRequest) context.Context {
	// Generate a request ID if not available from the event
	requestID := event.RequestContext.RequestID
	if requestID == "" {
		requestID = uuid.New().String()
	}

	// Start request timer
	startTime := time.Now()

	// Add request tracking information using context keys
	ctx = context.WithValue(ctx, requestIDContextKey, requestID)
	ctx = context.WithValue(ctx, startTimeContextKey, startTime)
	ctx = context.WithValue(ctx, sourceIPContextKey, event.RequestContext.Identity.SourceIP)
	ctx = context.WithValue(ctx, userAgentContextKey, event.RequestContext.Identity.UserAgent)

	// Create a context with timeout and ensure the cancel function is called when the function returns
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)

	// Ensure the cancel function is called when the Lambda execution completes
	// by attaching it to the parent context via a done hook
	go func() {
		<-ctx.Done() // Wait for context to be done (timeout or canceled)
		cancel()     // Call cancel to release resources
	}()

	return ctx
}

// getSessionPolicy retrieves the session policy for a given repository (config inline or S3 file)
func getSessionPolicy(cfg *gtvcfg.Config, consumer aws.AwsConsumerInterface, repository string) (*string, error) {
	// Start measuring time for this operation
	opStart := time.Now()
	defer func() {
		slog.Debug("getSessionPolicy operation completed",
			slog.String("repository", repository),
			slog.Duration("duration", time.Since(opStart)))
	}()

	var sessionPolicyString *string
	sessionPolicy, sessionPolicyFile := cfg.FindSessionPolicyForRepo(repository)

	// Try to get policy from S3 file if specified
	if sessionPolicyFile != nil {
		sessionPolicyData, err := consumer.GetS3Object(cfg.S3SessionPolicyBucket, *sessionPolicyFile)
		if err != nil {
			slog.Error("Failed to read session policy file",
				slog.String("bucket", cfg.S3SessionPolicyBucket),
				slog.String("key", *sessionPolicyFile),
				slog.String("error", err.Error()))
			return nil, fmt.Errorf("failed to read session policy file: %w", ErrSessionPolicyAccess)
		}

		// Read the content and ensure the reader is closed
		defer func() {
			if err := sessionPolicyData.Close(); err != nil {
				slog.Error("Failed to close session policy data reader", "error", err)
			}
		}()

		// Limit the size of policy files that can be read
		policyBytes, err := io.ReadAll(io.LimitReader(sessionPolicyData, 1024*1024)) // 1MB limit
		if err != nil {
			slog.Error("Failed to read session policy data",
				slog.String("bucket", cfg.S3SessionPolicyBucket),
				slog.String("key", *sessionPolicyFile),
				slog.String("error", err.Error()))
			return nil, fmt.Errorf("failed to read session policy data: %w", ErrSessionPolicyAccess)
		}

		// Validate that the policy is valid JSON
		var jsonCheck any
		if err := json.Unmarshal(policyBytes, &jsonCheck); err != nil {
			slog.Error("Invalid JSON in session policy file",
				slog.String("bucket", cfg.S3SessionPolicyBucket),
				slog.String("key", *sessionPolicyFile),
				slog.String("error", err.Error()))
			return nil, fmt.Errorf("invalid JSON in session policy file: %w", ErrSessionPolicyAccess)
		}

		// Store the policy string
		policy := string(policyBytes)
		sessionPolicyString = &policy

		slog.Debug("Session policy loaded from S3",
			slog.String("repository", repository),
			slog.String("bucket", cfg.S3SessionPolicyBucket),
			slog.String("key", *sessionPolicyFile),
			slog.Int("policySize", len(policy)))
	}

	// Use inline policy if provided (overrides S3 file if both exist)
	if sessionPolicy != nil {
		sessionPolicyString = sessionPolicy
		slog.Debug("Using inline session policy",
			slog.String("repository", repository),
			slog.Int("policySize", len(*sessionPolicy)))
	}

	return sessionPolicyString, nil
}

// Handler lambda function interface
type Handler func(ctx context.Context, event events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error)

// NewHandler creates the actual Handler function
func NewHandler(cfg *gtvcfg.Config, consumer aws.AwsConsumerInterface, validator validator.TokenValidatorInterface) Handler {
	return func(ctx context.Context, event events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
		// Create a request context with tracking information and timeout
		ctx = createRequestContext(ctx, event)
		requestID, _ := ctx.Value(requestIDContextKey).(string)
		startTime, _ := ctx.Value(startTimeContextKey).(time.Time)

		// Add request ID and additional data to all logs for this request
		log := slog.With(
			slog.String("requestId", requestID),
			slog.String("path", event.Path),
			slog.String("method", event.HTTPMethod),
			slog.String("sourceIp", event.RequestContext.Identity.SourceIP),
			slog.String("userAgent", event.RequestContext.Identity.UserAgent),
		)

		// Parse request data
		requestData, err := UnmarshalRequestData(event)
		if err != nil {
			return RespondError(ctx, err, http.StatusBadRequest)
		}

		// Create a redacted token for logging (first 10 chars and last 10 chars)
		redactedToken := utils.RedactToken(requestData.Token, 10, 10)
		log.Debug("Validating token", slog.String("token", redactedToken))

		// Validate the token and extract claims
		claims, err := validator.Validate(requestData.Token)
		if err != nil {
			log.Error("Token validation failed",
				slog.String("error", err.Error()),
				slog.String("token", redactedToken),
			)

			return RespondError(ctx, fmt.Errorf("token validation failed: %w", err), http.StatusUnauthorized)
		}

		// Repository from github claims and role from request data
		requestedRole := requestData.Role

		// Add claims information to logger plus some extra info
		log = log.With(
			slog.Group("request",
				slog.String("repository", claims.Repository),
				slog.String("ref", claims.Ref),
				slog.String("branch", utils.ExtractBranchFromRef(claims.Ref)),
				slog.String("role", requestedRole),
				slog.String("actor", claims.Actor),
				slog.String("requestTime", event.RequestContext.RequestTime),
				slog.String("domainName", event.RequestContext.DomainName),
			),
		)

		// Convert claims to map for constraint checking
		claimsMap := make(map[string]any)
		claimsJSON, _ := json.Marshal(claims)
		if err := json.Unmarshal(claimsJSON, &claimsMap); err != nil {
			log.Error("Failed to process claims", slog.String("error", err.Error()))
			return RespondError(ctx, fmt.Errorf("failed to process claims: %w", err), http.StatusInternalServerError)
		}

		log.Info("Token validation successful",
			slog.Any("claims", claims),
			slog.Duration("validationTime", time.Since(startTime)),
		)

		// Match role to repository with constraints
		matched, roles := cfg.MatchRolesToRepoWithConstraints(claims.Repository, claimsMap)

		// If no match or requested role not in allowed roles
		if !matched || (len(roles) > 0 && !slices.Contains(roles, requestedRole)) {
			log.Error("Role not allowed for repository or doesn't meet constraints",
				slog.String("repository", claims.Repository),
				slog.String("role", requestedRole),
				slog.String("ref", claims.Ref),
				slog.String("branch", utils.ExtractBranchFromRef(claims.Ref)),
				slog.Any("allowedRoles", roles))

			return RespondError(ctx, ErrRoleNotPermitted, http.StatusForbidden)
		}

		// Attempting to get session policy
		sessionPolicy, err := getSessionPolicy(cfg, consumer, claims.Repository)
		if err != nil {
			log.Error("Failed to read session policy", slog.String("error", err.Error()))
			return RespondError(ctx, err, http.StatusInternalServerError)
		}

		// Time to assume role
		log.Debug("Assuming role",
			slog.String("role", requestedRole),
			slog.Bool("hasSessionPolicy", sessionPolicy != nil))

		// Assume role
		credentials, err := consumer.AssumeRole(requestedRole, cfg.RoleSessionName, sessionPolicy, nil, claims)
		if err != nil {
			log.Error("Failed to assume role",
				slog.String("error", err.Error()),
				slog.String("role", requestedRole))
			return RespondError(ctx, fmt.Errorf("failed to assume role: %w", ErrAssumeRoleFailed), http.StatusInternalServerError)
		}

		// Log the successful assume role operation
		log.Info("Successfully assumed role",
			slog.String("role", requestedRole),
			slog.String("accessKeyId", *credentials.AccessKeyId),
			slog.Time("expiration", *credentials.Expiration),
			slog.Duration("totalTime", time.Since(startTime)))

		return RespondJSON(ctx, credentials)
	}
}
