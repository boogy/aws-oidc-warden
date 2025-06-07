package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/boogy/aws-oidc-warden/pkg/aws"
	"github.com/boogy/aws-oidc-warden/pkg/config"
	"github.com/boogy/aws-oidc-warden/pkg/utils"
	"github.com/boogy/aws-oidc-warden/pkg/validator"
)

// RequestProcessor contains the core business logic for processing authentication requests
type RequestProcessor struct {
	config    *config.Config
	consumer  aws.AwsConsumerInterface
	validator validator.TokenValidatorInterface
}

// NewRequestProcessor creates a new instance of request processor
func NewRequestProcessor(cfg *config.Config, consumer aws.AwsConsumerInterface, validator validator.TokenValidatorInterface) *RequestProcessor {
	return &RequestProcessor{
		config:    cfg,
		consumer:  consumer,
		validator: validator,
	}
}

// ProcessRequest contains the main business logic for processing requests
func (r *RequestProcessor) ProcessRequest(ctx context.Context, requestData *RequestData, requestID string, log *slog.Logger) (*types.Credentials, error) {
	startTime, _ := ctx.Value(StartTimeContextKey).(time.Time)

	// Create a redacted token for logging (first 10 chars and last 10 chars)
	redactedToken := utils.RedactToken(requestData.Token, 10, 10)
	log.Debug("Validating token", slog.String("token", redactedToken))

	// Validate the token and extract claims
	claims, err := r.validator.Validate(requestData.Token)
	if err != nil {
		log.Error("Token validation failed",
			slog.String("error", err.Error()),
			slog.String("token", redactedToken),
		)
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	// Repository from github claims and role from request data
	requestedRole := requestData.Role

	// Add claims information to logger
	log = log.With(
		slog.Group("request",
			slog.String("repository", claims.Repository),
			slog.String("ref", claims.Ref),
			slog.String("branch", utils.ExtractBranchFromRef(claims.Ref)),
			slog.String("role", requestedRole),
			slog.String("actor", claims.Actor),
		),
	)

	// Convert claims to map for constraint checking
	claimsMap := make(map[string]any)
	claimsJSON, _ := json.Marshal(claims)
	if err := json.Unmarshal(claimsJSON, &claimsMap); err != nil {
		log.Error("Failed to process claims", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to process claims: %w", err)
	}

	log.Info("Token validation successful",
		slog.Any("claims", claims),
		slog.Duration("validationTime", time.Since(startTime)),
	)

	// Match role to repository with constraints
	matched, roles := r.config.MatchRolesToRepoWithConstraints(claims.Repository, claimsMap)

	// If no match or requested role not in allowed roles
	if !matched || (len(roles) > 0 && !slices.Contains(roles, requestedRole)) {
		log.Error("Role not allowed for repository or doesn't meet constraints",
			slog.String("repository", claims.Repository),
			slog.String("role", requestedRole),
			slog.String("ref", claims.Ref),
			slog.String("branch", utils.ExtractBranchFromRef(claims.Ref)),
			slog.Any("allowedRoles", roles))

		return nil, ErrRoleNotPermitted
	}

	// Attempting to get session policy
	sessionPolicy, err := r.getSessionPolicy(claims.Repository)
	if err != nil {
		log.Error("Failed to read session policy", slog.String("error", err.Error()))
		return nil, err
	}

	// Time to assume role
	log.Debug("Assuming role",
		slog.String("role", requestedRole),
		slog.Bool("hasSessionPolicy", sessionPolicy != nil))

	// Assume role
	credentials, err := r.consumer.AssumeRole(requestedRole, r.config.RoleSessionName, sessionPolicy, nil, claims)
	if err != nil {
		log.Error("Failed to assume role",
			slog.String("error", err.Error()),
			slog.String("role", requestedRole))
		return nil, fmt.Errorf("failed to assume role: %w", ErrAssumeRoleFailed)
	}

	// Log the successful assume role operation
	log.Info("Successfully assumed role",
		slog.String("role", requestedRole),
		slog.String("accessKeyId", *credentials.AccessKeyId),
		slog.Time("expiration", *credentials.Expiration),
		slog.Duration("totalTime", time.Since(startTime)))

	return credentials, nil
}

// getSessionPolicy retrieves the session policy for a given repository (config inline or S3 file)
func (r *RequestProcessor) getSessionPolicy(repository string) (*string, error) {
	// Start measuring time for this operation
	opStart := time.Now()
	defer func() {
		slog.Debug("getSessionPolicy operation completed",
			slog.String("repository", repository),
			slog.Duration("duration", time.Since(opStart)))
	}()

	var sessionPolicyString *string
	sessionPolicy, sessionPolicyFile := r.config.FindSessionPolicyForRepo(repository)

	// Try to get policy from S3 file if specified
	if sessionPolicyFile != nil {
		sessionPolicyData, err := r.consumer.GetS3Object(r.config.S3SessionPolicyBucket, *sessionPolicyFile)
		if err != nil {
			slog.Error("Failed to read session policy file",
				slog.String("bucket", r.config.S3SessionPolicyBucket),
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
				slog.String("bucket", r.config.S3SessionPolicyBucket),
				slog.String("key", *sessionPolicyFile),
				slog.String("error", err.Error()))
			return nil, fmt.Errorf("failed to read session policy data: %w", ErrSessionPolicyAccess)
		}

		// Validate that the policy is valid JSON
		var jsonCheck any
		if err := json.Unmarshal(policyBytes, &jsonCheck); err != nil {
			slog.Error("Invalid JSON in session policy file",
				slog.String("bucket", r.config.S3SessionPolicyBucket),
				slog.String("key", *sessionPolicyFile),
				slog.String("error", err.Error()))
			return nil, fmt.Errorf("invalid JSON in session policy file: %w", ErrSessionPolicyAccess)
		}

		// Store the policy string
		policy := string(policyBytes)
		sessionPolicyString = &policy

		slog.Debug("Session policy loaded from S3",
			slog.String("repository", repository),
			slog.String("bucket", r.config.S3SessionPolicyBucket),
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
