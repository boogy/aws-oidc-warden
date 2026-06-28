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
	"github.com/boogy/aws-oidc-warden/internal/aws"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/utils"
	"github.com/boogy/aws-oidc-warden/internal/validator"
)

// RequestProcessor contains the core business logic for processing authentication requests
type RequestProcessor struct {
	provider  *config.Provider
	consumer  aws.AwsConsumerInterface
	extractor validator.ClaimsExtractorInterface
}

// NewRequestProcessor creates a new instance of request processor
func NewRequestProcessor(provider *config.Provider, consumer aws.AwsConsumerInterface, extractor validator.ClaimsExtractorInterface) *RequestProcessor {
	return &RequestProcessor{
		provider:  provider,
		consumer:  consumer,
		extractor: extractor,
	}
}

// ProcessRequest contains the main business logic for processing requests
func (r *RequestProcessor) ProcessRequest(ctx context.Context, requestData *RequestData, input validator.ExtractionInput, requestID string, log *slog.Logger) (*types.Credentials, error) {
	startTime, _ := ctx.Value(StartTimeContextKey).(time.Time)

	// Pick up any hot-reloaded configuration (no-op unless reload is enabled),
	// then use a single config snapshot for the whole request.
	r.provider.MaybeRefresh(ctx)
	cfg := r.provider.Get()

	log.Debug("Extracting claims", slog.String("mode", func() string {
		if input.Token != "" {
			return "self"
		}
		if len(input.AuthorizerClaims) > 0 {
			return "apigw"
		}
		if input.ALBOIDCData != "" {
			return "alb"
		}
		return "unknown"
	}()))

	// Extract claims via the configured extractor (self-validation or delegated mode).
	// All extraction errors wrap ErrTokenValidationFailed so adapters map them to HTTP 401.
	claims, err := r.extractor.Extract(ctx, input)
	if err != nil {
		log.Error("Claims extraction failed", slog.String("error", err.Error()))
		return nil, fmt.Errorf("%w: %w", ErrTokenValidationFailed, err)
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

	// Account guardrail: reject target accounts outside the allow-list before
	// reading role tags or assuming anything. Only relevant when tag-auth (and
	// thus cross-account) is enabled.
	if cfg.TagAuth != nil && cfg.TagAuth.Enabled {
		ok, aerr := r.consumer.IsTargetAccountAllowed(requestedRole)
		if aerr != nil {
			log.Error("Account allow-list check failed", slog.String("error", aerr.Error()))
			return nil, ErrAssumeRoleFailed
		}
		if !ok {
			log.Error("Target account not allowed", slog.String("role", requestedRole))
			return nil, ErrAccountNotAllowed
		}
	}

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

	// Match role to repository with explicit constraints
	matched, roles := cfg.MatchRolesToRepoWithConstraints(claims.Repository, claimsMap)
	explicitlyAllowed := matched && (len(roles) == 0 || slices.Contains(roles, requestedRole))

	// Fall back to tag-based authorization: read the requested role's IAM tags
	// and check they authorize these claims. Cross-account aware via GetRoleTags.
	allowed := explicitlyAllowed
	if !allowed && cfg.TagAuth != nil && cfg.TagAuth.Enabled {
		roleTags, terr := r.consumer.GetRoleTags(requestedRole)
		if terr != nil {
			log.Warn("Tag-based authorization: could not read role tags",
				slog.String("role", requestedRole), slog.String("error", terr.Error()))
		} else if cfg.TagAuth.Authorize(roleTags, claimsMap) {
			allowed = true
			log.Info("Authorized via role tags", slog.String("role", requestedRole))
		}
	}

	if !allowed {
		log.Error("Role not allowed for repository or doesn't meet constraints",
			slog.String("repository", claims.Repository),
			slog.String("role", requestedRole),
			slog.String("ref", claims.Ref),
			slog.String("branch", utils.ExtractBranchFromRef(claims.Ref)),
			slog.Any("allowedRoles", roles))

		return nil, ErrRoleNotPermitted
	}

	// Attempting to get session policy
	sessionPolicy, err := r.getSessionPolicy(cfg, claims.Repository)
	if err != nil {
		log.Error("Failed to read session policy", slog.String("error", err.Error()))
		return nil, err
	}

	// Time to assume role
	log.Debug("Assuming role",
		slog.String("role", requestedRole),
		slog.Bool("hasSessionPolicy", sessionPolicy != nil))

	// Assume role
	credentials, err := r.consumer.AssumeRole(requestedRole, cfg.RoleSessionName, sessionPolicy, nil, claims)
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
func (r *RequestProcessor) getSessionPolicy(cfg *config.Config, repository string) (*string, error) {
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
		sessionPolicyData, err := r.consumer.GetS3Object(cfg.S3SessionPolicyBucket, *sessionPolicyFile)
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
