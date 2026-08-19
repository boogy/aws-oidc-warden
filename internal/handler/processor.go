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
	audit     AuditSink // structured audit trail sink; nil is a safe no-op (see audit.go)
	frontend  string    // adapter name (apigateway/apigatewayv2/alb/lambdaurl), for the audit record
}

// NewRequestProcessor creates a new instance of request processor. audit may
// be nil (audit trail becomes a no-op; standardized logging still happens).
func NewRequestProcessor(provider *config.Provider, consumer aws.AwsConsumerInterface, extractor validator.ClaimsExtractorInterface, audit AuditSink, frontend string) *RequestProcessor {
	return &RequestProcessor{
		provider:  provider,
		consumer:  consumer,
		extractor: extractor,
		audit:     audit,
		frontend:  frontend,
	}
}

// ProcessRequest contains the main business logic for processing requests
func (r *RequestProcessor) ProcessRequest(ctx context.Context, requestData *RequestData, input validator.ExtractionInput, requestID string, log *slog.Logger) (*types.Credentials, error) {
	startTime, _ := ctx.Value(StartTimeContextKey).(time.Time)

	// Pick up any hot-reloaded configuration (no-op unless reload is enabled),
	// then use a single config snapshot for the whole request.
	r.provider.MaybeRefresh(ctx)
	cfg := r.provider.Get()

	jwtMode := inputMode(input)
	log.Debug("Extracting claims", slog.String("jwtMode", jwtMode))

	// rec accumulates the fields for this request's audit record/standardized
	// log attrs. Built up as more is learned; finalizeDeny/finalizeAllow do the
	// terminal redaction + durable-write-before-credentials handling.
	rec := &auditRecord{
		RequestID:     requestID,
		Frontend:      r.frontend,
		JWTMode:       jwtMode,
		RequestedRole: requestData.Role,
	}
	rec.SourceIP, _ = ctx.Value(SourceIPContextKey).(string)
	rec.SourceIPFrom, _ = ctx.Value(SourceIPSourceContextKey).(string)
	// elapsed is the single source for every millisecond timing on this
	// request: the audit record's processingMs and the validationMs/totalMs log
	// attrs. Going through it rather than calling time.Since(startTime) inline
	// keeps the zero guard in one place — startTime is absent whenever the
	// caller did not set StartTimeContextKey, and time.Since(time.Time{}) is
	// ~64000 years, which as a millisecond integer is indistinguishable from
	// garbage.
	elapsed := func() int64 {
		if startTime.IsZero() {
			return 0
		}
		return time.Since(startTime).Milliseconds()
	}

	// Extract claims via the configured extractor (self-validation or delegated mode).
	// All extraction errors wrap ErrTokenValidationFailed so adapters map them to HTTP 401.
	claims, err := r.extractor.Extract(ctx, input)
	if err != nil {
		rec.Stage = "extract"
		rec.Reason = err.Error()
		rec.ProcessingMS = elapsed()
		log.Error("Claims extraction failed", slog.String("stage", rec.Stage), slog.String("error", err.Error()))
		return nil, r.finalizeDeny(ctx, log, cfg, rec, fmt.Errorf("%w: %w", ErrTokenValidationFailed, err))
	}

	// Repository from github claims and role from request data
	requestedRole := requestData.Role

	// Now that claims are verified, fill in the standardized issuer/subject
	// fields shared by every subsequent stage's audit record/log attrs.
	rec.Issuer = claims.Issuer
	rec.Provider = issuerProvider(cfg, claims.Issuer)
	rec.JWTSub = claims.Sub
	rec.Subject = claims.Subject
	rec.Audience = claimsAudience(claims)
	// Identifying claims ("who did this") are attached here, before the
	// authorization stages, so a deny record carries them too — a denied
	// attempt is exactly when you need to know who made it. redact() drops
	// them when log_claim_values is off.
	if cfg.LogClaimValues {
		rec.Claims = auditClaims(cfg, claims.Issuer, claims.Raw)
	}

	// Add request context to the logger. The requested role ARN is not a claim
	// value and is always logged; repository/ref/branch/actor ARE claim values,
	// so they're only attached when log_claim_values permits (suppress claim
	// values in the log stream, not just the audit record).
	if cfg.LogClaimValues {
		log = log.With(
			slog.Group("request",
				slog.String("repository", claims.Repository),
				slog.String("ref", claims.Ref),
				slog.String("branch", utils.ExtractBranchFromRef(claims.Ref)),
				slog.String("role", requestedRole),
				slog.String("actor", claims.Actor),
			),
		)
	} else {
		log = log.With(slog.Group("request", slog.String("role", requestedRole)))
	}

	// Account guardrail: reject target accounts outside the allow-list before
	// reading role tags or assuming anything. Runs on every request regardless
	// of cross-account transport; IsTargetAccountAllowed itself encodes
	// disabled-means-hub-only (fail closed).
	ok, aerr := r.consumer.IsTargetAccountAllowed(requestedRole)
	if aerr != nil {
		rec.Stage = "account_check"
		rec.Reason = aerr.Error()
		rec.ProcessingMS = elapsed()
		log.Error("Account allow-list check failed", slog.String("stage", rec.Stage), slog.String("error", aerr.Error()))
		return nil, r.finalizeDeny(ctx, log, cfg, rec, ErrAssumeRoleFailed)
	}
	if !ok {
		rec.Stage = "account_check"
		rec.Reason = "target account not allowed"
		rec.ProcessingMS = elapsed()
		log.Error("Target account not allowed", slog.String("stage", rec.Stage), slog.String("role", requestedRole))
		return nil, r.finalizeDeny(ctx, log, cfg, rec, ErrAccountNotAllowed)
	}

	// Conditions and tag-auth match against raw verified claim names, so use the
	// verified raw claim set directly. It carries every claim — including
	// provider-native and custom claims that have no types.Claims struct field
	// (generic issuers) — whereas a JSON round-trip of the typed struct drops
	// claims.Raw (json:"-") and yields only zero-valued GitHub fields for a
	// generic issuer.
	claimsMap := claims.Raw
	if claimsMap == nil {
		claimsMap = map[string]any{}
	}

	// Concise success line at Info; the full claim set (a bag of claim VALUES)
	// only at Debug AND only when log_claim_values permits it — otherwise it
	// would leak every raw claim value the audit record/standardized log line
	// carefully suppresses.
	log.Info("Token validation successful",
		slog.Int64("validationMs", elapsed()),
	)
	if cfg.LogClaimValues {
		log.Debug("Validated claims", slog.Any("claims", claims))
	}

	// Match role to (issuer, subject) with explicit conditions
	matched, roles := cfg.AuthorizeRoles(claims.Issuer, claims.Subject, claimsMap)
	explicitlyAllowed := matched && slices.Contains(roles, requestedRole)

	// Fall back to tag-based authorization: read the requested role's IAM tags
	// and check they authorize these claims. Cross-account aware via GetRoleTags.
	allowed := explicitlyAllowed
	if explicitlyAllowed {
		rec.MatchedVia = "explicit"
	}
	if !allowed && cfg.TagAuth != nil && cfg.TagAuth.Enabled {
		roleTags, terr := r.consumer.GetRoleTags(requestedRole)
		if terr != nil {
			log.Warn("Tag-based authorization: could not read role tags",
				slog.String("role", requestedRole), slog.String("error", terr.Error()))
		} else if cfg.TagAuth.Authorize(roleTags, claimsMap, claims.Issuer, claims.Subject) {
			allowed = true
			rec.MatchedVia = "tag-auth"
			log.Info("Authorized via role tags", slog.String("role", requestedRole))
		}
	}

	if !allowed {
		rec.Stage = "authorize"
		rec.Reason = "role not allowed for repository or doesn't meet constraints"
		rec.ProcessingMS = elapsed()
		denyAttrs := []any{slog.String("stage", rec.Stage), slog.Any("allowedRoles", roles)}
		if cfg.LogClaimValues {
			denyAttrs = append(denyAttrs,
				slog.String("repository", claims.Repository),
				slog.String("ref", claims.Ref),
				slog.String("branch", utils.ExtractBranchFromRef(claims.Ref)))
		}
		log.Error("Role not allowed for repository or doesn't meet constraints", denyAttrs...)

		return nil, r.finalizeDeny(ctx, log, cfg, rec, ErrRoleNotPermitted)
	}

	// Attempting to get session policy
	sessionPolicy, policyRef, err := r.getSessionPolicy(cfg, log, claims.Issuer, claims.Subject, requestedRole, claimsMap)
	if err != nil {
		rec.Stage = "session_policy"
		rec.Reason = err.Error()
		rec.ProcessingMS = elapsed()
		log.Error("Failed to read session policy", slog.String("stage", rec.Stage), slog.String("error", err.Error()))
		return nil, r.finalizeDeny(ctx, log, cfg, rec, err)
	}

	// A per-mapping role_session_name overrides the global default, so
	// CloudTrail names the requester rather than the service. Resolution goes
	// through the same authorizing mapping as the session policy.
	sessionName := cfg.RoleSessionName
	if override := cfg.FindRoleSessionName(claims.Issuer, claims.Subject, requestedRole, claims.Raw); override != "" {
		sessionName = override
	}

	// Info, not Debug: this is the last line before a privileged credential is
	// minted, so it must be visible at the default level. It replaces the
	// uncorrelated slog.Info in internal/aws/service_wrapper.go, which had no
	// requestId. role is not repeated here — the request-scoped logger already
	// carries it in the "request" group bound above.
	log.Info("Assuming role",
		slog.Bool("hasSessionPolicy", sessionPolicy != nil),
		slog.String("sessionName", sessionName))

	// Assume role
	sessionTagSpec := cfg.IssuerSessionTags(claims.Issuer)
	credentials, err := r.consumer.AssumeRole(requestedRole, sessionName, sessionPolicy, nil, claims, sessionTagSpec)
	if err != nil {
		rec.Stage = "assume_role"
		rec.Reason = err.Error()
		rec.ProcessingMS = elapsed()
		log.Error("Failed to assume role",
			slog.String("stage", rec.Stage), slog.String("error", err.Error()))
		return nil, r.finalizeDeny(ctx, log, cfg, rec, fmt.Errorf("failed to assume role: %w", ErrAssumeRoleFailed))
	}

	// Log the successful assume role operation. STS always populates these
	// fields in practice, but guard the derefs so a pathological response can
	// never panic the handler after a successful assume.
	accessKeyID := ""
	if credentials.AccessKeyId != nil {
		accessKeyID = *credentials.AccessKeyId
	}
	var credExpiration time.Time
	if credentials.Expiration != nil {
		credExpiration = *credentials.Expiration
	}
	log.Info("Successfully assumed role",
		slog.String("accessKeyId", accessKeyID),
		slog.Time("expiration", credExpiration),
		slog.Int64("totalMs", elapsed()))

	// Fill in the allow-only audit fields: granted role, account, session tag
	// names (always) and resolved session-tag values (only when
	// cfg.LogClaimValues permits claim values to be logged/audited), session
	// policy reference, and token expiry.
	rec.GrantedRole = requestedRole
	rec.SessionName = sessionName
	rec.SessionTagKeys = sessionTagKeyNames(sessionTagSpec)
	if cfg.LogClaimValues {
		rec.SessionTags = resolvedSessionTags(claims.Raw, sessionTagSpec)
	}
	rec.SessionPolicyRef = policyRef
	if account, _, aerr := aws.ParseRoleARN(requestedRole); aerr == nil {
		rec.AccountID = account
	}
	if credentials.Expiration != nil {
		rec.Expiry = credentials.Expiration
	}
	rec.ProcessingMS = elapsed()

	// finalizeAllow sets decision + emits the standardized decision line (via
	// recordDecision) from the redacted record, then durably writes the audit
	// record before returning credentials (fail-closed when audit_required).
	return r.finalizeAllow(ctx, log, cfg, rec, credentials)
}

// getSessionPolicy retrieves the session policy for a given (issuer, subject)
// pair (config inline or S3 file), along with a policyRef label identifying
// which source it came from ("inline", the S3 key, or "" when none is
// configured) for the audit record's SessionPolicyRef field — computed here,
// alongside the single cfg.FindSessionPolicy lookup, so callers don't need a
// second lookup just to label the decision.
func (r *RequestProcessor) getSessionPolicy(cfg *config.Config, log *slog.Logger, issuer, subject, role string, claims map[string]any) (sessionPolicyString *string, policyRef string, err error) {
	// Start measuring time for this operation
	opStart := time.Now()
	defer func() {
		log.Debug("getSessionPolicy operation completed",
			subjectAttr(cfg, subject),
			slog.Int64("durationMs", time.Since(opStart).Milliseconds()))
	}()

	sessionPolicy, sessionPolicyFile := cfg.FindSessionPolicy(issuer, subject, role, claims)

	// Try to get policy from S3 file if specified
	if sessionPolicyFile != nil {
		policyRef = *sessionPolicyFile

		sessionPolicyData, err := r.consumer.GetS3Object(cfg.S3SessionPolicyBucket, *sessionPolicyFile)
		if err != nil {
			log.Error("Failed to read session policy file",
				slog.String("bucket", cfg.S3SessionPolicyBucket),
				slog.String("key", *sessionPolicyFile),
				slog.String("error", err.Error()))
			return nil, "", fmt.Errorf("failed to read session policy file: %w", ErrSessionPolicyAccess)
		}

		// Read the content and ensure the reader is closed
		defer func() {
			if err := sessionPolicyData.Close(); err != nil {
				log.Error("Failed to close session policy data reader", "error", err)
			}
		}()

		// Limit the size of policy files that can be read
		policyBytes, err := io.ReadAll(io.LimitReader(sessionPolicyData, 1024*1024)) // 1MB limit
		if err != nil {
			log.Error("Failed to read session policy data",
				slog.String("bucket", cfg.S3SessionPolicyBucket),
				slog.String("key", *sessionPolicyFile),
				slog.String("error", err.Error()))
			return nil, "", fmt.Errorf("failed to read session policy data: %w", ErrSessionPolicyAccess)
		}

		// Validate that the policy is valid JSON
		var jsonCheck any
		if err := json.Unmarshal(policyBytes, &jsonCheck); err != nil {
			log.Error("Invalid JSON in session policy file",
				slog.String("bucket", cfg.S3SessionPolicyBucket),
				slog.String("key", *sessionPolicyFile),
				slog.String("error", err.Error()))
			return nil, "", fmt.Errorf("invalid JSON in session policy file: %w", ErrSessionPolicyAccess)
		}

		// Store the policy string
		policy := string(policyBytes)
		sessionPolicyString = &policy

		log.Debug("Session policy loaded from S3",
			subjectAttr(cfg, subject),
			slog.String("bucket", cfg.S3SessionPolicyBucket),
			slog.String("key", *sessionPolicyFile),
			slog.Int("policySize", len(policy)))
	}

	// Use inline policy if provided (overrides S3 file if both exist)
	if sessionPolicy != nil {
		sessionPolicyString = sessionPolicy
		policyRef = "inline"
		log.Debug("Using inline session policy",
			subjectAttr(cfg, subject),
			slog.Int("policySize", len(*sessionPolicy)))
	}

	return sessionPolicyString, policyRef, nil
}
