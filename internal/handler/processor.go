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
	gtypes "github.com/boogy/aws-oidc-warden/internal/types"
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

	r.provider.MaybeRefresh(ctx)
	cfg := r.provider.Get()

	// Pin this snapshot for extraction too, so a reload landing mid-request
	// can't validate and authorize against different config generations.
	input.Config = cfg

	jwtMode := inputMode(input)
	log.Debug("Extracting claims", slog.String("jwtMode", jwtMode))

	rec := &auditRecord{
		RequestID:     requestID,
		Frontend:      r.frontend,
		JWTMode:       jwtMode,
		RequestedRole: requestData.Role,
	}
	rec.SourceIP, _ = ctx.Value(SourceIPContextKey).(string)
	rec.SourceIPFrom, _ = ctx.Value(SourceIPSourceContextKey).(string)
	rec.FrontendRequestID, _ = ctx.Value(FrontendRequestIDContextKey).(string)
	// Single source for every ms timing here; guards the zero case since
	// time.Since(time.Time{}) would otherwise read as ~64000 years.
	elapsed := func() int64 {
		if startTime.IsZero() {
			return 0
		}
		return time.Since(startTime).Milliseconds()
	}

	// deny finishes a rejected request. rec.Stage and rec.Reason must already
	// be set; log is read at call time, so it picks up the enriched logger.
	deny := func(msg string, ret error, attrs ...any) error {
		rec.ProcessingMS = elapsed()
		log.Error(msg, append([]any{slog.String("stage", rec.Stage)}, attrs...)...)
		return r.finalizeDeny(ctx, log, cfg, rec, ret)
	}

	claims, err := r.extractor.Extract(ctx, input)
	if err != nil {
		rec.setErrorReason("extract", err)
		return nil, deny("Claims extraction failed", fmt.Errorf("%w: %w", ErrTokenValidationFailed, err), rec.reasonAttr(cfg.LogClaimValues))
	}

	requestedRole := requestData.Role

	rec.Issuer = claims.Issuer
	rec.Provider = issuerProvider(cfg, claims.Issuer)
	rec.JWTSub = claims.Sub
	rec.Subject = claims.Subject
	rec.Audience = claimsAudience(claims)
	// Attached before the authorization stages too, so a deny record still
	// carries "who did this"; redact() drops these when log_claim_values is off.
	if cfg.LogClaimValues {
		rec.Claims = auditClaims(cfg, claims.Issuer, claims.Raw)
	}

	if cfg.LogClaimValues {
		log = log.With(slog.Group("request",
			append([]any{slog.String("role", requestedRole)}, identityAttrs(claims)...)...))
	} else {
		log = log.With(slog.Group("request", slog.String("role", requestedRole)))
	}

	// IsTargetAccountAllowed encodes disabled-means-hub-only (fail closed).
	ok, aerr := r.consumer.IsTargetAccountAllowed(requestedRole)
	if aerr != nil {
		rec.setErrorReason("account_check", aerr)
		return nil, deny("Account allow-list check failed", ErrAssumeRoleFailed, rec.reasonAttr(cfg.LogClaimValues))
	}
	if !ok {
		rec.Stage = "account_check"
		rec.Reason = "target account not allowed"
		return nil, deny("Target account not allowed", ErrAccountNotAllowed)
	}

	// claims.Raw, not the typed struct: generic issuers' claims have no
	// struct field, and a JSON round-trip of the struct drops claims.Raw (json:"-").
	claimsMap := claims.Raw
	if claimsMap == nil {
		claimsMap = map[string]any{}
	}

	log.Info("Token validation successful",
		slog.Int64("validationMs", elapsed()),
	)
	if cfg.LogClaimValues {
		log.Debug("Validated claims", slog.Any("claims", claims))
	}

	decision := cfg.Authorize(claims.Issuer, claims.Subject, requestedRole, claimsMap)
	roles := decision.Roles
	explicitlyAllowed := decision.Matched && slices.Contains(roles, requestedRole)

	allowed := explicitlyAllowed
	if explicitlyAllowed {
		rec.MatchedVia = "explicit"
	}
	if !allowed && cfg.TagAuth != nil && cfg.TagAuth.Enabled {
		roleTags, terr := r.consumer.GetRoleTags(requestedRole)
		if terr != nil {
			log.Warn("Tag-based authorization: could not read role tags",
				slog.String("error", terr.Error()))
		} else if cfg.TagAuth.Authorize(roleTags, claimsMap, claims.Issuer, claims.Subject) {
			allowed = true
			rec.MatchedVia = "tag-auth"
			log.Info("Authorized via role tags")
		}
	}

	if !allowed {
		rec.Stage = "authorize"
		rec.Reason = "role not allowed for this subject or its conditions are not met"
		denyAttrs := []any{slog.Any("allowedRoles", roles)}
		if cfg.LogClaimValues {
			denyAttrs = append(denyAttrs, identityAttrs(claims)...)
		}
		return nil, deny("Role not allowed for this subject or its conditions are not met", ErrRoleNotPermitted, denyAttrs...)
	}

	sessionPolicy, policyRef, err := r.getSessionPolicy(cfg, log, claims.Subject, decision)
	if err != nil {
		rec.setErrorReason("session_policy", err)
		return nil, deny("Failed to read session policy", err, rec.reasonAttr(cfg.LogClaimValues))
	}

	// Per-mapping override, resolved via the same mapping that authorized the
	// role, so CloudTrail can name the requester rather than the service.
	sessionName := cfg.RoleSessionName
	if override := decision.RoleSessionName(); override != "" {
		sessionName = override
	}

	// Info, not Debug: last line before a privileged credential is minted.
	log.Info("Assuming role",
		slog.Bool("hasSessionPolicy", sessionPolicy != nil),
		slog.String("sessionName", sessionName))

	sessionTagSpec := cfg.IssuerSessionTags(claims.Issuer)
	credentials, err := r.consumer.AssumeRole(requestedRole, sessionName, sessionPolicy, nil, claims, sessionTagSpec)
	if err != nil {
		rec.setErrorReason("assume_role", err)
		return nil, deny("Failed to assume role", fmt.Errorf("failed to assume role: %w", ErrAssumeRoleFailed), rec.reasonAttr(cfg.LogClaimValues))
	}

	// Guard the derefs so a pathological STS response can't panic the handler.
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

	return r.finalizeAllow(ctx, log, cfg, rec, credentials)
}

// getSessionPolicy retrieves the session policy for an (issuer, subject) pair
// (config inline or S3 file), plus a policyRef label ("inline", the S3 key,
// or "") for the audit record's SessionPolicyRef field.
func (r *RequestProcessor) getSessionPolicy(cfg *config.Config, log *slog.Logger, subject string, decision config.Decision) (sessionPolicyString *string, policyRef string, err error) {
	opStart := time.Now()
	defer func() {
		log.Debug("getSessionPolicy operation completed",
			subjectAttr(cfg, subject),
			slog.Int64("durationMs", time.Since(opStart).Milliseconds()))
	}()

	sessionPolicy, sessionPolicyFile := decision.SessionPolicy()

	if sessionPolicyFile != nil {
		policyRef = *sessionPolicyFile

		logPolicyErr := func(msg string, err error) {
			log.Error(msg,
				slog.String("bucket", cfg.S3SessionPolicyBucket),
				slog.String("key", *sessionPolicyFile),
				slog.String("error", err.Error()))
		}

		sessionPolicyData, err := r.consumer.GetS3Object(cfg.S3SessionPolicyBucket, *sessionPolicyFile)
		if err != nil {
			logPolicyErr("Failed to read session policy file", err)
			return nil, "", fmt.Errorf("failed to read session policy file: %w", ErrSessionPolicyAccess)
		}

		defer func() {
			if err := sessionPolicyData.Close(); err != nil {
				log.Error("Failed to close session policy data reader", "error", err)
			}
		}()

		policyBytes, err := io.ReadAll(io.LimitReader(sessionPolicyData, 1024*1024)) // 1MB limit
		if err != nil {
			logPolicyErr("Failed to read session policy data", err)
			return nil, "", fmt.Errorf("failed to read session policy data: %w", ErrSessionPolicyAccess)
		}

		var jsonCheck any
		if err := json.Unmarshal(policyBytes, &jsonCheck); err != nil {
			logPolicyErr("Invalid JSON in session policy file", err)
			return nil, "", fmt.Errorf("invalid JSON in session policy file: %w", ErrSessionPolicyAccess)
		}

		policy := string(policyBytes)
		sessionPolicyString = &policy

		log.Debug("Session policy loaded from S3",
			subjectAttr(cfg, subject),
			slog.String("bucket", cfg.S3SessionPolicyBucket),
			slog.String("key", *sessionPolicyFile),
			slog.Int("policySize", len(policy)))
	}

	// Inline overrides the S3 file if both are set.
	if sessionPolicy != nil {
		sessionPolicyString = sessionPolicy
		policyRef = "inline"
		log.Debug("Using inline session policy",
			subjectAttr(cfg, subject),
			slog.Int("policySize", len(*sessionPolicy)))
	}

	return sessionPolicyString, policyRef, nil
}

// identityAttrs builds "who made this request" log attributes for a verified
// token. repository/ref/actor are GitHub-native and omitted (not emitted
// empty) for other providers. Callers must gate on cfg.LogClaimValues.
func identityAttrs(claims *gtypes.Claims) []any {
	if claims == nil {
		return nil
	}
	attrs := []any{slog.String("subject", claims.Subject)}
	if claims.Repository != "" {
		attrs = append(attrs, slog.String("repository", claims.Repository))
	}
	if claims.Ref != "" {
		attrs = append(attrs,
			slog.String("ref", claims.Ref),
			slog.String("branch", utils.ExtractBranchFromRef(claims.Ref)))
	}
	if claims.Actor != "" {
		attrs = append(attrs, slog.String("actor", claims.Actor))
	}
	return attrs
}
