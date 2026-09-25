package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/boogy/aws-oidc-warden/internal/aws"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/logevent"
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
	logevent.Debug(ctx, log, logevent.TokenExtract, "extracting claims", slog.String("jwtMode", jwtMode))

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
	deny := func(msg string, ret error, attrs ...slog.Attr) error {
		rec.ProcessingMS = elapsed()
		sattrs := append([]slog.Attr{slog.String("stage", rec.Stage)}, attrs...)
		logevent.Debug(ctx, log, logevent.AuthzStageDeny, msg, sattrs...)
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
		reqAttrs := []any{slog.String("role", requestedRole)}
		for _, a := range identityAttrs(claims) {
			reqAttrs = append(reqAttrs, a)
		}
		log = log.With(slog.Group("request", reqAttrs...))
	} else {
		log = log.With(slog.Group("request", slog.String("role", requestedRole)))
	}

	// IsTargetAccountAllowed encodes disabled-means-hub-only (fail closed).
	ok, aerr := r.consumer.IsTargetAccountAllowed(ctx, requestedRole)
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

	logevent.Debug(ctx, log, logevent.TokenValidated, "token validated",
		slog.Int64("validationMs", elapsed()),
	)
	if cfg.LogClaimValues {
		logevent.Debug(ctx, log, logevent.TokenClaims, "validated claims", slog.Any("claims", claims))
	}

	decision := cfg.Authorize(claims.Issuer, claims.Subject, requestedRole, claimsMap)
	roles := decision.Roles
	explicitlyAllowed := decision.Matched && slices.Contains(roles, requestedRole)

	allowed := explicitlyAllowed
	if explicitlyAllowed {
		rec.MatchedVia = "explicit"
	}
	if !allowed && cfg.TagAuth != nil && cfg.TagAuth.Enabled {
		roleTags, terr := r.consumer.GetRoleTags(ctx, requestedRole)
		if terr != nil {
			logevent.Warn(ctx, log, logevent.AuthzTagAuthLookupFailure, "role tag lookup failed",
				slog.String("error", terr.Error()))
		} else if cfg.TagAuth.Authorize(roleTags, claimsMap, claims.Issuer, claims.Subject) {
			allowed = true
			rec.MatchedVia = "tag-auth"
			logevent.Info(ctx, log, logevent.AuthzTagAuthSuccess, "authorized via role tags")
		}
	}

	if !allowed {
		rec.Stage = "authorize"
		rec.Reason = "role not allowed for this subject or its conditions are not met"
		denyAttrs := []slog.Attr{slog.Any("allowedRoles", roles)}
		if cfg.LogClaimValues {
			denyAttrs = append(denyAttrs, identityAttrs(claims)...)
		}
		return nil, deny("Role not allowed for this subject or its conditions are not met", ErrRoleNotPermitted, denyAttrs...)
	}

	sessionPolicy, policyRef, err := r.getSessionPolicy(ctx, cfg, log, claims.Subject, decision)
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

	sessionTagSpec := cfg.EffectiveSessionTags(claims.Issuer, decision)
	credentials, err := r.consumer.AssumeRole(ctx, requestedRole, sessionName, sessionPolicy, nil, claims, sessionTagSpec)
	if err != nil {
		rec.setErrorReason("assume_role", err)
		// A trust-policy/IAM refusal is the caller's answer (403); anything else
		// (throttling, expired hub creds, bad policy document) is ours (500).
		ret := ErrAssumeRoleFailed
		if errors.Is(err, aws.ErrAssumeRoleDenied) {
			ret = ErrAssumeRoleDenied
		}
		return nil, deny("Failed to assume role", fmt.Errorf("failed to assume role: %w", ret), rec.reasonAttr(cfg.LogClaimValues))
	}

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
func (r *RequestProcessor) getSessionPolicy(ctx context.Context, cfg *config.Config, log *slog.Logger, subject string, decision config.Decision) (sessionPolicyString *string, policyRef string, err error) {
	opStart := time.Now()
	durationMs := func() int64 { return time.Since(opStart).Milliseconds() }

	sessionPolicy, sessionPolicyFile := decision.SessionPolicy()

	if sessionPolicyFile != nil {
		policyRef = *sessionPolicyFile

		logPolicyErr := func(msg string, err error) {
			logevent.Error(ctx, log, logevent.PolicySessionLoadFailure, msg,
				slog.String("bucket", cfg.S3SessionPolicyBucket),
				slog.String("key", *sessionPolicyFile),
				slog.String("error", err.Error()))
		}

		sessionPolicyData, err := r.consumer.GetS3Object(ctx, cfg.S3SessionPolicyBucket, *sessionPolicyFile)
		if err != nil {
			logPolicyErr("failed to read session policy file", err)
			return nil, "", fmt.Errorf("failed to read session policy file: %w", ErrSessionPolicyAccess)
		}

		defer func() {
			if cerr := sessionPolicyData.Close(); cerr != nil {
				logevent.Warn(ctx, log, logevent.AppResourceCloseFailure, "failed to close resource",
					slog.String("resource", "session_policy_s3_object"), slog.String("error", cerr.Error()))
			}
		}()

		policyBytes, err := io.ReadAll(io.LimitReader(sessionPolicyData, 1024*1024)) // 1MB limit
		if err != nil {
			logPolicyErr("failed to read session policy data", err)
			return nil, "", fmt.Errorf("failed to read session policy data: %w", ErrSessionPolicyAccess)
		}

		var jsonCheck any
		if err := json.Unmarshal(policyBytes, &jsonCheck); err != nil {
			logPolicyErr("invalid JSON in session policy file", err)
			return nil, "", fmt.Errorf("invalid JSON in session policy file: %w", ErrSessionPolicyAccess)
		}

		policy := string(policyBytes)
		sessionPolicyString = &policy

		logevent.Debug(ctx, log, logevent.PolicySessionLoaded, "session policy loaded",
			subjectAttr(cfg, subject),
			slog.String("source", "s3"),
			slog.String("bucket", cfg.S3SessionPolicyBucket),
			slog.String("key", *sessionPolicyFile),
			slog.Int("policySize", len(policy)),
			slog.Int64("durationMs", durationMs()))
	}

	// Inline overrides the S3 file if both are set.
	if sessionPolicy != nil {
		sessionPolicyString = sessionPolicy
		policyRef = "inline"
		logevent.Debug(ctx, log, logevent.PolicySessionLoaded, "session policy loaded",
			subjectAttr(cfg, subject),
			slog.String("source", "inline"),
			slog.Int("policySize", len(*sessionPolicy)),
			slog.Int64("durationMs", durationMs()))
	}

	return sessionPolicyString, policyRef, nil
}

// identityAttrs builds "who made this request" log attributes for a verified
// token. repository/ref/actor are GitHub-native and omitted (not emitted
// empty) for other providers. Callers must gate on cfg.LogClaimValues.
func identityAttrs(claims *gtypes.Claims) []slog.Attr {
	if claims == nil {
		return nil
	}
	attrs := []slog.Attr{slog.String("subject", claims.Subject)}
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
