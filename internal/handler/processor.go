package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync/atomic"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/aws"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/idp"
	"github.com/boogy/aws-oidc-warden/internal/logevent"
	gtypes "github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/boogy/aws-oidc-warden/internal/utils"
	"github.com/boogy/aws-oidc-warden/internal/validator"
)

// RequestProcessor contains the core business logic for processing authentication requests
type RequestProcessor struct {
	provider    *config.Provider
	consumer    aws.AwsConsumerInterface
	extractor   validator.ClaimsExtractorInterface
	audit       AuditSink // nil is a no-op
	frontend    string
	idp         *idp.Service
	frozenFP    string
	lastChecked atomic.Pointer[config.Config]
}

// WithIdP enables the IdP mint path; a nil service leaves it disabled.
func (r *RequestProcessor) WithIdP(s *idp.Service) *RequestProcessor {
	r.idp = s
	if s != nil {
		r.frozenFP = s.Config().Fingerprint()
	}
	return r
}

// warnFrozenDrift warns once per config generation whose frozen idp settings differ from cold start, including an added or removed idp block.
func (r *RequestProcessor) warnFrozenDrift(ctx context.Context, log *slog.Logger, cfg *config.Config) {
	if r.lastChecked.Swap(cfg) == cfg {
		return
	}
	fp := ""
	if cfg.IdP != nil {
		fp = cfg.IdP.Fingerprint()
	}
	if fp != r.frozenFP {
		logevent.Warn(ctx, log, logevent.ConfigIdPReloadIgnored, "idp settings changed on reload; restart to apply")
	}
}

// NewRequestProcessor creates a request processor; a nil audit sink disables the audit trail.
func NewRequestProcessor(provider *config.Provider, consumer aws.AwsConsumerInterface, extractor validator.ClaimsExtractorInterface, audit AuditSink, frontend string) *RequestProcessor {
	return &RequestProcessor{
		provider:  provider,
		consumer:  consumer,
		extractor: extractor,
		audit:     audit,
		frontend:  frontend,
	}
}

const (
	actionAssumeRole = "assume_role"
	actionMintToken  = "mint_token"
)

// authzOutcome carries the state of an authorized (or denied) request between pipeline stages.
type authzOutcome struct {
	cfg       *config.Config
	claims    *gtypes.Claims
	claimsMap map[string]any
	decision  config.Decision
	rec       *auditRecord
	log       *slog.Logger
	elapsed   func() int64
}

const reasonAccountNotAllowed = "target account not allowed"

// deny finishes a rejected request. o.rec.Stage and o.rec.Reason must already be set.
func (r *RequestProcessor) deny(ctx context.Context, o *authzOutcome, msg string, ret error, attrs ...slog.Attr) error {
	o.rec.ProcessingMS = o.elapsed()
	sattrs := append([]slog.Attr{slog.String("stage", o.rec.Stage)}, attrs...)
	logevent.Debug(ctx, o.log, logevent.AuthzStageDeny, msg, sattrs...)
	return r.finalizeDeny(ctx, o.log, o.cfg, o.rec, ret)
}

// authorizeRequest runs refresh, extraction, account check and authorization; it records the deny itself on failure.
func (r *RequestProcessor) authorizeRequest(ctx context.Context, requestData *RequestData, input validator.ExtractionInput, requestID string, log *slog.Logger) (*authzOutcome, error) {
	startTime, _ := ctx.Value(StartTimeContextKey).(time.Time)

	r.provider.RefreshIfDue(ctx)
	cfg := r.provider.Get()

	// One config generation for both extraction and authorization.
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
	// time.Since(time.Time{}) would read as ~64000 years.
	elapsed := func() int64 {
		if startTime.IsZero() {
			return 0
		}
		return time.Since(startTime).Milliseconds()
	}

	o := &authzOutcome{cfg: cfg, rec: rec, log: log, elapsed: elapsed}

	claims, err := r.extractor.Extract(ctx, input)
	if err != nil {
		rec.setErrorReason("extract", err)
		return nil, r.deny(ctx, o, "Claims extraction failed", fmt.Errorf("%w: %w", ErrTokenValidationFailed, err), rec.reasonAttr(cfg.LogClaimValues))
	}

	// Stale is gated only after authentication so anonymous callers cannot wait on a refresh or trigger the Error log.
	if _, _, stale := r.provider.Stale(); stale {
		r.provider.MaybeRefresh(ctx)
		if age, limit, stale := r.provider.Stale(); stale {
			o.rec.Stage, o.rec.Reason = "config", "mappings older than mappings_max_stale"
			logevent.Error(ctx, log, logevent.ConfigMappingsStale, "role mappings are stale; refusing request",
				slog.Int64("ageMs", age.Milliseconds()), slog.Int64("maxStaleMs", limit.Milliseconds()))
			return nil, r.deny(ctx, o, "Configuration stale", ErrConfigStale)
		}
		cfg = r.provider.Get()
		input.Config, o.cfg = cfg, cfg
		if claims, err = r.extractor.Extract(ctx, input); err != nil {
			rec.setErrorReason("extract", err)
			return nil, r.deny(ctx, o, "Claims extraction failed", fmt.Errorf("%w: %w", ErrTokenValidationFailed, err), rec.reasonAttr(cfg.LogClaimValues))
		}
	}
	o.claims = claims

	requestedRole := requestData.Role

	rec.Issuer = claims.Issuer
	rec.Provider = issuerProvider(cfg, claims.Issuer)
	rec.JWTSub = claims.Sub
	rec.Subject = claims.Subject
	rec.Audience = claimsAudience(claims)
	// Set before authorization so deny records carry identity; redact() honours log_claim_values.
	if cfg.LogClaimValues {
		rec.Claims = auditClaims(cfg, claims.Issuer, claims.Raw)
	}

	if cfg.LogClaimValues {
		reqAttrs := []any{slog.String("roleArn", requestedRole)}
		for _, a := range identityAttrs(claims) {
			reqAttrs = append(reqAttrs, a)
		}
		o.log = o.log.With(slog.Group("request", reqAttrs...))
	} else {
		o.log = o.log.With(slog.Group("request", slog.String("roleArn", requestedRole)))
	}
	log = o.log

	// IsTargetAccountAllowed encodes disabled-means-hub-only (fail closed).
	ok, aerr := r.consumer.IsTargetAccountAllowed(ctx, requestedRole)
	if aerr != nil {
		rec.setErrorReason("account_check", aerr)
		return nil, r.deny(ctx, o, "Account allow-list check failed", ErrAssumeRoleFailed, rec.reasonAttr(cfg.LogClaimValues))
	}
	if !ok {
		rec.Stage, rec.Reason = "account_check", reasonAccountNotAllowed
		return nil, r.deny(ctx, o, "Target account not allowed", ErrAccountNotAllowed)
	}

	// claims.Raw: generic issuers' claims have no typed struct field.
	claimsMap := claims.Raw
	if claimsMap == nil {
		claimsMap = map[string]any{}
	}
	o.claimsMap = claimsMap

	logevent.Debug(ctx, log, logevent.TokenValidated, "token validated",
		slog.Int64("validationMs", elapsed()),
	)
	if cfg.LogClaimValues {
		logevent.Debug(ctx, log, logevent.TokenClaims, "validated claims", slog.Any("claims", claims))
	}

	decision := cfg.Authorize(claims.Issuer, claims.Subject, requestedRole, claimsMap)
	o.decision = decision
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
		return nil, r.deny(ctx, o, "Role not allowed for this subject or its conditions are not met", ErrRoleNotPermitted, denyAttrs...)
	}

	return o, nil
}

// ProcessRequest authorizes once, then issues credentials through the IdP for an IdP-enabled role or AssumeRole otherwise.
func (r *RequestProcessor) ProcessRequest(ctx context.Context, requestData *RequestData, input validator.ExtractionInput, requestID string, log *slog.Logger) (*IssuedCredentials, error) {
	o, err := r.authorizeRequest(ctx, requestData, input, requestID, log)
	if err != nil {
		return nil, err
	}
	r.warnFrozenDrift(ctx, o.log, o.cfg)
	o.rec.RequestedDurationSeconds = int(requestData.DurationSeconds)
	if err := checkDuration(requestData.DurationSeconds); err != nil {
		o.rec.Stage, o.rec.Reason = "duration", "invalid or excessive duration"
		return nil, r.deny(ctx, o, "Duration refused", err)
	}
	useIdP, reason, err := r.selectIdP(o.cfg, o.decision, requestData.Role, requestData.DurationSeconds)
	if err != nil {
		o.rec.Stage, o.rec.Reason = "duration", reason
		return nil, r.deny(ctx, o, "Duration refused", err)
	}
	o.rec.Action = actionAssumeRole
	if useIdP {
		o.rec.Action = actionMintToken
	}
	sessionName, nameSource, err := resolveSessionName(o.decision.RoleSessionName(), requestData.SessionName, o.cfg.RoleSessionName, o.decision.SessionNameAllowed())
	if err != nil {
		o.rec.Stage, o.rec.Reason = "session_name", "session name refused"
		return nil, r.deny(ctx, o, "Session name refused", err)
	}
	o.rec.SessionNameSource, o.rec.RequestedSessionName = nameSource, auditSessionName(requestData.SessionName)
	if requestData.SessionName != "" && nameSource != "request" {
		logevent.Warn(ctx, o.log, logevent.AuthzSessionNameIgnored, "requested session name ignored", slog.String("sessionNameSource", nameSource))
	}
	if useIdP {
		return r.issueIdP(ctx, o, requestData, sessionName, requestID)
	}
	return r.issueAssumeRole(ctx, o, requestData, sessionName)
}

// issueAssumeRole assumes the role from the warden's own credentials.
func (r *RequestProcessor) issueAssumeRole(ctx context.Context, o *authzOutcome, requestData *RequestData, sessionName string) (*IssuedCredentials, error) {
	cfg, claims, rec, log := o.cfg, o.claims, o.rec, o.log
	requestedRole := requestData.Role

	ceiling := time.Duration(utils.RoleChainingMaxSecs) * time.Second
	if m := o.decision.MaxSessionDuration(); m > 0 && m < ceiling {
		ceiling = m
	}
	duration, err := resolveDuration(requestData.DurationSeconds, ceiling)
	if err != nil {
		rec.Stage, rec.Reason = "duration", "invalid or excessive duration"
		return nil, r.deny(ctx, o, "Duration refused", err)
	}

	sessionPolicy, policyRef, err := r.getSessionPolicy(ctx, cfg, log, claims.Subject, o.decision)
	if err != nil {
		rec.setErrorReason("session_policy", err)
		return nil, r.deny(ctx, o, "Failed to read session policy", err, rec.reasonAttr(cfg.LogClaimValues))
	}

	sessionTagSpec := cfg.EffectiveSessionTags(claims.Issuer, o.decision)
	credentials, err := r.consumer.AssumeRole(ctx, requestedRole, sessionName, sessionPolicy, &duration, claims, sessionTagSpec)
	if errors.Is(err, aws.ErrAccountNotAllowed) {
		rec.Stage, rec.Reason = "account_check", reasonAccountNotAllowed
		return nil, r.deny(ctx, o, "Target account not allowed", ErrAccountNotAllowed)
	}
	if err != nil {
		rec.setErrorReason("assume_role", err)
		// IAM refusal is 403; any other failure is ours (500).
		ret := ErrAssumeRoleFailed
		if errors.Is(err, aws.ErrAssumeRoleDenied) {
			ret = ErrAssumeRoleDenied
		}
		return nil, r.deny(ctx, o, "Failed to assume role", fmt.Errorf("failed to assume role: %w", ret), rec.reasonAttr(cfg.LogClaimValues))
	}

	rec.GrantedRole = requestedRole
	rec.SessionName = sessionName
	rec.DurationSeconds = int(duration)
	rec.SessionTagKeys = sessionTagKeyNames(sessionTagSpec)
	if cfg.LogClaimValues {
		rec.SessionTags = resolvedSessionTags(ctx, claims.Raw, sessionTagSpec)
	}
	rec.SessionPolicyRef = policyRef
	if account, _, aerr := utils.ParseRoleARN(requestedRole); aerr == nil {
		rec.AccountID = account
	}
	if credentials.Expiration != nil {
		rec.Expiry = credentials.Expiration
	}
	rec.ProcessingMS = o.elapsed()

	if err := r.finalizeAllow(ctx, log, cfg, rec); err != nil {
		return nil, err
	}
	return &IssuedCredentials{Credentials: *credentials}, nil
}

// getSessionPolicy returns the session policy and its audit label ("inline", the S3 key, or "").
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

		policyBytes, err := utils.ReadAllCapped(sessionPolicyData, utils.MaxConfigBytes, "session policy")
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

// identityAttrs builds caller-identity log attributes; callers must gate on cfg.LogClaimValues.
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
