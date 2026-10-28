package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/logevent"
	gtypes "github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/boogy/aws-oidc-warden/internal/utils"
	"github.com/boogy/aws-oidc-warden/internal/validator"
)

// AuditSink persists one JSON record per decision; a nil sink is safe.
// WriteRecord is synchronous and can fail the request closed; BufferRecord is best-effort and batched.
type AuditSink interface {
	WriteRecord(ctx context.Context, record []byte) error
	BufferRecord(record []byte) error
}

// auditRecord is one authorization decision, redacted in place before it is logged or written to the sink.
type auditRecord struct {
	RequestID string `json:"requestId"`
	// FrontendRequestID is the join key back to API Gateway/ALB access logs.
	FrontendRequestID string `json:"frontendRequestId,omitempty"`
	Frontend          string `json:"frontend"`
	JWTMode           string `json:"jwtMode"`
	Decision          string `json:"decision"`        // "allow" | "deny"
	Stage             string `json:"stage,omitempty"` // failing stage; deny only
	Action            string `json:"action,omitempty"`

	// SourceIPFrom: "frontend" (AWS-attested) or "x-forwarded-for" (spoofable).
	SourceIP     string `json:"sourceIp,omitempty"`
	SourceIPFrom string `json:"sourceIpFrom,omitempty"`
	Reason       string `json:"reason,omitempty"` // deny only
	// reasonFromError marks Reason as err.Error(), which may quote claim values; set via setErrorReason.
	reasonFromError bool
	// preAuth marks a deny that precedes authentication; it is always batched, never a synchronous S3 write.
	preAuth bool

	Issuer   string   `json:"issuer,omitempty"`
	Provider string   `json:"provider,omitempty"`
	JWTSub   string   `json:"jwtSub,omitempty"`  // raw "sub" claim, pre-canonicalization
	Subject  string   `json:"subject,omitempty"` // canonical identity (types.Claims.Subject)
	Audience []string `json:"audience,omitempty"`

	// MatchedVia: "explicit" (role_mappings/role_groups) or "tag-auth". Allow only.
	MatchedVia    string `json:"matchedVia,omitempty"`
	RequestedRole string `json:"requestedRole,omitempty"`
	GrantedRole   string `json:"grantedRole,omitempty"` // allow only
	AccountID     string `json:"accountId,omitempty"`
	SessionName   string `json:"sessionName,omitempty"` // actual STS session name used; allow only

	TokenID                  string `json:"tokenId,omitempty"`
	IdPSessionCapSeconds     *int   `json:"idpSessionCapSeconds,omitempty"`
	RequestedDurationSeconds int    `json:"requestedDurationSeconds,omitempty"`
	DurationSeconds          int    `json:"durationSeconds,omitempty"`
	SourceIdentity           string `json:"sourceIdentity,omitempty"`
	SourceIdentityTruncated  bool   `json:"sourceIdentityTruncated,omitempty"`
	AccessKeyID              string `json:"accessKeyId,omitempty"`
	SessionNameSource        string `json:"sessionNameSource,omitempty"`
	RequestedSessionName     string `json:"requestedSessionName,omitempty"`

	// SessionTagKeys (names) are always safe to record. SessionTags (values)
	// only when LogClaimValues is on and a role was actually granted.
	SessionTagKeys   []string          `json:"sessionTagKeys,omitempty"`
	SessionTags      map[string]string `json:"sessionTags,omitempty"`
	SessionPolicyRef string            `json:"sessionPolicyRef,omitempty"`

	// Claims: full verified claim set for GitHub issuers, mapped claims
	// otherwise. Populated only when LogClaimValues is on.
	Claims map[string]string `json:"claims,omitempty"`

	Expiry *time.Time `json:"expiry,omitempty"`

	ProcessingMS int64 `json:"processingMs"` // per-request wall-clock time
}

// redact zeroes claim values when logClaimValues is false; must run before the record is logged or marshaled.
func (rec *auditRecord) redact(logClaimValues bool) {
	if logClaimValues {
		return
	}
	rec.JWTSub = ""
	rec.Subject = ""
	rec.Audience = nil
	rec.SessionTags = nil
	rec.Claims = nil
	rec.SourceIdentity = ""
	rec.RequestedSessionName = ""
	rec.Reason = rec.effectiveReason(logClaimValues) // replaced, not cleared
	rec.reasonFromError = false
}

// setErrorReason records an error-derived deny reason; assigning rec.Reason directly escapes the log_claim_values gate.
func (rec *auditRecord) setErrorReason(stage string, err error) {
	rec.Stage = stage
	rec.Reason = err.Error()
	rec.reasonFromError = true
}

// effectiveReason is the reason as emitted: the stage summary when an error-derived reason is suppressed.
func (rec *auditRecord) effectiveReason(logClaimValues bool) string {
	if logClaimValues || !rec.reasonFromError {
		return rec.Reason
	}
	return stageSummary(rec.Stage)
}

// reasonAttr returns the deny reason as the standardized "error" log attr,
// gated identically to the durable record.
func (rec *auditRecord) reasonAttr(logClaimValues bool) slog.Attr {
	return slog.String("error", rec.effectiveReason(logClaimValues))
}

// stageSummary is the claim-free replacement for an error-derived reason: it
// names the stage that failed and nothing about the identity that failed it.
func stageSummary(stage string) string {
	switch stage {
	case "extract":
		return "token validation failed"
	case "account_check":
		return "account allow-list check failed"
	case "session_policy":
		return "session policy read failed"
	case "assume_role":
		return "role assumption failed"
	case "idp_mint":
		return "token minting failed"
	default:
		return "request denied"
	}
}

// matchedRole is the granted role, else the requested role.
func (rec *auditRecord) matchedRole() string {
	if rec.GrantedRole != "" {
		return rec.GrantedRole
	}
	return rec.RequestedRole
}

// auditLogAttrs builds the decision line's attrs; identity fields come from ctxHandler.
func auditLogAttrs(rec *auditRecord, logClaimValues bool) []slog.Attr {
	attrs := []slog.Attr{
		slog.String("frontend", rec.Frontend),
		slog.String("jwtMode", rec.JWTMode),
		slog.String("decision", rec.Decision),
		slog.String("matchedRole", rec.matchedRole()),
		slog.Int64("processingMs", rec.ProcessingMS),
	}
	appendIf := func(key, value string) {
		if value != "" {
			attrs = append(attrs, slog.String(key, value))
		}
	}
	appendIf("issuer", rec.Issuer)
	appendIf("provider", rec.Provider)
	appendIf("accountId", rec.AccountID)
	appendIf("sessionName", rec.SessionName)
	appendIf("stage", rec.Stage)
	appendIf("action", rec.Action)
	appendIf("tokenId", rec.TokenID)
	appendIf("sourceIdentity", rec.SourceIdentity)
	appendIf("sessionNameSource", rec.SessionNameSource)
	appendIf("accessKeyId", rec.AccessKeyID)
	if rec.DurationSeconds > 0 {
		attrs = append(attrs, slog.Int("durationSeconds", rec.DurationSeconds))
	}
	appendIf("reason", rec.effectiveReason(logClaimValues))
	if logClaimValues {
		appendIf("requestedSessionName", rec.RequestedSessionName)
		appendIf("jwtSub", rec.JWTSub)
		appendIf("subject", rec.Subject)
		if len(rec.Audience) > 0 {
			attrs = append(attrs, slog.Any("audience", rec.Audience))
		}
		if len(rec.Claims) > 0 {
			attrs = append(attrs, slog.Any("claims", rec.Claims))
		}
	}
	return attrs
}

// subjectAttr is the subject log attribute, omitted when cfg.LogClaimValues is false; every subject log site must use it.
func subjectAttr(cfg *config.Config, subject string) slog.Attr {
	if !cfg.LogClaimValues || subject == "" {
		return slog.Attr{}
	}
	return slog.String("subject", subject)
}

// recordDecision logs the redacted rec and sends it to the sink; a synchronous-path failure wraps ErrAuditWriteFailed and must fail closed.
func (r *RequestProcessor) recordDecision(ctx context.Context, log *slog.Logger, cfg *config.Config, rec *auditRecord) error {
	rec.redact(cfg.LogClaimValues)
	// Unauthenticated floods must not hammer the shared S3 prefix and fail real allows closed.
	enforced := cfg.AuditEnforced() && !rec.preAuth

	attrs := auditLogAttrs(rec, cfg.LogClaimValues)
	decisionEvent := logevent.AuthzDecision.WithOutcome(rec.Decision)
	if rec.Decision == "allow" {
		logevent.Info(ctx, log, decisionEvent, "authorization decision", attrs...)
	} else {
		logevent.Warn(ctx, log, decisionEvent, "authorization decision", attrs...)
	}

	if r.audit == nil {
		// config.Validate() can't catch a missing sink; enforce here instead.
		if enforced {
			err := fmt.Errorf("%w: audit_required is set but no audit sink is configured", ErrAuditWriteFailed)
			logevent.Error(ctx, log, logevent.AuditWriteFailure, "failed to write audit record", slog.String("error", err.Error()))
			return err
		}
		return nil
	}

	data, err := json.Marshal(rec)
	if err != nil {
		logevent.Error(ctx, log, logevent.AuditMarshalFailure, "failed to marshal audit record", slog.String("error", err.Error()))
		if enforced {
			return fmt.Errorf("%w: %w", ErrAuditWriteFailed, err)
		}
		return nil
	}

	if enforced {
		if werr := r.audit.WriteRecord(ctx, data); werr != nil {
			logevent.Error(ctx, log, logevent.AuditWriteFailure, "failed to write audit record", slog.String("error", werr.Error()))
			return fmt.Errorf("%w: %w", ErrAuditWriteFailed, werr)
		}
		return nil
	}

	if werr := r.audit.BufferRecord(data); werr != nil {
		logevent.Error(ctx, log, logevent.AuditBufferFailure, "failed to buffer audit record", slog.String("error", werr.Error()))
	}
	return nil
}

// finalizeDeny records a deny decision and returns origErr, folding in
// ErrAuditWriteFailed (visible via errors.Is) if the audit write itself failed.
func (r *RequestProcessor) finalizeDeny(ctx context.Context, log *slog.Logger, cfg *config.Config, rec *auditRecord, origErr error) error {
	rec.Decision = "deny"
	if auditErr := r.recordDecision(ctx, log, cfg, rec); auditErr != nil {
		return fmt.Errorf("%w: %w", origErr, auditErr)
	}
	return origErr
}

// finalizeAllow records an allow decision synchronously: credentials are never handed back without a durable record.
func (r *RequestProcessor) finalizeAllow(ctx context.Context, log *slog.Logger, cfg *config.Config, rec *auditRecord) error {
	rec.Decision = "allow"
	return r.recordDecision(ctx, log, cfg, rec)
}

// inputMode classifies which extraction path a request used, for the "jwtMode" field.
func inputMode(input validator.ExtractionInput) string {
	switch {
	case input.Token != "":
		return "self"
	case len(input.AuthorizerClaims) > 0:
		return "apigw"
	case input.ALBOIDCData != "":
		return "alb"
	default:
		return "unknown"
	}
}

// setIdentity records the verified caller on every post-extract record; redact() honours log_claim_values.
func (rec *auditRecord) setIdentity(cfg *config.Config, claims *gtypes.Claims) {
	rec.Issuer = claims.Issuer
	rec.Provider = issuerProvider(cfg, claims.Issuer)
	rec.JWTSub = claims.Sub
	rec.Subject = claims.Subject
	rec.Audience = claimsAudience(claims)
	if cfg.LogClaimValues {
		rec.Claims = auditClaims(cfg, claims.Issuer, claims.Raw)
	}
}

// setGrant records the issued session shared by the AssumeRole and IdP paths.
func (rec *auditRecord) setGrant(cfg *config.Config, role, sessionName string, durationSeconds int, policyRef string, tags []ststypes.Tag, expiry *time.Time) {
	rec.GrantedRole = role
	rec.SessionName = sessionName
	rec.DurationSeconds = durationSeconds
	rec.SessionPolicyRef = policyRef
	rec.SessionTagKeys = sessionTagKeyNames(tags)
	if cfg.LogClaimValues {
		rec.SessionTags = sessionTagValues(tags)
	}
	if account, _, err := utils.ParseRoleARN(role); err == nil {
		rec.AccountID = account
	}
	rec.Expiry = expiry
}

// issuerProvider looks up the configured provider name ("github"/"generic") for a verified issuer.
func issuerProvider(cfg *config.Config, issuer string) string {
	for i := range cfg.Issuers {
		if cfg.Issuers[i].Issuer == issuer {
			return cfg.Issuers[i].Provider
		}
	}
	return ""
}

// claimsAudience returns the audience claim as a plain []string for the audit record.
func claimsAudience(claims *gtypes.Claims) []string {
	if claims == nil || len(claims.Audience) == 0 {
		return nil
	}
	return []string(claims.Audience)
}

// sessionTagKeyNames returns the names of the attached session tags, in order.
func sessionTagKeyNames(tags []ststypes.Tag) []string {
	if len(tags) == 0 {
		return nil
	}
	names := make([]string, 0, len(tags))
	for _, t := range tags {
		if t.Key != nil {
			names = append(names, *t.Key)
		}
	}
	return names
}

// claimAliases renames audit claims; skipped when the token already carries the alias target.
var claimAliases = map[string]string{
	"repository":    "repo",
	"repository_id": "repo_id",
}

// auditClaims is every verified claim for provider "github", else only cfg.AuditableClaims so PII is never copied.
// Callers must gate on cfg.LogClaimValues.
func auditClaims(cfg *config.Config, issuer string, rawClaims map[string]any) map[string]string {
	if len(rawClaims) == 0 {
		return nil
	}

	include := func(string) bool { return true } // github: everything
	if issuerProvider(cfg, issuer) != "github" {
		include = func(name string) bool { return cfg.AuditableClaims(issuer, name) }
	}

	out := make(map[string]string, len(rawClaims))
	for name, raw := range rawClaims {
		if raw == nil || !include(name) {
			continue
		}
		value := utils.FormatClaimValue(raw)
		if value == "" {
			continue
		}
		key := name
		// Rename only if the alias target won't itself be emitted, else both
		// claims collide on one key.
		if alias, ok := claimAliases[name]; ok && !claimEmitted(rawClaims, alias, include) {
			key = alias
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// claimEmitted reports whether name would itself be recorded by auditClaims,
// applying the same drop rules as the loop above. Collision test for claimAliases.
func claimEmitted(rawClaims map[string]any, name string, include func(string) bool) bool {
	raw, ok := rawClaims[name]
	if !ok || raw == nil || !include(name) {
		return false
	}
	return utils.FormatClaimValue(raw) != ""
}

// sessionTagValues maps the attached session tags to their values; callers must gate on cfg.LogClaimValues.
func sessionTagValues(tags []ststypes.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	out := make(map[string]string, len(tags))
	for _, t := range tags {
		if t.Key != nil && t.Value != nil {
			out[*t.Key] = *t.Value
		}
	}
	return out
}
