package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"time"

	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/boogy/aws-oidc-warden/internal/aws"
	"github.com/boogy/aws-oidc-warden/internal/config"
	gtypes "github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/boogy/aws-oidc-warden/internal/utils"
	"github.com/boogy/aws-oidc-warden/internal/validator"
)

// AuditSink is the durability boundary for the structured audit trail: one
// JSON record per allow/deny decision. Duck-typed (satisfied by
// *s3logger.S3Logger) to avoid an import cycle. A nil sink is safe:
// recordDecision no-ops the write and still emits the log line.
// WriteRecord is synchronous (used when cfg.AuditEnforced(), so a failure can
// fail the request closed); BufferRecord is best-effort, batched.
type AuditSink interface {
	WriteRecord(ctx context.Context, record []byte) error
	BufferRecord(record []byte) error
}

// auditRecord is the structured record for one authorization decision, fed to
// both the standardized slog line (auditLogAttrs) and the durable audit sink
// (json.Marshal). Built once and redacted in place before either consumer
// sees it, so the two can never disagree about what was suppressed.
type auditRecord struct {
	RequestID string `json:"requestId"`
	// FrontendRequestID is the join key back to API Gateway/ALB access logs.
	FrontendRequestID string `json:"frontendRequestId,omitempty"`
	Frontend          string `json:"frontend"`
	JWTMode           string `json:"jwtMode"`
	Decision          string `json:"decision"`        // "allow" | "deny"
	Stage             string `json:"stage,omitempty"` // failing stage; deny only

	// SourceIPFrom: "frontend" (AWS-attested) or "x-forwarded-for" (spoofable).
	SourceIP     string `json:"sourceIp,omitempty"`
	SourceIPFrom string `json:"sourceIpFrom,omitempty"`
	Reason       string `json:"reason,omitempty"` // deny only
	// reasonFromError: Reason came from err.Error(), which may quote claim
	// values, so it must follow the log_claim_values gate. Unexported so the
	// JSON shape is stable regardless of the gate. Set via setErrorReason.
	reasonFromError bool

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

// redact zeroes claim VALUES (never names/decision/reason/IDs) when
// logClaimValues is false. Must run before the record is logged or marshaled
// for the audit sink.
func (rec *auditRecord) redact(logClaimValues bool) {
	if logClaimValues {
		return
	}
	rec.JWTSub = ""
	rec.Subject = ""
	rec.Audience = nil
	rec.SessionTags = nil
	rec.Claims = nil
	rec.Reason = rec.effectiveReason(logClaimValues) // replaced, not cleared
	rec.reasonFromError = false
}

// setErrorReason records a deny reason from an error. Every stage reporting
// err.Error() as the reason must use this, not assign rec.Reason directly,
// or the error text escapes the log_claim_values gate.
func (rec *auditRecord) setErrorReason(stage string, err error) {
	rec.Stage = stage
	rec.Reason = err.Error()
	rec.reasonFromError = true
}

// effectiveReason is the reason as it may be emitted: raw text unless it was
// error-derived and claim values are suppressed, in which case the stage
// summary. Shared by the log line and the durable record.
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
	default:
		return "request denied"
	}
}

// matchedRole is the role the decision pertains to, for the standardized
// "matchedRole" log field: the granted role once one was assumed, otherwise
// the requested role (deny paths never grant one).
func (rec *auditRecord) matchedRole() string {
	if rec.GrantedRole != "" {
		return rec.GrantedRole
	}
	return rec.RequestedRole
}

// auditLogAttrs returns the standardized slog attribute set for one decision.
// requestId/frontendRequestId/sourceIp/sourceIpFrom are deliberately excluded:
// adapters already bind them via slog.With, and duplicating here would emit
// duplicate keys in the same log line (the durable record still has them).
// logClaimValues gates jwtSub/subject/audience/claims identically to
// auditRecord.redact(), so a suppressed value is absent from the log stream too.
func auditLogAttrs(rec *auditRecord, logClaimValues bool) []any {
	attrs := []any{
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
	appendIf("reason", rec.effectiveReason(logClaimValues))
	if logClaimValues {
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

// subjectAttr returns the canonical subject as a log attribute, omitted when
// cfg.LogClaimValues is false or subject is empty. Log sites outside the
// audit record must use this rather than logging subject directly, so the
// gate holds across the whole log stream.
func subjectAttr(cfg *config.Config, subject string) slog.Attr {
	if !cfg.LogClaimValues || subject == "" {
		return slog.Attr{}
	}
	return slog.String("subject", subject)
}

// recordDecision redacts rec per cfg.LogClaimValues, emits the standardized
// decision log line from the redacted record, then sends it to the audit
// sink as one JSON record: synchronously via WriteRecord when
// cfg.AuditEnforced(), otherwise best-effort via BufferRecord.
//
// Callers must set rec.Decision before calling. When cfg.AuditEnforced() is
// true, a missing sink, marshal failure, or write failure all return an
// error wrapping ErrAuditWriteFailed and the caller must fail closed; when
// false, failures are logged and swallowed so the decision still proceeds.
func (r *RequestProcessor) recordDecision(ctx context.Context, log *slog.Logger, cfg *config.Config, rec *auditRecord) error {
	rec.redact(cfg.LogClaimValues)

	attrs := auditLogAttrs(rec, cfg.LogClaimValues)
	if rec.Decision == "allow" {
		log.Info("authorization decision", attrs...)
	} else {
		log.Warn("authorization decision", attrs...)
	}

	if r.audit == nil {
		// config.Validate() can't catch a missing sink; enforce here instead.
		if cfg.AuditEnforced() {
			return fmt.Errorf("%w: audit_required is set but no audit sink is configured", ErrAuditWriteFailed)
		}
		return nil
	}

	data, err := json.Marshal(rec)
	if err != nil {
		log.Error("failed to marshal audit record", slog.String("error", err.Error()))
		if cfg.AuditEnforced() {
			return fmt.Errorf("%w: %w", ErrAuditWriteFailed, err)
		}
		return nil
	}

	if cfg.AuditEnforced() {
		if werr := r.audit.WriteRecord(ctx, data); werr != nil {
			log.Error("failed to write audit record", slog.String("error", werr.Error()))
			return fmt.Errorf("%w: %w", ErrAuditWriteFailed, werr)
		}
		return nil
	}

	if werr := r.audit.BufferRecord(data); werr != nil {
		log.Error("failed to buffer audit record", slog.String("error", werr.Error()))
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

// finalizeAllow records an allow decision. The write happens synchronously
// before this returns, so a required write failure yields (nil, error) —
// credentials are never handed back without a durable record.
func (r *RequestProcessor) finalizeAllow(ctx context.Context, log *slog.Logger, cfg *config.Config, rec *auditRecord, credentials *ststypes.Credentials) (*ststypes.Credentials, error) {
	rec.Decision = "allow"
	if auditErr := r.recordDecision(ctx, log, cfg, rec); auditErr != nil {
		return nil, auditErr
	}
	return credentials, nil
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

// sessionTagKeyNames returns the sorted tag key names an issuer's session_tags
// spec would populate. Names are always safe to log regardless of LogClaimValues.
func sessionTagKeyNames(tagSpec map[string]string) []string {
	if len(tagSpec) == 0 {
		return nil
	}
	keys := make([]string, 0, len(tagSpec))
	for k := range tagSpec {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// claimAliases renames claims on their way into the audit record for a
// stable vocabulary (GitHub's repository/repository_id -> repo/repo_id).
// Skipped when the token already carries a claim under the alias target
// (see auditClaims), to avoid one overwriting the other unpredictably.
var claimAliases = map[string]string{
	"repository":    "repo",
	"repository_id": "repo_id",
}

// auditClaims resolves the claims recorded for a decision: the full verified
// claim set for provider "github" (non-secret workflow metadata), but for
// every other provider only claims the issuer's own config references
// (cfg.AuditableClaims) — an arbitrary OIDC issuer's tokens may carry emails
// or group memberships this service must not copy into an audit object.
// Conditions are included so the record can explain what decided it. Values
// are formatted identically to BuildSessionTags. Callers must gate on
// cfg.LogClaimValues before populating.
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

// resolvedSessionTags computes the STS session tag values for the audit
// record's SessionTags field, reusing aws.BuildSessionTags (the function
// AssumeRole itself uses). Only called when cfg.LogClaimValues is true.
func resolvedSessionTags(rawClaims map[string]any, tagSpec map[string]string) map[string]string {
	tags := aws.BuildSessionTags(rawClaims, tagSpec)
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
