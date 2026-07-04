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
	"github.com/boogy/aws-oidc-warden/internal/validator"
)

// AuditSink is the durability boundary for the structured audit trail
// (SHARED.md invariant #11): one JSON record per allow/deny decision.
// *s3logger.S3Logger satisfies this via its WriteRecord/BufferRecord methods —
// duck-typed, so this package never imports s3logger and there's no import
// cycle. A nil AuditSink is always safe: recordDecision no-ops the write and
// only emits the standardized log line.
//
// Two write paths, chosen by cfg.AuditRequired (see recordDecision):
//   - WriteRecord: synchronous, batch-bypassing. Used only when audit_required
//     is true, so a failure can fail the request closed before credentials are
//     returned.
//   - BufferRecord: best-effort, appended to the amortized batch buffer
//     (flushed by size/age/cleanup). Used when audit_required is false, so an
//     ordinary decision never blocks on a synchronous S3 PUT.
type AuditSink interface {
	WriteRecord(ctx context.Context, record []byte) error
	BufferRecord(record []byte) error
}

// auditRecord is the structured record for one authorization decision, fed to
// both the standardized slog line (auditLogAttrs) and the durable audit sink
// (json.Marshal). Building it once and redacting it in place before either
// consumer sees it guarantees the log line and the audit trail can never
// disagree about what was suppressed.
//
// kid is deliberately absent: types.Claims carries no post-verification key
// ID, and adding one would mean touching validator internals, which is out of
// scope for this group.
type auditRecord struct {
	RequestID string `json:"requestId"`
	Frontend  string `json:"frontend"`
	JWTMode   string `json:"jwtMode"`
	Decision  string `json:"decision"`        // "allow" | "deny"
	Stage     string `json:"stage,omitempty"` // failing stage; deny only
	// Reason is the deny reason (I5's "denyReason" field, named "reason" here
	// to match the standardized slog attribute set in auditLogAttrs — one name
	// for the same value in both the log line and the audit record). Deny only.
	Reason string `json:"reason,omitempty"`

	Issuer   string   `json:"issuer,omitempty"`
	Provider string   `json:"provider,omitempty"`
	JWTSub   string   `json:"jwtSub,omitempty"`  // raw "sub" claim, pre-canonicalization
	Subject  string   `json:"subject,omitempty"` // canonical identity (types.Claims.Subject)
	Audience []string `json:"audience,omitempty"`

	// MatchedVia records which authorization path allowed the request:
	// "explicit" (repo_role_mappings/role_groups) or "tag-auth" (IAM role tag
	// fallback). Allow decisions only.
	MatchedVia    string `json:"matchedVia,omitempty"`
	RequestedRole string `json:"requestedRole,omitempty"`
	GrantedRole   string `json:"grantedRole,omitempty"` // == RequestedRole once granted; allow only
	AccountID     string `json:"accountId,omitempty"`

	// SessionTagKeys (tag names only) are always safe to log/audit. SessionTags
	// (resolved values) are only populated when LogClaimValues is on, and only
	// for allow decisions where a role was actually granted.
	SessionTagKeys   []string          `json:"sessionTagKeys,omitempty"`
	SessionTags      map[string]string `json:"sessionTags,omitempty"`
	SessionPolicyRef string            `json:"sessionPolicyRef,omitempty"`

	Expiry *time.Time `json:"expiry,omitempty"`

	// ProcessingMS is per-request wall-clock time (I5's per-stage timing, at the
	// granularity available without threading a stage-timer through every branch
	// of ProcessRequest). Emitted on both allow and deny.
	//
	// TODO(v2): optional EMF metrics — emit ProcessingMS/decision/stage as
	// CloudWatch Embedded Metric Format instead of (or alongside) this JSON
	// record, for native CloudWatch Metrics dashboards/alarms without a log
	// insights query. Deferred: no EMF dependency added in this group.
	ProcessingMS int64 `json:"processingMs"`
}

// redact zeroes claim VALUES (never names/decision/reason/IDs) when
// logClaimValues is false, per SHARED.md invariant #11 and I4. Must run
// before the record is logged or marshaled for the audit sink.
func (rec *auditRecord) redact(logClaimValues bool) {
	if logClaimValues {
		return
	}
	rec.JWTSub = ""
	rec.Subject = ""
	rec.Audience = nil
	rec.SessionTags = nil
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

// auditLogAttrs returns the standardized slog attribute set (I1) for one
// decision: requestId, frontend, jwtMode, issuer, provider, jwtSub, subject,
// audience, decision, reason, matchedRole, accountId, processingMs, stage.
// Callers append these to their existing log.Error/log.Info call rather than
// replacing the descriptive message, so the standardized contract is added
// without renaming unrelated logs.
//
// logClaimValues gates the same claim VALUES that auditRecord.redact()
// suppresses for the durable sink (jwtSub, subject, audience) — so when
// log_claim_values=false those values are absent from the emitted log stream
// too, not just the audit record (SHARED.md invariant #11 / I4: suppress in
// BOTH). Claim NAMES, decision, reason, and non-claim metadata
// (requestId/issuer/provider/role/account/stage) are always emitted.
func auditLogAttrs(rec *auditRecord, logClaimValues bool) []any {
	jwtSub, subject, audience := rec.JWTSub, rec.Subject, rec.Audience
	if !logClaimValues {
		jwtSub, subject, audience = "", "", nil
	}
	return []any{
		slog.String("requestId", rec.RequestID),
		slog.String("frontend", rec.Frontend),
		slog.String("jwtMode", rec.JWTMode),
		slog.String("issuer", rec.Issuer),
		slog.String("provider", rec.Provider),
		slog.String("jwtSub", jwtSub),
		slog.String("subject", subject),
		slog.Any("audience", audience),
		slog.String("decision", rec.Decision),
		slog.String("reason", rec.Reason),
		slog.String("matchedRole", rec.matchedRole()),
		slog.String("accountId", rec.AccountID),
		slog.Int64("processingMs", rec.ProcessingMS),
		slog.String("stage", rec.Stage),
	}
}

// recordDecision is the single terminal point for a decision: it redacts rec
// per cfg.LogClaimValues, emits the ONE standardized decision log line (I1)
// from the redacted record — so the log stream and the durable sink are keyed
// off the identical, already-redacted record and can never disagree about the
// decision or what was suppressed — then sends it to the audit sink as one
// JSON record (never string concatenation — encoding/json escapes control
// characters, so a claim value with embedded newlines/control chars cannot
// break the record structure or inject a fake log line): synchronously via
// WriteRecord when cfg.AuditRequired, otherwise best-effort via BufferRecord
// (batched, see AuditSink).
//
// Callers must set rec.Decision before calling. A nil sink still emits the log
// line (only the durable write is skipped). When cfg.AuditRequired is true, a
// marshal or write failure is returned as an error wrapping
// ErrAuditWriteFailed, and the caller must fail the request closed rather than
// return credentials; when false, the failure is logged and swallowed so the
// decision still proceeds (best-effort).
func (r *RequestProcessor) recordDecision(ctx context.Context, log *slog.Logger, cfg *config.Config, rec *auditRecord) error {
	rec.redact(cfg.LogClaimValues)

	// Standardized decision line (I1). Allow at Info; deny at Warn — a denial
	// is a security-relevant signal (I3) but not an operational error.
	attrs := auditLogAttrs(rec, cfg.LogClaimValues)
	if rec.Decision == "allow" {
		log.Info("authorization decision", attrs...)
	} else {
		log.Warn("authorization decision", attrs...)
	}

	if r.audit == nil {
		return nil
	}

	data, err := json.Marshal(rec)
	if err != nil {
		log.Error("failed to marshal audit record", slog.String("error", err.Error()))
		if cfg.AuditRequired {
			return fmt.Errorf("%w: %w", ErrAuditWriteFailed, err)
		}
		return nil
	}

	if cfg.AuditRequired {
		if werr := r.audit.WriteRecord(ctx, data); werr != nil {
			log.Error("failed to write audit record", slog.String("error", werr.Error()))
			return fmt.Errorf("%w: %w", ErrAuditWriteFailed, werr)
		}
		return nil
	}

	// Best-effort: buffer into the amortized batch; a failure is logged and
	// swallowed so the decision still proceeds.
	if werr := r.audit.BufferRecord(data); werr != nil {
		log.Error("failed to buffer audit record", slog.String("error", werr.Error()))
	}
	return nil
}

// finalizeDeny records a deny decision (redaction + best-effort/durable audit
// write per cfg.AuditRequired) and returns the error the caller should
// propagate: origErr unchanged, unless a required audit write itself failed,
// in which case ErrAuditWriteFailed is folded in alongside it so both are
// visible via errors.Is.
func (r *RequestProcessor) finalizeDeny(ctx context.Context, log *slog.Logger, cfg *config.Config, rec *auditRecord, origErr error) error {
	rec.Decision = "deny"
	if auditErr := r.recordDecision(ctx, log, cfg, rec); auditErr != nil {
		return fmt.Errorf("%w: %w", origErr, auditErr)
	}
	return origErr
}

// finalizeAllow records an allow decision. The audit write happens
// synchronously, before this returns, so cfg.AuditRequired's durability
// guarantee (write-before-credentials) is satisfied by ordinary control flow:
// a required write failure returns (nil, error) — no credentials are ever
// handed back to the caller.
func (r *RequestProcessor) finalizeAllow(ctx context.Context, log *slog.Logger, cfg *config.Config, rec *auditRecord, credentials *ststypes.Credentials) (*ststypes.Credentials, error) {
	rec.Decision = "allow"
	if auditErr := r.recordDecision(ctx, log, cfg, rec); auditErr != nil {
		return nil, auditErr
	}
	return credentials, nil
}

// inputMode classifies which extraction path a request used, for the
// standardized "jwtMode" field. Computed unconditionally (not just under
// debug logging) so it's always available for the audit record.
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

// issuerProvider looks up the configured provider name ("github"/"generic")
// for a verified issuer, for the audit record's Provider field. A linear scan
// over cfg.Issuers is cheap at this N and avoids adding a new exported lookup
// method to internal/config for a single call site.
func issuerProvider(cfg *config.Config, issuer string) string {
	for i := range cfg.Issuers {
		if cfg.Issuers[i].Issuer == issuer {
			return cfg.Issuers[i].Provider
		}
	}
	return ""
}

// claimsAudience returns the verified token's audience claim as a plain
// []string for the audit record (jwt.RegisteredClaims.Audience is a named
// ClaimStrings type under the hood).
func claimsAudience(claims *gtypes.Claims) []string {
	if claims == nil || len(claims.Audience) == 0 {
		return nil
	}
	return []string(claims.Audience)
}

// sessionTagKeyNames returns the sorted STS session tag key names an issuer's
// session_tags spec would populate. Tag key NAMES (never resolved values) are
// always safe to log/audit regardless of LogClaimValues.
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

// resolvedSessionTags computes the actual STS session tag values that would
// be attached to the assumed-role session, for the audit record's
// SessionTags field. Only called when cfg.LogClaimValues is true, and reuses
// aws.BuildSessionTags (the exact function AssumeRole uses) rather than
// duplicating its claim-lookup/validation logic.
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
