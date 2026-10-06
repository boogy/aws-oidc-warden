package handler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/boogy/aws-oidc-warden/internal/aws"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/idp"
	"github.com/boogy/aws-oidc-warden/internal/logevent"
	"github.com/boogy/aws-oidc-warden/internal/utils"
)

const msgMinted = "Token validation successful and IdP credentials issued"

// IssuedCredentials is the success payload; the IdP fields are set only for a minted session and the token is never part of it.
type IssuedCredentials struct {
	ststypes.Credentials
	Issuer          string `json:"issuer,omitempty"`
	RoleARN         string `json:"roleArn,omitempty"`
	SessionName     string `json:"sessionName,omitempty"`
	SourceIdentity  string `json:"sourceIdentity,omitempty"`
	DurationSeconds int    `json:"durationSeconds,omitempty"`
	TokenID         string `json:"tokenId,omitempty"`
}

func (c *IssuedCredentials) message() string {
	if c.TokenID != "" {
		return msgMinted
	}
	return msgAssumed
}

func (r *RequestProcessor) idpEnabled(cfg *config.Config) bool {
	return r.idp != nil && cfg.IdP != nil && cfg.IdP.Enabled
}

// selectIdP routes an IdP-eligible role to the IdP when enabled, else allows only sessions within the AssumeRole cap; refusals carry their audit reason.
func (r *RequestProcessor) selectIdP(cfg *config.Config, d config.Decision, requested int32) (useIdP bool, reason string, err error) {
	eligible := d.IDPTokenAllowed()
	if eligible && r.idpEnabled(cfg) {
		return true, "", nil
	}
	if requested <= utils.RoleChainingMaxSecs {
		return false, "", nil
	}
	switch {
	case r.idp == nil || cfg.IdP == nil:
		return false, "over 1h without idp", ErrDurationExceedsCap
	case !eligible:
		return false, "over 1h but role not idp-enabled", ErrIdPNotPermitted
	default:
		return false, "over 1h but idp disabled", ErrIdPUnavailable
	}
}

// issueIdP mints an IdP token in-process for an authorized request and exchanges it for credentials.
func (r *RequestProcessor) issueIdP(ctx context.Context, o *authzOutcome, requestData *RequestData, sessionName, requestID string) (*IssuedCredentials, error) {
	cfg, claims, rec, log := o.cfg, o.claims, o.rec, o.log
	role := requestData.Role

	refuse := func(stage, reason, msg string, ret error) (*IssuedCredentials, error) {
		rec.Stage, rec.Reason = stage, reason
		return nil, r.deny(ctx, o, msg, ret)
	}

	ceiling := o.decision.MaxSessionDuration()
	capSecs := int(ceiling / time.Second)
	rec.IdPSessionCapSeconds = &capSecs
	duration, err := resolveDuration(requestData.DurationSeconds, ceiling)
	if err != nil {
		return refuse("duration", "invalid or excessive duration", "Duration refused", err)
	}

	var sourceIdentity string
	var truncated bool
	if frozen := r.idp.Config(); frozen.IncludeSourceIdentityClaim() {
		sourceIdentity, truncated, err = renderSourceIdentity(frozen.SourceIdentity, frozen.SourceIdentityOverflow, requestID, claims.Issuer, claims.Subject, claims.Raw)
		if err != nil {
			return refuse("idp_mint", "source identity could not be derived", "Source identity could not be derived", err)
		}
	}

	sessionPolicy, policyRef, err := r.getSessionPolicy(ctx, cfg, log, claims.Subject, o.decision)
	if err != nil {
		rec.setErrorReason("session_policy", err)
		return nil, r.deny(ctx, o, "Failed to read session policy", err, rec.reasonAttr(cfg.LogClaimValues))
	}

	tags := aws.BuildSessionTags(ctx, claims.Raw, cfg.EffectiveSessionTags(claims.Issuer, o.decision))
	req := idp.MintRequest{
		RoleARN:        role,
		SourceIssuer:   claims.Issuer,
		SourceSubject:  claims.Subject,
		RequestID:      requestID,
		SourceIdentity: sourceIdentity,
		Tags:           tags,
	}
	if cfg.TransitiveSessionTags() {
		for _, t := range req.Tags {
			if t.Key != nil {
				req.TransitiveKeys = append(req.TransitiveKeys, *t.Key)
			}
		}
	}

	tok, err := r.idp.Mint(ctx, req)
	if err != nil {
		var ret error
		switch {
		case errors.Is(err, idp.ErrInvalidSubject):
			logevent.Warn(ctx, log, logevent.IdPSubjectInvalid, "IdP subject could not be rendered",
				slog.String("roleArn", role), slog.String("error", err.Error()))
			ret = ErrIdPSubjectInvalid
		case errors.Is(err, idp.ErrTokenTooLarge):
			logevent.Error(ctx, log, logevent.IdPTokenTooLarge, "IdP token exceeds the STS size limit",
				slog.String("roleArn", role), slog.String("error", err.Error()))
			ret = ErrIdPTokenTooLarge
		case errors.Is(err, idp.ErrInvalidSourceIdentity):
			logevent.Warn(ctx, log, logevent.IdPSourceIdentityInvalid, "IdP source identity rejected",
				slog.String("roleArn", role), slog.String("error", err.Error()))
			ret = ErrIdPSourceIdentityInvalid
		case errors.Is(err, idp.ErrUnavailable):
			logevent.Warn(ctx, log, logevent.IdPUnavailable, "IdP signing keys unavailable", slog.String("error", err.Error()))
			ret = ErrIdPUnavailable
		default:
			logevent.Error(ctx, log, logevent.IdPSignFailure, "IdP token signing failed",
				slog.String("roleArn", role), slog.String("error", err.Error()))
			ret = ErrIdPUnavailable
		}
		rec.Stage, rec.Reason = "idp_mint", "token minting failed"
		return nil, r.deny(ctx, o, "Token minting failed", fmt.Errorf("%w: %w", ret, err))
	}

	logevent.Debug(ctx, log, logevent.IdPTokenMinted, "IdP token minted",
		slog.String("tokenId", tok.ID),
		slog.String("roleArn", role),
		slog.String("kid", tok.KeyID),
		slog.Time("expiresAt", tok.ExpiresAt))

	creds, err := r.consumer.AssumeRoleWithWebIdentity(ctx, role, sessionName, tok.Value, sessionPolicy, duration)
	rec.TokenID = tok.ID
	if errors.Is(err, aws.ErrAccountNotAllowed) {
		return refuse("account_check", reasonAccountNotAllowed, "Target account not allowed", ErrAccountNotAllowed)
	}
	if err != nil {
		code := aws.STSErrorCode(err)
		rec.setErrorReason("idp_exchange", errors.New("sts error: "+code))
		logevent.Warn(ctx, log, logevent.IdPExchangeFailure, "web identity exchange failed",
			slog.String("roleArn", role), slog.String("stsErrorCode", code))
		return nil, r.deny(ctx, o, "Web identity exchange failed", fmt.Errorf("%w: sts error %s", exchangeError(err), code), rec.reasonAttr(cfg.LogClaimValues))
	}
	if creds == nil || creds.AccessKeyId == nil || *creds.AccessKeyId == "" {
		rec.Stage, rec.Reason = "idp_exchange", "no credentials returned"
		return nil, r.deny(ctx, o, "Web identity exchange returned no credentials", ErrAssumeRoleFailed)
	}

	rec.GrantedRole = role
	rec.AccessKeyID = *creds.AccessKeyId
	rec.SessionName = sessionName
	rec.SourceIdentity = sourceIdentity
	rec.SourceIdentityTruncated = truncated
	rec.DurationSeconds = int(duration)
	rec.SessionPolicyRef = policyRef
	rec.SessionTagKeys = sessionTagKeyNames(tags)
	if cfg.LogClaimValues {
		rec.SessionTags = sessionTagValues(tags)
	}
	if account, _, aerr := utils.ParseRoleARN(role); aerr == nil {
		rec.AccountID = account
	}
	rec.Expiry = creds.Expiration
	rec.ProcessingMS = o.elapsed()

	if err := r.finalizeAllow(ctx, log, cfg, rec); err != nil {
		return nil, err
	}

	attrs := []slog.Attr{
		slog.String("tokenId", tok.ID),
		slog.String("accessKeyId", *creds.AccessKeyId),
		slog.Int("durationSeconds", int(duration)),
		slog.String("sessionName", sessionName),
	}
	if cfg.LogClaimValues {
		attrs = append(attrs, slog.String("sourceIdentity", sourceIdentity))
	}
	logevent.Info(ctx, log, logevent.IdPCredentialsSuccess, msgMinted, attrs...)

	return &IssuedCredentials{
		Credentials:     *creds,
		Issuer:          r.idp.Config().Issuer,
		RoleARN:         role,
		SessionName:     sessionName,
		SourceIdentity:  sourceIdentity,
		DurationSeconds: int(duration),
		TokenID:         tok.ID,
	}, nil
}
