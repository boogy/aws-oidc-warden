package handler

import (
	"cmp"
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
	case cfg.IdP == nil:
		return false, "over 1h without idp", ErrDurationExceedsCap
	case !eligible:
		return false, "over 1h but role not idp-enabled", ErrIdPNotPermitted
	case r.idp == nil:
		return false, "over 1h but idp added after startup", ErrIdPUnavailable
	default:
		return false, "over 1h but idp disabled", ErrIdPUnavailable
	}
}

// issueIdP mints an IdP token in-process for an authorized request and exchanges it for credentials.
func (r *RequestProcessor) issueIdP(ctx context.Context, o *authzOutcome, requestData *RequestData, sessionName, requestID string) (*IssuedCredentials, error) {
	cfg, claims, rec, log := o.cfg, o.claims, o.rec, o.log
	role := requestData.Role

	ceiling := o.decision.MaxSessionDuration()
	capSecs := int(ceiling / time.Second)
	rec.IdPSessionCapSeconds = &capSecs
	duration, err := resolveDuration(requestData.DurationSeconds, ceiling)
	if err != nil {
		return nil, r.refuse(ctx, o, "duration", "invalid or excessive duration", "Duration refused", err)
	}

	var sourceIdentity string
	var truncated bool
	if r.sourceIdentity != nil {
		sourceIdentity, truncated, err = r.sourceIdentity.render(requestID, claims.Issuer, claims.Subject, claims.Raw)
		if err != nil {
			return nil, r.refuse(ctx, o, "idp_mint", "source identity could not be derived", "Source identity could not be derived", err)
		}
	}

	sessionPolicy, policyRef, tags, err := r.grantScope(ctx, o)
	if err != nil {
		return nil, err
	}
	req := idp.MintRequest{
		RoleARN:        role,
		SourceIssuer:   claims.Issuer,
		SourceSubject:  claims.Subject,
		RequestID:      requestID,
		SourceIdentity: sourceIdentity,
		Tags:           tags,
	}
	if cfg.TransitiveSessionTags() {
		req.TransitiveKeys = aws.TransitiveKeys(req.Tags)
	}

	tok, err := r.idp.Mint(ctx, req)
	if err != nil {
		var ret error
		reason := ""
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
			ret, reason = ErrIdPUnavailable, "idp token signing failed"
		}
		rec.Stage, rec.Reason = "idp_mint", cmp.Or(reason, ret.Error())
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
		return nil, r.refuse(ctx, o, "account_check", reasonAccountNotAllowed, "Target account not allowed", ErrAccountNotAllowed)
	}
	if err != nil {
		code := aws.STSErrorCode(err)
		reason := "sts error: " + code
		attrs := []slog.Attr{slog.String("roleArn", role), slog.String("stsErrorCode", code)}
		if code == "" {
			kind := exchangeFailureKind(err)
			reason = "exchange failed: " + kind
			attrs = append(attrs, slog.String("failureKind", kind))
		}
		rec.Stage, rec.Reason = "idp_exchange", reason
		logevent.Warn(ctx, log, logevent.IdPExchangeFailure, "web identity exchange failed", attrs...)
		return nil, r.deny(ctx, o, "Web identity exchange failed", fmt.Errorf("%w: %s", exchangeError(err), reason), rec.reasonAttr(cfg.LogClaimValues))
	}

	rec.setGrant(cfg, role, sessionName, int(duration), policyRef, tags, creds.Expiration)
	rec.AccessKeyID = *creds.AccessKeyId
	rec.SourceIdentity = sourceIdentity
	rec.SourceIdentityTruncated = truncated
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
		Issuer:          r.idpIssuer,
		RoleARN:         role,
		SessionName:     sessionName,
		SourceIdentity:  sourceIdentity,
		DurationSeconds: int(duration),
		TokenID:         tok.ID,
	}, nil
}
