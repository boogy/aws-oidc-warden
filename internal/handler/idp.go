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
	"github.com/boogy/aws-oidc-warden/internal/validator"
)

const msgMinted = "Token validation successful and IdP credentials issued"

// IdPCredentials is the success payload of the IdP endpoint; the token is never part of it.
type IdPCredentials struct {
	ststypes.Credentials
	Issuer          string `json:"issuer"`
	RoleARN         string `json:"roleArn"`
	SessionName     string `json:"sessionName"`
	SourceIdentity  string `json:"sourceIdentity"`
	DurationSeconds int    `json:"durationSeconds"`
	TokenID         string `json:"tokenId"`
}

func (r *RequestProcessor) idpEnabled(cfg *config.Config) bool {
	return r.idp != nil && cfg.IdP != nil && cfg.IdP.Enabled
}

// ProcessMint authorizes the request, mints an IdP token in-process and exchanges it for credentials.
func (r *RequestProcessor) ProcessMint(ctx context.Context, requestData *RequestData, input validator.ExtractionInput, requestID string, log *slog.Logger) (*IdPCredentials, error) {
	o, err := r.authorizeRequest(ctx, requestData, input, requestID, log, actionMintToken)
	if err != nil {
		return nil, err
	}
	r.warnFrozenDrift(ctx, o.log, o.cfg)
	cfg, claims, rec, log := o.cfg, o.claims, o.rec, o.log
	role := requestData.Role

	refuse := func(stage, reason, msg string, ret error) (*IdPCredentials, error) {
		rec.Stage, rec.Reason = stage, reason
		return nil, r.deny(ctx, o, msg, ret)
	}

	if !r.idpEnabled(cfg) {
		return refuse("idp", "idp disabled", "IdP is disabled", ErrIdPUnavailable)
	}
	if !o.decision.IDPTokenAllowed() {
		return refuse("idp", "mapping has not opted into idp_token", "Mapping has not opted into IdP tokens", ErrIdPNotPermitted)
	}
	if !cfg.IdPRoleAllowed(role) {
		return refuse("idp", "role not in idp.allowed_roles", "Role is not in idp.allowed_roles", ErrIdPNotPermitted)
	}

	ceiling := o.decision.IdPMaxSessionDuration()
	capSecs := int(ceiling / time.Second)
	rec.IdPSessionCapSeconds = &capSecs
	rec.RequestedDurationSeconds = int(requestData.DurationSeconds)
	duration, err := resolveDuration(requestData.DurationSeconds, ceiling)
	if err != nil {
		return refuse("idp", "invalid or excessive duration", "Duration refused", err)
	}

	sessionName, nameSource, err := resolveSessionName(o.decision.RoleSessionName(), o.decision.AllowSessionName(), requestData.SessionName, claims.Subject, cfg.RoleSessionName)
	if err != nil {
		return refuse("idp", "session name refused", "Session name refused", err)
	}
	rec.sessionNameDerived = nameSource == "subject"

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

	spec := cfg.EffectiveSessionTags(claims.Issuer, o.decision)
	req := idp.MintRequest{
		RoleARN:        role,
		SourceIssuer:   claims.Issuer,
		SourceSubject:  claims.Subject,
		RequestID:      requestID,
		SourceIdentity: sourceIdentity,
		Tags:           aws.BuildSessionTags(ctx, claims.Raw, spec),
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
			ret = ErrIdPNotPermitted
		case errors.Is(err, idp.ErrTokenTooLarge):
			logevent.Error(ctx, log, logevent.IdPTokenTooLarge, "IdP token exceeds the STS size limit",
				slog.String("roleArn", role), slog.String("error", err.Error()))
			ret = ErrIdPTokenTooLarge
		case errors.Is(err, idp.ErrInvalidSourceIdentity):
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
	rec.SessionNameSource = nameSource
	rec.SourceIdentity = sourceIdentity
	rec.SourceIdentityTruncated = truncated
	rec.DurationSeconds = int(duration)
	rec.SessionPolicyRef = policyRef
	rec.SessionTagKeys = sessionTagKeyNames(spec)
	if cfg.LogClaimValues {
		rec.SessionTags = resolvedSessionTags(ctx, claims.Raw, spec)
	}
	if account, _, aerr := aws.ParseRoleARN(role); aerr == nil {
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
	}
	if cfg.LogClaimValues {
		attrs = append(attrs, slog.String("sessionName", sessionName), slog.String("sourceIdentity", sourceIdentity))
	}
	logevent.Info(ctx, log, logevent.IdPCredentialsSuccess, msgMinted, attrs...)

	return &IdPCredentials{
		Credentials:     *creds,
		Issuer:          r.idp.Config().Issuer,
		RoleARN:         role,
		SessionName:     sessionName,
		SourceIdentity:  sourceIdentity,
		DurationSeconds: int(duration),
		TokenID:         tok.ID,
	}, nil
}
