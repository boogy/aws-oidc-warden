package handler

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/aws"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/utils"
)

var sourceIDPlaceholder = regexp.MustCompile(`\{(request_id|subject|issuer|claim:[^{}]*)\}`)

// checkDuration rejects a requested duration outside STS bounds; 0 means omitted.
func checkDuration(requested int32) error {
	if requested != 0 && !utils.ValidSTSSessionSecs(requested) {
		return ErrInvalidDuration
	}
	return nil
}

// resolveDuration returns the session duration for a checkDuration-valid request; a non-positive ceiling falls back to the default.
func resolveDuration(requested int32, ceiling time.Duration) (int32, error) {
	ceilingSecs := int32(ceiling / time.Second)
	if ceilingSecs <= 0 {
		ceilingSecs = utils.DefaultSTSSessionSecs
	}
	if requested == 0 {
		return min(int32(utils.DefaultSTSSessionSecs), ceilingSecs), nil
	}
	if requested > ceilingSecs {
		return 0, ErrDurationExceedsCap
	}
	return requested, nil
}

// resolveSessionName applies mapping > request (ignored unless allowed) > global; a used requested name is validated.
func resolveSessionName(fixed, requested, fallback string, allowRequested bool) (name, source string, err error) {
	switch {
	case fixed != "":
		return fixed, "mapping", nil
	case requested != "" && allowRequested:
		if !utils.ValidSTSName(requested) {
			return "", "", ErrInvalidSessionName
		}
		return requested, "request", nil
	}
	return fallback, "default", nil
}

// auditSessionName returns a requested session name as-is when STS-valid, else sanitized and capped.
func auditSessionName(requested string) string {
	if requested == "" || utils.ValidSTSName(requested) {
		return requested
	}
	return utils.FitSTSName(requested)
}

// renderSourceIdentity expands tmpl into an STS-safe SourceIdentity; truncated reports an overflow cut.
func renderSourceIdentity(tmpl, overflow, requestID, issuer, subject string, claims map[string]any) (value string, truncated bool, err error) {
	var b strings.Builder
	last := 0
	for _, m := range sourceIDPlaceholder.FindAllStringSubmatchIndex(tmpl, -1) {
		b.WriteString(utils.SanitizeSTSName(tmpl[last:m[0]]))
		last = m[1]

		var v string
		key := tmpl[m[2]:m[3]]
		switch key {
		case "request_id":
			v = requestID
		case "subject":
			v = subject
		case "issuer":
			u, perr := url.Parse(issuer)
			if perr != nil || u.Host == "" {
				return "", false, ErrIdPSourceIdentityInvalid
			}
			v = u.Host + strings.TrimSuffix(u.Path, "/")
		default:
			raw, ok := claims[strings.TrimPrefix(key, "claim:")]
			if !ok {
				return "", false, ErrIdPSourceIdentityInvalid
			}
			v = utils.FormatClaimValue(raw)
		}
		b.WriteString(utils.SanitizeSTSNameHashed(v))
	}
	b.WriteString(utils.SanitizeSTSName(tmpl[last:]))

	out := b.String()
	if len(out) < 2 {
		return "", false, ErrIdPSourceIdentityInvalid
	}
	if len(out) > utils.MaxSTSNameLen && overflow == config.IdPOverflowReject {
		return "", false, ErrIdPSourceIdentityInvalid
	}
	if len(out) > utils.MaxSTSNameLen {
		return utils.FitSanitizedSTSName(out), true, nil
	}
	return out, false, nil
}

// exchangeError maps an AssumeRoleWithWebIdentity failure to its handler sentinel.
func exchangeError(err error) error {
	switch {
	case errors.Is(err, aws.ErrAccountNotAllowed):
		return ErrAccountNotAllowed
	case errors.Is(err, aws.ErrWebIdentityDenied):
		return ErrIdPExchangeDenied
	case errors.Is(err, aws.ErrWebIdentityUnavailable):
		return ErrIdPExchangeUnavailable
	case errors.Is(err, aws.ErrWebIdentityDurationExceedsRoleMax):
		return ErrDurationExceedsRoleMax
	case errors.Is(err, aws.ErrWebIdentityPackedPolicyTooLarge):
		return ErrIdPTokenTooLarge
	default:
		return ErrAssumeRoleFailed
	}
}
