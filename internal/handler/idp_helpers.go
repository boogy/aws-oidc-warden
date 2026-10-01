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

const (
	minDurationSecs = 900
	maxDurationSecs = 43200
	defDurationSecs = 3600
)

var (
	sessionNamePattern  = regexp.MustCompile(`^[\w+=,.@-]{2,64}$`)
	sourceIDPlaceholder = regexp.MustCompile(`\{(request_id|subject|issuer|claim:[^{}]*)\}`)
)

// resolveDuration returns the session duration in seconds; a non-positive ceiling falls back to the default.
func resolveDuration(requested int32, ceiling time.Duration) (int32, error) {
	ceilingSecs := int32(ceiling / time.Second)
	if ceilingSecs <= 0 {
		ceilingSecs = defDurationSecs
	}
	if requested == 0 {
		return min(int32(defDurationSecs), ceilingSecs), nil
	}
	if requested < minDurationSecs || requested > maxDurationSecs {
		return 0, ErrInvalidDuration
	}
	if requested > ceilingSecs {
		return 0, ErrDurationExceedsCap
	}
	return requested, nil
}

// resolveSessionName picks the role session name and reports its source: mapping, request or subject/default.
func resolveSessionName(fixed string, allow bool, requested, subject, fallback string) (name, source string, err error) {
	if fixed != "" && requested != "" {
		return "", "", ErrSessionNameNotPermitted
	}
	if fixed != "" {
		return fixed, "mapping", nil
	}
	if requested != "" {
		if !allow {
			return "", "", ErrSessionNameNotPermitted
		}
		if !sessionNamePattern.MatchString(requested) {
			return "", "", ErrInvalidSessionName
		}
		return requested, "request", nil
	}
	if fitted := utils.FitSTSName(subject); len(fitted) >= 2 {
		return fitted, "subject", nil
	}
	return fallback, "default", nil
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
			v = u.Host
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
