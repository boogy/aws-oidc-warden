package handler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"regexp"
	"slices"
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

// sourceIdentityTemplate is a source_identity template split once at cold start.
type sourceIdentityTemplate struct {
	lits     []string // STS-sanitized literals; len(keys)+1
	keys     []string
	overflow string
}

func parseSourceIdentity(tmpl, overflow string) *sourceIdentityTemplate {
	t := &sourceIdentityTemplate{overflow: overflow}
	last := 0
	for _, m := range sourceIDPlaceholder.FindAllStringSubmatchIndex(tmpl, -1) {
		t.lits = append(t.lits, utils.SanitizeSTSName(tmpl[last:m[0]]))
		t.keys = append(t.keys, tmpl[m[2]:m[3]])
		last = m[1]
	}
	t.lits = append(t.lits, utils.SanitizeSTSName(tmpl[last:]))
	return t
}

// render expands the template into an STS-safe SourceIdentity; truncated reports an overflow cut.
func (t *sourceIdentityTemplate) render(requestID, issuer, subject string, claims map[string]any) (value string, truncated bool, err error) {
	var b strings.Builder
	raw := make([]string, 0, len(t.keys))
	altered := false
	for i, key := range t.keys {
		b.WriteString(t.lits[i])

		var v string
		switch key {
		case "request_id":
			v = requestID
		case "subject":
			v = subject
		case "issuer":
			var ok bool
			if v, ok = config.SourceIdentityIssuer(issuer); !ok {
				return "", false, ErrIdPSourceIdentityInvalid
			}
		default:
			cv, ok := claims[strings.TrimPrefix(key, "claim:")]
			if !ok || isEmptyClaim(cv) {
				return "", false, ErrIdPSourceIdentityInvalid
			}
			if v = utils.FormatClaimValue(cv); v == "" {
				return "", false, ErrIdPSourceIdentityInvalid
			}
		}
		s := utils.SanitizeSTSName(v)
		altered = altered || s != v || t.blursBoundary(v, i)
		raw = append(raw, v)
		b.WriteString(s)
	}
	b.WriteString(t.lits[len(t.keys)])

	out := b.String()
	if !altered && len(out) <= utils.MaxSTSNameLen {
		if len(out) < 2 {
			return "", false, ErrIdPSourceIdentityInvalid
		}
		return out, false, nil
	}
	tail := sourceIdentityTail(raw)
	if len(out)+len(tail) <= utils.MaxSTSNameLen {
		return out + tail, false, nil
	}
	if t.overflow == config.IdPOverflowReject {
		return "", false, ErrIdPSourceIdentityInvalid
	}
	return out[:utils.MaxSTSNameLen-len(tail)] + tail, true, nil
}

// blursBoundary reports whether a non-final value could hide its end: no next literal, or one containing its first byte.
func (t *sourceIdentityTemplate) blursBoundary(v string, i int) bool {
	if i == len(t.keys)-1 {
		return false
	}
	next := t.lits[i+1]
	return next == "" || strings.IndexByte(v, next[0]) >= 0
}

// sourceIdentityTail is "+" and 11 base64url chars of SHA-256 over the length-prefixed raw values.
func sourceIdentityTail(raw []string) string {
	h := sha256.New()
	var n [8]byte
	for _, v := range raw {
		binary.BigEndian.PutUint64(n[:], uint64(len(v)))
		h.Write(n[:])
		h.Write([]byte(v))
	}
	return "+" + base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:8])
}

func isEmptyClaim(raw any) bool {
	switch c := raw.(type) {
	case nil:
		return true
	case []any:
		return len(c) == 0
	case map[string]any:
		return len(c) == 0
	}
	return false
}

// exchangeFailureKind labels a non-API failure without its text, which may echo the token.
func exchangeFailureKind(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, aws.ErrWebIdentityNoCredentials):
		return "no_credentials"
	case isTimeout(err):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.As(err, &ne):
		return "network"
	}
	return "other"
}

// isTimeout reports whether any error in err's tree reports Timeout.
func isTimeout(err error) bool {
	if t, ok := err.(interface{ Timeout() bool }); ok && t.Timeout() {
		return true
	}
	switch u := err.(type) {
	case interface{ Unwrap() error }:
		return isTimeout(u.Unwrap())
	case interface{ Unwrap() []error }:
		return slices.ContainsFunc(u.Unwrap(), isTimeout)
	}
	return false
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
