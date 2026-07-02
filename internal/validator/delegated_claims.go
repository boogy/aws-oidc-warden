package validator

import (
	"fmt"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/golang-jwt/jwt/v5"
)

// claimBounds carries the time-bound knobs Validate applies in self mode
// (JWTLeeway/MaxTokenLifetime/MaxTokenAge on TokenValidator) so
// checkAndNormalizeClaims can apply the identical bounds to claims that
// arrive by a different trust path (apigw/alb).
type claimBounds struct {
	leeway      time.Duration
	maxLifetime time.Duration
	maxAge      time.Duration
}

// checkAndNormalizeClaims is the single claim-check-and-normalize path shared
// by self mode (via Validate) and both delegated extractors (apigw/alb): it
// performs exactly self-mode Validate()'s steps 6-10 against already-trusted
// raw claims — sub non-empty, iat required and not in the future beyond
// leeway, exp required and not expired beyond leeway, nbf (if present) not in
// the future beyond leeway, the optional lifetime/age caps, audience
// ANY-match, required_claims, then normalizeClaims. Delegated modes differ
// from self mode only in how raw got here (trusting an upstream signature
// verifier instead of verifying one locally) — everything after that point
// runs through this one function, so it cannot silently drift weaker
// (SHARED.md invariant #6).
//
// now is passed in (rather than read from time.Now) so callers — including
// tests — control the clock explicitly.
func checkAndNormalizeClaims(raw jwt.MapClaims, spec *issuerSpec, b claimBounds, now time.Time) (*types.Claims, error) {
	// sub non-empty.
	sub, err := raw.GetSubject()
	if err != nil || sub == "" {
		return nil, fmt.Errorf("%w: sub", ErrMissingRequiredClaim)
	}

	// iat required (mirrors self mode: WithIssuedAt() alone does not make it
	// mandatory, so it is enforced explicitly), and not in the future beyond
	// leeway (mirrors the jwt/v5 parser's own verifyIssuedAt check).
	iat, err := raw.GetIssuedAt()
	if err != nil || iat == nil {
		return nil, fmt.Errorf("%w: iat", ErrMissingRequiredClaim)
	}
	if now.Before(iat.Add(-b.leeway)) {
		return nil, fmt.Errorf("token used before issued: iat=%s now=%s", iat, now)
	}

	// exp required (mirrors WithExpirationRequired()), not expired beyond leeway.
	exp, err := raw.GetExpirationTime()
	if err != nil || exp == nil {
		return nil, fmt.Errorf("%w: exp", ErrMissingRequiredClaim)
	}
	if !now.Before(exp.Add(b.leeway)) {
		return nil, fmt.Errorf("token has expired: exp=%s now=%s", exp, now)
	}

	// nbf, if present, enforced with leeway (mirrors the parser's unconditional
	// verifyNotBefore check in self mode).
	nbf, err := raw.GetNotBefore()
	if err != nil {
		return nil, fmt.Errorf("invalid nbf claim: %w", err)
	}
	if nbf != nil && now.Before(nbf.Add(-b.leeway)) {
		return nil, fmt.Errorf("token is not valid yet: nbf=%s now=%s", nbf, now)
	}

	// Lifetime/age caps (both opt-in; zero value disables the check).
	if b.maxLifetime > 0 && exp.Sub(iat.Time) > b.maxLifetime {
		return nil, fmt.Errorf("%w: %s > %s", ErrTokenLifetimeExceeded, exp.Sub(iat.Time), b.maxLifetime)
	}
	if b.maxAge > 0 && now.Sub(iat.Time) > b.maxAge {
		return nil, fmt.Errorf("%w: %s > %s", ErrTokenTooOld, now.Sub(iat.Time), b.maxAge)
	}

	// Audience ANY-match against this issuer's configured audiences.
	tokenAudience, err := raw.GetAudience()
	if err != nil {
		return nil, fmt.Errorf("invalid aud claim: %w", err)
	}
	if !audienceMatches(tokenAudience, spec.Audiences) {
		return nil, fmt.Errorf("%w: got %v, want one of %v", ErrInvalidAudience, tokenAudience, spec.Audiences)
	}

	// required_claims present and non-empty, checked on the raw claims.
	for _, name := range spec.RequiredClaims {
		v, present := raw[name]
		if !present {
			return nil, fmt.Errorf("%w: %q", ErrMissingRequiredClaim, name)
		}
		if s, isStr := v.(string); isStr && s == "" {
			return nil, fmt.Errorf("%w: %q", ErrMissingRequiredClaim, name)
		}
	}

	// Normalize to canonical subject + raw claims map.
	return normalizeClaims(raw, spec.Provider, spec.ClaimMappings)
}
