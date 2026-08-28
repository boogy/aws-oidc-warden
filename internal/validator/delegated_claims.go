package validator

import (
	"fmt"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/golang-jwt/jwt/v5"
)

// claimBounds carries the time-bound knobs Validate applies in self mode
// (jwt_leeway/max_token_lifetime/max_token_age) so checkAndNormalizeClaims
// can apply the identical bounds to claims arriving via a different trust
// path (apigw/alb).
type claimBounds struct {
	leeway      time.Duration
	maxLifetime time.Duration
	maxAge      time.Duration
}

// checkAndNormalizeClaims is the single claim-check-and-normalize path shared
// by self mode (via Validate) and both delegated extractors (apigw/alb):
// self-mode Validate()'s steps 6-10 against already-trusted raw claims — sub
// non-empty, iat/exp/nbf within leeway, the optional lifetime/age caps,
// audience ANY-match, required_claims, then normalizeClaims. Delegated modes
// differ from self mode only in how raw got here (trusting an upstream
// signature verifier instead of verifying one locally); everything after that
// point runs through this one function so it cannot silently drift weaker.
//
// now is passed in (rather than read from time.Now) so callers — including
// tests — control the clock explicitly.
func checkAndNormalizeClaims(raw jwt.MapClaims, spec *issuerSpec, b claimBounds, now time.Time) (*types.Claims, error) {
	sub, err := raw.GetSubject()
	if err != nil || sub == "" {
		return nil, fmt.Errorf("%w: sub", ErrMissingRequiredClaim)
	}

	// iat required (WithIssuedAt() alone does not make it mandatory) and not
	// in the future beyond leeway.
	iat, err := raw.GetIssuedAt()
	if err != nil || iat == nil {
		return nil, fmt.Errorf("%w: iat", ErrMissingRequiredClaim)
	}
	if now.Before(iat.Add(-b.leeway)) {
		return nil, fmt.Errorf("token used before issued: iat=%s now=%s", iat, now)
	}

	exp, err := raw.GetExpirationTime()
	if err != nil || exp == nil {
		return nil, fmt.Errorf("%w: exp", ErrMissingRequiredClaim)
	}
	if !now.Before(exp.Add(b.leeway)) {
		return nil, fmt.Errorf("token has expired: exp=%s now=%s", exp, now)
	}

	nbf, err := raw.GetNotBefore()
	if err != nil {
		return nil, fmt.Errorf("invalid nbf claim: %w", err)
	}
	if nbf != nil && now.Before(nbf.Add(-b.leeway)) {
		return nil, fmt.Errorf("token is not valid yet: nbf=%s now=%s", nbf, now)
	}

	// Lifetime/age caps: both opt-in, zero value disables the check.
	if b.maxLifetime > 0 && exp.Sub(iat.Time) > b.maxLifetime {
		return nil, fmt.Errorf("%w: %s > %s", ErrTokenLifetimeExceeded, exp.Sub(iat.Time), b.maxLifetime)
	}
	if b.maxAge > 0 && now.Sub(iat.Time) > b.maxAge {
		return nil, fmt.Errorf("%w: %s > %s", ErrTokenTooOld, now.Sub(iat.Time), b.maxAge)
	}

	tokenAudience, err := raw.GetAudience()
	if err != nil {
		return nil, fmt.Errorf("invalid aud claim: %w", err)
	}
	if !audienceMatches(tokenAudience, spec.Audiences) {
		return nil, fmt.Errorf("%w: got %v, want one of %v", ErrInvalidAudience, tokenAudience, spec.Audiences)
	}

	// A JSON null is treated as absent — presence alone must not satisfy a
	// required claim.
	for _, name := range spec.RequiredClaims {
		v, present := raw[name]
		if !present || v == nil {
			return nil, fmt.Errorf("%w: %q", ErrMissingRequiredClaim, name)
		}
		if s, isStr := v.(string); isStr && s == "" {
			return nil, fmt.Errorf("%w: %q", ErrMissingRequiredClaim, name)
		}
	}

	return normalizeClaims(raw, spec.Provider, spec.ClaimMappings)
}

// resolveDelegatedSpec returns the sole configured issuer's spec plus the
// live time bounds for a delegated mode. Fails closed if the config is not
// exactly one issuer.
//
// Used by alb mode only: an ALB has exactly one OIDC IdP, so a multi-issuer
// config is genuinely ambiguous there. apigw mode resolves per request via
// resolveIssuerSpec instead, since each route's JWT authorizer pins its own issuer.
func resolveDelegatedSpec(cfg *config.Config) (*issuerSpec, claimBounds, error) {
	if len(cfg.Issuers) != 1 {
		return nil, claimBounds{}, fmt.Errorf("delegated jwt_validation mode requires exactly one configured issuer, got %d", len(cfg.Issuers))
	}
	return newIssuerSpec(&cfg.Issuers[0]), boundsFrom(cfg), nil
}

// resolveIssuerSpec returns the spec for the exact issuer iss, plus the live
// time bounds. Exact match only, mirroring buildSnapshot's registry keying.
// An issuer with no config entry is denied with ErrUnknownIssuer rather than
// falling back to any other issuer's spec.
//
// A linear scan is deliberate: issuer counts are single digits (API Gateway
// allows at most 10 authorizers per HTTP API), cheaper than building a map per request.
func resolveIssuerSpec(cfg *config.Config, iss string) (*issuerSpec, claimBounds, error) {
	for i := range cfg.Issuers {
		if cfg.Issuers[i].Issuer == iss {
			return newIssuerSpec(&cfg.Issuers[i]), boundsFrom(cfg), nil
		}
	}
	return nil, claimBounds{}, fmt.Errorf("%w: %q", ErrUnknownIssuer, iss)
}

// boundsFrom reads the time-bound knobs live from cfg, so a hot-reloaded
// jwt_leeway/max_token_lifetime/max_token_age applies without a restart.
func boundsFrom(cfg *config.Config) claimBounds {
	return claimBounds{
		leeway:      cfg.LeewayOrDefault(),
		maxLifetime: cfg.MaxTokenLifetime,
		maxAge:      cfg.MaxTokenAge,
	}
}
