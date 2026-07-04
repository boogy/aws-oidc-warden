package validator

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/golang-jwt/jwt/v5"
)

// APIGWExtractor reads pre-validated claims from the API Gateway HTTP API v2
// JWT Authorizer context (event.requestContext.authorizer.jwt.claims).
// It does NOT verify signatures — that responsibility belongs to API Gateway.
// If AuthorizerClaims is nil or empty, it rejects the request to prevent
// direct Lambda invocations that bypass the authorizer.
// Defense-in-depth: re-validates issuer, audience, expiry, and every other
// claim self mode checks (sub, iat, nbf, lifetime/age caps, required_claims)
// through the same checkAndNormalizeClaims path Validate() uses — delegated
// trust in the upstream signature verification is the only difference from
// self mode (SHARED.md invariant #6).
type APIGWExtractor struct {
	provider *config.Provider
}

// NewAPIGWExtractor creates an APIGWExtractor for the delegated "apigw"
// mode's single configured issuer. provider is read on every Extract() call
// (via resolveDelegatedSpec), so a hot-reloaded audiences/claim_mappings/
// required_claims/jwt_leeway change takes effect without a restart, matching
// self mode.
func NewAPIGWExtractor(provider *config.Provider) *APIGWExtractor {
	return &APIGWExtractor{provider: provider}
}

// Extract maps the API Gateway authorizer claims to types.Claims, re-validating
// issuer and all of self mode's claim checks for defense in depth.
func (a *APIGWExtractor) Extract(_ context.Context, input ExtractionInput) (*types.Claims, error) {
	if len(input.AuthorizerClaims) == 0 {
		return nil, fmt.Errorf("no authorizer claims present: request may have bypassed API Gateway JWT Authorizer")
	}

	raw, err := mapClaimsFromStrings(input.AuthorizerClaims)
	if err != nil {
		return nil, err
	}

	cfg := a.provider.Get()
	spec, bounds, err := resolveDelegatedSpec(cfg)
	if err != nil {
		return nil, err
	}

	// Re-validate issuer — guards against a reused or misconfigured JWT
	// Authorizer, and against a token from a different, unconfigured issuer.
	iss, err := raw.GetIssuer()
	if err != nil || iss != spec.Issuer {
		return nil, fmt.Errorf("iss mismatch: got %q, want %q", iss, spec.Issuer)
	}

	return checkAndNormalizeClaims(raw, spec, bounds, time.Now())
}

// numericClaimKeys are converted from string to float64 before being placed
// into a jwt.MapClaims: MapClaims.GetExpirationTime/GetIssuedAt/GetNotBefore
// only parse a float64 or json.Number, never a raw string (see
// jwt.MapClaims.parseNumericDate). Every other claim stays a string.
var numericClaimKeys = map[string]bool{"exp": true, "iat": true, "nbf": true}

// mapClaimsFromStrings converts the API Gateway authorizer's
// map[string]string claims into a jwt.MapClaims suitable for
// checkAndNormalizeClaims and normalizeClaims.
func mapClaimsFromStrings(raw map[string]string) (jwt.MapClaims, error) {
	mc := make(jwt.MapClaims, len(raw))
	for k, v := range raw {
		if !numericClaimKeys[k] {
			mc[k] = v
			continue
		}
		if v == "" {
			continue
		}
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return nil, fmt.Errorf("claim %q is not numeric: %w", k, err)
		}
		mc[k] = f
	}
	return mc, nil
}
