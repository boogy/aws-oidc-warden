package validator

import (
	"context"
	"fmt"
	"strconv"
	"strings"
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
// self mode.
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
		if k == "aud" {
			mc[k] = parseAuthorizerAudience(v)
			continue
		}
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

// parseAuthorizerAudience decodes the authorizer's string form of the "aud"
// claim. A token with a multi-value aud reaches the authorizer context as one
// bracketed, space-separated string (e.g. "[aud1 aud2]" — the HTTP API JWT
// Authorizer stringifies array claims), which would otherwise never match a
// configured audience. A single-value aud (the common case) passes through
// unchanged; jwt.MapClaims.GetAudience accepts both string and []string.
//
// The verbatim string is kept as a candidate alongside the split values, so a
// single-value aud that legitimately looks bracketed (e.g. "[internal]")
// still matches an identically-configured audience. Splitting assumes
// audience values contain no spaces (they are URIs/identifiers in practice);
// an audience value WITH spaces could fragment into a piece that matches a
// configured audience — acceptable here because this check is
// defense-in-depth behind API Gateway's own audience validation, which has
// already run against the authorizer's configured audience list.
func parseAuthorizerAudience(v string) any {
	if len(v) < 2 || v[0] != '[' || v[len(v)-1] != ']' {
		return v
	}
	return append([]string{v}, strings.Fields(v[1:len(v)-1])...)
}
