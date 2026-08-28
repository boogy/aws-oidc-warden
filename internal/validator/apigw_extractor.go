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
// JWT Authorizer context. Signature trust is delegated upstream; every other
// check self mode runs still applies. Empty AuthorizerClaims is rejected:
// a direct Lambda invoke must not bypass the authorizer.
type APIGWExtractor struct {
	provider *config.Provider
}

// NewAPIGWExtractor creates an APIGWExtractor over the configured issuers.
// The provider is read per Extract call, so hot reloads apply without restart.
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

	cfg := input.configOr(a.provider)

	// iss is upstream-verified, not self-asserted. An unconfigured iss denies
	// outright and is never resolved to another issuer's spec.
	iss, err := raw.GetIssuer()
	if err != nil || iss == "" {
		return nil, fmt.Errorf("%w: missing or invalid iss claim", ErrUnknownIssuer)
	}
	spec, bounds, err := resolveIssuerSpec(cfg, iss)
	if err != nil {
		return nil, err
	}

	return checkAndNormalizeClaims(raw, spec, bounds, time.Now())
}

// numericClaimKeys need float64: MapClaims.GetExpirationTime and friends
// never parse a raw string.
var numericClaimKeys = map[string]bool{"exp": true, "iat": true, "nbf": true}

// opaqueExemptClaimKeys are never wrapped in types.OpaqueClaim: aud is decoded
// by parseAuthorizerAudience, exp/iat/nbf are numeric, and iss must stay a
// plain string for GetIssuer-based routing.
var opaqueExemptClaimKeys = map[string]bool{"aud": true, "exp": true, "iat": true, "nbf": true, "iss": true}

// looksStringified reports whether v is Go's %v rendering of an array or object.
func looksStringified(v string) bool {
	if strings.HasPrefix(v, "map[") && strings.HasSuffix(v, "]") {
		return true
	}
	return strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]")
}

// mapClaimsFromStrings converts the authorizer's map[string]string claims into
// a jwt.MapClaims. A value rendered from an array or object is wrapped in
// types.OpaqueClaim so a none_of veto fires on it instead of failing open;
// sub is eligible too, and a wrapped sub then fails closed in stringClaim.
func mapClaimsFromStrings(raw map[string]string) (jwt.MapClaims, error) {
	mc := make(jwt.MapClaims, len(raw))
	for k, v := range raw {
		if k == "aud" {
			mc[k] = parseAuthorizerAudience(v)
			continue
		}
		if !numericClaimKeys[k] {
			if !opaqueExemptClaimKeys[k] && looksStringified(v) {
				mc[k] = types.OpaqueClaim(v)
				continue
			}
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

// parseAuthorizerAudience decodes the authorizer's string form of "aud": a
// multi-value aud arrives as one bracketed, space-separated string. The
// verbatim string is kept as a candidate alongside the split values, so a
// single-value aud that legitimately looks bracketed still matches.
// Splitting assumes audience values contain no spaces; keep this issuer's
// `audiences` identical to the Authorizer's list and the ambiguity cannot open.
func parseAuthorizerAudience(v string) any {
	if len(v) < 2 || v[0] != '[' || v[len(v)-1] != ']' {
		return v
	}
	return append([]string{v}, strings.Fields(v[1:len(v)-1])...)
}
