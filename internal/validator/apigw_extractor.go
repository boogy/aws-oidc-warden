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

// NewAPIGWExtractor creates an APIGWExtractor over the configured issuers.
// provider is read on every Extract() call (and the spec is resolved per
// request from the verified iss), so a hot-reloaded issuer set, audiences,
// claim_mappings, required_claims or jwt_leeway change takes effect without a
// restart, matching self mode.
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

	// Resolve the spec from the issuer the upstream verified. API Gateway
	// forwards authorizer claims only after checking the signature AND an
	// exact issuer match against that route's authorizer, so iss here is
	// upstream-verified rather than self-asserted — the same property self
	// mode gets from verifying the signature locally. An iss with no config
	// entry is denied outright, never resolved to another issuer's spec, so a
	// reused or misconfigured authorizer fails closed.
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
// an audience value WITH spaces fragments, and a piece can then satisfy the
// ANY-match in delegated_claims.go. The ambiguity is inherent and not fixable
// here: the authorizer context is map[string]string, so ["a b"] and ["a","b"]
// arrive as the identical string "[a b]" with the distinction already lost.
// Keeping both readings is the permissive choice, and it is acceptable only
// because of what has to be true to exploit it: API Gateway's own JWT
// Authorizer must ALREADY have accepted that space-containing aud, meaning the
// exact string "a b" is in the Authorizer's configured audience list, while
// this issuer's `audiences` lists only the fragment "a". Keep the two audience
// lists identical and the gap cannot open.
func parseAuthorizerAudience(v string) any {
	if len(v) < 2 || v[0] != '[' || v[len(v)-1] != ']' {
		return v
	}
	return append([]string{v}, strings.Fields(v[1:len(v)-1])...)
}
