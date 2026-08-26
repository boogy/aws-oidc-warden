package validator

import (
	"context"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/types"
)

// ExtractionInput carries raw per-request data for claims extraction.
// Only populate the fields relevant to the configured mode.
type ExtractionInput struct {
	// Config pins the config generation for this request. The processor
	// captures one *Config for the whole request and puts it here, so claim
	// extraction and the authorization that follows it are decided by the SAME
	// generation.
	//
	// Without it every extractor called provider.Get() again, which is a
	// SECOND read of a pointer a concurrent hot reload can have swapped in
	// between. One request could then be token-validated against generation
	// N+1 — its issuers, audiences, claim mappings and time bounds — and
	// authorized against generation N. That is not the benign "in-flight
	// request sees a stale config" case, where one consistent generation
	// decides everything: a refresh that widens validation while narrowing
	// authorization (rotating an audience while retiring a role mapping in the
	// same push) would authorize a caller NEITHER generation allows on its
	// own.
	//
	// Nil is allowed and means "read the provider", which keeps direct callers
	// and tests that construct an input by hand working unchanged.
	Config *config.Config

	// Token is the raw JWT string; used only in "self" mode.
	Token string

	// AuthorizerClaims contains pre-validated claims from API Gateway HTTP API
	// v2 JWT Authorizer (event.requestContext.authorizer.jwt.claims).
	AuthorizerClaims map[string]string

	// ALBOIDCData is the value of the x-amzn-oidc-data header set by ALB OIDC.
	// It is a JWT signed by ALB and must be verified before use.
	ALBOIDCData string

	// AWSRegion is required in "alb" mode to fetch the ALB signing public key
	// from https://public-keys.auth.elb.{region}.amazonaws.com/{kid}.
	AWSRegion string
}

// ClaimsExtractorInterface abstracts how GitHub OIDC claims are obtained.
// Implementations either validate the JWT themselves ("self") or decode
// pre-validated claims provided by a trusted upstream ("apigw", "alb").
type ClaimsExtractorInterface interface {
	Extract(ctx context.Context, input ExtractionInput) (*types.Claims, error)
}

// configOr returns the request-pinned config, falling back to the provider
// when the caller did not pin one.
func (i ExtractionInput) configOr(provider *config.Provider) *config.Config {
	if i.Config != nil {
		return i.Config
	}
	return provider.Get()
}
