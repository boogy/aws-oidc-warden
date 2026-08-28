package validator

import (
	"context"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/types"
)

// ExtractionInput carries raw per-request data for claims extraction.
// Only populate the fields relevant to the configured mode.
type ExtractionInput struct {
	// Config pins the config generation for this request, so claim extraction
	// and the authorization that follows are decided by the SAME generation
	// rather than two provider.Get() reads a concurrent hot reload could
	// split across. Nil means "read the provider".
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
