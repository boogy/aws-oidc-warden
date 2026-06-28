package validator

import (
	"context"

	"github.com/boogy/aws-oidc-warden/internal/types"
)

// ExtractionInput carries raw per-request data for claims extraction.
// Only populate the fields relevant to the configured mode.
type ExtractionInput struct {
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
	Extract(ctx context.Context, input ExtractionInput) (*types.GithubClaims, error)
}
