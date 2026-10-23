package validator

import (
	"context"

	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/golang-jwt/jwt/v5"
)

// FetchJWKS fetches issuer's JWKS via the cache, with no jwks_uri override.
func (t *TokenValidator) FetchJWKS(ctx context.Context, issuer string) (*types.JWKS, error) {
	return t.fetchJWKS(ctx, &issuerSpec{Issuer: issuer}, false)
}

// GenKeyFunc returns a jwt.Keyfunc over jwks with an issuer-unscoped key memo.
func (t *TokenValidator) GenKeyFunc(jwks *types.JWKS) jwt.Keyfunc {
	return t.genKeyFuncForIssuer("", jwks)
}
