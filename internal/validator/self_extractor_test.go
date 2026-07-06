package validator_test

import (
	"context"
	"errors"
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockTokenValidator struct {
	claims *types.Claims
	err    error
}

func (m *mockTokenValidator) Validate(token string) (*types.Claims, error) {
	return m.claims, m.err
}
func (m *mockTokenValidator) FetchJWKS(issuer string) (*types.JWKS, error) { return nil, nil }
func (m *mockTokenValidator) GenKeyFunc(jwks *types.JWKS) jwt.Keyfunc      { return nil }

func TestSelfExtractor_Extract(t *testing.T) {
	want := &types.Claims{Repository: "org/repo"}
	ex := validator.NewSelfExtractor(&mockTokenValidator{claims: want})

	got, err := ex.Extract(context.Background(), validator.ExtractionInput{Token: "tok"})
	require.NoError(t, err)
	assert.Equal(t, want.Repository, got.Repository)
}

func TestSelfExtractor_Extract_ValidationError(t *testing.T) {
	ex := validator.NewSelfExtractor(&mockTokenValidator{err: errors.New("bad sig")})
	_, err := ex.Extract(context.Background(), validator.ExtractionInput{Token: "tok"})
	require.Error(t, err)
}

func TestSelfExtractor_Extract_EmptyToken(t *testing.T) {
	ex := validator.NewSelfExtractor(&mockTokenValidator{})
	_, err := ex.Extract(context.Background(), validator.ExtractionInput{Token: ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token is required")
}
