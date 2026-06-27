package handler_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/handler"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubValidator always returns an error to simulate JWT validation failure.
type stubValidator struct{ err error }

func (s *stubValidator) Validate(string) (*types.GithubClaims, error)   { return nil, s.err }
func (s *stubValidator) ParseToken(string) (*types.GithubClaims, error) { return nil, s.err }
func (s *stubValidator) FetchJWKS(string) (*types.JWKS, error)          { return nil, nil }
func (s *stubValidator) GenKeyFunc(*types.JWKS) jwt.Keyfunc             { return nil }

func TestProcessRequest_TokenValidationErrorIsSentinel(t *testing.T) {
	cfg := &config.Config{
		Issuer:          "https://token.actions.githubusercontent.com",
		Audiences:       []string{"sts.amazonaws.com"},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 0},
	}
	require.NoError(t, cfg.Validate())

	provider := config.NewStaticProvider(cfg)
	v := &stubValidator{err: errors.New("token is expired")}
	proc := handler.NewRequestProcessor(provider, nil, v)

	_, err := proc.ProcessRequest(
		context.Background(),
		&handler.RequestData{Token: "t", Role: "r"},
		"req-id",
		slog.Default(),
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, handler.ErrTokenValidationFailed),
		"expected ErrTokenValidationFailed in error chain, got: %v", err)
}
