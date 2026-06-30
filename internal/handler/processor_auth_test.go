package handler_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/handler"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubExtractor always returns an error to simulate extraction failure.
type stubExtractor struct{ err error }

func (s *stubExtractor) Extract(_ context.Context, _ validator.ExtractionInput) (*types.GithubClaims, error) {
	return nil, s.err
}

func TestProcessRequest_TokenValidationErrorIsSentinel(t *testing.T) {
	cfg := &config.Config{
		Issuer:          "https://token.actions.githubusercontent.com",
		Audiences:       []string{"sts.amazonaws.com"},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 0},
	}
	require.NoError(t, cfg.Validate())

	provider := config.NewStaticProvider(cfg)
	ex := &stubExtractor{err: errors.New("token is expired")}
	proc := handler.NewRequestProcessor(provider, nil, ex)

	_, err := proc.ProcessRequest(
		context.Background(),
		&handler.RequestData{Token: "t", Role: "r"},
		validator.ExtractionInput{Token: "t"},
		"req-id",
		slog.Default(),
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, handler.ErrTokenValidationFailed),
		"expected ErrTokenValidationFailed in error chain, got: %v", err)
}
