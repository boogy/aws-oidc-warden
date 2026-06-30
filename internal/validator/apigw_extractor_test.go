package validator_test

import (
	"context"
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIGWExtractor_Extract(t *testing.T) {
	ex := validator.NewAPIGWExtractor("https://token.actions.githubusercontent.com", []string{"sts.amazonaws.com"})
	claims, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: map[string]string{
			"iss":        "https://token.actions.githubusercontent.com",
			"sub":        "repo:org/repo:ref:refs/heads/main",
			"aud":        "sts.amazonaws.com",
			"exp":        "9999999999",
			"iat":        "1000000000",
			"repository": "org/repo",
			"ref":        "refs/heads/main",
			"ref_type":   "branch",
			"actor":      "octocat",
			"sha":        "abc123",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "org/repo", claims.Repository)
	assert.Equal(t, "refs/heads/main", claims.Ref)
	assert.Equal(t, "octocat", claims.Actor)
	assert.Equal(t, "branch", claims.RefType)
	assert.Equal(t, "https://token.actions.githubusercontent.com", claims.Issuer)
}

func TestAPIGWExtractor_MissingClaims(t *testing.T) {
	ex := validator.NewAPIGWExtractor("https://token.actions.githubusercontent.com", []string{"sts.amazonaws.com"})
	_, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: nil,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no authorizer claims")
}

func TestAPIGWExtractor_MissingRepository(t *testing.T) {
	ex := validator.NewAPIGWExtractor("https://token.actions.githubusercontent.com", []string{"sts.amazonaws.com"})
	_, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: map[string]string{"iss": "https://token.actions.githubusercontent.com"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "repository")
}

func TestAPIGWExtractor_ExpiredToken(t *testing.T) {
	ex := validator.NewAPIGWExtractor("https://token.actions.githubusercontent.com", []string{"sts.amazonaws.com"})
	_, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: map[string]string{
			"iss":        "https://token.actions.githubusercontent.com",
			"aud":        "sts.amazonaws.com",
			"repository": "org/repo",
			"exp":        "1000000000", // far in the past
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestAPIGWExtractor_MissingExp(t *testing.T) {
	ex := validator.NewAPIGWExtractor("https://token.actions.githubusercontent.com", []string{"sts.amazonaws.com"})
	_, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: map[string]string{
			"iss": "https://token.actions.githubusercontent.com", "aud": "sts.amazonaws.com",
			"repository": "org/repo",
			// no exp
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exp")
}

func TestAPIGWExtractor_IssuerMismatch(t *testing.T) {
	ex := validator.NewAPIGWExtractor("https://token.actions.githubusercontent.com", []string{"sts.amazonaws.com"})
	_, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: map[string]string{
			"iss": "https://evil.example.com", "aud": "sts.amazonaws.com",
			"repository": "org/repo", "exp": "9999999999",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "iss")
}

func TestAPIGWExtractor_AudienceMismatch(t *testing.T) {
	ex := validator.NewAPIGWExtractor("https://token.actions.githubusercontent.com", []string{"sts.amazonaws.com"})
	_, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: map[string]string{
			"iss": "https://token.actions.githubusercontent.com", "aud": "wrong-audience",
			"repository": "org/repo", "exp": "9999999999",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aud")
}

func TestAPIGWExtractor_MinimalClaims(t *testing.T) {
	ex := validator.NewAPIGWExtractor("https://token.actions.githubusercontent.com", []string{"sts.amazonaws.com"})
	claims, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: map[string]string{
			"iss":        "https://token.actions.githubusercontent.com",
			"aud":        "sts.amazonaws.com",
			"sub":        "repo:org/repo:ref:refs/heads/main",
			"repository": "org/repo",
			"exp":        "9999999999",
			// no iat, actor, ref, ref_type, etc. — optional claims
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "org/repo", claims.Repository)
	assert.Empty(t, claims.Actor, "absent optional claims must produce zero values")
	assert.NotNil(t, claims.ExpiresAt)
}
