package validator_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// githubIssuerConfig is the delegated-mode equivalent of the self-mode
// registry entry a real config would produce for a github-provider issuer:
// audiences + required_claims, as config.Validate() would leave them.
func githubIssuerConfig(issuer string, audiences ...string) *config.IssuerConfig {
	return &config.IssuerConfig{
		Issuer:         issuer,
		Provider:       "github",
		Audiences:      audiences,
		RequiredClaims: []string{"repository"},
	}
}

func unixStr(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10)
}

func TestAPIGWExtractor_Extract(t *testing.T) {
	iss := githubIssuerConfig("https://token.actions.githubusercontent.com", "sts.amazonaws.com")
	ex := validator.NewAPIGWExtractor(iss, 30*time.Second, 0, 0)
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
	assert.Equal(t, "org/repo", claims.Subject, "canonical subject defaults to the repository claim for provider github")
	assert.Equal(t, "refs/heads/main", claims.Ref)
	assert.Equal(t, "octocat", claims.Actor)
	assert.Equal(t, "branch", claims.RefType)
	assert.Equal(t, "https://token.actions.githubusercontent.com", claims.Issuer)
}

func TestAPIGWExtractor_MissingClaims(t *testing.T) {
	iss := githubIssuerConfig("https://token.actions.githubusercontent.com", "sts.amazonaws.com")
	ex := validator.NewAPIGWExtractor(iss, 30*time.Second, 0, 0)
	_, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: nil,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no authorizer claims")
}

func TestAPIGWExtractor_MissingRepository(t *testing.T) {
	iss := githubIssuerConfig("https://token.actions.githubusercontent.com", "sts.amazonaws.com")
	ex := validator.NewAPIGWExtractor(iss, 30*time.Second, 0, 0)
	_, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: map[string]string{
			"iss": "https://token.actions.githubusercontent.com",
			"sub": "repo:org/repo:ref:refs/heads/main",
			"aud": "sts.amazonaws.com",
			"exp": "9999999999",
			"iat": "1000000000",
			// no repository — required_claims must reject it.
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "repository")
}

func TestAPIGWExtractor_MissingSubject(t *testing.T) {
	iss := githubIssuerConfig("https://token.actions.githubusercontent.com", "sts.amazonaws.com")
	ex := validator.NewAPIGWExtractor(iss, 30*time.Second, 0, 0)
	_, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: map[string]string{
			"iss":        "https://token.actions.githubusercontent.com",
			"aud":        "sts.amazonaws.com",
			"exp":        "9999999999",
			"iat":        "1000000000",
			"repository": "org/repo",
			// no sub — self mode requires it non-empty; delegated must too.
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sub")
}

func TestAPIGWExtractor_ExpiredToken(t *testing.T) {
	iss := githubIssuerConfig("https://token.actions.githubusercontent.com", "sts.amazonaws.com")
	ex := validator.NewAPIGWExtractor(iss, 30*time.Second, 0, 0)
	_, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: map[string]string{
			"iss":        "https://token.actions.githubusercontent.com",
			"sub":        "repo:org/repo:ref:refs/heads/main",
			"aud":        "sts.amazonaws.com",
			"repository": "org/repo",
			"iat":        "999999000",
			"exp":        "1000000000", // far in the past
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestAPIGWExtractor_MissingExp(t *testing.T) {
	iss := githubIssuerConfig("https://token.actions.githubusercontent.com", "sts.amazonaws.com")
	ex := validator.NewAPIGWExtractor(iss, 30*time.Second, 0, 0)
	_, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: map[string]string{
			"iss": "https://token.actions.githubusercontent.com", "aud": "sts.amazonaws.com",
			"sub":        "repo:org/repo:ref:refs/heads/main",
			"iat":        "1000000000",
			"repository": "org/repo",
			// no exp
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exp")
}

func TestAPIGWExtractor_IssuerMismatch(t *testing.T) {
	iss := githubIssuerConfig("https://token.actions.githubusercontent.com", "sts.amazonaws.com")
	ex := validator.NewAPIGWExtractor(iss, 30*time.Second, 0, 0)
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
	iss := githubIssuerConfig("https://token.actions.githubusercontent.com", "sts.amazonaws.com")
	ex := validator.NewAPIGWExtractor(iss, 30*time.Second, 0, 0)
	_, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: map[string]string{
			"iss": "https://token.actions.githubusercontent.com", "aud": "wrong-audience",
			"sub":        "repo:org/repo:ref:refs/heads/main",
			"iat":        "1000000000",
			"repository": "org/repo", "exp": "9999999999",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aud")
}

func TestAPIGWExtractor_MinimalClaims(t *testing.T) {
	iss := githubIssuerConfig("https://token.actions.githubusercontent.com", "sts.amazonaws.com")
	ex := validator.NewAPIGWExtractor(iss, 30*time.Second, 0, 0)
	claims, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: map[string]string{
			"iss":        "https://token.actions.githubusercontent.com",
			"aud":        "sts.amazonaws.com",
			"sub":        "repo:org/repo:ref:refs/heads/main",
			"iat":        "1000000000",
			"repository": "org/repo",
			"exp":        "9999999999",
			// no actor, ref, ref_type, etc. — optional claims
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "org/repo", claims.Repository)
	assert.Empty(t, claims.Actor, "absent optional claims must produce zero values")
	assert.NotNil(t, claims.ExpiresAt)
}

func TestAPIGWExtractor_FutureIssuedAt(t *testing.T) {
	iss := githubIssuerConfig("https://token.actions.githubusercontent.com", "sts.amazonaws.com")
	ex := validator.NewAPIGWExtractor(iss, 30*time.Second, 0, 0)
	_, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: map[string]string{
			"iss":        "https://token.actions.githubusercontent.com",
			"aud":        "sts.amazonaws.com",
			"sub":        "repo:org/repo:ref:refs/heads/main",
			"repository": "org/repo",
			"exp":        "9999999999",
			"iat":        unixStr(time.Now().Add(time.Hour)),
		},
	})
	require.Error(t, err)
}

func TestAPIGWExtractor_MaxTokenAgeExceeded(t *testing.T) {
	iss := githubIssuerConfig("https://token.actions.githubusercontent.com", "sts.amazonaws.com")
	ex := validator.NewAPIGWExtractor(iss, 30*time.Second, 0, time.Minute)
	_, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: map[string]string{
			"iss":        "https://token.actions.githubusercontent.com",
			"aud":        "sts.amazonaws.com",
			"sub":        "repo:org/repo:ref:refs/heads/main",
			"repository": "org/repo",
			"exp":        "9999999999",
			"iat":        unixStr(time.Now().Add(-time.Hour)),
		},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, validator.ErrTokenTooOld)
}

func TestAPIGWExtractor_MaxTokenLifetimeExceeded(t *testing.T) {
	iss := githubIssuerConfig("https://token.actions.githubusercontent.com", "sts.amazonaws.com")
	ex := validator.NewAPIGWExtractor(iss, 30*time.Second, time.Minute, 0)
	now := time.Now()
	_, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: map[string]string{
			"iss":        "https://token.actions.githubusercontent.com",
			"aud":        "sts.amazonaws.com",
			"sub":        "repo:org/repo:ref:refs/heads/main",
			"repository": "org/repo",
			"iat":        unixStr(now),
			"exp":        unixStr(now.Add(time.Hour)), // exp-iat=1h > 1m cap
		},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, validator.ErrTokenLifetimeExceeded)
}
