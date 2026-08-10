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

// newTestAPIGWExtractor builds an APIGWExtractor backed by a static
// single-issuer config.Provider, mirroring what NewAPIGWExtractor's
// production caller (bootstrap.go) wires from a real config: the extractor
// now reads iss/leeway/maxLifetime/maxAge live from the provider on every
// Extract() call instead of freezing them at construction.
func newTestAPIGWExtractor(iss *config.IssuerConfig, leeway, maxLifetime, maxAge time.Duration) *validator.APIGWExtractor {
	cfg := &config.Config{
		Issuers:          []config.IssuerConfig{*iss},
		RoleSessionName:  "test",
		JWTLeeway:        &leeway,
		MaxTokenLifetime: maxLifetime,
		MaxTokenAge:      maxAge,
	}
	return validator.NewAPIGWExtractor(config.NewStaticProvider(cfg))
}

func TestAPIGWExtractor_Extract(t *testing.T) {
	iss := githubIssuerConfig("https://token.actions.githubusercontent.com", "sts.amazonaws.com")
	ex := newTestAPIGWExtractor(iss, 30*time.Second, 0, 0)
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

// TestAPIGWExtractor_BracketedMultiValueAudience covers the HTTP API JWT
// Authorizer's stringified form of an array aud claim ("[aud1 aud2]"): the
// extractor must split it back into individual audiences so ANY-match against
// the issuer's configured audiences still works.
func TestAPIGWExtractor_BracketedMultiValueAudience(t *testing.T) {
	iss := githubIssuerConfig("https://token.actions.githubusercontent.com", "sts.amazonaws.com")
	ex := newTestAPIGWExtractor(iss, 30*time.Second, 0, 0)
	claims, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: map[string]string{
			"iss":        "https://token.actions.githubusercontent.com",
			"sub":        "repo:org/repo:ref:refs/heads/main",
			"aud":        "[other.example.com sts.amazonaws.com]",
			"exp":        "9999999999",
			"iat":        "1000000000",
			"repository": "org/repo",
		},
	})
	require.NoError(t, err)
	assert.Contains(t, []string(claims.Audience), "sts.amazonaws.com")
}

// TestAPIGWExtractor_BracketedLiteralAudience verifies a single-value aud that
// legitimately looks bracketed still matches an identically-configured
// audience: the verbatim string stays a candidate alongside the split values.
func TestAPIGWExtractor_BracketedLiteralAudience(t *testing.T) {
	iss := githubIssuerConfig("https://token.actions.githubusercontent.com", "[internal]")
	ex := newTestAPIGWExtractor(iss, 30*time.Second, 0, 0)
	_, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: map[string]string{
			"iss":        "https://token.actions.githubusercontent.com",
			"sub":        "repo:org/repo:ref:refs/heads/main",
			"aud":        "[internal]",
			"exp":        "9999999999",
			"iat":        "1000000000",
			"repository": "org/repo",
		},
	})
	require.NoError(t, err)
}

// TestAPIGWExtractor_BracketedAudienceNoMatch verifies a bracketed multi-value
// aud with no configured audience still denies (the split must not widen
// matching).
func TestAPIGWExtractor_BracketedAudienceNoMatch(t *testing.T) {
	iss := githubIssuerConfig("https://token.actions.githubusercontent.com", "sts.amazonaws.com")
	ex := newTestAPIGWExtractor(iss, 30*time.Second, 0, 0)
	_, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: map[string]string{
			"iss":        "https://token.actions.githubusercontent.com",
			"sub":        "repo:org/repo:ref:refs/heads/main",
			"aud":        "[other.example.com another.example.com]",
			"exp":        "9999999999",
			"iat":        "1000000000",
			"repository": "org/repo",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aud")
}

func TestAPIGWExtractor_MissingClaims(t *testing.T) {
	iss := githubIssuerConfig("https://token.actions.githubusercontent.com", "sts.amazonaws.com")
	ex := newTestAPIGWExtractor(iss, 30*time.Second, 0, 0)
	_, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: nil,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no authorizer claims")
}

func TestAPIGWExtractor_MissingRepository(t *testing.T) {
	iss := githubIssuerConfig("https://token.actions.githubusercontent.com", "sts.amazonaws.com")
	ex := newTestAPIGWExtractor(iss, 30*time.Second, 0, 0)
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
	ex := newTestAPIGWExtractor(iss, 30*time.Second, 0, 0)
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
	ex := newTestAPIGWExtractor(iss, 30*time.Second, 0, 0)
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
	ex := newTestAPIGWExtractor(iss, 30*time.Second, 0, 0)
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
	ex := newTestAPIGWExtractor(iss, 30*time.Second, 0, 0)
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
	ex := newTestAPIGWExtractor(iss, 30*time.Second, 0, 0)
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
	ex := newTestAPIGWExtractor(iss, 30*time.Second, 0, 0)
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
	ex := newTestAPIGWExtractor(iss, 30*time.Second, 0, 0)
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
	ex := newTestAPIGWExtractor(iss, 30*time.Second, 0, time.Minute)
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
	ex := newTestAPIGWExtractor(iss, 30*time.Second, time.Minute, 0)
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

// newTestAPIGWExtractorMulti builds an APIGWExtractor over several configured
// issuers, which is what apigw mode allows once each route carries its own JWT
// authorizer.
func newTestAPIGWExtractorMulti(issuers ...config.IssuerConfig) *validator.APIGWExtractor {
	leeway := 30 * time.Second
	cfg := &config.Config{
		Issuers:         issuers,
		RoleSessionName: "test",
		JWTLeeway:       &leeway,
	}
	return validator.NewAPIGWExtractor(config.NewStaticProvider(cfg))
}

func gitlabIssuerConfig(issuer string, audiences ...string) *config.IssuerConfig {
	return &config.IssuerConfig{
		Issuer:         issuer,
		Provider:       "generic",
		Audiences:      audiences,
		ClaimMappings:  map[string]string{"subject": "project_path"},
		RequiredClaims: []string{"project_path"},
	}
}

// Each token must be validated against its OWN issuer's spec: provider,
// audiences, claim_mappings and required_claims all come from the entry whose
// issuer matches the verified iss.
func TestAPIGWExtractor_MultiIssuer_RoutesToOwnSpec(t *testing.T) {
	gh := githubIssuerConfig("https://token.actions.githubusercontent.com", "sts.amazonaws.com")
	gl := gitlabIssuerConfig("https://gitlab.com", "aws-oidc-warden")
	ex := newTestAPIGWExtractorMulti(*gh, *gl)
	now := time.Now()

	ghClaims, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: map[string]string{
			"iss":        "https://token.actions.githubusercontent.com",
			"sub":        "repo:org/repo:ref:refs/heads/main",
			"aud":        "sts.amazonaws.com",
			"exp":        unixStr(now.Add(time.Hour)),
			"iat":        unixStr(now),
			"repository": "org/repo",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "org/repo", ghClaims.Subject, "github provider derives the subject from repository")

	glClaims, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: map[string]string{
			"iss":          "https://gitlab.com",
			"sub":          "project_path:group/proj:ref_type:branch:ref:main",
			"aud":          "aws-oidc-warden",
			"exp":          unixStr(now.Add(time.Hour)),
			"iat":          unixStr(now),
			"project_path": "group/proj",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "group/proj", glClaims.Subject, "generic provider derives the subject from claim_mappings")
}

// A token whose iss has no config entry must be denied, even though some other
// configured issuer would have accepted its audience.
func TestAPIGWExtractor_MultiIssuer_UnknownIssuerDenied(t *testing.T) {
	gh := githubIssuerConfig("https://token.actions.githubusercontent.com", "sts.amazonaws.com")
	gl := gitlabIssuerConfig("https://gitlab.com", "aws-oidc-warden")
	ex := newTestAPIGWExtractorMulti(*gh, *gl)
	now := time.Now()

	_, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: map[string]string{
			"iss":        "https://evil.example.com",
			"sub":        "repo:org/repo",
			"aud":        "sts.amazonaws.com",
			"exp":        unixStr(now.Add(time.Hour)),
			"iat":        unixStr(now),
			"repository": "org/repo",
		},
	})
	require.ErrorIs(t, err, validator.ErrUnknownIssuer)
}

// No cross-issuer audience leakage: issuer A's token carrying issuer B's
// audience must fail A's audience check, not silently pass against the union.
func TestAPIGWExtractor_MultiIssuer_NoCrossIssuerAudience(t *testing.T) {
	gh := githubIssuerConfig("https://token.actions.githubusercontent.com", "sts.amazonaws.com")
	gl := gitlabIssuerConfig("https://gitlab.com", "aws-oidc-warden")
	ex := newTestAPIGWExtractorMulti(*gh, *gl)
	now := time.Now()

	_, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: map[string]string{
			"iss":        "https://token.actions.githubusercontent.com",
			"sub":        "repo:org/repo",
			"aud":        "aws-oidc-warden", // gitlab's audience
			"exp":        unixStr(now.Add(time.Hour)),
			"iat":        unixStr(now),
			"repository": "org/repo",
		},
	})
	require.ErrorIs(t, err, validator.ErrInvalidAudience)
}

// A missing iss claim must deny before any spec is chosen — never default to
// the first configured issuer.
func TestAPIGWExtractor_MultiIssuer_MissingIssuerDenied(t *testing.T) {
	gh := githubIssuerConfig("https://token.actions.githubusercontent.com", "sts.amazonaws.com")
	gl := gitlabIssuerConfig("https://gitlab.com", "aws-oidc-warden")
	ex := newTestAPIGWExtractorMulti(*gh, *gl)
	now := time.Now()

	_, err := ex.Extract(context.Background(), validator.ExtractionInput{
		AuthorizerClaims: map[string]string{
			"sub":        "repo:org/repo",
			"aud":        "sts.amazonaws.com",
			"exp":        unixStr(now.Add(time.Hour)),
			"iat":        unixStr(now),
			"repository": "org/repo",
		},
	})
	require.ErrorIs(t, err, validator.ErrUnknownIssuer)
}
