package validator

import (
	"testing"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func twoIssuerConfig() *config.Config {
	leeway := 30 * time.Second
	return &config.Config{
		RoleSessionName: "test",
		JWTLeeway:       &leeway,
		Issuers: []config.IssuerConfig{
			{
				Issuer:         "https://token.actions.githubusercontent.com",
				Provider:       "github",
				Audiences:      []string{"sts.amazonaws.com"},
				RequiredClaims: []string{"repository"},
			},
			{
				Issuer:         "https://gitlab.com",
				Provider:       "generic",
				Audiences:      []string{"aws-oidc-warden"},
				ClaimMappings:  map[string]string{"subject": "project_path"},
				RequiredClaims: []string{"project_path"},
			},
		},
	}
}

// resolveIssuerSpec must return the spec belonging to the requested issuer —
// never the first entry, and never a merged view of both.
func TestResolveIssuerSpec_SelectsMatchingIssuer(t *testing.T) {
	cfg := twoIssuerConfig()

	spec, bounds, err := resolveIssuerSpec(cfg, "https://gitlab.com")
	require.NoError(t, err)
	assert.Equal(t, "generic", spec.Provider)
	assert.Equal(t, []string{"aws-oidc-warden"}, spec.Audiences)
	assert.Equal(t, map[string]string{"subject": "project_path"}, spec.ClaimMappings)
	assert.Equal(t, 30*time.Second, bounds.leeway)

	spec, _, err = resolveIssuerSpec(cfg, "https://token.actions.githubusercontent.com")
	require.NoError(t, err)
	assert.Equal(t, "github", spec.Provider)
	assert.Equal(t, []string{"sts.amazonaws.com"}, spec.Audiences)
}

// An issuer with no config entry must fail closed with ErrUnknownIssuer — the
// same sentinel self mode uses (validator.go:288) — and must not fall back to
// any other issuer's spec.
func TestResolveIssuerSpec_UnknownIssuerFailsClosed(t *testing.T) {
	cfg := twoIssuerConfig()

	spec, _, err := resolveIssuerSpec(cfg, "https://evil.example.com")
	require.ErrorIs(t, err, ErrUnknownIssuer)
	assert.Nil(t, spec)
}

// Exact matching only: no normalization of trailing slashes or case, matching
// config.Validate's duplicate-issuer semantics.
func TestResolveIssuerSpec_ExactMatchOnly(t *testing.T) {
	cfg := twoIssuerConfig()

	_, _, err := resolveIssuerSpec(cfg, "https://gitlab.com/")
	require.ErrorIs(t, err, ErrUnknownIssuer)

	_, _, err = resolveIssuerSpec(cfg, "https://GitLab.com")
	require.ErrorIs(t, err, ErrUnknownIssuer)
}
