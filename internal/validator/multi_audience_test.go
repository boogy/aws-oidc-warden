package validator_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/cache"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidate_AudienceMatchTableDriven exercises IssuerConfig.Audiences'
// ANY-match semantics across a range of configured audience sets and token
// audiences: any single matching audience must validate, and a token whose
// audience isn't in the configured set must always be rejected.
func TestValidate_AudienceMatchTableDriven(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwks := &types.JWKS{Keys: []types.JSONWebKey{jwkFromKey("k1", &key.PublicKey)}}
	srv := oidcServer(t, func() *types.JWKS { return jwks })

	tests := []struct {
		name                string
		configuredAudiences []string
		tokenAudience       string
		wantErr             bool
	}{
		{
			name:                "single configured audience, matching token",
			configuredAudiences: []string{"sts.amazonaws.com"},
			tokenAudience:       "sts.amazonaws.com",
			wantErr:             false,
		},
		{
			name:                "single configured audience, non-matching token",
			configuredAudiences: []string{"sts.amazonaws.com"},
			tokenAudience:       "attacker.example.com",
			wantErr:             true,
		},
		{
			name:                "multiple configured audiences, first matches",
			configuredAudiences: []string{"sts.amazonaws.com", "https://api.company.com", "internal.company.com"},
			tokenAudience:       "sts.amazonaws.com",
			wantErr:             false,
		},
		{
			name:                "multiple configured audiences, middle matches",
			configuredAudiences: []string{"sts.amazonaws.com", "https://api.company.com", "internal.company.com"},
			tokenAudience:       "https://api.company.com",
			wantErr:             false,
		},
		{
			name:                "multiple configured audiences, last matches",
			configuredAudiences: []string{"sts.amazonaws.com", "https://api.company.com", "internal.company.com"},
			tokenAudience:       "internal.company.com",
			wantErr:             false,
		},
		{
			name:                "multiple configured audiences, none match",
			configuredAudiences: []string{"sts.amazonaws.com", "https://api.company.com", "internal.company.com"},
			tokenAudience:       "not-in-the-list.example.com",
			wantErr:             true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := githubIssuer(srv.URL, tt.configuredAudiences...)
			require.NoError(t, cfg.Validate())

			v := validator.NewTokenValidator(config.NewStaticProvider(cfg), cache.NewMemoryCache())

			token := signToken(t, key, "k1", srv.URL, tt.tokenAudience)
			claims, err := v.Validate(token)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, claims)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, claims)
			assert.Equal(t, "owner/repo", claims.Repository)
			assert.Contains(t, claims.Audience, tt.tokenAudience)
		})
	}
}

// TestValidate_EmptyAudiencesConfiguredDeniesEverything guards against a
// config-level regression: an issuer with no configured audiences (which
// config.Validate() itself rejects) must not be reachable at runtime even if
// it somehow is — audienceMatches denies on an empty expected set, as
// defense in depth against a mis-cloned config bypassing Validate().
func TestValidate_EmptyAudiencesConfiguredDeniesEverything(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwks := &types.JWKS{Keys: []types.JSONWebKey{jwkFromKey("k1", &key.PublicKey)}}
	srv := oidcServer(t, func() *types.JWKS { return jwks })

	// Hand-built, deliberately bypassing config.Validate() (which would
	// reject an issuer with zero audiences) to test the runtime guard itself.
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{
			{Issuer: srv.URL, Provider: "github", RequiredClaims: []string{"repository"}},
		},
		Cache:                &config.Cache{TTL: 10 * time.Minute},
		AllowInsecureIssuers: true,
	}

	v := validator.NewTokenValidator(config.NewStaticProvider(cfg), cache.NewMemoryCache())

	token := signToken(t, key, "k1", srv.URL, "sts.amazonaws.com")
	_, err = v.Validate(token)
	assert.Error(t, err)
}
