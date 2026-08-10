package handler

import (
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func multiIssuerConfig(mode string) *config.Config {
	return &config.Config{
		RoleSessionName: "test",
		JWTValidation:   config.JWTValidation{Mode: mode},
		Issuers: []config.IssuerConfig{
			{
				Issuer:    "https://token.actions.githubusercontent.com",
				Provider:  "github",
				Audiences: []string{"sts.amazonaws.com"},
			},
			{
				Issuer:        "https://gitlab.com",
				Provider:      "generic",
				Audiences:     []string{"aws-oidc-warden"},
				ClaimMappings: map[string]string{"subject": "project_path"},
			},
		},
	}
}

// apigw mode gives each route its own JWT authorizer, so several configured
// issuers is a valid deployment and must not fail closed at cold start.
func TestNewClaimsExtractor_APIGWAllowsMultipleIssuers(t *testing.T) {
	ex, err := newClaimsExtractor(config.NewStaticProvider(multiIssuerConfig("apigw")), nil)
	require.NoError(t, err)
	assert.NotNil(t, ex)
}

// alb mode still trusts a single OIDC IdP, so a multi-issuer config stays
// ambiguous and must be rejected.
func TestNewClaimsExtractor_ALBStillRequiresSingleIssuer(t *testing.T) {
	cfg := multiIssuerConfig("alb")
	cfg.JWTValidation.ALBExpectedSigner = "arn:aws:elasticloadbalancing:eu-west-1:111122223333:loadbalancer/app/x/y"

	ex, err := newClaimsExtractor(config.NewStaticProvider(cfg), nil)
	require.Error(t, err)
	assert.Nil(t, ex)
	assert.Contains(t, err.Error(), "exactly one configured issuer")
}

// A single-issuer apigw config keeps working unchanged.
func TestNewClaimsExtractor_APIGWSingleIssuerStillWorks(t *testing.T) {
	cfg := multiIssuerConfig("apigw")
	cfg.Issuers = cfg.Issuers[:1]

	ex, err := newClaimsExtractor(config.NewStaticProvider(cfg), nil)
	require.NoError(t, err)
	assert.NotNil(t, ex)
}
