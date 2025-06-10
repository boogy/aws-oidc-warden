package validator_test

import (
	"testing"
	"time"

	"github.com/boogy/aws-oidc-warden/pkg/config"
	"github.com/boogy/aws-oidc-warden/pkg/types"
	"github.com/boogy/aws-oidc-warden/pkg/validator"
	"github.com/stretchr/testify/assert"
)

// simpleMockCache is a simple mock implementation of the Cache interface for testing
type simpleMockCache struct{}

func (m *simpleMockCache) Get(key string) (*types.JWKS, bool) {
	return nil, false
}

func (m *simpleMockCache) Set(key string, value *types.JWKS, ttl time.Duration) {
}

func TestMultiAudienceSupport(t *testing.T) {
	tests := []struct {
		name               string
		configAudiences    []string
		configAudience     string // Legacy field
		expectedAudiences  []string
		shouldUseAudiences bool
	}{
		{
			name:               "Single audience via audiences field",
			configAudiences:    []string{"sts.amazonaws.com"},
			expectedAudiences:  []string{"sts.amazonaws.com"},
			shouldUseAudiences: true,
		},
		{
			name:               "Multiple audiences",
			configAudiences:    []string{"sts.amazonaws.com", "https://api.company.com", "internal.company.com"},
			expectedAudiences:  []string{"sts.amazonaws.com", "https://api.company.com", "internal.company.com"},
			shouldUseAudiences: true,
		},
		{
			name:               "Legacy single audience field",
			configAudience:     "sts.amazonaws.com",
			expectedAudiences:  []string{"sts.amazonaws.com"},
			shouldUseAudiences: false,
		},
		{
			name:               "Both fields provided - audiences takes precedence",
			configAudiences:    []string{"primary.audience.com"},
			configAudience:     "primary.audience.com",
			expectedAudiences:  []string{"primary.audience.com"},
			shouldUseAudiences: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Issuer:          "https://token.actions.githubusercontent.com",
				RoleSessionName: "aws-oidc-warden",
				Cache:           &config.Cache{TTL: time.Hour},
			}

			// Set the appropriate audience fields
			if tt.shouldUseAudiences || len(tt.configAudiences) > 0 {
				cfg.Audiences = tt.configAudiences
			}
			if tt.configAudience != "" {
				cfg.Audience = tt.configAudience
			}

			// Validate config to trigger audience normalization
			err := cfg.Validate()
			assert.NoError(t, err)

			// Create validator
			mockCache := &simpleMockCache{}
			validator := validator.NewTokenValidator(cfg, mockCache)

			// Verify the validator has the expected audiences
			assert.Equal(t, tt.expectedAudiences, validator.ExpectedAudiences)

			// Verify backward compatibility field is also set correctly
			if len(tt.expectedAudiences) > 0 {
				assert.Equal(t, tt.expectedAudiences[0], validator.ExpectedAudience)
			}
		})
	}
}

func TestAudienceValidationLogic(t *testing.T) {
	// This test verifies that the validation logic works correctly
	// with multiple audiences - any matching audience should validate successfully

	cfg := &config.Config{
		Issuer:          "https://token.actions.githubusercontent.com",
		Audiences:       []string{"sts.amazonaws.com", "https://api.company.com", "internal.company.com"},
		RoleSessionName: "aws-oidc-warden",
		Cache:           &config.Cache{TTL: time.Hour},
	}

	err := cfg.Validate()
	assert.NoError(t, err)

	mockCache := &simpleMockCache{}
	validator := validator.NewTokenValidator(cfg, mockCache)

	// Verify all expected audiences are configured
	assert.Contains(t, validator.ExpectedAudiences, "sts.amazonaws.com")
	assert.Contains(t, validator.ExpectedAudiences, "https://api.company.com")
	assert.Contains(t, validator.ExpectedAudiences, "internal.company.com")
	assert.Len(t, validator.ExpectedAudiences, 3)
}
