package validator_test

import (
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/stretchr/testify/assert"
)

func TestExtractionInputFields(t *testing.T) {
	input := validator.ExtractionInput{
		Token:            "tok",
		AuthorizerClaims: map[string]string{"repository": "org/repo"},
		ALBOIDCData:      "alb-jwt",
		AWSRegion:        "us-east-1",
	}
	assert.Equal(t, "tok", input.Token)
	assert.Equal(t, "org/repo", input.AuthorizerClaims["repository"])
	assert.Equal(t, "alb-jwt", input.ALBOIDCData)
	assert.Equal(t, "us-east-1", input.AWSRegion)
}
