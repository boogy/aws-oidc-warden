package validator

import (
	"context"
	"fmt"

	"github.com/boogy/aws-oidc-warden/internal/types"
)

// SelfExtractor validates the JWT signature and claims using the full
// TokenValidatorInterface. This is the default mode.
type SelfExtractor struct {
	v TokenValidatorInterface
}

// NewSelfExtractor creates a SelfExtractor backed by the given validator.
func NewSelfExtractor(v TokenValidatorInterface) *SelfExtractor {
	return &SelfExtractor{v: v}
}

// Extract validates the JWT in input.Token and returns the verified claims.
func (s *SelfExtractor) Extract(_ context.Context, input ExtractionInput) (*types.GithubClaims, error) {
	if input.Token == "" {
		return nil, fmt.Errorf("token is required in self-validation mode")
	}
	return s.v.Validate(input.Token)
}
