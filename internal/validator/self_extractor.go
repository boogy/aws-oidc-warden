package validator

import (
	"context"
	"fmt"

	"github.com/boogy/aws-oidc-warden/internal/config"
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

// pinnedValidator is the optional seam a validator implements to be decided
// by a caller-supplied config generation. Unexported, so only *TokenValidator
// satisfies it; an external mock of TokenValidatorInterface takes the
// Validate path below unchanged.
type pinnedValidator interface {
	validateWith(cfg *config.Config, tokenString string) (*types.Claims, error)
}

// Extract validates the JWT in input.Token and returns the verified claims.
// When the caller pinned a config (ExtractionInput.Config), the token is
// validated against that same generation rather than a fresh provider read.
func (s *SelfExtractor) Extract(_ context.Context, input ExtractionInput) (*types.Claims, error) {
	if input.Token == "" {
		return nil, fmt.Errorf("token is required in self-validation mode")
	}
	if pv, ok := s.v.(pinnedValidator); ok && input.Config != nil {
		return pv.validateWith(input.Config, input.Token)
	}
	return s.v.Validate(input.Token)
}
