package handler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/boogy/aws-oidc-warden/internal/utils"
)

const maxBodyBytes = 1024 * 1024

// validateRole validates that a role ARN is non-empty, within size bounds, and
// has a recognized AWS partition prefix. Extracted for reuse by both
// ValidateRequestData and ParseRoleOnlyRequestBody.
func validateRole(role string) error {
	if strings.TrimSpace(role) == "" {
		return ErrEmptyRole
	}
	if len(role) > MaxRoleLength {
		return ErrRoleTooLarge
	}
	for _, prefix := range ValidPrefixes {
		if strings.HasPrefix(role, prefix) {
			return nil
		}
	}
	return fmt.Errorf("role %q does not have a recognized AWS partition prefix: %w", role, ErrInvalidRoleFormat)
}

// ValidateRequestData validates common request data fields
func ValidateRequestData(token, role string) error {
	if strings.TrimSpace(token) == "" {
		return ErrEmptyToken
	}
	if len(token) > MaxTokenLength {
		return ErrTokenTooLarge
	}
	return validateRole(role)
}

// ParseRoleOnlyRequestBody parses and validates a delegated-mode request body.
// In delegated mode the JWT is validated by an upstream service; only the role
// ARN must be present in the request body.
func ParseRoleOnlyRequestBody(body string) (*RequestData, error) {
	if strings.TrimSpace(body) == "" {
		return nil, fmt.Errorf("request body is empty: %w", ErrInvalidJSON)
	}
	if len(body) > maxBodyBytes {
		return nil, fmt.Errorf("request body too large: %w", ErrInvalidJSON)
	}
	var data RequestData
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return nil, fmt.Errorf("invalid JSON format: %w", ErrInvalidJSON)
	}
	if err := validateRole(data.Role); err != nil {
		return nil, err
	}
	return &data, nil
}

// ParseRequestBody parses and validates JSON request body into RequestData
func ParseRequestBody(body string) (*RequestData, error) {
	// Validate request body is not empty
	if strings.TrimSpace(body) == "" {
		return nil, fmt.Errorf("request body is empty: %w", ErrInvalidJSON)
	}

	// Check if body exceeds maximum allowed size (sanity check)
	if len(body) > maxBodyBytes { // 1MB limit
		return nil, fmt.Errorf("request body too large: %w", ErrInvalidJSON)
	}

	var requestData RequestData
	if err := json.Unmarshal([]byte(body), &requestData); err != nil {
		slog.Error("Failed to unmarshal request body",
			slog.String("error", err.Error()),
			slog.String("bodyPreview", utils.TruncateString(body, 100)))
		return nil, fmt.Errorf("invalid JSON format: %w", ErrInvalidJSON)
	}

	// Validate the parsed data
	if err := ValidateRequestData(requestData.Token, requestData.Role); err != nil {
		return nil, err
	}

	return &requestData, nil
}
