package handler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
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

// decodeRequestBody bounds and decodes a JSON request body. onDecodeErr, when
// non-nil, is called with the unmarshal error before it is translated to
// ErrInvalidJSON.
func decodeRequestBody(body string, onDecodeErr func(error)) (*RequestData, error) {
	if strings.TrimSpace(body) == "" {
		return nil, fmt.Errorf("request body is empty: %w", ErrInvalidJSON)
	}
	if len(body) > maxBodyBytes {
		return nil, fmt.Errorf("request body too large: %w", ErrInvalidJSON)
	}

	var data RequestData
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		if onDecodeErr != nil {
			onDecodeErr(err)
		}
		return nil, fmt.Errorf("invalid JSON format: %w", ErrInvalidJSON)
	}
	return &data, nil
}

// ParseRoleOnlyRequestBody parses and validates a delegated-mode request body.
// In delegated mode the JWT is validated by an upstream service; only the role
// ARN must be present in the request body.
func ParseRoleOnlyRequestBody(body string) (*RequestData, error) {
	data, err := decodeRequestBody(body, nil)
	if err != nil {
		return nil, err
	}
	if err := validateRole(data.Role); err != nil {
		return nil, err
	}
	return data, nil
}

// ParseRequestBody parses and validates JSON request body into RequestData
func ParseRequestBody(body string) (*RequestData, error) {
	data, err := decodeRequestBody(body, func(err error) {
		// No body preview: a malformed body may still contain a (partial) bearer token.
		slog.Error("Failed to unmarshal request body",
			slog.String("error", err.Error()),
			slog.Int("bodyBytes", len(body)))
	})
	if err != nil {
		return nil, err
	}

	if err := ValidateRequestData(data.Token, data.Role); err != nil {
		return nil, err
	}
	return data, nil
}
