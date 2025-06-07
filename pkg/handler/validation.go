package handler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/boogy/aws-oidc-warden/pkg/utils"
)

// ValidateRequestData validates common request data fields
func ValidateRequestData(token, role string) error {
	// Validate token is not empty
	if strings.TrimSpace(token) == "" {
		return ErrEmptyToken
	}

	// Check token length for security (prevent DoS)
	if len(token) > MaxTokenLength {
		return ErrTokenTooLarge
	}

	// Validate role
	if strings.TrimSpace(role) == "" {
		return ErrEmptyRole
	}

	// Check role length for security
	if len(role) > MaxRoleLength {
		return ErrRoleTooLarge
	}

	isValidPrefix := false
	for _, prefix := range ValidPrefixes {
		if strings.HasPrefix(role, prefix) {
			isValidPrefix = true
			break
		}
	}

	if !isValidPrefix {
		return fmt.Errorf("role does not appear to be a valid AWS IAM role ARN: %w", ErrEmptyRole)
	}

	return nil
}

// ParseRequestBody parses and validates JSON request body into RequestData
func ParseRequestBody(body string) (*RequestData, error) {
	// Validate request body is not empty
	if strings.TrimSpace(body) == "" {
		return nil, fmt.Errorf("request body is empty: %w", ErrInvalidJSON)
	}

	// Check if body exceeds maximum allowed size (sanity check)
	if len(body) > 1024*1024 { // 1MB limit
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
