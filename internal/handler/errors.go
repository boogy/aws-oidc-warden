package handler

import (
	"errors"
	"net/http"
)

// classifyError maps sentinel errors to an error code, human-readable message,
// and (optionally) overrides statusCode. Shared by all frontend adapters to
// avoid duplicating the switch in each respondError implementation.
func classifyError(err error, statusCode *int) (errCode, errMsg string) {
	errCode = "internal_error"
	errMsg = "An internal error occurred"
	switch {
	case errors.Is(err, ErrEmptyToken), errors.Is(err, ErrTokenTooLarge),
		errors.Is(err, ErrEmptyRole), errors.Is(err, ErrInvalidRoleFormat),
		errors.Is(err, ErrRoleTooLarge), errors.Is(err, ErrInvalidJSON):
		errCode = "invalid_request"
		errMsg = "Invalid request parameters"
		*statusCode = http.StatusBadRequest
	case errors.Is(err, ErrTokenValidationFailed):
		errCode = "token_invalid"
		errMsg = "Token validation failed"
		*statusCode = http.StatusUnauthorized
	case errors.Is(err, ErrRoleNotPermitted), errors.Is(err, ErrAccountNotAllowed):
		errCode = "permission_denied"
		errMsg = "Permission denied for the requested operation"
		*statusCode = http.StatusForbidden
	case errors.Is(err, ErrSessionPolicyAccess):
		errCode = "policy_error"
		errMsg = "Error accessing policy information"
		*statusCode = http.StatusInternalServerError
	case errors.Is(err, ErrAssumeRoleFailed):
		errCode = "assume_role_failed"
		errMsg = "Failed to assume the requested role"
		*statusCode = http.StatusInternalServerError
	case errors.Is(err, ErrAuditWriteFailed):
		errCode = "audit_write_failed"
		errMsg = "Request denied: durable audit logging is required and unavailable"
		*statusCode = http.StatusInternalServerError
	}
	return
}
