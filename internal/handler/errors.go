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
	// Checked first: finalizeDeny folds this into the original deny error, so
	// it must win over the original sentinel or a broken audit pipeline never alerts.
	case errors.Is(err, ErrAuditWriteFailed):
		errCode = "audit_write_failed"
		errMsg = "Request denied: durable audit logging is required and unavailable"
		*statusCode = http.StatusInternalServerError
	case errors.Is(err, ErrConfigStale):
		errCode = "config_stale"
		errMsg = "Service configuration is stale; try again later"
		*statusCode = http.StatusServiceUnavailable
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
	case errors.Is(err, ErrAssumeRoleDenied):
		errCode = "assume_role_denied"
		errMsg = "AWS STS denied the role assumption for the requested role"
		*statusCode = http.StatusForbidden
	case errors.Is(err, ErrAssumeRoleFailed):
		errCode = "assume_role_failed"
		errMsg = "Failed to assume the requested role"
		*statusCode = http.StatusInternalServerError
	case errors.Is(err, ErrIdPNotPermitted):
		errCode = "idp_not_permitted"
		errMsg = "IdP token not permitted for this role"
		*statusCode = http.StatusForbidden
	case errors.Is(err, ErrIdPUnavailable):
		errCode = "idp_signing_unavailable"
		errMsg = "IdP token signing temporarily unavailable"
		*statusCode = http.StatusServiceUnavailable
	case errors.Is(err, ErrMethodNotAllowed):
		errCode = "method_not_allowed"
		errMsg = "Method not allowed"
		*statusCode = http.StatusMethodNotAllowed
	case errors.Is(err, ErrIdPPathNotFound):
		errCode = "idp_path_not_found"
		errMsg = "IdP path not found"
		*statusCode = http.StatusNotFound
	case errors.Is(err, ErrIdPTokenTooLarge):
		errCode = "idp_token_too_large"
		errMsg = "IdP token exceeds the STS size limit; reduce session tags"
		*statusCode = http.StatusInternalServerError
	case errors.Is(err, ErrInvalidDuration):
		errCode = "invalid_duration"
		errMsg = "durationSeconds must be between 900 and 43200"
		*statusCode = http.StatusBadRequest
	case errors.Is(err, ErrDurationExceedsCap):
		errCode = "duration_exceeds_cap"
		errMsg = "durationSeconds exceeds the maximum configured for this role"
		*statusCode = http.StatusBadRequest
	case errors.Is(err, ErrDurationExceedsRoleMax):
		errCode = "duration_exceeds_role_max"
		errMsg = "durationSeconds exceeds the role's MaxSessionDuration"
		*statusCode = http.StatusBadRequest
	case errors.Is(err, ErrInvalidSessionName):
		errCode = "invalid_session_name"
		errMsg = "sessionName must be 2-64 characters of [A-Za-z0-9_+=,.@-]"
		*statusCode = http.StatusBadRequest
	case errors.Is(err, ErrIdPSourceIdentityInvalid):
		errCode = "idp_source_identity_invalid"
		errMsg = "Source identity could not be derived for this request"
		*statusCode = http.StatusForbidden
	case errors.Is(err, ErrIdPExchangeDenied):
		errCode = "idp_exchange_denied"
		errMsg = "AWS refused the web identity exchange; check the role trust policy"
		*statusCode = http.StatusForbidden
	case errors.Is(err, ErrIdPExchangeUnavailable):
		errCode = "idp_exchange_unavailable"
		errMsg = "AWS could not reach the IdP; retry"
		*statusCode = http.StatusServiceUnavailable
	}
	return
}
