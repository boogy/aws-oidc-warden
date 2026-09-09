package handler

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

// Every sentinel's public contract: the errorCode a client branches on and the
// status it branches on it with. An STS authorization refusal must not share
// the 5xx of a broker fault.
func TestClassifyError(t *testing.T) {
	tests := []struct {
		err        error
		wantCode   string
		wantStatus int
	}{
		{ErrEmptyToken, "invalid_request", http.StatusBadRequest},
		{ErrTokenValidationFailed, "token_invalid", http.StatusUnauthorized},
		{ErrRoleNotPermitted, "permission_denied", http.StatusForbidden},
		{ErrAccountNotAllowed, "permission_denied", http.StatusForbidden},
		{ErrSessionPolicyAccess, "policy_error", http.StatusInternalServerError},
		{ErrAssumeRoleDenied, "assume_role_denied", http.StatusForbidden},
		{ErrAssumeRoleFailed, "assume_role_failed", http.StatusInternalServerError},
		{ErrAuditWriteFailed, "audit_write_failed", http.StatusInternalServerError},
		{errors.New("unmapped"), "internal_error", http.StatusInternalServerError},
	}

	for _, tc := range tests {
		t.Run(tc.wantCode+"/"+tc.err.Error(), func(t *testing.T) {
			status := http.StatusInternalServerError
			// Wrapped, as every call site wraps it before responding.
			code, msg := classifyError(fmt.Errorf("stage failed: %w", tc.err), &status)
			if code != tc.wantCode || status != tc.wantStatus {
				t.Errorf("got (%s, %d), want (%s, %d)", code, status, tc.wantCode, tc.wantStatus)
			}
			if msg == "" {
				t.Error("empty client message")
			}
		})
	}
}

// A denial and a fault must never both match: the switch is ordered, so a
// sentinel wrapping regression would silently collapse the 403 back into a 500.
func TestClassifyErrorDenialAndFaultAreDisjoint(t *testing.T) {
	if errors.Is(ErrAssumeRoleDenied, ErrAssumeRoleFailed) || errors.Is(ErrAssumeRoleFailed, ErrAssumeRoleDenied) {
		t.Fatal("assume-role sentinels must be independent")
	}
}
