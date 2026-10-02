package handler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/boogy/aws-oidc-warden/internal/aws"
	"github.com/boogy/aws-oidc-warden/internal/config"
	gtypes "github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		{ErrConfigStale, "config_stale", http.StatusServiceUnavailable},
		{fmt.Errorf("%w: %w", ErrConfigStale, ErrAuditWriteFailed), "audit_write_failed", http.StatusInternalServerError},
		{ErrIdPNotPermitted, "idp_not_permitted", http.StatusForbidden},
		{ErrIdPUnavailable, "idp_signing_unavailable", http.StatusServiceUnavailable},
		{ErrMethodNotAllowed, "method_not_allowed", http.StatusMethodNotAllowed},
		{ErrIdPPathNotFound, "idp_path_not_found", http.StatusNotFound},
		{ErrIdPTokenTooLarge, "idp_token_too_large", http.StatusInternalServerError},
		{ErrInvalidDuration, "invalid_duration", http.StatusBadRequest},
		{ErrDurationExceedsCap, "duration_exceeds_cap", http.StatusBadRequest},
		{ErrDurationExceedsRoleMax, "duration_exceeds_role_max", http.StatusBadRequest},
		{ErrInvalidSessionName, "invalid_session_name", http.StatusBadRequest},
		{ErrSessionNameNotPermitted, "session_name_not_permitted", http.StatusForbidden},
		{ErrIdPSourceIdentityInvalid, "idp_source_identity_invalid", http.StatusForbidden},
		{ErrIdPExchangeDenied, "idp_exchange_denied", http.StatusForbidden},
		{ErrIdPExchangeUnavailable, "idp_exchange_unavailable", http.StatusServiceUnavailable},
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

func TestClassifyErrorIdPSentinelsDistinct(t *testing.T) {
	all := []error{
		ErrIdPNotPermitted, ErrIdPUnavailable, ErrMethodNotAllowed, ErrIdPPathNotFound,
		ErrIdPTokenTooLarge, ErrInvalidDuration, ErrDurationExceedsCap, ErrDurationExceedsRoleMax,
		ErrInvalidSessionName, ErrSessionNameNotPermitted,
		ErrIdPSourceIdentityInvalid, ErrIdPExchangeDenied, ErrIdPExchangeUnavailable,
		ErrAssumeRoleDenied, ErrAssumeRoleFailed,
	}
	for i, a := range all {
		for j, b := range all {
			if i != j && errors.Is(a, b) {
				t.Errorf("%v matches %v", a, b)
			}
		}
	}
}

type stubConsumer struct {
	aws.AwsConsumerInterface
	assumeCalls int
	sessionName string
	duration    int32
}

func (s *stubConsumer) IsTargetAccountAllowed(context.Context, string) (bool, error) {
	return true, nil
}

func (s *stubConsumer) GetRoleTags(context.Context, string) (map[string]string, error) {
	s.assumeCalls++
	return nil, nil
}

func (s *stubConsumer) AssumeRole(_ context.Context, _, sessionName string, _ *string, duration *int32, _ *gtypes.Claims, _ map[string]string) (*types.Credentials, error) {
	s.assumeCalls++
	s.sessionName = sessionName
	if duration != nil {
		s.duration = *duration
	}
	return &types.Credentials{}, nil
}

type stubExtractor struct{ claims *gtypes.Claims }

func (e *stubExtractor) Extract(context.Context, validator.ExtractionInput) (*gtypes.Claims, error) {
	return e.claims, nil
}

func TestCredentialPathSessionFields(t *testing.T) {
	const issuer = "https://token.actions.githubusercontent.com"
	const role = "arn:aws:iam::123456789012:role/MyRole"
	tests := []struct {
		name         string
		fixed        string
		req          *RequestData
		wantErr      error
		wantName     string
		wantDuration int32
	}{
		{"defaults", "", &RequestData{Role: role}, nil, "test", 3600},
		{"mapping name default", "mapped", &RequestData{Role: role}, nil, "mapped", 3600},
		{"requested name", "", &RequestData{Role: role, SessionName: "asked"}, nil, "asked", 3600},
		{"mapping name overrides request", "mapped", &RequestData{Role: role, SessionName: "asked"}, nil, "mapped", 3600},
		{"invalid name", "", &RequestData{Role: role, SessionName: "bad name!"}, ErrInvalidSessionName, "", 0},
		{"invalid name with mapping name", "mapped", &RequestData{Role: role, SessionName: "a"}, ErrInvalidSessionName, "", 0},
		{"duration honoured", "", &RequestData{Role: role, DurationSeconds: 900}, nil, "test", 900},
		{"duration at 1h", "", &RequestData{Role: role, DurationSeconds: 3600}, nil, "test", 3600},
		{"duration over 1h", "", &RequestData{Role: role, DurationSeconds: 3601}, ErrDurationExceedsCap, "", 0},
		{"duration below minimum", "", &RequestData{Role: role, DurationSeconds: 899}, ErrInvalidDuration, "", 0},
		{"negative duration", "", &RequestData{Role: role, DurationSeconds: -1}, ErrInvalidDuration, "", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{
				Issuers: []config.IssuerConfig{{
					Issuer:    issuer,
					Provider:  "github",
					Audiences: []string{"sts.amazonaws.com"},
				}},
				RoleSessionName: "test",
				Cache:           &config.Cache{TTL: 0},
				RoleMappings: []config.RoleMapping{{
					Subject:         config.Patterns{"org/repo"},
					Roles:           []string{role},
					RoleSessionName: tc.fixed,
				}},
			}
			require.NoError(t, cfg.Validate())
			consumer := &stubConsumer{}
			ex := &stubExtractor{claims: &gtypes.Claims{
				RegisteredClaims: jwt.RegisteredClaims{Issuer: issuer, Subject: "org/repo"},
				Repository:       "org/repo",
			}}
			proc := NewRequestProcessor(config.NewStaticProvider(cfg), consumer, ex, nil, "test")
			_, err := proc.ProcessRequest(context.Background(), tc.req, validator.ExtractionInput{}, "req-1", slog.Default())
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Zero(t, consumer.assumeCalls)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantName, consumer.sessionName)
			assert.Equal(t, tc.wantDuration, consumer.duration)
		})
	}
}
