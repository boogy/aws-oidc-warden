package handler

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/aws"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestResolveDuration(t *testing.T) {
	tests := []struct {
		name      string
		requested int32
		ceiling   time.Duration
		want      int32
		wantErr   error
	}{
		{"omitted", 0, time.Hour, 3600, nil},
		{"omitted, 30m ceiling", 0, 30 * time.Minute, 1800, nil},
		{"omitted, ceiling 0 (fail closed)", 0, 0, 3600, nil},
		{"7200 under 4h", 7200, 4 * time.Hour, 7200, nil},
		{"over ceiling", 18000, 4 * time.Hour, 0, ErrDurationExceedsCap},
		{"default ceiling blocks 2h", 7200, time.Hour, 0, ErrDurationExceedsCap},
		{"43200 under default", 43200, time.Hour, 0, ErrDurationExceedsCap},
		{"43200 under 12h", 43200, 12 * time.Hour, 43200, nil},
		{"ceiling 0 never means 12h", 7200, 0, 0, ErrDurationExceedsCap},
		{"too short", 600, 12 * time.Hour, 0, ErrInvalidDuration},
		{"too long", 43201, 12 * time.Hour, 0, ErrInvalidDuration},
		{"negative", -1, 12 * time.Hour, 0, ErrInvalidDuration},
		{"exact min", 900, time.Hour, 900, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveDuration(tt.requested, tt.ceiling)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestResolveSessionName(t *testing.T) {
	tests := []struct {
		name       string
		fixed      string
		requested  string
		want       string
		wantSource string
		wantErr    error
	}{
		{"mapping name", "fixed", "", "fixed", "mapping", nil},
		{"mapping overrides request", "fixed", "asked", "fixed", "mapping", nil},
		{"invalid request with mapping name", "fixed", "bad name!", "", "", ErrInvalidSessionName},
		{"request", "", "asked", "asked", "request", nil},
		{"invalid chars", "", "no spaces!", "", "", ErrInvalidSessionName},
		{"too short", "", "a", "", "", ErrInvalidSessionName},
		{"too long", "", strings.Repeat("a", 65), "", "", ErrInvalidSessionName},
		{"global default", "", "", "fallback", "default", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, source, err := resolveSessionName(tt.fixed, tt.requested, "fallback")
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
			require.Equal(t, tt.wantSource, source)
		})
	}
}

func TestRenderSourceIdentity(t *testing.T) {
	const gh = "https://token.actions.githubusercontent.com"
	const ghHost = "token.actions.githubusercontent.com"
	long := strings.Repeat("r", 65)
	tests := []struct {
		name      string
		tmpl      string
		overflow  string
		issuer    string
		subject   string
		claims    map[string]any
		want      string
		wantTrunc bool
		wantErr   error
	}{
		{"request id", "{request_id}", "", gh, "s", nil, "req-1", false, nil},
		{"subject altered gets hash", "{subject}", "", gh, "org/repo", nil, utils.SanitizeSTSNameHashed("org/repo"), false, nil},
		{"subject unaltered no hash", "{subject}", "", gh, "orgrepo", nil, "orgrepo", false, nil},
		{"claim", "{claim:repository}", "", gh, "s", map[string]any{"repository": "org/repo"}, utils.SanitizeSTSNameHashed("org/repo"), false, nil},
		{"issuer host", "{issuer}", "", gh, "s", nil, ghHost, false, nil},
		{"default template shape", "{issuer}:{subject}", "", gh, "org/repo", nil, ghHost + "=" + utils.SanitizeSTSNameHashed("org/repo"), false, nil},
		{"over 64 truncate", "{claim:repository}", config.IdPOverflowTruncate, gh, "s", map[string]any{"repository": long}, utils.FitSanitizedSTSName(long), true, nil},
		{"over 64 reject", "{claim:repository}", config.IdPOverflowReject, gh, "s", map[string]any{"repository": long}, "", false, ErrIdPSourceIdentityInvalid},
		{"under 2", "{claim:repository}", "", gh, "s", map[string]any{"repository": "a"}, "", false, ErrIdPSourceIdentityInvalid},
		{"missing claim", "{claim:repository}", "", gh, "s", map[string]any{}, "", false, ErrIdPSourceIdentityInvalid},
		{"claim of non-string type", "{claim:n}", "", gh, "s", map[string]any{"n": 42}, "42", false, nil},
		{"unparsable issuer", "{issuer}", "", "://bad", "s", nil, "", false, ErrIdPSourceIdentityInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, truncated, err := renderSourceIdentity(tt.tmpl, tt.overflow, "req-1", tt.issuer, tt.subject, tt.claims)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
			require.Equal(t, tt.wantTrunc, truncated)
			if tt.wantTrunc {
				require.Len(t, got, utils.MaxSTSNameLen)
			}
		})
	}

	render := func(tmpl, issuer, subject string) string {
		got, _, err := renderSourceIdentity(tmpl, "", "req-1", issuer, subject, nil)
		require.NoError(t, err)
		return got
	}
	t.Run("two issuers same subject differ", func(t *testing.T) {
		require.NotEqual(t,
			render("{issuer}:{subject}", "https://a.example", "org/repo"),
			render("{issuer}:{subject}", "https://b.example", "org/repo"))
	})
	t.Run("a/b vs a=b differ", func(t *testing.T) {
		require.NotEqual(t, render("{subject}", gh, "a/b"), render("{subject}", gh, "a=b"))
	})
}

func TestExchangeError(t *testing.T) {
	tests := []struct {
		name string
		in   error
		want error
	}{
		{"denied", aws.ErrWebIdentityDenied, ErrIdPExchangeDenied},
		{"unavailable", aws.ErrWebIdentityUnavailable, ErrIdPExchangeUnavailable},
		{"duration exceeds role max", aws.ErrWebIdentityDurationExceedsRoleMax, ErrDurationExceedsRoleMax},
		{"packed policy too large", aws.ErrWebIdentityPackedPolicyTooLarge, ErrIdPTokenTooLarge},
		{"unknown", errors.New("boom"), ErrAssumeRoleFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := fmt.Errorf("x: %w", tt.in)
			got := exchangeError(in)
			require.ErrorIs(t, got, tt.want)
			require.NotErrorIs(t, got, tt.in)
		})
	}
}
