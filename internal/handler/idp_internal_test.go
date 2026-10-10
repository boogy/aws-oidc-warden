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
			var got int32
			err := checkDuration(tt.requested)
			if err == nil {
				got, err = resolveDuration(tt.requested, tt.ceiling)
			}
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
		allow      bool
		wantErr    error
	}{
		{"mapping name", "fixed", "", "fixed", "mapping", true, nil},
		{"mapping overrides request", "fixed", "asked", "fixed", "mapping", true, nil},
		{"invalid request ignored for mapping name", "fixed", "bad name!", "fixed", "mapping", true, nil},
		{"request", "", "asked", "asked", "request", true, nil},
		{"request ignored without opt-in", "", "asked", "fallback", "default", false, nil},
		{"invalid request ignored without opt-in", "", "bad name!", "fallback", "default", false, nil},
		{"invalid chars", "", "no spaces!", "", "", true, ErrInvalidSessionName},
		{"too short", "", "a", "", "", true, ErrInvalidSessionName},
		{"too long", "", strings.Repeat("a", 65), "", "", true, ErrInvalidSessionName},
		{"global default", "", "", "fallback", "default", true, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, source, err := resolveSessionName(tt.fixed, tt.requested, "fallback", tt.allow)
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
	tail := func(raw ...string) string { return sourceIdentityTail(raw) }
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
		{"subject altered gets hash", "{subject}", "", gh, "org/repo", nil, "org=repo" + tail("org/repo"), false, nil},
		{"subject unaltered no hash", "{subject}", "", gh, "orgrepo", nil, "orgrepo", false, nil},
		{"claim", "{claim:repository}", "", gh, "s", map[string]any{"repository": "org/repo"}, "org=repo" + tail("org/repo"), false, nil},
		{"issuer host", "{issuer}", "", gh, "s", nil, ghHost, false, nil},
		{"default template shape", "{issuer}:{subject}", "", gh, "org/repo", nil, ghHost + "=org=repo" + tail(ghHost, "org/repo"), false, nil},
		{"default template fits 16-char github subject", "{issuer}:{subject}", config.IdPOverflowReject, gh, "octo-org/api-svc", nil, ghHost + "=octo-org=api-svc" + tail(ghHost, "octo-org/api-svc"), false, nil},
		{"default template truncates long github subject", "{issuer}:{subject}", "", gh, "octo-org/api-service", nil, (ghHost + "=octo-org=api-service")[:52] + tail(ghHost, "octo-org/api-service"), true, nil},
		{"default template rejects long github subject", "{issuer}:{subject}", config.IdPOverflowReject, gh, "octo-org/api-service", nil, "", false, ErrIdPSourceIdentityInvalid},
		{"altered value overflowing only with tail rejects", "{subject}", config.IdPOverflowReject, gh, strings.Repeat("r", 60) + "/x", nil, "", false, ErrIdPSourceIdentityInvalid},
		{"over 64 truncate", "{claim:repository}", config.IdPOverflowTruncate, gh, "s", map[string]any{"repository": long}, strings.Repeat("r", 52) + tail(long), true, nil},
		{"over 64 reject", "{claim:repository}", config.IdPOverflowReject, gh, "s", map[string]any{"repository": long}, "", false, ErrIdPSourceIdentityInvalid},
		{"under 2", "{claim:repository}", "", gh, "s", map[string]any{"repository": "a"}, "", false, ErrIdPSourceIdentityInvalid},
		{"missing claim", "{claim:repository}", "", gh, "s", map[string]any{}, "", false, ErrIdPSourceIdentityInvalid},
		{"null claim", "{claim:actor}-gh", "", gh, "s", map[string]any{"actor": nil}, "", false, ErrIdPSourceIdentityInvalid},
		{"empty claim", "{claim:actor}-gh", "", gh, "s", map[string]any{"actor": ""}, "", false, ErrIdPSourceIdentityInvalid},
		{"empty list claim", "{claim:actor}-gh", "", gh, "s", map[string]any{"actor": []any{}}, "", false, ErrIdPSourceIdentityInvalid},
		{"empty object claim", "{claim:actor}-gh", "", gh, "s", map[string]any{"actor": map[string]any{}}, "", false, ErrIdPSourceIdentityInvalid},
		{"claim of non-string type", "{claim:n}", "", gh, "s", map[string]any{"n": 42}, "42", false, nil},
		{"unparsable issuer", "{issuer}", "", "://bad", "s", nil, "", false, ErrIdPSourceIdentityInvalid},
		{"hostless issuer", "{issuer}:{subject}", "", "a.example.com", "s", nil, "", false, ErrIdPSourceIdentityInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, truncated, err := parseSourceIdentity(tt.tmpl, tt.overflow).render("req-1", tt.issuer, tt.subject, tt.claims)
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
		got, _, err := parseSourceIdentity(tmpl, "").render("req-1", issuer, subject, nil)
		require.NoError(t, err)
		return got
	}
	t.Run("two issuers same subject differ", func(t *testing.T) {
		require.NotEqual(t,
			render("{issuer}:{subject}", "https://a.example", "org/repo"),
			render("{issuer}:{subject}", "https://b.example", "org/repo"))
	})
	t.Run("same host different path differ", func(t *testing.T) {
		require.NotEqual(t,
			render("{issuer}:{subject}", "https://kc.example.com/realms/a", "x"),
			render("{issuer}:{subject}", "https://kc.example.com/realms/b", "x"))
	})
	t.Run("trailing slash ignored", func(t *testing.T) {
		require.Equal(t, render("{issuer}", "https://a.example/", "x"), render("{issuer}", "https://a.example", "x"))
	})
	t.Run("a/b vs a=b differ", func(t *testing.T) {
		require.NotEqual(t, render("{subject}", gh, "a/b"), render("{subject}", gh, "a=b"))
	})
	t.Run("truncated values sharing a prefix differ", func(t *testing.T) {
		prefix := strings.Repeat("r", 70)
		require.NotEqual(t, render("{subject}", gh, prefix+"a"), render("{subject}", gh, prefix+"b"))
	})
	t.Run("tail separates value boundaries", func(t *testing.T) {
		a, _, err := parseSourceIdentity("{subject}{claim:x}", "").render("r", gh, "a/", map[string]any{"x": "b"})
		require.NoError(t, err)
		b, _, err := parseSourceIdentity("{subject}{claim:x}", "").render("r", gh, "a", map[string]any{"x": "/b"})
		require.NoError(t, err)
		require.NotEqual(t, a, b)
	})
	t.Run("tail is STS-safe", func(t *testing.T) {
		require.Regexp(t, `^\+[\w-]{11}$`, tail("a/b"))
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
