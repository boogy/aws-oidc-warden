package handler_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
	gtvaws "github.com/boogy/aws-oidc-warden/internal/aws"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/handler"
	"github.com/boogy/aws-oidc-warden/internal/idp"
	"github.com/boogy/aws-oidc-warden/internal/idp/idptest"
	"github.com/boogy/aws-oidc-warden/internal/utils"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testRoleARN  = "arn:aws:iam::123456789012:role/MyRole"
	otherRoleARN = "arn:aws:iam::123456789012:role/Other"
	testSecret   = "SECRETEXAMPLEwJalr"
	testSessTok  = "SESSIONTOKENEXAMPLEFwoG"
)

var errBoom = errors.New("boom")

func (f *fakeAuditSink) dump(t *testing.T) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var parts []string
	for _, r := range f.records {
		parts = append(parts, string(r))
	}
	return strings.Join(parts, "\n")
}

func (f *fakeAuditSink) at(t *testing.T, i int) map[string]any {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	require.Greater(t, len(f.records), i)
	var m map[string]any
	require.NoError(t, json.Unmarshal(f.records[i], &m))
	return m
}

func idpConfig(t *testing.T, idpToken bool, policy string, mutate ...func(*config.Config)) *config.Config {
	t.Helper()
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer:    testIssuer,
			Provider:  "github",
			Audiences: []string{"sts.amazonaws.com"},
		}},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 0},
		RoleMappings: []config.RoleMapping{{
			Subject:       config.Patterns{"org/repo"},
			Roles:         []string{testRoleARN},
			IDPToken:      idpToken,
			SessionPolicy: policy,
		}},
		IdP: &config.IdPConfig{
			Enabled:     true,
			Issuer:      "https://idp.example.com",
			Audience:    "sts.amazonaws.com",
			SigningKeys: []config.IdPSigningKey{{File: "/unused", Algorithm: "ES256", Status: config.IdPKeyActive}},
		},
	}
	for _, m := range mutate {
		m(cfg)
	}
	require.NoError(t, cfg.Validate())
	return cfg
}

type countingSigner struct {
	idp.Signer
	calls int
	err   error
	last  []byte
}

func (s *countingSigner) Sign(ctx context.Context, in []byte) ([]byte, error) {
	s.calls++
	s.last = append(s.last[:0], in...)
	if s.err != nil {
		return nil, s.err
	}
	return s.Signer.Sign(ctx, in)
}

func (s *countingSigner) lastClaims(t *testing.T) map[string]any {
	t.Helper()
	parts := strings.Split(string(s.last), ".")
	require.Len(t, parts, 2)
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	return m
}

func idpService(t *testing.T, cfg *config.Config, signer *countingSigner, loadErr error) *idp.Service {
	t.Helper()
	loader := func(context.Context) ([]idp.LoadedKey, error) {
		if loadErr != nil {
			return nil, loadErr
		}
		return []idp.LoadedKey{{Signer: signer, Status: config.IdPKeyActive}}, nil
	}
	return idp.NewService(*cfg.IdP, loader)
}

func idpProcessorFor(t *testing.T, cfg *config.Config, cons gtvaws.AwsConsumerInterface, ext validator.ClaimsExtractorInterface) (*handler.RequestProcessor, *fakeAuditSink, *countingSigner) {
	t.Helper()
	signer := &countingSigner{Signer: idptest.NewSigner(t)}
	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), cons, ext, sink, "apigatewayv2").
		WithIdP(idpService(t, cfg, signer, nil))
	return proc, sink, signer
}

func idpClaims(raw map[string]any) *fixedExtractor {
	c := allowClaims("org/repo")
	if raw != nil {
		c.Raw = raw
	}
	return &fixedExtractor{claims: c}
}

func idpLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func mint(t *testing.T, proc *handler.RequestProcessor, rd handler.RequestData, buf *bytes.Buffer) (*handler.IssuedCredentials, error) {
	t.Helper()
	if rd.Role == "" {
		rd.Role = testRoleARN
	}
	return proc.ProcessRequest(context.Background(), &rd, validator.ExtractionInput{Token: "t"}, "req-1", idpLogger(buf))
}

func mockWI(t *testing.T) *fakeConsumer { return mockConsumer(t) }

func TestProcessMint(t *testing.T) {
	tests := []struct {
		name       string
		optedIn    bool
		role       string
		duration   int32
		wantErr    error
		wantMint   bool
		wantAction any
	}{
		{"opted_in_mints", true, testRoleARN, 0, nil, true, "mint_token"},
		{"opted_in_mints_within_1h", true, testRoleARN, 900, nil, true, "mint_token"},
		{"not_opted_in_over_1h", false, testRoleARN, 7200, handler.ErrIdPNotPermitted, false, nil},
		{"role_not_granted", true, otherRoleARN, 0, handler.ErrRoleNotPermitted, false, nil},
		{"role_not_granted_over_1h", true, otherRoleARN, 7200, handler.ErrRoleNotPermitted, false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := idpConfig(t, tt.optedIn, "")
			cons := mockWI(t)
			proc, sink, _ := idpProcessorFor(t, cfg, cons, idpClaims(nil))
			var buf bytes.Buffer
			res, err := mint(t, proc, handler.RequestData{Role: tt.role, DurationSeconds: tt.duration}, &buf)

			assert.Zero(t, cons.assumeCalls)
			assert.Zero(t, cons.tagCalls)
			rec := sink.last(t)
			assert.Equal(t, tt.wantAction, rec["action"])
			if tt.wantMint {
				require.NoError(t, err)
				assert.Equal(t, "AKIAEXAMPLE", *res.AccessKeyId)
				assert.Equal(t, 1, cons.wiCalls)
				assert.Equal(t, "allow", rec["decision"])
				assert.NotEmpty(t, rec["tokenId"])
			} else {
				require.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, res)
				assert.Zero(t, cons.wiCalls)
				assert.Equal(t, "deny", rec["decision"])
			}
			assert.NotContains(t, sink.dump(t), testSecret)
			if cons.lastWI.token != "" {
				assert.NotContains(t, sink.dump(t), cons.lastWI.token)
			}
		})
	}
}

func TestProcessMintDuration(t *testing.T) {
	apiErr := &smithy.GenericAPIError{Code: "ValidationError", Message: "DurationSeconds exceeds the MaxSessionDuration"}
	roleMax := fmt.Errorf("%w: %w", gtvaws.ErrWebIdentityDurationExceedsRoleMax, apiErr)
	h := time.Hour
	tests := []struct {
		name      string
		mapCap    time.Duration
		requested int32
		exchErr   error
		want      int32
		wantCap   int
		err       error
		signed    bool
	}{
		{"omitted", 0, 0, nil, 3600, 3600, nil, true},
		{"omitted_30m_cap", 30 * time.Minute, 0, nil, 1800, 1800, nil, true},
		{"7200_4h_cap", 4 * h, 7200, nil, 7200, 14400, nil, true},
		{"over_cap", 4 * h, 18000, nil, 0, 0, handler.ErrDurationExceedsCap, false},
		{"default_ceiling", 0, 7200, nil, 0, 0, handler.ErrDurationExceedsCap, false},
		{"43200_12h_cap", 12 * h, 43200, nil, 43200, 43200, nil, true},
		{"too_short", 12 * h, 600, nil, 0, 0, handler.ErrInvalidDuration, false},
		{"too_long", 12 * h, 43201, nil, 0, 0, handler.ErrInvalidDuration, false},
		{"negative", 12 * h, -1, nil, 0, 0, handler.ErrInvalidDuration, false},
		{"role_max", 0, 3600, roleMax, 0, 0, handler.ErrDurationExceedsRoleMax, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := idpConfig(t, true, "", func(c *config.Config) { c.RoleMappings[0].MaxSessionDuration = tt.mapCap })
			cons := mockWI(t)
			cons.wiErr = tt.exchErr
			proc, sink, signer := idpProcessorFor(t, cfg, cons, idpClaims(nil))
			var buf bytes.Buffer
			res, err := mint(t, proc, handler.RequestData{DurationSeconds: tt.requested}, &buf)

			wantCalls := 0
			if tt.signed {
				wantCalls = 1
			}
			assert.Equal(t, wantCalls, signer.calls)
			rec := sink.last(t)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				assert.Nil(t, res)
				assert.Equal(t, "deny", rec["decision"])
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, cons.lastWI.duration)
			assert.EqualValues(t, tt.want, res.DurationSeconds)
			assert.EqualValues(t, tt.want, rec["durationSeconds"])
			assert.EqualValues(t, tt.requested, orZero(rec["requestedDurationSeconds"]))
			assert.EqualValues(t, tt.wantCap, rec["idpSessionCapSeconds"])
		})
	}
}

func TestAssumeRoleHonoursMappingSessionCap(t *testing.T) {
	tests := []struct {
		name      string
		requested int32
		want      int32
		err       error
	}{
		{"omitted_defaults_to_cap", 0, 900, nil},
		{"at_cap", 900, 900, nil},
		{"over_cap", 3600, 0, handler.ErrDurationExceedsCap},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := idpConfig(t, true, "", func(c *config.Config) {
				c.RoleMappings[0].MaxSessionDuration = 15 * time.Minute
				c.IdP.Enabled = false
			})
			cons := mockWI(t)
			proc, _, signer := idpProcessorFor(t, cfg, cons, idpClaims(nil))
			_, err := mint(t, proc, handler.RequestData{DurationSeconds: tt.requested}, &bytes.Buffer{})

			assert.Zero(t, signer.calls)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				assert.Zero(t, cons.assumeCalls)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, cons.gotDuration)
		})
	}
}

func orZero(v any) any {
	if v == nil {
		return float64(0)
	}
	return v
}

func TestProcessMintSessionName(t *testing.T) {
	tests := []struct {
		name       string
		fixed      string
		allow      bool
		requested  string
		wantName   string
		wantSource string
		err        error
	}{
		{"fixed", "fixed", false, "", "fixed", "mapping", nil},
		{"fixed_overrides_request", "fixed", false, "asked", "fixed", "mapping", nil},
		{"request", "", true, "asked", "asked", "request", nil},
		{"request_ignored_without_opt_in", "", false, "asked", "test", "default", nil},
		{"bad_charset", "", true, "bad name!", "", "", handler.ErrInvalidSessionName},
		{"too_short", "", true, "a", "", "", handler.ErrInvalidSessionName},
		{"bad_request_ignored_for_fixed", "fixed", false, "a", "fixed", "mapping", nil},
		{"global_default", "", true, "", "test", "default", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := idpConfig(t, true, "", func(c *config.Config) {
				c.RoleMappings[0].RoleSessionName = tt.fixed
				c.RoleMappings[0].AllowSessionName = tt.allow
				c.LogClaimValues = true
			})
			cons := mockWI(t)
			proc, sink, signer := idpProcessorFor(t, cfg, cons, idpClaims(nil))
			var buf bytes.Buffer
			res, err := mint(t, proc, handler.RequestData{SessionName: tt.requested}, &buf)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				assert.Zero(t, signer.calls)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantName, res.SessionName)
			assert.Equal(t, tt.wantName, cons.lastWI.name)
			rec := sink.last(t)
			assert.Equal(t, tt.wantSource, rec["sessionNameSource"])
			if tt.requested == "" {
				assert.NotContains(t, rec, "requestedSessionName")
			} else {
				assert.Equal(t, tt.requested, rec["requestedSessionName"])
			}
		})
	}
}

func TestProcessMintSourceIdentity(t *testing.T) {
	inbound := "token.actions.githubusercontent.com"
	tests := []struct {
		name      string
		tmpl      string
		overflow  string
		want      string
		truncated bool
		err       error
	}{
		{"default", "", "", inbound + "=" + utils.SanitizeSTSNameHashed("org/repo"), false, nil},
		{"request_id", "{request_id}", "", "req-1", false, nil},
		{"claim", "{claim:repository}", "", utils.SanitizeSTSNameHashed("org/repo"), false, nil},
		{"truncate", strings.Repeat("a", 70), "", strings.Repeat("a", 47), true, nil},
		{"reject_overflow", strings.Repeat("a", 70), config.IdPOverflowReject, "", false, handler.ErrIdPSourceIdentityInvalid},
		{"too_short", "a", "", "", false, handler.ErrIdPSourceIdentityInvalid},
		{"missing_claim", "{claim:nope}", "", "", false, handler.ErrIdPSourceIdentityInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := idpConfig(t, true, "", func(c *config.Config) {
				if tt.tmpl != "" {
					c.IdP.SourceIdentity = tt.tmpl
				}
				if tt.overflow != "" {
					c.IdP.SourceIdentityOverflow = tt.overflow
				}
			})
			cons := mockWI(t)
			proc, sink, signer := idpProcessorFor(t, cfg, cons, idpClaims(nil))
			var buf bytes.Buffer
			res, err := mint(t, proc, handler.RequestData{}, &buf)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				assert.Zero(t, signer.calls)
				assert.Zero(t, cons.wiCalls)
				return
			}
			require.NoError(t, err)
			if tt.truncated {
				assert.Len(t, res.SourceIdentity, 64)
				assert.True(t, strings.HasPrefix(res.SourceIdentity, tt.want))
			} else {
				assert.Equal(t, tt.want, res.SourceIdentity)
			}
			assert.Equal(t, tt.truncated, sink.last(t)["sourceIdentityTruncated"] == true)
		})
	}
}

func TestProcessMintSourceIdentityClaimOff(t *testing.T) {
	tests := []struct {
		name string
		tmpl string
	}{
		{"default_template", ""},
		{"missing_claim_template", "{claim:nope}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := idpConfig(t, true, "", func(c *config.Config) {
				c.LogClaimValues = true
				off := false
				c.IdP.IncludeSourceIdentity = &off
				if tt.tmpl != "" {
					c.IdP.SourceIdentity = tt.tmpl
				}
			})
			proc, sink, _ := idpProcessorFor(t, cfg, mockWI(t), idpClaims(nil))
			var buf bytes.Buffer
			res, err := mint(t, proc, handler.RequestData{}, &buf)
			require.NoError(t, err)
			assert.Empty(t, res.SourceIdentity)
			assert.NotContains(t, sink.last(t), "sourceIdentity")
		})
	}
}

func TestProcessMintSourceIdentityFrozenAtColdStart(t *testing.T) {
	cfg := idpConfig(t, true, "", func(c *config.Config) {
		c.LogClaimValues = true
		c.IdP.SourceIdentity = "{request_id}"
	})
	signer := &countingSigner{Signer: idptest.NewSigner(t)}
	svc := idpService(t, cfg, signer, nil)
	cfg.IdP.SourceIdentity = "swapped-literal"
	cfg.IdP.SourceIdentityOverflow = config.IdPOverflowReject
	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockWI(t), idpClaims(nil), sink, "apigatewayv2").WithIdP(svc)

	var buf bytes.Buffer
	res, err := mint(t, proc, handler.RequestData{}, &buf)
	require.NoError(t, err)
	assert.Equal(t, "req-1", res.SourceIdentity)
	assert.Equal(t, "req-1", sink.last(t)["sourceIdentity"])
}

func TestProcessMintPassesSessionPolicy(t *testing.T) {
	const policy = `{"Version":"2012-10-17","Statement":[]}`
	cfg := idpConfig(t, true, policy)
	cons := mockWI(t)
	proc, sink, _ := idpProcessorFor(t, cfg, cons, idpClaims(nil))
	var buf bytes.Buffer
	_, err := mint(t, proc, handler.RequestData{}, &buf)
	require.NoError(t, err)
	require.NotNil(t, cons.lastWI.policy)
	require.JSONEq(t, policy, *cons.lastWI.policy)
	assert.NotEmpty(t, sink.last(t)["sessionPolicyRef"])
}

func TestProcessMintExchangeErrors(t *testing.T) {
	roleMax := fmt.Errorf("%w: %w", gtvaws.ErrWebIdentityDurationExceedsRoleMax, errBoom)
	tests := []struct {
		name  string
		wiErr error
		creds *ststypes.Credentials
		want  error
	}{
		{"denied", fmt.Errorf("%w: %w", gtvaws.ErrWebIdentityDenied, errBoom), nil, handler.ErrIdPExchangeDenied},
		{"unavailable", fmt.Errorf("%w: %w", gtvaws.ErrWebIdentityUnavailable, errBoom), nil, handler.ErrIdPExchangeUnavailable},
		{"role_max", roleMax, nil, handler.ErrDurationExceedsRoleMax},
		{"packed", fmt.Errorf("%w: %w", gtvaws.ErrWebIdentityPackedPolicyTooLarge, errBoom), nil, handler.ErrIdPTokenTooLarge},
		{"account_not_allowed", fmt.Errorf("%w: %s", gtvaws.ErrAccountNotAllowed, testRoleARN), nil, handler.ErrAccountNotAllowed},
		{"other", &smithy.GenericAPIError{Code: "Throttling", Message: "slow"}, nil, handler.ErrAssumeRoleFailed},
		{"nil_access_key", nil, &ststypes.Credentials{}, handler.ErrAssumeRoleFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := idpConfig(t, true, "")
			cons := mockWI(t)
			cons.wiErr, cons.wiCreds = tt.wiErr, tt.creds
			proc, sink, _ := idpProcessorFor(t, cfg, cons, idpClaims(nil))
			var buf bytes.Buffer
			res, err := mint(t, proc, handler.RequestData{}, &buf)
			require.ErrorIs(t, err, tt.want)
			assert.Nil(t, res)
			rec := sink.last(t)
			assert.Equal(t, "deny", rec["decision"])
			switch {
			case errors.Is(tt.wiErr, gtvaws.ErrAccountNotAllowed):
				assert.Equal(t, "account_check", rec["stage"])
				assert.Equal(t, "target account not allowed", rec["reason"])
				assert.NotEmpty(t, rec["tokenId"])
			case tt.wiErr != nil:
				assert.Equal(t, "idp_exchange", rec["stage"])
				assert.Equal(t, "web identity exchange failed", rec["reason"])
			}
		})
	}
}

func TestProcessMintSignErrors(t *testing.T) {
	bigRaw := map[string]any{"repository": "org/repo"}
	bigSpec := map[string]string{}
	for i := range 50 {
		k := fmt.Sprintf("c%02d", i) + strings.Repeat("k", 120)
		bigRaw[k] = strings.Repeat("v", 256)
		bigSpec[k] = k
	}
	tests := []struct {
		name    string
		signErr error
		loadErr error
		tmpl    string
		subTmpl string
		subject string
		spec    map[string]string
		raw     map[string]any
		want    error
		signed  int
	}{
		{name: "sign_failure", signErr: errBoom, want: handler.ErrIdPUnavailable, signed: 1},
		{name: "too_large", spec: bigSpec, raw: bigRaw, want: handler.ErrIdPTokenTooLarge},
		{name: "loader_error", loadErr: errBoom, want: handler.ErrIdPUnavailable},
		{name: "invalid_subject", subTmpl: "{source_issuer}#{source_subject}#{role_arn}", subject: "org/my repo", want: handler.ErrIdPSubjectInvalid},
		{name: "source_identity", tmpl: "{claim:nope}", want: handler.ErrIdPSourceIdentityInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := idpConfig(t, true, "", func(c *config.Config) {
				if tt.tmpl != "" {
					c.IdP.SourceIdentity = tt.tmpl
				}
				if tt.spec != nil {
					c.Issuers[0].SessionTags = tt.spec
				}
				if tt.subTmpl != "" {
					c.IdP.SubjectTemplate = tt.subTmpl
					c.RoleMappings[0].Subject = config.Patterns{"org/.+"}
				}
			})
			cons := mockWI(t)
			signer := &countingSigner{Signer: idptest.NewSigner(t), err: tt.signErr}
			sink := &fakeAuditSink{}
			ext := idpClaims(tt.raw)
			if tt.subject != "" {
				ext = &fixedExtractor{claims: allowClaims(tt.subject)}
			}
			proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), cons, ext, sink, "apigatewayv2").
				WithIdP(idpService(t, cfg, signer, tt.loadErr))
			var buf bytes.Buffer
			res, err := mint(t, proc, handler.RequestData{}, &buf)
			require.ErrorIs(t, err, tt.want)
			assert.Nil(t, res)
			assert.Equal(t, tt.signed, signer.calls)
			assert.Zero(t, cons.wiCalls)
			rec := sink.last(t)
			assert.Equal(t, "deny", rec["decision"])
			assert.Equal(t, "idp_mint", rec["stage"])
		})
	}
}

func TestProcessMintWarnsOnceOnFrozenIdPDrift(t *testing.T) {
	cfg := idpConfig(t, true, "")
	signer := &countingSigner{Signer: idptest.NewSigner(t)}
	svc := idpService(t, cfg, signer, nil)
	cfg.IdP.Audience = "drifted.example.com"
	var fetches atomic.Int32
	provider := config.NewProvider(cfg, time.Hour, "yaml", func(context.Context) ([]byte, error) {
		// A changed overlay is what makes each refresh a new config generation.
		if fetches.Add(1)%2 == 0 {
			return []byte("log_level: debug\n"), nil
		}
		return []byte("log_level: info\n"), nil
	})
	proc := handler.NewRequestProcessor(provider, mockWI(t), idpClaims(nil), &fakeAuditSink{}, "apigatewayv2").WithIdP(svc)

	var buf bytes.Buffer
	count := func() int { return strings.Count(buf.String(), "config.idp.reload_ignored") }
	for range 2 {
		_, err := mint(t, proc, handler.RequestData{}, &buf)
		require.NoError(t, err)
	}
	assert.Equal(t, 1, count())

	require.NoError(t, provider.Refresh(context.Background()))
	_, err := mint(t, proc, handler.RequestData{}, &buf)
	require.NoError(t, err)
	assert.Equal(t, 2, count())
}

func TestProcessMintNeverReturnsToken(t *testing.T) {
	cfg := idpConfig(t, true, "")
	cons := mockWI(t)
	proc, _, _ := idpProcessorFor(t, cfg, cons, idpClaims(nil))
	var buf bytes.Buffer
	res, err := mint(t, proc, handler.RequestData{}, &buf)
	require.NoError(t, err)
	b, err := json.Marshal(res)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "eyJ")
	assert.NotContains(t, string(b), `token"`)
	assert.NotContains(t, string(b), cons.lastWI.token)
}

func TestProcessMintNeverLogsCredentials(t *testing.T) {
	cfg := idpConfig(t, true, "", func(c *config.Config) { c.LogClaimValues = true })
	cons := mockWI(t)
	proc, sink, _ := idpProcessorFor(t, cfg, cons, idpClaims(nil))
	var buf bytes.Buffer
	_, err := mint(t, proc, handler.RequestData{}, &buf)
	require.NoError(t, err)
	assert.Equal(t, "AKIAEXAMPLE", sink.last(t)["accessKeyId"])
	for _, sec := range []string{testSecret, testSessTok, cons.lastWI.token} {
		assert.NotContains(t, sink.dump(t), sec)
		assert.NotContains(t, buf.String(), sec)
	}
}

func TestProcessMintNeverLeaksTokenSegments(t *testing.T) {
	tests := []struct {
		name string
		lcv  bool
		echo bool
	}{
		{"success_lcv_off", false, false},
		{"success_lcv_on", true, false},
		{"echo_lcv_off", false, true},
		{"echo_lcv_on", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := idpConfig(t, true, "", func(c *config.Config) { c.LogClaimValues = tt.lcv })
			cons := mockWI(t)
			cons.wiErrEchoToken = tt.echo
			proc, sink, _ := idpProcessorFor(t, cfg, cons, idpClaims(nil))
			var buf bytes.Buffer
			_, err := mint(t, proc, handler.RequestData{}, &buf)
			if tt.echo {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			segs := strings.Split(cons.lastWI.token, ".")
			require.Len(t, segs, 3)
			for i, seg := range segs {
				assert.NotContains(t, sink.dump(t), seg, "audit segment %d", i)
				assert.NotContains(t, buf.String(), seg, "log segment %d", i)
				if err != nil {
					assert.NotContains(t, err.Error(), seg, "error segment %d", i)
				}
			}
		})
	}
}

func TestProcessMintRedactsSourceIdentity(t *testing.T) {
	srcID := "token.actions.githubusercontent.com=" + utils.SanitizeSTSNameHashed("org/repo")
	tests := []struct {
		name      string
		lcv       bool
		requested string
		wantName  string
	}{
		{"off_default_name", false, "", "test"},
		{"on_default_name", true, "", "test"},
		{"off_request_name", false, "asked", "asked"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := idpConfig(t, true, "", func(c *config.Config) {
				c.LogClaimValues = tt.lcv
				c.RoleMappings[0].AllowSessionName = true
			})
			proc, sink, _ := idpProcessorFor(t, cfg, mockWI(t), idpClaims(nil))
			var buf bytes.Buffer
			_, err := mint(t, proc, handler.RequestData{SessionName: tt.requested}, &buf)
			require.NoError(t, err)
			audit, logs := sink.dump(t), buf.String()

			assert.Contains(t, audit, `"sessionName":"`+tt.wantName+`"`, "audit sessionName")
			assert.Contains(t, logs, `"sessionName":"`+tt.wantName+`"`, "log sessionName")
			assert.Equal(t, tt.lcv, strings.Contains(audit, srcID), "audit sourceIdentity")
			assert.Equal(t, tt.lcv, strings.Contains(logs, srcID), "log sourceIdentity")
		})
	}
}

func TestProcessRequestRouting(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*config.Config)
		optedIn  bool
		duration int32
		wantErr  error
		wantWI   int
		wantAR   int
	}{
		{"opted_in_uses_idp", nil, true, 0, nil, 1, 0},
		{"not_opted_in_uses_assume_role", nil, false, 3600, nil, 0, 1},
		{"not_opted_in_over_1h", nil, false, 3601, handler.ErrIdPNotPermitted, 0, 0},
		{"kill_switch_within_1h_uses_assume_role", func(c *config.Config) { c.IdP.Enabled = false }, true, 0, nil, 0, 1},
		{"kill_switch_over_1h", func(c *config.Config) { c.IdP.Enabled = false }, true, 7200, handler.ErrIdPUnavailable, 0, 0},
		{"ceiling_over_1h_uses_idp_within_1h", func(c *config.Config) { c.RoleMappings[0].MaxSessionDuration = 4 * time.Hour }, false, 900, nil, 1, 0},
		{"ceiling_over_1h_uses_idp_over_1h", func(c *config.Config) { c.RoleMappings[0].MaxSessionDuration = 4 * time.Hour }, false, 7200, nil, 1, 0},
		{"ceiling_1h_uses_assume_role", func(c *config.Config) { c.RoleMappings[0].MaxSessionDuration = time.Hour }, false, 3600, nil, 0, 1},
		{"ceiling_over_1h_kill_switch_over_1h", func(c *config.Config) {
			c.RoleMappings[0].MaxSessionDuration = 4 * time.Hour
			c.IdP.Enabled = false
		}, false, 7200, handler.ErrIdPUnavailable, 0, 0},
		{"over_12h_invalid", nil, true, 43201, handler.ErrInvalidDuration, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mutate []func(*config.Config)
			if tt.mutate != nil {
				mutate = append(mutate, tt.mutate)
			}
			cfg := idpConfig(t, tt.optedIn, "", mutate...)
			cons := mockWI(t)
			proc, sink, signer := idpProcessorFor(t, cfg, cons, idpClaims(nil))
			var buf bytes.Buffer
			_, err := mint(t, proc, handler.RequestData{DurationSeconds: tt.duration}, &buf)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				assert.Zero(t, signer.calls)
				assert.Equal(t, "deny", sink.last(t)["decision"])
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantWI, cons.wiCalls)
			assert.Equal(t, tt.wantAR, cons.assumeCalls)
		})
	}
}

func TestProcessRequestOverOneHourWithoutIdP(t *testing.T) {
	cfg := auditTestCfg(t, false, false)
	cons := mockConsumer(t)
	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), cons, idpClaims(nil), sink, "test")
	_, err := proc.ProcessRequest(context.Background(), &handler.RequestData{Role: testRoleARN, DurationSeconds: 7200},
		validator.ExtractionInput{Token: "t"}, "req-1", slog.Default())
	require.ErrorIs(t, err, handler.ErrDurationExceedsCap)
	assert.Zero(t, cons.assumeCalls)
	assert.EqualValues(t, 7200, sink.last(t)["requestedDurationSeconds"])
}

func TestProcessRequestOverOneHourAfterIdPBlockRemoved(t *testing.T) {
	built := idpConfig(t, true, "")
	live := idpConfig(t, false, "", func(c *config.Config) { c.IdP = nil })
	cons := mockWI(t)
	signer := &countingSigner{Signer: idptest.NewSigner(t)}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(live), cons, idpClaims(nil), &fakeAuditSink{}, "test").
		WithIdP(idpService(t, built, signer, nil))
	var buf bytes.Buffer
	_, err := mint(t, proc, handler.RequestData{DurationSeconds: 7200}, &buf)
	require.ErrorIs(t, err, handler.ErrDurationExceedsCap)
	assert.Zero(t, signer.calls)
	assert.Zero(t, cons.wiCalls)
	assert.Zero(t, cons.assumeCalls)
}

func TestProcessRequestAuditActionAssumeRole(t *testing.T) {
	cfg := auditTestCfg(t, false, false)
	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t), idpClaims(nil), sink, "test")
	_, err := proc.ProcessRequest(context.Background(), &handler.RequestData{Role: testRoleARN},
		validator.ExtractionInput{Token: "t"}, "req-1", slog.Default())
	require.NoError(t, err)
	assert.Equal(t, "assume_role", sink.last(t)["action"])
}

func TestProcessMintAuditFailureWithholdsCredentials(t *testing.T) {
	cfg := idpConfig(t, true, "", func(c *config.Config) {
		c.AuditRequired, c.LogToS3, c.LogBucket = true, true, "b"
	})
	proc, sink, _ := idpProcessorFor(t, cfg, mockWI(t), idpClaims(nil))
	sink.err = errors.New("s3 down")
	var buf bytes.Buffer
	res, err := mint(t, proc, handler.RequestData{}, &buf)
	require.ErrorIs(t, err, handler.ErrAuditWriteFailed)
	assert.Nil(t, res)
}

// stsFake is the STS/IAM layer under a real AwsConsumer; it records what AssumeRole sent.
type stsFake struct {
	lastAssume *sts.AssumeRoleInput
	lastWI     *sts.AssumeRoleWithWebIdentityInput
}

func (f *stsFake) creds() *ststypes.Credentials {
	exp := time.Now().Add(time.Hour)
	return &ststypes.Credentials{
		AccessKeyId: aws.String("AKIAEXAMPLE"), SecretAccessKey: aws.String(testSecret),
		SessionToken: aws.String(testSessTok), Expiration: &exp,
	}
}

func (f *stsFake) GetS3Object(context.Context, string, string, int) (io.ReadCloser, error) {
	return nil, errors.New("unused")
}

func (f *stsFake) GetS3ObjectIfChanged(context.Context, string, string, string, string, int) ([]byte, string, error) {
	return nil, "", errors.New("not implemented")
}
func (f *stsFake) AssumeRole(_ context.Context, in *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
	f.lastAssume = in
	return &sts.AssumeRoleOutput{Credentials: f.creds()}, nil
}
func (f *stsFake) AssumeRoleWithWebIdentity(_ context.Context, in *sts.AssumeRoleWithWebIdentityInput) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	f.lastWI = in
	return &sts.AssumeRoleWithWebIdentityOutput{Credentials: f.creds()}, nil
}
func (f *stsFake) GetRole(context.Context, *iam.GetRoleInput) (*iam.GetRoleOutput, error) {
	return &iam.GetRoleOutput{}, nil
}
func (f *stsFake) GetRoleAs(context.Context, *iam.GetRoleInput, aws.CredentialsProvider) (*iam.GetRoleOutput, error) {
	return &iam.GetRoleOutput{}, nil
}
func (f *stsFake) GetCallerAccount(context.Context) (string, error) { return "123456789012", nil }
func (f *stsFake) GetCallerIdentityInfo(context.Context) (string, bool, error) {
	return "123456789012", false, nil
}

func captureConsumer(t *testing.T, cfg *config.Config) (*gtvaws.AwsConsumer, *stsFake) {
	t.Helper()
	f := &stsFake{}
	c := gtvaws.NewAwsConsumer(cfg)
	c.AWS = f
	return c, f
}

func TestSessionTagParity(t *testing.T) {
	many := map[string]string{}
	manyRaw := map[string]any{"repository": "org/repo"}
	for i := range 50 {
		k := fmt.Sprintf("t%02d", i)
		many[k] = k
		manyRaw[k] = "v"
	}
	tests := []struct {
		name       string
		issuerSpec map[string]string
		mapSpec    map[string]string
		raw        map[string]any
		transitive bool
		wantTags   int
	}{
		{"mixed_types", map[string]string{"s": "str", "n": "num", "b": "flag", "l": "list"},
			nil, map[string]any{"repository": "org/repo", "str": "v", "num": float64(42), "flag": true, "list": []any{"a", "b"}}, false, 3},
		{"invalid_value_skipped", map[string]string{"ok": "good", "bad": "bad"},
			nil, map[string]any{"repository": "org/repo", "good": "fine", "bad": "<>"}, false, 1},
		{"missing_claim_skipped", map[string]string{"ok": "repository", "gone": "absent"},
			nil, nil, false, 1},
		{"capped_at_50", many, nil, manyRaw, false, 50},
		{"mapping_extras", map[string]string{"repo": "repository"}, map[string]string{"extra": "actor"},
			map[string]any{"repository": "org/repo", "actor": "octocat"}, false, 2},
		{"transitive", map[string]string{"repo": "repository"}, nil, nil, true, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := idpConfig(t, true, "", func(c *config.Config) {
				c.LogClaimValues = true
				c.SessionTagsTransitive = tt.transitive
				c.Issuers[0].SessionTags = tt.issuerSpec
				c.RoleMappings[0].SessionTags = tt.mapSpec
			})
			cons, fake := captureConsumer(t, cfg)
			signer := &countingSigner{Signer: idptest.NewSigner(t)}
			sink := &fakeAuditSink{}
			classic := handler.NewRequestProcessor(config.NewStaticProvider(cfg), cons, idpClaims(tt.raw), sink, "apigatewayv2")
			proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), cons, idpClaims(tt.raw), sink, "apigatewayv2").
				WithIdP(idpService(t, cfg, signer, nil))

			_, err := classic.ProcessRequest(context.Background(), &handler.RequestData{Role: testRoleARN},
				validator.ExtractionInput{Token: "t"}, "req-1", slog.Default())
			require.NoError(t, err)
			var buf bytes.Buffer
			_, err = mint(t, proc, handler.RequestData{}, &buf)
			require.NoError(t, err)

			require.Len(t, fake.lastAssume.Tags, tt.wantTags)
			tagClaims, _ := signer.lastClaims(t)["https://aws.amazon.com/tags"].(map[string]any)
			require.NotNil(t, tagClaims)
			principal, _ := tagClaims["principal_tags"].(map[string]any)
			require.Len(t, principal, tt.wantTags)
			for _, tag := range fake.lastAssume.Tags {
				assert.Equal(t, []any{*tag.Value}, principal[*tag.Key], *tag.Key)
			}
			tokenTransitive := asStrings(tagClaims["transitive_tag_keys"])
			assert.ElementsMatch(t, fake.lastAssume.TransitiveTagKeys, tokenTransitive)
			if tt.transitive {
				assert.NotEmpty(t, tokenTransitive)
			}

			a, m := sink.at(t, 0), sink.at(t, 1)
			assert.Equal(t, a["sessionTags"], m["sessionTags"])
			assert.Equal(t, a["sessionTagKeys"], m["sessionTagKeys"])
		})
	}
}

func asStrings(v any) []string {
	var out []string
	items, _ := v.([]any)
	for _, i := range items {
		out = append(out, i.(string))
	}
	return out
}

func TestProcessWarnsWhenReloadAddsIdPBlock(t *testing.T) {
	cfg := idpConfig(t, false, "")
	cfg.IdP = nil
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockWI(t), idpClaims(nil), &fakeAuditSink{}, "apigatewayv2")
	var buf bytes.Buffer
	_, err := mint(t, proc, handler.RequestData{}, &buf)
	require.NoError(t, err)
	assert.Zero(t, strings.Count(buf.String(), "config.idp.reload_ignored"))

	added := idpConfig(t, false, "")
	proc = handler.NewRequestProcessor(config.NewStaticProvider(added), mockWI(t), idpClaims(nil), &fakeAuditSink{}, "apigatewayv2")
	_, err = mint(t, proc, handler.RequestData{}, &buf)
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(buf.String(), "config.idp.reload_ignored"))
}

func TestSessionTagsBuiltOncePerRequest(t *testing.T) {
	tests := []struct {
		name           string
		idpToken       bool
		logClaimValues bool
	}{
		{"assume_role", false, false},
		{"assume_role_audited_values", false, true},
		{"mint", true, false},
		{"mint_audited_values", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := idpConfig(t, tt.idpToken, "", func(c *config.Config) {
				c.LogClaimValues = tt.logClaimValues
				c.Issuers[0].SessionTags = map[string]string{"ok": "good", "bad": "bad"}
			})
			raw := map[string]any{"repository": "org/repo", "good": "fine", "bad": "<>"}
			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(idpLogger(&buf))
			t.Cleanup(func() { slog.SetDefault(prev) })

			proc, sink, _ := idpProcessorFor(t, cfg, mockWI(t), idpClaims(raw))
			_, err := mint(t, proc, handler.RequestData{}, &buf)
			require.NoError(t, err)

			assert.Equal(t, 1, strings.Count(buf.String(), `"eventType":"sts.session_tag.dropped"`))
			rec := sink.last(t)
			assert.Equal(t, []any{"ok"}, rec["sessionTagKeys"])
			if tt.logClaimValues {
				assert.Equal(t, map[string]any{"ok": "fine"}, rec["sessionTags"])
			} else {
				assert.Nil(t, rec["sessionTags"])
			}
		})
	}
}
