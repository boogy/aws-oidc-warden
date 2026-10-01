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

func mint(t *testing.T, proc *handler.RequestProcessor, rd handler.RequestData, buf *bytes.Buffer) (*handler.IdPCredentials, error) {
	t.Helper()
	if rd.Role == "" {
		rd.Role = testRoleARN
	}
	return proc.ProcessMint(context.Background(), &rd, validator.ExtractionInput{Token: "t"}, "req-1", idpLogger(buf))
}

func mockWI(t *testing.T) *fakeConsumer { return mockConsumer(t) }

func TestProcessMint(t *testing.T) {
	tests := []struct {
		name     string
		optedIn  bool
		role     string
		wantErr  error
		wantMint bool
	}{
		{"opted_in_mints", true, testRoleARN, nil, true},
		{"not_opted_in", false, testRoleARN, handler.ErrIdPNotPermitted, false},
		{"role_not_granted", true, otherRoleARN, handler.ErrRoleNotPermitted, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := idpConfig(t, tt.optedIn, "")
			cons := mockWI(t)
			proc, sink, _ := idpProcessorFor(t, cfg, cons, idpClaims(nil))
			var buf bytes.Buffer
			res, err := mint(t, proc, handler.RequestData{Role: tt.role}, &buf)

			assert.Zero(t, cons.assumeCalls)
			assert.Zero(t, cons.tagCalls)
			rec := sink.last(t)
			assert.Equal(t, "mint_token", rec["action"])
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
		base      time.Duration
		requested int32
		exchErr   error
		want      int32
		wantCap   int
		err       error
		signed    bool
	}{
		{"omitted", 0, 0, 0, nil, 3600, 3600, nil, true},
		{"omitted_30m_cap", 30 * time.Minute, 0, 0, nil, 1800, 1800, nil, true},
		{"7200_4h_cap_base_12h", 4 * h, 12 * h, 7200, nil, 7200, 14400, nil, true},
		{"over_cap", 4 * h, 12 * h, 18000, nil, 0, 0, handler.ErrDurationExceedsCap, false},
		{"default_ceiling", 0, 0, 7200, nil, 0, 0, handler.ErrDurationExceedsCap, false},
		{"no_cap_43200_base_12h", 0, 12 * h, 43200, nil, 43200, 43200, nil, true},
		{"no_cap_43200_default_base", 0, 0, 43200, nil, 0, 0, handler.ErrDurationExceedsCap, false},
		{"too_short", 0, 12 * h, 600, nil, 0, 0, handler.ErrInvalidDuration, false},
		{"too_long", 0, 12 * h, 43201, nil, 0, 0, handler.ErrInvalidDuration, false},
		{"negative", 0, 12 * h, -1, nil, 0, 0, handler.ErrInvalidDuration, false},
		{"role_max", 0, 0, 3600, roleMax, 0, 0, handler.ErrDurationExceedsRoleMax, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := idpConfig(t, true, "", func(c *config.Config) {
				c.RoleMappings[0].IdPMaxSessionDuration = tt.mapCap
				if tt.base != 0 {
					c.IdP.MaxSessionDuration = tt.base
				}
			})
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

func orZero(v any) any {
	if v == nil {
		return float64(0)
	}
	return v
}

func TestProcessMintSessionName(t *testing.T) {
	long := "org/" + strings.Repeat("a", 100)
	tests := []struct {
		name       string
		fixed      string
		mapAllow   bool
		baseAllow  bool
		requested  string
		subject    string
		wantName   string
		wantSource string
		err        error
	}{
		{"fixed", "fixed", false, false, "", "org/repo", "fixed", "mapping", nil},
		{"fixed_plus_request", "fixed", true, true, "asked", "org/repo", "", "", handler.ErrSessionNameNotPermitted},
		{"opt_in_request", "", true, true, "asked", "org/repo", "asked", "request", nil},
		{"no_opt_in_request", "", false, false, "asked", "org/repo", "", "", handler.ErrSessionNameNotPermitted},
		{"bad_charset", "", true, true, "bad name!", "org/repo", "", "", handler.ErrInvalidSessionName},
		{"too_short", "", true, true, "a", "org/repo", "", "", handler.ErrInvalidSessionName},
		{"subject", "", false, false, "", "org/repo", "org=repo", "subject", nil},
		{"long_subject", "", false, false, "", long, utils.FitSTSName(long), "subject", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := idpConfig(t, true, "", func(c *config.Config) {
				c.RoleMappings[0].Subject = config.Patterns{"org/.+"}
				c.RoleMappings[0].RoleSessionName = tt.fixed
				c.RoleMappings[0].AllowSessionName = tt.mapAllow
				c.IdP.AllowSessionName = tt.baseAllow
			})
			cons := mockWI(t)
			ext := &fixedExtractor{claims: allowClaims(tt.subject)}
			proc, sink, signer := idpProcessorFor(t, cfg, cons, ext)
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
			assert.Equal(t, tt.wantSource, sink.last(t)["sessionNameSource"])
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
			if tt.wiErr != nil {
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
		{name: "invalid_subject", subTmpl: "{source_issuer}#{source_subject}#{role_arn}", subject: "org/my repo", want: handler.ErrIdPNotPermitted},
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
	provider := config.NewProvider(cfg, time.Hour, "yaml", func(context.Context) ([]byte, error) { return []byte("{}"), nil })
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

func TestProcessMintRedactsSubjectDerivedFields(t *testing.T) {
	srcID := "token.actions.githubusercontent.com=" + utils.SanitizeSTSNameHashed("org/repo")
	tests := []struct {
		name      string
		lcv       bool
		requested string
		wantName  string
		wantSrc   bool
	}{
		{"off_subject_name", false, "", "org=repo", false},
		{"on_subject_name", true, "", "org=repo", true},
		{"off_request_name", false, "asked", "asked", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := idpConfig(t, true, "", func(c *config.Config) {
				c.LogClaimValues = tt.lcv
				c.RoleMappings[0].AllowSessionName = true
				c.IdP.AllowSessionName = true
			})
			proc, sink, _ := idpProcessorFor(t, cfg, mockWI(t), idpClaims(nil))
			var buf bytes.Buffer
			_, err := mint(t, proc, handler.RequestData{SessionName: tt.requested}, &buf)
			require.NoError(t, err)
			audit, logs := sink.dump(t), buf.String()

			nameShown := tt.lcv || tt.requested != ""
			assert.Equal(t, nameShown, strings.Contains(audit, `"sessionName":"`+tt.wantName+`"`), "audit sessionName")
			assert.Equal(t, nameShown, strings.Contains(logs, `"sessionName":"`+tt.wantName+`"`), "log sessionName")
			assert.Equal(t, tt.lcv, strings.Contains(audit, srcID), "audit sourceIdentity")
			assert.Equal(t, tt.lcv, strings.Contains(logs, srcID), "log sourceIdentity")
		})
	}
}

func TestProcessMintDisabledKillSwitch(t *testing.T) {
	cfg := idpConfig(t, true, "", func(c *config.Config) { c.IdP.Enabled = false })
	cons := mockWI(t)
	proc, sink, signer := idpProcessorFor(t, cfg, cons, idpClaims(nil))
	var buf bytes.Buffer
	_, err := mint(t, proc, handler.RequestData{}, &buf)
	require.ErrorIs(t, err, handler.ErrIdPUnavailable)
	assert.Zero(t, signer.calls)
	assert.Zero(t, cons.wiCalls)
	assert.Equal(t, "deny", sink.last(t)["decision"])
}

func TestProcessMintRoleOutsideAllowedRolesDeniedBeforeSign(t *testing.T) {
	cfg := idpConfig(t, true, "", func(c *config.Config) { c.IdP.AllowedRoles = []string{otherRoleARN} })
	proc, sink, signer := idpProcessorFor(t, cfg, mockWI(t), idpClaims(nil))
	var buf bytes.Buffer
	_, err := mint(t, proc, handler.RequestData{}, &buf)
	require.ErrorIs(t, err, handler.ErrIdPNotPermitted)
	assert.Equal(t, "deny", sink.last(t)["decision"])
	assert.Zero(t, signer.calls)
}

func TestAssumeRolePathIgnoresIdPSessionCap(t *testing.T) {
	cfg := idpConfig(t, true, "", func(c *config.Config) { c.RoleMappings[0].IdPMaxSessionDuration = time.Hour })
	cons := mockWI(t)
	proc, _, _ := idpProcessorFor(t, cfg, cons, idpClaims(nil))
	_, err := proc.ProcessRequest(context.Background(), &handler.RequestData{Role: testRoleARN},
		validator.ExtractionInput{Token: "t"}, "req-1", slog.Default())
	require.NoError(t, err)
	assert.Equal(t, 1, cons.assumeCalls)
	assert.Zero(t, cons.wiCalls)
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

func (f *stsFake) GetS3Object(context.Context, string, string) (io.ReadCloser, error) {
	return nil, errors.New("unused")
}

func (f *stsFake) GetS3ObjectIfChanged(context.Context, string, string, string, string) ([]byte, string, error) {
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
func (f *stsFake) RefreshClients() {}

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
	for i := range 51 {
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
			proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), cons, idpClaims(tt.raw), sink, "apigatewayv2").
				WithIdP(idpService(t, cfg, signer, nil))

			_, err := proc.ProcessRequest(context.Background(), &handler.RequestData{Role: testRoleARN},
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
