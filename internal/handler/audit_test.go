package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/handler"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeAuditSink is a test double for handler.AuditSink. It captures every
// record it's asked to write (for assertions on record content/ordering) and
// can be told to fail, to exercise the audit_required durability paths.
// writes/buffers are tracked separately so tests can assert which of the two
// AuditSink paths (synchronous WriteRecord vs. batched BufferRecord) was used.
type fakeAuditSink struct {
	mu      sync.Mutex
	records [][]byte
	writes  int
	buffers int
	err     error
}

func (f *fakeAuditSink) WriteRecord(_ context.Context, record []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes++
	if f.err != nil {
		return f.err
	}
	cp := append([]byte(nil), record...)
	f.records = append(f.records, cp)
	return nil
}

func (f *fakeAuditSink) BufferRecord(record []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.buffers++
	if f.err != nil {
		return f.err
	}
	cp := append([]byte(nil), record...)
	f.records = append(f.records, cp)
	return nil
}

func (f *fakeAuditSink) last(t *testing.T) map[string]any {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	require.NotEmpty(t, f.records, "no audit record was written")
	var m map[string]any
	require.NoError(t, json.Unmarshal(f.records[len(f.records)-1], &m))
	return m
}

// auditTestCfg builds a minimal config with one issuer/role mapping for
// "org/repo", toggling the two audit-related knobs under test.
func auditTestCfg(t *testing.T, auditRequired, logClaimValues bool) *config.Config {
	t.Helper()
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer:    testIssuer,
			Provider:  "github",
			Audiences: []string{"sts.amazonaws.com"},
			SessionTags: map[string]string{
				"repo": "repository",
			},
		}},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 0},
		RoleMappings: []config.RoleMapping{{
			Subject: "org/repo",
			Roles:   []string{"arn:aws:iam::123456789012:role/MyRole"},
		}},
		LogClaimValues: logClaimValues,
		AuditRequired:  auditRequired,
	}
	if auditRequired {
		// Validate() requires log_to_s3+log_bucket when audit_required is set,
		// even though this test's sink is a fake standing in for the real one.
		cfg.LogToS3 = true
		cfg.LogBucket = "test-bucket"
	}
	require.NoError(t, cfg.Validate())
	return cfg
}

func allowClaims(subject string) *types.Claims {
	return &types.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   testIssuer,
			Subject:  subject,
			Audience: jwt.ClaimStrings{"sts.amazonaws.com"},
		},
		Sub:        "raw-sub-value",
		Repository: "org/repo",
		Ref:        "refs/heads/main",
		Actor:      "octocat",
		// Raw backs session-tag resolution (aws.BuildSessionTags reads from
		// it), mirroring what normalizeClaims populates in production.
		Raw: map[string]any{"repository": "org/repo"},
	}
}

// --- log-stream suppression (not just the audit sink) ---

// TestAudit_LogClaimValuesOff_SuppressesValuesInLogStream guards claim-value
// suppression at the LOG level: with log_claim_values=false, claim VALUES (raw sub,
// canonical subject, audience, repository, actor) must be absent from the
// emitted slog stream too — not only the durable audit sink. Decision, reason,
// and requestId stay present. Regression test for the earlier gap where only
// the sink record was redacted while auditLogAttrs logged the raw values.
func TestAudit_LogClaimValuesOff_SuppressesValuesInLogStream(t *testing.T) {
	for _, tc := range []struct {
		name           string
		logClaimValues bool
		wantValues     bool
	}{
		{"off suppresses", false, false},
		{"on includes", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := auditTestCfg(t, false, tc.logClaimValues)
			claims := allowClaims("org/repo")
			var buf bytes.Buffer
			// Bind requestId to the logger like every adapter does (slog.With);
			// auditLogAttrs deliberately does not add it again.
			log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})).
				With(slog.String("requestId", "req-logstream"))

			proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t), &fixedExtractor{claims: claims}, &fakeAuditSink{}, "test-frontend")
			_, err := proc.ProcessRequest(context.Background(),
				&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
				validator.ExtractionInput{Token: "t"},
				"req-logstream", log)
			require.NoError(t, err)

			out := buf.String()
			// Always-present, non-claim-value metadata.
			assert.Contains(t, out, "req-logstream", "requestId must always be logged")
			assert.Contains(t, out, `"decision":"allow"`, "decision must always be logged")

			// Claim VALUES: present only when log_claim_values=true.
			for _, v := range []string{"raw-sub-value", "octocat", "sts.amazonaws.com"} {
				if tc.wantValues {
					assert.Contains(t, out, v, "claim value %q should be logged when log_claim_values=true", v)
				} else {
					assert.NotContains(t, out, v, "claim value %q must NOT appear in logs when log_claim_values=false", v)
				}
			}
			// "org/repo" is both the subject and repository value; when off it
			// must not appear anywhere in the log stream.
			if tc.wantValues {
				assert.Contains(t, out, "org/repo")
			} else {
				assert.NotContains(t, out, "org/repo", "subject/repository value must be suppressed in logs when off")
			}
		})
	}
}

// --- allow path: record content ---

func TestAudit_AllowRecord_HasRequiredFields(t *testing.T) {
	cfg := auditTestCfg(t, false, true)
	claims := allowClaims("org/repo")
	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t), &fixedExtractor{claims: claims}, sink, "test-frontend")

	creds, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"},
		"req-allow", slog.Default())
	require.NoError(t, err)
	require.NotNil(t, creds)

	rec := sink.last(t)
	assert.Equal(t, "allow", rec["decision"])
	assert.Equal(t, "req-allow", rec["requestId"])
	assert.Equal(t, "test-frontend", rec["frontend"])
	assert.Equal(t, testIssuer, rec["issuer"])
	assert.Equal(t, "github", rec["provider"])
	assert.Equal(t, "org/repo", rec["subject"])
	assert.Equal(t, "raw-sub-value", rec["jwtSub"])
	assert.Equal(t, "arn:aws:iam::123456789012:role/MyRole", rec["requestedRole"])
	assert.Equal(t, "arn:aws:iam::123456789012:role/MyRole", rec["grantedRole"])
	assert.Equal(t, "123456789012", rec["accountId"])
	assert.Equal(t, "explicit", rec["matchedVia"])
	assert.NotNil(t, rec["expiry"])
	assert.Contains(t, rec, "processingMs")
}

func TestAudit_DenyRecord_HasStageAndReason(t *testing.T) {
	cfg := auditTestCfg(t, false, true)
	sink := &fakeAuditSink{}
	ex := &stubExtractor{err: errors.New("token is expired")}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), nil, ex, sink, "test-frontend")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"},
		"req-deny", slog.Default())
	require.Error(t, err)

	rec := sink.last(t)
	assert.Equal(t, "deny", rec["decision"])
	assert.Equal(t, "extract", rec["stage"])
	assert.NotEmpty(t, rec["reason"])
	assert.Equal(t, "req-deny", rec["requestId"])
}

func TestAudit_DenyRecord_AuthorizeStage(t *testing.T) {
	cfg := auditTestCfg(t, false, true)
	// Subject doesn't match any role mapping → deny at the authorize stage,
	// with issuer/subject known (claims were already extracted).
	claims := allowClaims("org/other-repo")
	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t), &fixedExtractor{claims: claims}, sink, "test-frontend")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"},
		"req-deny-authz", slog.Default())
	require.Error(t, err)
	assert.True(t, errors.Is(err, handler.ErrRoleNotPermitted))

	rec := sink.last(t)
	assert.Equal(t, "deny", rec["decision"])
	assert.Equal(t, "authorize", rec["stage"])
	assert.Equal(t, testIssuer, rec["issuer"])
	assert.Equal(t, "org/other-repo", rec["subject"])
}

// --- audit_required durability ---

func TestAudit_Required_WritesBeforeCredentialsReturned(t *testing.T) {
	cfg := auditTestCfg(t, true, true)
	claims := allowClaims("org/repo")
	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t), &fixedExtractor{claims: claims}, sink, "test")

	creds, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"},
		"req-durable", slog.Default())
	require.NoError(t, err)
	require.NotNil(t, creds)

	// The write is synchronous inside ProcessRequest, so by the time it
	// returns credentials the record must already be durably captured. With
	// audit_required=true the synchronous WriteRecord path is used, never the
	// batched BufferRecord path.
	assert.Equal(t, 1, sink.writes)
	assert.Equal(t, 0, sink.buffers)
	rec := sink.last(t)
	assert.Equal(t, "allow", rec["decision"])
}

// TestAudit_NotRequired_UsesBufferedPath asserts the fix for the finding where
// recordDecision always called the synchronous, batch-bypassing WriteRecord
// even when audit_required=false, defeating the batch buffer on every
// request. With audit_required=false, decisions must go through the
// best-effort BufferRecord path instead.
func TestAudit_NotRequired_UsesBufferedPath(t *testing.T) {
	cfg := auditTestCfg(t, false, true)
	claims := allowClaims("org/repo")
	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t), &fixedExtractor{claims: claims}, sink, "test")

	creds, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"},
		"req-buffered", slog.Default())
	require.NoError(t, err)
	require.NotNil(t, creds)

	assert.Equal(t, 1, sink.buffers)
	assert.Equal(t, 0, sink.writes)
	rec := sink.last(t)
	assert.Equal(t, "allow", rec["decision"])
}

func TestAudit_Required_WriteFailureOnAllow_DeniesAndReturnsNoCredentials(t *testing.T) {
	cfg := auditTestCfg(t, true, true)
	claims := allowClaims("org/repo")
	sink := &fakeAuditSink{err: errors.New("s3 unavailable")}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t), &fixedExtractor{claims: claims}, sink, "test")

	creds, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"},
		"req-fail-closed", slog.Default())

	require.Error(t, err)
	assert.Nil(t, creds)
	assert.True(t, errors.Is(err, handler.ErrAuditWriteFailed))
}

func TestAudit_NotRequired_WriteFailureOnAllow_StillSucceeds(t *testing.T) {
	cfg := auditTestCfg(t, false, true)
	claims := allowClaims("org/repo")
	sink := &fakeAuditSink{err: errors.New("s3 unavailable")}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t), &fixedExtractor{claims: claims}, sink, "test")

	creds, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"},
		"req-best-effort", slog.Default())

	require.NoError(t, err)
	require.NotNil(t, creds)
	// Best-effort path is BufferRecord, so its failure never surfaces here.
	assert.Equal(t, 1, sink.buffers)
	assert.Equal(t, 0, sink.writes)
}

func TestAudit_NilSink_IsNoOp(t *testing.T) {
	cfg := auditTestCfg(t, false, true)
	claims := allowClaims("org/repo")
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t), &fixedExtractor{claims: claims}, nil, "test")

	creds, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"},
		"req-nil-sink", slog.Default())

	require.NoError(t, err)
	require.NotNil(t, creds)
}

// --- log_claim_values redaction ---

func TestAudit_LogClaimValuesOff_SuppressesClaimValues(t *testing.T) {
	cfg := auditTestCfg(t, false, false)
	claims := allowClaims("org/repo")
	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t), &fixedExtractor{claims: claims}, sink, "test")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"},
		"req-redact", slog.Default())
	require.NoError(t, err)

	rec := sink.last(t)
	// Names/decision/reason/IDs always present...
	assert.Equal(t, "allow", rec["decision"])
	assert.Equal(t, testIssuer, rec["issuer"])
	assert.Equal(t, "arn:aws:iam::123456789012:role/MyRole", rec["grantedRole"])
	assert.Contains(t, rec, "sessionTagKeys")
	// ...but claim VALUES are suppressed.
	assert.Empty(t, rec["subject"])
	assert.Empty(t, rec["jwtSub"])
	assert.Empty(t, rec["audience"])
	assert.Empty(t, rec["sessionTags"])
}

func TestAudit_LogClaimValuesOn_IncludesClaimValues(t *testing.T) {
	cfg := auditTestCfg(t, false, true)
	claims := allowClaims("org/repo")
	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t), &fixedExtractor{claims: claims}, sink, "test")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"},
		"req-values", slog.Default())
	require.NoError(t, err)

	rec := sink.last(t)
	assert.Equal(t, "org/repo", rec["subject"])
	assert.Equal(t, "raw-sub-value", rec["jwtSub"])
	assert.NotEmpty(t, rec["audience"])
	sessionTags, ok := rec["sessionTags"].(map[string]any)
	require.True(t, ok, "sessionTags should be present when log_claim_values=true")
	assert.Equal(t, "org/repo", sessionTags["repo"])
}

// --- log-injection safety ---

func TestAudit_LogInjection_ControlCharsDoNotBreakRecordStructure(t *testing.T) {
	cfg := auditTestCfg(t, false, true)
	// A malicious/misconfigured subject containing a newline and a literal
	// quote: if the record were built by string concatenation this could
	// inject a fake extra JSON field or break the structure. json.Marshal
	// must escape it instead. (The doctored subject won't match the "org/repo"
	// role mapping pattern either, so this also exercises the deny path.)
	claims := allowClaims("org/repo\n\"injected\":\"true")
	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t), &fixedExtractor{claims: claims}, sink, "test")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"},
		"req-injection", slog.Default())
	require.Error(t, err) // subject no longer matches the role mapping pattern

	require.NotEmpty(t, sink.records)
	raw := sink.records[len(sink.records)-1]

	var rec map[string]any
	require.NoError(t, json.Unmarshal(raw, &rec), "audit record must remain valid JSON despite control chars in a claim value")
	assert.NotContains(t, rec, "injected", "no extra top-level field must be injected by the claim value")
	assert.Contains(t, rec["subject"], "injected") // the literal string, safely escaped as a value
}
