package handler_test

// The audit record: what every request writes, which claims it carries, when
// an audit failure must fail the request closed, and the audit_required gate.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/handler"
	"github.com/boogy/aws-oidc-warden/internal/s3logger"
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
			Subject: config.Patterns{"org/repo"},
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

// --- CloudWatch log stream cleanliness ---

// TestAuditLogAttrs_OmitsEmptyFields pins that the decision line does not
// carry empty keys. An allow decision has no stage/reason, and with
// log_claim_values off the claim values must be ABSENT, not blanked — a
// production stream showed "reason":"", "stage":"", "jwtSub":"",
// "subject":"", "audience":null on every successful request.
func TestAuditLogAttrs_OmitsEmptyFields(t *testing.T) {
	for _, tc := range []struct {
		name           string
		logClaimValues bool
		absent         []string
	}{
		{"allow with claim values", true, []string{`"stage"`, `"reason"`}},
		{"allow without claim values", false, []string{`"stage"`, `"reason"`, `"jwtSub"`, `"subject"`, `"audience"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := auditTestCfg(t, false, tc.logClaimValues)
			var buf bytes.Buffer
			log := slog.New(slog.NewJSONHandler(&buf, nil))
			proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t),
				&fixedExtractor{claims: allowClaims("org/repo")}, &fakeAuditSink{}, "test-frontend")

			_, err := proc.ProcessRequest(context.Background(),
				&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
				validator.ExtractionInput{Token: "t"}, "req-empty", log)
			require.NoError(t, err)

			out := buf.String()
			require.Contains(t, out, `"decision":"allow"`)
			for _, key := range tc.absent {
				assert.NotContains(t, out, key, "%s must be omitted, not emitted empty", key)
			}
		})
	}
}

// TestProcessor_DurationsAreMilliseconds pins that timing fields are emitted
// as readable millisecond counts, consistent with processingMs — not the raw
// nanosecond integers slog.Duration produces in JSON.
func TestProcessor_DurationsAreMilliseconds(t *testing.T) {
	cfg := auditTestCfg(t, false, true)
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t),
		&fixedExtractor{claims: allowClaims("org/repo")}, &fakeAuditSink{}, "test-frontend")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"}, "req-dur", log)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, `"validationMs":`)
	assert.Contains(t, out, `"totalMs":`)
	assert.NotContains(t, out, `"validationTime":`, "nanosecond duration must be gone")
	assert.NotContains(t, out, `"totalTime":`, "nanosecond duration must be gone")
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

// ---------- claims ----------

// githubRawClaims is a representative verified GitHub Actions claim set,
// including low-signal claims (actor_id, repository_id, run_number,
// workflow_sha) a curated list used to drop but a full dump now carries, plus
// empty base_ref/head_ref (PR-only claims, empty on a push event) to pin that
// empty claims are still skipped regardless of dump semantics.
func githubRawClaims() map[string]any {
	return map[string]any{
		"repository":            "org/repo",
		"repository_owner":      "org",
		"repository_visibility": "private",
		"ref":                   "refs/heads/main",
		"ref_type":              "branch",
		"event_name":            "push",
		"actor":                 "octocat",
		"workflow_ref":          "org/repo/.github/workflows/deploy.yml@refs/heads/main",
		"job_workflow_ref":      "org/repo/.github/workflows/deploy.yml@refs/heads/main",
		"sha":                   "abc123",
		"run_id":                "1234567890",
		"run_attempt":           "1",
		"runner_environment":    "github-hosted",
		// Dropped by the old curated list, carried by the full dump.
		"actor_id":      "583231",
		"repository_id": "42",
		"run_number":    "7",
		"workflow_sha":  "def456",
		"base_ref":      "",
		"head_ref":      "",
	}
}

func githubClaims(subject string) *types.Claims {
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
		Raw:        githubRawClaims(),
	}
}

func recClaims(t *testing.T, rec map[string]any) map[string]any {
	t.Helper()
	if rec["claims"] == nil {
		return nil
	}
	claims, ok := rec["claims"].(map[string]any)
	require.True(t, ok, "claims must be a JSON object, got %T", rec["claims"])
	return claims
}

// TestAuditClaims_GitHubDumpsEverythingWithAliases pins the full-dump
// semantics: every verified GitHub claim reaches the record, with the
// requested renames applied (repository -> repo, repository_id -> repo_id).
func TestAuditClaims_GitHubDumpsEverythingWithAliases(t *testing.T) {
	cfg := auditTestCfg(t, false, true)
	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t),
		&fixedExtractor{claims: githubClaims("org/repo")}, sink, "test-frontend")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"}, "req-claims", slog.Default())
	require.NoError(t, err)

	claims := recClaims(t, sink.last(t))
	require.NotNil(t, claims)

	// Renamed per the logging requirement.
	assert.Equal(t, "org/repo", claims["repo"])
	assert.Equal(t, "42", claims["repo_id"])
	assert.NotContains(t, claims, "repository", "repository must be emitted as repo")
	assert.NotContains(t, claims, "repository_id", "repository_id must be emitted as repo_id")

	// Explicitly required by the logging spec.
	for _, k := range []string{"actor", "ref", "workflow_ref", "job_workflow_ref", "sha"} {
		assert.NotEmpty(t, claims[k], "required claim %q must be logged", k)
	}

	// Previously dropped by the curated list — now present.
	assert.Equal(t, "583231", claims["actor_id"])
	assert.Equal(t, "7", claims["run_number"])
	assert.Equal(t, "def456", claims["workflow_sha"])

	// Empty claims are still skipped: they carry no information and cost bytes
	// in a per-request S3 object.
	assert.NotContains(t, claims, "base_ref")
}

// TestAuditClaims_NumericClaimsAreNotScientificNotation pins that a numeric
// claim reaches the audit record as a plain integer.
//
// This only became reachable with the full dump: claims are decoded into
// map[string]any, so every JSON number is a float64, and fmt's default float
// verb renders a 10-digit epoch second as "1.7555904e+09". An `exp` an auditor
// cannot read as a timestamp is a defect in the compliance artifact, so the
// value goes through utils.FormatClaimValue — the same helper BuildSessionTags
// uses, so the documented "a claim here and the same claim as a session tag can
// never disagree" guarantee still holds.
func TestAuditClaims_NumericClaimsAreNotScientificNotation(t *testing.T) {
	claims := githubClaims("org/repo")
	claims.Raw["exp"] = float64(1755590400) // as encoding/json decodes it
	claims.Raw["repository_id"] = float64(42)
	claims.Raw["run_number"] = float64(7)

	cfg := auditTestCfg(t, false, true)
	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t),
		&fixedExtractor{claims: claims}, sink, "test-frontend")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"}, "req-numeric", slog.Default())
	require.NoError(t, err)

	rec := recClaims(t, sink.last(t))
	require.NotNil(t, rec)
	assert.Equal(t, "1755590400", rec["exp"], "an epoch second must not be scientific notation")
	assert.Equal(t, "42", rec["repo_id"])
	assert.Equal(t, "7", rec["run_number"])
}

// TestAuditClaims_AliasSkippedWhenTargetClaimExists pins that the
// repository->repo rename does not overwrite a claim the token already carries
// under the alias target. Both landing on one key would drop a verified claim
// from the audit record, and which one survived would depend on Go's
// randomized map iteration order — a lossy, non-reproducible record.
func TestAuditClaims_AliasSkippedWhenTargetClaimExists(t *testing.T) {
	claims := githubClaims("org/repo")
	claims.Raw["repo"] = "already-taken"

	cfg := auditTestCfg(t, false, true)
	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t),
		&fixedExtractor{claims: claims}, sink, "test-frontend")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"}, "req-alias-clash", slog.Default())
	require.NoError(t, err)

	rec := recClaims(t, sink.last(t))
	require.NotNil(t, rec)
	assert.Equal(t, "already-taken", rec["repo"], "the token's own repo claim must win")
	assert.Equal(t, "org/repo", rec["repository"], "repository must keep its raw name rather than vanish")
}

// TestAuditRecord_IdentityFields pins the request-identity fields on the
// record itself: iss/sub/aud were already there, and the frontend join key
// plus the resolved client IP are added.
func TestAuditRecord_IdentityFields(t *testing.T) {
	cfg := auditTestCfg(t, false, true)
	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t),
		&fixedExtractor{claims: githubClaims("org/repo")}, sink, "test-frontend")

	ctx := context.WithValue(context.Background(), handler.SourceIPContextKey, "203.0.113.7")
	ctx = context.WithValue(ctx, handler.FrontendRequestIDContextKey, "CPyipjveDoEEPIA=")

	_, err := proc.ProcessRequest(ctx,
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"}, "req-identity", slog.Default())
	require.NoError(t, err)

	rec := sink.last(t)
	assert.Equal(t, testIssuer, rec["issuer"])
	assert.Equal(t, "raw-sub-value", rec["jwtSub"])
	assert.Equal(t, []any{"sts.amazonaws.com"}, rec["audience"])
	assert.Equal(t, "203.0.113.7", rec["sourceIp"])
	assert.Equal(t, "CPyipjveDoEEPIA=", rec["frontendRequestId"])
}

// TestAuditClaims_SuppressedWhenLogClaimValuesOff guards the gate: claims are
// claim VALUES, so log_claim_values=false must keep them out of both the
// durable record and the log stream.
func TestAuditClaims_SuppressedWhenLogClaimValuesOff(t *testing.T) {
	cfg := auditTestCfg(t, false, false)
	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t), &fixedExtractor{claims: githubClaims("org/repo")}, sink, "test-frontend")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"},
		"req-claims-off", slog.Default())
	require.NoError(t, err)

	assert.Nil(t, recClaims(t, sink.last(t)), "claims must be absent when log_claim_values=false")
}

// TestAuditClaims_OnDenyRecord pins that a denied attempt still records who
// made it — the case where the identity matters most.
func TestAuditClaims_OnDenyRecord(t *testing.T) {
	cfg := auditTestCfg(t, false, true)
	sink := &fakeAuditSink{}
	// Subject matches no mapping → deny at the authorize stage, after claims
	// were extracted.
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t), &fixedExtractor{claims: githubClaims("org/other-repo")}, sink, "test-frontend")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"},
		"req-claims-deny", slog.Default())
	require.Error(t, err)

	rec := sink.last(t)
	require.Equal(t, "deny", rec["decision"])
	claims := recClaims(t, rec)
	require.NotNil(t, claims, "deny records must carry the identifying claims too")
	assert.Equal(t, "org/repo", claims["repo"])
	assert.Equal(t, "octocat", claims["actor"])
}

// TestAuditClaims_GenericIssuerUsesClaimMappings pins the non-GitHub path: a
// generic issuer has no fixed claim vocabulary, so the audit record reports
// the claims its own claim_mappings reference — and nothing else.
func TestAuditClaims_GenericIssuerUsesClaimMappings(t *testing.T) {
	const gitlabIssuer = "https://gitlab.example.com"
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer:    gitlabIssuer,
			Provider:  "generic",
			Audiences: []string{"sts.amazonaws.com"},
			ClaimMappings: map[string]string{
				"subject":    "project_path",
				"ref":        "ref",
				"pipeline":   "pipeline_id",
				"user_login": "user_login",
			},
		}},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 0},
		RoleMappings: []config.RoleMapping{{
			Subject: config.Patterns{"group/project"},
			Issuer:  gitlabIssuer,
			Roles:   []string{"arn:aws:iam::123456789012:role/MyRole"},
		}},
		LogClaimValues: true,
	}
	require.NoError(t, cfg.Validate())

	claims := &types.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   gitlabIssuer,
			Subject:  "group/project",
			Audience: jwt.ClaimStrings{"sts.amazonaws.com"},
		},
		Sub: "project_path:group/project:ref:main",
		Raw: map[string]any{
			"project_path": "group/project",
			"ref":          "main",
			"pipeline_id":  4242, // non-string: formatted like a session tag value
			"user_login":   "alice",
			"namespace_id": "99", // not mapped → must not be reported
		},
	}

	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t), &fixedExtractor{claims: claims}, sink, "test-frontend")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"},
		"req-claims-generic", slog.Default())
	require.NoError(t, err)

	got := recClaims(t, sink.last(t))
	require.NotNil(t, got)
	assert.Equal(t, map[string]any{
		"project_path": "group/project",
		"ref":          "main",
		"pipeline_id":  "4242",
		"user_login":   "alice",
	}, got, "only the issuer's mapped claims, formatted as strings")

	// GitHub's curated names must not leak into a generic issuer's record.
	assert.NotContains(t, got, "repository")
}

// TestAuditClaims_GenericIssuerRepositoryAliasIsProviderIndependent pins that
// the repository -> repo rename applies to every provider, not just
// "github": a generic issuer whose own claim_mappings happen to name a raw
// "repository" claim still gets it aliased to "repo" in the audit record.
func TestAuditClaims_GenericIssuerRepositoryAliasIsProviderIndependent(t *testing.T) {
	const genericIssuer = "https://issuer.example.com"
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer:    genericIssuer,
			Provider:  "generic",
			Audiences: []string{"sts.amazonaws.com"},
			ClaimMappings: map[string]string{
				"subject": "repository",
			},
		}},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 0},
		RoleMappings: []config.RoleMapping{{
			Subject: config.Patterns{"acme/api"},
			Issuer:  genericIssuer,
			Roles:   []string{"arn:aws:iam::123456789012:role/MyRole"},
		}},
		LogClaimValues: true,
	}
	require.NoError(t, cfg.Validate())

	claims := &types.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   genericIssuer,
			Subject:  "acme/api",
			Audience: jwt.ClaimStrings{"sts.amazonaws.com"},
		},
		Sub: "acme/api",
		Raw: map[string]any{
			"repository": "acme/api",
		},
	}

	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t), &fixedExtractor{claims: claims}, sink, "test-frontend")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"},
		"req-claims-generic-alias", slog.Default())
	require.NoError(t, err)

	got := recClaims(t, sink.last(t))
	require.NotNil(t, got)
	assert.Equal(t, "acme/api", got["repo"], "the rename applies regardless of provider")
	assert.NotContains(t, got, "repository", "the raw claim name must not survive the rename")
}

// TestAuditClaims_AliasAppliesWhenTargetClaimIsNotEmitted pins the other half
// of the collision rule: a rename is suppressed only by a claim that actually
// reaches the record, never by one that was dropped on the way in.
//
// The check used to ask whether rawClaims held the alias target at all. For a
// generic issuer that carries both "repository" and an unmapped "repo", the
// unmapped claim is excluded from the record — yet its bare presence cancelled
// the rename, so the record lost the repo/repo_id vocabulary the alias exists
// to guarantee, and nothing took its place.
func TestAuditClaims_AliasAppliesWhenTargetClaimIsNotEmitted(t *testing.T) {
	const genericIssuer = "https://issuer.example.com"
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer:    genericIssuer,
			Provider:  "generic",
			Audiences: []string{"sts.amazonaws.com"},
			// "repo" is deliberately NOT mapped, so it is never recorded.
			ClaimMappings: map[string]string{"subject": "repository"},
		}},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 0},
		RoleMappings: []config.RoleMapping{{
			Subject: config.Patterns{"acme/api"},
			Issuer:  genericIssuer,
			Roles:   []string{"arn:aws:iam::123456789012:role/MyRole"},
		}},
		LogClaimValues: true,
	}
	require.NoError(t, cfg.Validate())

	claims := &types.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   genericIssuer,
			Subject:  "acme/api",
			Audience: jwt.ClaimStrings{"sts.amazonaws.com"},
		},
		Sub: "acme/api",
		Raw: map[string]any{
			"repository": "acme/api",
			"repo":       "not-recorded", // excluded by claim_mappings
		},
	}

	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t),
		&fixedExtractor{claims: claims}, sink, "test-frontend")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"}, "req-alias-not-emitted", slog.Default())
	require.NoError(t, err)

	got := recClaims(t, sink.last(t))
	require.NotNil(t, got)
	assert.Equal(t, "acme/api", got["repo"],
		"the rename must apply: the colliding claim is excluded from the record")
	assert.NotContains(t, got, "repository", "the raw claim name must not survive the rename")
}

// An empty alias-target claim is likewise not emitted (auditClaims drops empty
// formatted values), so it must not cancel the rename either.
func TestAuditClaims_AliasAppliesWhenTargetClaimIsEmpty(t *testing.T) {
	claims := githubClaims("org/repo")
	claims.Raw["repo"] = ""

	cfg := auditTestCfg(t, false, true)
	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t),
		&fixedExtractor{claims: claims}, sink, "test-frontend")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"}, "req-alias-empty", slog.Default())
	require.NoError(t, err)

	got := recClaims(t, sink.last(t))
	require.NotNil(t, got)
	assert.Equal(t, "org/repo", got["repo"], "an empty claim records nothing and must not block the rename")
	assert.NotContains(t, got, "repository")
}

// ---------- gating ----------

// --- audit_required with no sink wired ---

// audit_required promises credentials are never returned unless the decision
// was durably recorded. A nil sink has nothing to record to, so the promise
// cannot be kept and the request must fail closed. config.Validate() cannot
// catch this: it only sees log_to_s3/log_bucket, not whether the constructor
// was handed a sink (cmd/local/main.go passes nil).
func TestAudit_Required_NilSink_FailsClosed(t *testing.T) {
	cfg := auditTestCfg(t, true, false)
	require.True(t, cfg.AuditRequired)
	require.True(t, cfg.LogToS3, "Validate() accepts this config, which is what makes the gap reachable")

	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t),
		&fixedExtractor{claims: allowClaims("org/repo")}, nil /* as cmd/local does */, "test")

	creds, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"}, "req-nil-sink", slog.Default())

	require.Error(t, err, "credentials must not be returned with audit_required=true and no audit sink")
	assert.Nil(t, creds)
	assert.True(t, errors.Is(err, handler.ErrAuditWriteFailed),
		"a missing sink is an unmet audit requirement, not a permission or token failure: %v", err)
}

// A nil sink stays a no-op when audit_required is false — the durable write is
// optional there, so the request proceeds and credentials are returned.
func TestAudit_NotRequired_NilSink_StillAllows(t *testing.T) {
	cfg := auditTestCfg(t, false, false)
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t),
		&fixedExtractor{claims: allowClaims("org/repo")}, nil, "test")

	creds, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"}, "req-nil-sink-optional", slog.Default())

	require.NoError(t, err)
	assert.NotNil(t, creds)
}

// --- getSessionPolicy debug logging ---

// getSessionPolicy's debug lines name the canonical subject. They must go
// through the per-request logger (so requestId correlates, and so the
// log_claim_values assertions in TestAudit_LogClaimValuesOff_… actually police
// them) and must honour log_claim_values. Previously they used the package-level
// slog, which wrote past any captured logger — the leak was invisible to a test
// that only inspected the request logger's output.
func TestAudit_GetSessionPolicyDebug_UsesRequestLoggerAndHonoursClaimGate(t *testing.T) {
	for _, tc := range []struct {
		name           string
		logClaimValues bool
	}{
		{"gate off suppresses subject", false},
		{"gate on includes subject", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := auditTestCfg(t, false, tc.logClaimValues)
			// Exercise the inline-policy branch as well as the deferred timing
			// line, so both subject-bearing debug sites are covered.
			cfg.RoleMappings[0].SessionPolicy = `{"Version":"2012-10-17","Statement":[]}`
			require.NoError(t, cfg.Validate())

			var buf bytes.Buffer
			log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})).
				With(slog.String("requestId", "req-policy-debug"))

			proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t),
				&fixedExtractor{claims: allowClaims("org/repo")}, &fakeAuditSink{}, "test")

			_, err := proc.ProcessRequest(context.Background(),
				&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
				validator.ExtractionInput{Token: "t"}, "req-policy-debug", log)
			require.NoError(t, err)

			out := buf.String()
			// Both debug sites must reach the captured request logger. If either
			// regresses to the package-level slog these disappear from buf and
			// the claim-value assertions below stop guarding anything.
			assert.Contains(t, out, "getSessionPolicy operation completed",
				"the deferred timing line must be emitted via the request logger")
			assert.Contains(t, out, "Using inline session policy",
				"the inline-policy line must be emitted via the request logger")
			assert.Contains(t, out, "req-policy-debug", "request-scoped logs must carry the requestId")

			if tc.logClaimValues {
				assert.Contains(t, out, `"subject":"org/repo"`,
					"subject should be logged when log_claim_values=true")
			} else {
				assert.NotContains(t, out, "org/repo",
					"subject must be suppressed in debug logs when log_claim_values=false")
			}
		})
	}
}

// --- error-derived deny reasons follow the claim-value gate ---

// TestAudit_ErrorReasonRedactedWhenClaimValuesOff pins that a deny reason
// built from an error string is gated like any other claim value.
//
// Extraction, session-policy and STS errors routinely quote the identity that
// failed — an expired token names its subject, an STS denial quotes the role
// ARN and session name. log_claim_values=false promises those values stay out
// of both the log stream and the durable record, but `reason` was emitted raw
// on both, so the operator who turned the gate on still shipped the subject to
// the audit bucket.
func TestAudit_ErrorReasonRedactedWhenClaimValuesOff(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))

	cfg := auditTestCfg(t, false, false) // log_claim_values = false
	sink := &fakeAuditSink{}
	leaky := errors.New("token expired for subject org/secret-repo:ref:refs/heads/main")
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t),
		&stubExtractor{err: leaky}, sink, "test-frontend")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"}, "req-reason-gate", log)
	require.Error(t, err)

	rec := sink.last(t)
	require.Equal(t, "deny", rec["decision"])
	assert.Equal(t, "token validation failed", rec["reason"],
		"the raw error text reached the durable audit record despite log_claim_values=false")
	assert.NotContains(t, buf.String(), "org/secret-repo",
		"the raw error text reached the log stream despite log_claim_values=false")

	// The field must stay present: an audit record that cannot say why a
	// request was denied is not an audit record.
	require.NotEmpty(t, rec["reason"], "reason must be replaced, never dropped")
	require.Equal(t, "extract", rec["stage"])
}

// With the gate on, the full diagnostic text is preserved — the fix must not
// cost operators their error detail in the default configuration.
func TestAudit_ErrorReasonPreservedWhenClaimValuesOn(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))

	cfg := auditTestCfg(t, false, true) // log_claim_values = true
	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t),
		&stubExtractor{err: errors.New("token expired for subject org/secret-repo")}, sink, "test-frontend")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"}, "req-reason-open", log)
	require.Error(t, err)

	assert.Equal(t, "token expired for subject org/secret-repo", sink.last(t)["reason"])
	assert.Contains(t, buf.String(), "org/secret-repo")
}

// A fixed-phrase reason carries no claim value and must survive the gate
// verbatim — replacing it with the stage summary would lose the more specific
// explanation for no benefit.
func TestAudit_StaticReasonSurvivesClaimValueGate(t *testing.T) {
	cfg := auditTestCfg(t, false, false)
	sink := &fakeAuditSink{}
	// Subject matches no mapping → deny at authorize with a fixed phrase.
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t),
		&fixedExtractor{claims: allowClaims("org/other-repo")}, sink, "test-frontend")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"}, "req-reason-static", slog.Default())
	require.Error(t, err)

	assert.Equal(t, "role not allowed for this subject or its conditions are not met",
		sink.last(t)["reason"])
}

// ---------- audit_required ----------

// leakyConsumer wraps fakeConsumer so AssumeRole can fail with a realistic
// AWS SDK error string (which embeds ARNs / account IDs).
type leakyConsumer struct {
	*fakeConsumer
	assumeErr error
}

func (l *leakyConsumer) AssumeRole(roleARN, _ string, _ *string, _ *int32, _ *types.Claims, _ map[string]string) (*ststypes.Credentials, error) {
	if l.assumeErr != nil {
		return nil, l.assumeErr
	}
	return l.assumeOut, nil
}

// --- 1. audit_required fail-closed vs. the REAL s3logger sink ---

// The S3Logger captures *config.Config by pointer at bootstrap
// (bootstrap.go:120 `s3logger.NewS3Logger(provider.Get())`), while
// recordDecision reads the LIVE config from provider.Get() on every request.
// After a hot reload the two disagree. This models: boot config had
// log_to_s3=false / audit_required=false (both defaults), reloaded config
// turns audit_required=true + log_to_s3=true.
func TestAudit_RequiredAudit_StaleS3LoggerConfig_ReturnsCredentialsWithNoDurableWrite(t *testing.T) {
	bootCfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer: testIssuer, Provider: "github", Audiences: []string{"sts.amazonaws.com"},
		}},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 0},
		RoleMappings: []config.RoleMapping{{
			Subject: config.Patterns{"org/repo"},
			Roles:   []string{"arn:aws:iam::123456789012:role/MyRole"},
		}},
		LogToS3:       false, // default
		AuditRequired: false, // default
	}
	require.NoError(t, bootCfg.Validate())

	// The real sink, built from the boot config exactly as bootstrap does.
	sink := s3logger.NewS3Logger(bootCfg)

	// Hot-reloaded config: operator turns on required auditing without a redeploy.
	liveCfg := &config.Config{
		Issuers:         bootCfg.Issuers,
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 0},
		RoleMappings:    bootCfg.RoleMappings,
		LogToS3:         true,
		LogBucket:       "audit-bucket",
		AuditRequired:   true,
	}
	require.NoError(t, liveCfg.Validate())

	proc := handler.NewRequestProcessor(
		config.NewStaticProvider(liveCfg), mockConsumer(t),
		&fixedExtractor{claims: allowClaims("org/repo")}, sink, "test")

	creds, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"}, "req-stale", slog.Default())

	// audit_required=true promises: no credentials unless the record was
	// durably written. The sink has no S3 client at all here.
	t.Logf("err=%v creds!=nil=%v", err, creds != nil)
	require.Error(t, err, "FAIL-OPEN: credentials returned although audit_required=true and the sink wrote nothing")
	assert.Nil(t, creds)
}

// --- 2. error bodies from the untested apigateway Handler path ---

func TestAudit_APIGatewayHandler_AssumeRoleErrorBodyLeaksNothing(t *testing.T) {
	cfg := auditTestCfg(t, false, true)
	sdkErr := errors.New("operation error STS: AssumeRole, https response error StatusCode: 403, " +
		"api error AccessDenied: User: arn:aws:sts::999988887777:assumed-role/warden-hub/lambda is not authorized " +
		"to perform: sts:AssumeRole on resource: arn:aws:iam::123456789012:role/MyRole")

	consumer := &leakyConsumer{fakeConsumer: mockConsumer(t), assumeErr: sdkErr}
	h := handler.NewAwsApiGateway(config.NewStaticProvider(cfg), consumer,
		&fixedExtractor{claims: allowClaims("org/repo")}, nil)

	resp, err := h.Handler(context.Background(), events.APIGatewayProxyRequest{
		Path: "/", HTTPMethod: "POST",
		Body: `{"token":"eyJhbGciOiJSUzI1NiJ9.payload.sig","role":"arn:aws:iam::123456789012:role/MyRole"}`,
	})
	require.NoError(t, err)
	t.Logf("status=%d headers=%v body=%s", resp.StatusCode, resp.Headers, resp.Body)

	assert.NotContains(t, resp.Body, "999988887777")
	assert.NotContains(t, resp.Body, "arn:aws:iam::")
	assert.NotContains(t, resp.Body, "AccessDenied")
	assert.NotContains(t, resp.Body, "eyJhbGciOiJSUzI1NiJ9")
}

// Success path: confirm what headers a live-credential response actually
// carries, and that no request token is echoed.
func TestAudit_APIGatewayHandler_SuccessResponseHeadersAndBody(t *testing.T) {
	cfg := auditTestCfg(t, false, true)
	h := handler.NewAwsApiGateway(config.NewStaticProvider(cfg), mockConsumer(t),
		&fixedExtractor{claims: allowClaims("org/repo")}, nil)

	resp, err := h.Handler(context.Background(), events.APIGatewayProxyRequest{
		Path: "/", HTTPMethod: "GET", // NOTE: method is never checked by the handler
		Body: `{"token":"eyJhbGciOiJSUzI1NiJ9.payload.sig","role":"arn:aws:iam::123456789012:role/MyRole"}`,
	})
	require.NoError(t, err)
	t.Logf("status=%d headers=%#v", resp.StatusCode, resp.Headers)
	t.Logf("body=%s", resp.Body)

	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(resp.Body), &got))
	assert.Equal(t, float64(200), got["statusCode"])
	assert.NotContains(t, resp.Body, "eyJhbGciOiJSUzI1NiJ9")

	// A 200 carries live AWS credentials, so it must not be storable. The
	// handlers never inspect the HTTP method, so "caches don't store POST
	// responses" cannot be relied on — the header has to be explicit.
	assert.Equal(t, "no-store", resp.Headers["Cache-Control"],
		"a credential-bearing response must be marked no-store")

	// No CORS is emitted at all, so there is no Origin reflection to abuse.
	// Asserted so that adding CORS to a credentialed endpoint is a deliberate act.
	assert.NotContains(t, resp.Headers, "Access-Control-Allow-Origin")
	assert.NotContains(t, resp.Headers, "Access-Control-Allow-Credentials")
	assert.Contains(t, strings.ToLower(resp.Headers["Content-Type"]), "json")
}

// TestAuditClaims_GenericIssuerRecordsDecisionRelevantClaims pins the widened
// inclusion rule for non-github providers: the record carries every claim the
// issuer's own config references — claim_mappings targets, required_claims,
// session_tags targets, and every claim named by a condition on one of that
// issuer's role_mappings — and nothing else.
//
// The condition half is the one that matters. Before 3.0.0 the record held
// only claim_mappings targets, so a request that turned on a `groups` claim
// (an any_of requiring it, a none_of vetoing on it) produced a record that
// could not explain its own decision: the deciding value was absent. A claim
// nothing in the config mentions (`email` here) still stays out.
func TestAuditClaims_GenericIssuerRecordsDecisionRelevantClaims(t *testing.T) {
	const genericIssuer = "https://issuer.example.com"
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer:    genericIssuer,
			Provider:  "generic",
			Audiences: []string{"sts.amazonaws.com"},
			ClaimMappings: map[string]string{
				"subject": "project_path",
			},
			RequiredClaims: []string{"project_id"},
			SessionTags:    map[string]string{"Tier": "plan_tier"},
		}},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 0},
		RoleMappings: []config.RoleMapping{{
			Subject: config.Patterns{"group/project"},
			Issuer:  genericIssuer,
			Roles:   []string{"arn:aws:iam::123456789012:role/MyRole"},
			Conditions: &config.Condition{
				Claims: map[string]config.Patterns{"groups": {"platform"}},
				NoneOf: []*config.Condition{{
					Claims: map[string]config.Patterns{"quarantined": {"true"}},
				}},
			},
		}},
		LogClaimValues: true,
	}
	require.NoError(t, cfg.Validate())

	claims := &types.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   genericIssuer,
			Subject:  "group/project",
			Audience: jwt.ClaimStrings{"sts.amazonaws.com"},
		},
		Sub: "group/project",
		Raw: map[string]any{
			"project_path": "group/project", // claim_mappings target
			"project_id":   "4242",          // required_claims
			"plan_tier":    "gold",          // session_tags target
			"groups":       "platform",      // condition claim (flat)
			"quarantined":  "false",         // condition claim (inside none_of)
			"email":        "alice@example.com",
			"name":         "Alice",
		},
	}

	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t), &fixedExtractor{claims: claims}, sink, "test-frontend")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"},
		"req-claims-generic-decision", slog.Default())
	require.NoError(t, err)

	got := recClaims(t, sink.last(t))
	require.NotNil(t, got)
	assert.Equal(t, map[string]any{
		"project_path": "group/project",
		"project_id":   "4242",
		"plan_tier":    "gold",
		"groups":       "platform",
		"quarantined":  "false",
	}, got, "every config-referenced claim, and only those")

	// Claims the operator never named anywhere must never be copied out.
	assert.NotContains(t, got, "email")
	assert.NotContains(t, got, "name")
}
