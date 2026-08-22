package handler_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/handler"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

	assert.Equal(t, "role not allowed for repository or doesn't meet constraints",
		sink.last(t)["reason"])
}
