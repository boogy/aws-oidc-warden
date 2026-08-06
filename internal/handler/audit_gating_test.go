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
