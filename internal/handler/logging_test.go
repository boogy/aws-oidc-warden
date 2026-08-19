package handler

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogOutputIsJSON pins that every emitted line parses as JSON. Downstream
// log ingestion parses these lines; a text handler would silently break every
// query built against them, and this service's log stream is the audit trail's
// live counterpart.
func TestLogOutputIsJSON(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	logger.Info("decision",
		slog.String("requestId", "8f7e6d5c-4b3a-2910-8f7e-6d5c4b3a2910"),
		slog.String("decision", "allow"),
		slog.Any("claims", map[string]string{"repo": "acme/api"}))

	for line := range strings.Lines(strings.TrimSpace(buf.String())) {
		var parsed map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &parsed),
			"every log line must be valid JSON, got: %s", line)
	}
}

// TestBootstrapLoggerIsJSONHandler pins that the bootstrap-installed logger is
// always a JSON handler, never a text handler, so a future change can't
// quietly switch the production log format. White-box (package handler) so it
// can call initializeLogger directly rather than exercising the full
// NewBootstrap path, which also loads AWS SDK config and the on-disk config
// file — neither of which this test cares about.
func TestBootstrapLoggerIsJSONHandler(t *testing.T) {
	_, logger, err := initializeLogger()
	require.NoError(t, err)
	_, ok := logger.Handler().(*slog.JSONHandler)
	assert.True(t, ok, "bootstrap must install a JSON handler, never a text handler")
}
