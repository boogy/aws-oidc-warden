package logevent

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/version"
)

func TestSetup_InstallsBaseAttrsAndSetsDefault(t *testing.T) {
	prevDefault := slog.Default()
	prevVersion := version.Version
	t.Cleanup(func() {
		slog.SetDefault(prevDefault)
		version.Version = prevVersion
	})
	version.Version = "9.9.9"

	var buf bytes.Buffer
	logger := Setup(&buf, slog.LevelDebug, "apigateway")

	if slog.Default() != logger {
		t.Error("Setup must install the returned logger as slog.Default()")
	}

	logger.Info("ready")

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v (%s)", err, buf.String())
	}
	want := map[string]any{
		keyService:       serviceName,
		keyVersion:       "9.9.9",
		keyAdapter:       "apigateway",
		keySchemaVersion: float64(schemaVersion),
	}
	for key, wantVal := range want {
		if parsed[key] != wantVal {
			t.Errorf("%s = %v, want %v", key, parsed[key], wantVal)
		}
	}
}

func TestSetup_HandlerIsJSON(t *testing.T) {
	prevDefault := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prevDefault) })

	var buf bytes.Buffer
	logger := Setup(&buf, slog.LevelInfo, "local")

	logger.Debug("filtered")
	if buf.Len() != 0 {
		t.Fatalf("Debug line emitted at Info level: %s", buf.String())
	}

	logger.Info("kept")
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("Setup must install a JSON handler, got unparseable output: %v (%s)", err, buf.String())
	}
}

// json.Unmarshal is last-wins on duplicate keys, so count raw substrings.
func TestSetup_EndToEndNoDuplicateKeys(t *testing.T) {
	prevDefault := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prevDefault) })

	var buf bytes.Buffer
	logger := Setup(&buf, slog.LevelDebug, "alb")

	ctx := WithRequest(context.Background(), Request{
		ID: "req-1", FrontendID: "fe-1", SourceIP: "203.0.113.7", SourceIPFrom: "x-forwarded-for",
	})
	Warn(ctx, logger, AuthzDecision.WithOutcome("deny"), "denied", slog.String("role", "deploy"))

	line := strings.TrimSpace(buf.String())
	keys := []string{
		keyEventType, keyEventCategory, keyOutcome, keyService, keyVersion, keyAdapter,
		keySchemaVersion, keyRequestID, keyFrontendRequestID, keySourceIP, keySourceIPFrom,
		"role", "msg", "level", "time",
	}
	for _, key := range keys {
		if count := strings.Count(line, "\""+key+"\":"); count > 1 {
			t.Errorf("key %q appears %d times, want at most 1: %s", key, count, line)
		}
	}
}
