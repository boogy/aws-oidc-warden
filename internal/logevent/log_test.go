package logevent

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestLevelHelpers_WriteEventTypeAndCategory(t *testing.T) {
	for _, tc := range []struct {
		name  string
		log   func(ctx context.Context, l *slog.Logger, e Event, msg string, attrs ...slog.Attr)
		level string
	}{
		{"Debug", Debug, "DEBUG"},
		{"Info", Info, "INFO"},
		{"Warn", Warn, "WARN"},
		{"Error", Error, "ERROR"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			l := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

			tc.log(context.Background(), l, STSAssumeRoleFailure, "assume role failed", slog.String("role", "deploy"))

			var parsed map[string]any
			if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
				t.Fatalf("output is not valid JSON: %v (%s)", err, buf.String())
			}
			if parsed["level"] != tc.level {
				t.Errorf("level = %v, want %v", parsed["level"], tc.level)
			}
			if parsed[keyEventType] != "sts.assume_role.failure" {
				t.Errorf("eventType = %v, want sts.assume_role.failure", parsed[keyEventType])
			}
			if parsed[keyEventCategory] != "sts" {
				t.Errorf("eventCategory = %v, want sts", parsed[keyEventCategory])
			}
			if parsed[keyOutcome] != "failure" {
				t.Errorf("outcome = %v, want failure", parsed[keyOutcome])
			}
			if parsed["role"] != "deploy" {
				t.Errorf("role = %v, want deploy", parsed["role"])
			}
			if parsed["msg"] != "assume role failed" {
				t.Errorf("msg = %v, want static message unchanged", parsed["msg"])
			}
		})
	}
}

func TestLogEvent_OutcomeOmittedWhenEmpty(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	Debug(context.Background(), l, CacheHit, "cache hit", slog.String("backend", "memory"))

	line := buf.String()
	if strings.Contains(line, "\""+keyOutcome+"\"") {
		t.Errorf("outcome key present for an event with no derivable outcome: %s", line)
	}
}

func TestLogEvent_NilLoggerUsesDefault(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	Info(context.Background(), nil, AppStart, "starting")

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v (%s)", err, buf.String())
	}
	if parsed[keyEventType] != "app.start" {
		t.Errorf("eventType = %v, want app.start (nil logger must fall back to slog.Default())", parsed[keyEventType])
	}
}

func TestLogEvent_NoDuplicateKeys(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	Warn(context.Background(), l, STSSessionTagDropped, "tag dropped",
		slog.String("dropReason", "invalid_key"), slog.String("role", "deploy"))

	line := strings.TrimSpace(buf.String())
	for _, key := range []string{keyEventType, keyEventCategory, "dropReason", "role", "msg", "level", "time"} {
		if count := strings.Count(line, "\""+key+"\":"); count > 1 {
			t.Errorf("key %q appears %d times, want at most 1: %s", key, count, line)
		}
	}
}

func TestLogEvent_DisabledLevelEmitsNothing(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError}))

	Warn(context.Background(), l, STSSessionTagDropped, "should be filtered")

	if buf.Len() != 0 {
		t.Fatalf("output emitted for a level disabled on the handler: %s", buf.String())
	}
}

func TestLogEvent_RecordsApplicationCallSite(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: true}))

	Info(context.Background(), l, AppStart, "starting") // this line is the call site that must be recorded

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v (%s)", err, buf.String())
	}
	source, ok := parsed["source"].(map[string]any)
	if !ok {
		t.Fatalf("expected a source field with AddSource:true, got %v", parsed)
	}
	file, _ := source["file"].(string)
	if !strings.HasSuffix(file, "log_test.go") {
		t.Errorf("source file = %q, want log_test.go (the application call site, not log.go)", file)
	}
}

func TestLevelHelpers_UseTheRequestedLevel(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	Debug(context.Background(), l, CacheHit, "should be filtered")
	if buf.Len() != 0 {
		t.Fatalf("Debug line emitted despite Warn-level handler: %s", buf.String())
	}

	Warn(context.Background(), l, STSSessionTagDropped, "should pass")
	if buf.Len() == 0 {
		t.Fatal("Warn line was filtered by a Warn-level handler, want it emitted")
	}
}
