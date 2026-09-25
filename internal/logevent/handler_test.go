package logevent

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
)

func newTestHandler(buf *bytes.Buffer) slog.Handler {
	return NewHandler(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestHandler_AddsRequestFieldsWhenPresent(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(newTestHandler(&buf))
	ctx := WithRequest(context.Background(), Request{
		ID: "req-1", FrontendID: "fe-1", SourceIP: "203.0.113.7", SourceIPFrom: "x-forwarded-for",
	})

	l.InfoContext(ctx, "line")

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v (%s)", err, buf.String())
	}
	for key, want := range map[string]string{
		keyRequestID:         "req-1",
		keyFrontendRequestID: "fe-1",
		keySourceIP:          "203.0.113.7",
		keySourceIPFrom:      "x-forwarded-for",
	} {
		if parsed[key] != want {
			t.Errorf("%s = %v, want %v", key, parsed[key], want)
		}
	}
}

func TestHandler_SuppressesSourceIPFromWhenFrontendAttested(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(newTestHandler(&buf))
	ctx := WithRequest(context.Background(), Request{SourceIP: "203.0.113.7", SourceIPFrom: sourceFromFrontend})

	l.InfoContext(ctx, "line")

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v (%s)", err, buf.String())
	}
	if _, ok := parsed[keySourceIPFrom]; ok {
		t.Errorf("sourceIpFrom present for the platform-attested value, want suppressed: %v", parsed)
	}
	if parsed[keySourceIP] != "203.0.113.7" {
		t.Errorf("sourceIp = %v, want 203.0.113.7", parsed[keySourceIP])
	}
}

func TestHandler_OmitsFieldsWhenNoRequestOnContext(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(newTestHandler(&buf))

	l.InfoContext(context.Background(), "line")

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v (%s)", err, buf.String())
	}
	for _, key := range []string{keyRequestID, keyFrontendRequestID, keySourceIP, keySourceIPFrom} {
		if _, ok := parsed[key]; ok {
			t.Errorf("%s present with no Request on context, want omitted", key)
		}
	}
}

func TestHandler_OmitsEmptyRequestFields(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(newTestHandler(&buf))
	ctx := WithRequest(context.Background(), Request{ID: "req-1"})

	l.InfoContext(ctx, "line")

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v (%s)", err, buf.String())
	}
	for _, key := range []string{keyFrontendRequestID, keySourceIP, keySourceIPFrom} {
		if _, ok := parsed[key]; ok {
			t.Errorf("%s present though empty on the Request, want omitted", key)
		}
	}
	if parsed[keyRequestID] != "req-1" {
		t.Errorf("requestId = %v, want req-1", parsed[keyRequestID])
	}
}

func TestHandler_WithAttrsPersistsAndStillInjectsContext(t *testing.T) {
	var buf bytes.Buffer
	base := newTestHandler(&buf)
	withAttrs := base.WithAttrs([]slog.Attr{slog.String("service", "aws-oidc-warden")})
	l := slog.New(withAttrs)

	ctx := WithRequest(context.Background(), Request{ID: "req-1"})
	l.InfoContext(ctx, "line")

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v (%s)", err, buf.String())
	}
	if parsed["service"] != "aws-oidc-warden" {
		t.Errorf("service = %v, want aws-oidc-warden (WithAttrs must persist)", parsed["service"])
	}
	if parsed[keyRequestID] != "req-1" {
		t.Errorf("requestId = %v, want req-1 (WithAttrs must still return a ctx-injecting handler)", parsed[keyRequestID])
	}
}

func TestHandler_WithGroupNestsRequestFields(t *testing.T) {
	var buf bytes.Buffer
	base := newTestHandler(&buf)
	grouped := base.WithGroup("g")
	l := slog.New(grouped)

	ctx := WithRequest(context.Background(), Request{ID: "req-1"})
	l.InfoContext(ctx, "line")

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v (%s)", err, buf.String())
	}
	group, ok := parsed["g"].(map[string]any)
	if !ok {
		t.Fatalf("expected nested group %q, got %v", "g", parsed)
	}
	if group[keyRequestID] != "req-1" {
		t.Errorf("requestId under group g = %v, want req-1 (documented WithGroup nesting behavior)", group[keyRequestID])
	}
}

func TestHandler_EnabledDelegatesToInner(t *testing.T) {
	var buf bytes.Buffer
	h := NewHandler(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	if h.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("Enabled(Debug) = true on a Warn-level inner handler, want false")
	}
	if !h.Enabled(context.Background(), slog.LevelWarn) {
		t.Error("Enabled(Warn) = false on a Warn-level inner handler, want true")
	}
}
