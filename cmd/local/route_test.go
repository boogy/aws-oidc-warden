package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

func TestBuildEvent(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		target     string
		wantPath   string
		wantMethod string
	}{
		{"idp token", http.MethodPost, "/idp/token", "/idp/token", "POST"},
		{"discovery", http.MethodGet, "/.well-known/openid-configuration", "/.well-known/openid-configuration", "GET"},
		{"verify", http.MethodPost, "/verify", "/verify", "POST"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, tt.target+"?a=1", nil)
			r.Header.Set("X-Test", "v")
			ev := buildEvent(r, []byte("body"), "rid", "1.2.3.4")
			if ev.Path != tt.wantPath || ev.HTTPMethod != tt.wantMethod {
				t.Errorf("got %s %s, want %s %s", ev.HTTPMethod, ev.Path, tt.wantMethod, tt.wantPath)
			}
			if ev.Body != "body" || ev.Headers["X-Test"] != "v" || ev.QueryStringParameters["a"] != "1" ||
				ev.RequestContext.RequestID != "rid" || ev.RequestContext.Identity.SourceIP != "1.2.3.4" {
				t.Errorf("event fields not copied: %+v", ev)
			}
		})
	}
}

func TestLocalHandlerCopiesHeaders(t *testing.T) {
	stub := func(_ context.Context, ev events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusOK,
			Headers:    map[string]string{"Cache-Control": "max-age=60", "Allow": "GET, HEAD"},
			Body:       ev.Path,
		}, nil
	}
	h := localHandler(slog.New(slog.NewTextHandler(io.Discard, nil)), 0, stub)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if rec.Header().Get("Cache-Control") != "max-age=60" || rec.Header().Get("Allow") != "GET, HEAD" {
		t.Errorf("headers = %v", rec.Header())
	}
	if rec.Body.String() != "/.well-known/jwks.json" {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestLocalHandlerVerifyRejectsNonPost(t *testing.T) {
	called := false
	stub := func(context.Context, events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
		called = true
		return events.APIGatewayProxyResponse{StatusCode: http.StatusOK}, nil
	}
	h := localHandler(slog.New(slog.NewTextHandler(io.Discard, nil)), 0, stub)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/verify", strings.NewReader("")))
	if rec.Code != http.StatusMethodNotAllowed || called {
		t.Errorf("code = %d, called = %v", rec.Code, called)
	}
}
