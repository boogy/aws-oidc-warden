package main

import (
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/handler"
)

func TestServeWaitsForShutdownToDrain(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	srv := newServer("", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		_, _ = io.WriteString(w, "done")
	}), 0)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan os.Signal, 1)
	returned := make(chan error, 1)
	go func() { returned <- serve(t.Context(), slog.Default(), srv, ln, stop, 5*time.Second) }()

	body := make(chan string, 1)
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String())
		if err != nil {
			body <- err.Error()
			return
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		body <- string(b)
	}()
	<-entered

	stop <- os.Interrupt
	select {
	case err := <-returned:
		t.Fatalf("serve returned (%v) while a request was still draining", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	if err := <-returned; err != nil {
		t.Fatalf("serve returned %v after a clean shutdown", err)
	}
	if got := <-body; got != "done" {
		t.Errorf("in-flight response = %q, want %q", got, "done")
	}
}

func TestServeReturnsListenerError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	srv := newServer("", http.NotFoundHandler(), 0)
	if err := serve(t.Context(), slog.Default(), srv, ln, make(chan os.Signal), time.Second); err == nil {
		t.Fatal("expected the accept error to be returned")
	}
}

func TestNewServerLimits(t *testing.T) {
	for _, latency := range []time.Duration{0, 2 * time.Second, time.Minute} {
		srv := newServer(":0", http.NotFoundHandler(), latency)
		if min := latency + handler.DefaultTimeout; srv.WriteTimeout <= min {
			t.Errorf("latency %v: WriteTimeout %v must exceed latency + handler timeout (%v)", latency, srv.WriteTimeout, min)
		}
		if srv.MaxHeaderBytes != 64<<10 {
			t.Errorf("MaxHeaderBytes = %d, want %d", srv.MaxHeaderBytes, 64<<10)
		}
	}
}

func TestParseCliFlagsHost(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantHost string
		wantAddr string
	}{
		{"default is loopback", []string{"x"}, "127.0.0.1", "127.0.0.1:8080"},
		{"container", []string{"x", "-host", "0.0.0.0", "-port", "9090"}, "0.0.0.0", "0.0.0.0:9090"},
		{"ipv6", []string{"x", "-host=::1"}, "::1", "[::1]:8080"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldFlags, oldArgs := flag.CommandLine, os.Args
			t.Cleanup(func() { flag.CommandLine, os.Args = oldFlags, oldArgs })
			flag.CommandLine = flag.NewFlagSet("x", flag.ContinueOnError)
			os.Args = tt.args

			settings, err := parseCliFlags()
			if err != nil {
				t.Fatal(err)
			}
			if settings.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", settings.Host, tt.wantHost)
			}
			if got := net.JoinHostPort(settings.Host, strconv.Itoa(settings.Port)); got != tt.wantAddr {
				t.Errorf("addr = %q, want %q", got, tt.wantAddr)
			}
		})
	}
}
