package utils_test

import (
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/utils"
)

// TestExtractBranchFromRef covers the helper tag-auth applies to EVERY
// issuer's `ref` claim, not just GitHub's. The pass-through cases are the
// point: a non-branch ref must come back unchanged so the caller's
// "full ref OR short branch" comparison still has something exact to match.
func TestExtractBranchFromRef(t *testing.T) {
	tests := []struct{ name, ref, want string }{
		{"branch ref is shortened", "refs/heads/main", "main"},
		{"nested branch keeps its slashes", "refs/heads/feature/multi-issuer", "feature/multi-issuer"},
		{"tag ref passes through", "refs/tags/v3.0.0", "refs/tags/v3.0.0"},
		{"pull ref passes through", "refs/pull/42/merge", "refs/pull/42/merge"},
		{"bare branch name passes through", "main", "main"},
		{"gitlab-style ref passes through", "refs/merge-requests/7/head", "refs/merge-requests/7/head"},
		{"empty stays empty", "", ""},
		{"prefix alone yields empty branch", "refs/heads/", ""},
		{"case-different prefix is not a branch ref", "Refs/Heads/main", "Refs/Heads/main"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := utils.ExtractBranchFromRef(tt.ref); got != tt.want {
				t.Errorf("ExtractBranchFromRef(%q) = %q, want %q", tt.ref, got, tt.want)
			}
		})
	}
}

// TestParseLogLevel pins the accepted names and the fail-loud default. A silent
// fallback to info would hide a typo in AOW_LOG_LEVEL and quietly change how
// much of the pipeline is observable.
func TestParseLogLevel(t *testing.T) {
	ok := map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"DEBUG":   slog.LevelDebug,
		"info":    slog.LevelInfo,
		"Info":    slog.LevelInfo,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"WARNING": slog.LevelWarn,
		"error":   slog.LevelError,
		"ERROR":   slog.LevelError,
	}
	for in, want := range ok {
		got, err := utils.ParseLogLevel(in)
		if err != nil {
			t.Errorf("ParseLogLevel(%q): unexpected error %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseLogLevel(%q) = %v, want %v", in, got, want)
		}
	}
	for _, in := range []string{"", "verbose", "trace", "fatal", " info", "info "} {
		if _, err := utils.ParseLogLevel(in); err == nil {
			t.Errorf("ParseLogLevel(%q) returned no error", in)
		}
	}
}

// TestGetEnv covers the set/unset/empty distinction: an operator who exports a
// variable as empty has expressed a choice, and it must not be overwritten by
// the fallback.
func TestGetEnv(t *testing.T) {
	const key = "AOW_TEST_GETENV_PROBE"

	if got := utils.GetEnv(key, "fallback"); got != "fallback" {
		t.Errorf("unset var: got %q, want %q", got, "fallback")
	}

	t.Setenv(key, "explicit")
	if got := utils.GetEnv(key, "fallback"); got != "explicit" {
		t.Errorf("set var: got %q, want %q", got, "explicit")
	}

	t.Setenv(key, "")
	if got := utils.GetEnv(key, "fallback"); got != "" {
		t.Errorf("explicitly-empty var: got %q, want %q", got, "")
	}
	if _, ok := os.LookupEnv(key); !ok {
		t.Fatal("test precondition: var should still be set")
	}
}

// TestRedactToken covers the redaction helper's contract. The short-token cases
// matter most: a token too short to split must be fully masked, so the redacted
// form never leaks proportionally more of a small secret.
func TestRedactToken(t *testing.T) {
	tests := []struct {
		name          string
		token         string
		firstN, lastN int
		want          string
	}{
		{"empty token", "", 4, 4, ""},
		{"long token keeps head and tail", "abcdefghijklmnopqrst", 4, 4, "abcd...qrst"},
		{"exactly firstN+lastN is fully masked", "abcdefgh", 4, 4, "********"},
		{"shorter than window is fully masked", "abc", 4, 4, "***"},
		// A zero window reveals nothing at all, not even the length — safer
		// than the full mask, which is length-preserving by construction.
		{"zero window reveals nothing", "abcdef", 0, 0, "..."},
		{"head only", "abcdefghij", 3, 0, "abc..."},
		{"tail only", "abcdefghij", 0, 3, "...hij"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := utils.RedactToken(tt.token, tt.firstN, tt.lastN); got != tt.want {
				t.Errorf("RedactToken(%q, %d, %d) = %q, want %q", tt.token, tt.firstN, tt.lastN, got, tt.want)
			}
		})
	}
}

// TestRedactToken_NegativeCountsDoNotPanic guards the clamp. Before it, a
// negative count sliced out of range and panicked inside the log call the
// helper exists to make safe.
func TestRedactToken_NegativeCountsDoNotPanic(t *testing.T) {
	const token = "abcdefghijklmnop"
	cases := []struct {
		firstN, lastN int
		want          string
	}{
		{-1, 4, "...mnop"},
		{4, -1, "abcd..."},
		{-5, -5, "abcdefghijklmnop"[:0] + "..."},
	}
	for _, c := range cases {
		got := utils.RedactToken(token, c.firstN, c.lastN)
		if got != c.want {
			t.Errorf("RedactToken(token, %d, %d) = %q, want %q", c.firstN, c.lastN, got, c.want)
		}
		if strings.Contains(got, "efghijkl") {
			t.Errorf("RedactToken(token, %d, %d) leaked the token middle: %q", c.firstN, c.lastN, got)
		}
	}
}
