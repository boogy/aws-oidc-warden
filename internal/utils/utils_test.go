package utils_test

import (
	"encoding/json"
	"log/slog"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// TestRedactToken_OversizedCountsDoNotPanic guards the other half of the clamp.
// Clamping only the negatives is not enough: firstN+lastN is summed before the
// too-short guard, and for counts near MaxInt that sum overflows and wraps
// negative, so `tokenLen <= firstN+lastN` is false and execution falls through
// to a slice that is guaranteed out of range. Each count is therefore clamped
// to the token length before the sum, which also makes every oversized case
// collapse onto the fully-masked answer a too-long request should give.
func TestRedactToken_OversizedCountsDoNotPanic(t *testing.T) {
	const token = "sometoken1234567890"
	masked := strings.Repeat("*", len(token))
	cases := []struct {
		name          string
		firstN, lastN int
		want          string
	}{
		{"first overflows the sum", math.MaxInt, 1, masked},
		{"last overflows the sum", 1, math.MaxInt, masked},
		{"both overflow the sum", math.MaxInt, math.MaxInt, masked},
		{"first alone is oversized", math.MaxInt, 0, masked},
		{"merely longer than the token", len(token) + 1, len(token) + 1, masked},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := utils.RedactToken(token, c.firstN, c.lastN)
			if got != c.want {
				t.Errorf("RedactToken(token, %d, %d) = %q, want %q", c.firstN, c.lastN, got, c.want)
			}
			if strings.Contains(got, "token12345") {
				t.Errorf("RedactToken(token, %d, %d) leaked the token: %q", c.firstN, c.lastN, got)
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

// TestFormatClaimValue covers the reason this helper exists: JWT claims are
// decoded into map[string]any, so every JSON number is a float64, and fmt's
// default float verb renders a 10-digit epoch second in scientific notation.
func TestFormatClaimValue(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  any
		want string
	}{
		// The defect this helper fixes: %v on float64(1755590400) is
		// "1.7555904e+09", which no auditor reads as a timestamp and no SIEM
		// parses as a number.
		{"epoch second", float64(1755590400), "1755590400"},
		{"small integral number", float64(42), "42"},
		{"zero", float64(0), "0"},
		{"negative integral", float64(-7), "-7"},
		// Non-integral values keep their fractional part; there is nothing to
		// gain by reshaping them.
		{"fractional stays fractional", 1.5, "1.5"},
		// Strings are the common case and must pass through untouched.
		{"string", "org/repo", "org/repo"},
		{"empty string", "", ""},
		{"bool", true, "true"},
		// Past float64's exact-integer range an int64 conversion would print a
		// value the token never carried, so fall back to %v.
		{"beyond exact integer range", float64(1 << 60), "1.152921504606847e+18"},
		// 2^53 is the last exactly-representable integer, so it converts
		// losslessly and must be printed as an integer; 2^53+2 is the next
		// representable one above the bound and must not be.
		{"at exact integer bound", float64(1 << 53), "9007199254740992"},
		{"negative exact integer bound", float64(-(1 << 53)), "-9007199254740992"},
		{"just past exact integer bound", float64(1<<53) + 2, "9.007199254740994e+15"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, utils.FormatClaimValue(tc.raw))
		})
	}
}

// TestFormatClaimValue_RoundTripsRealClaimDecode pins the behavior against an
// actual JSON decode rather than hand-built float64s, since the whole point is
// what encoding/json hands back for a numeric claim.
func TestFormatClaimValue_RoundTripsRealClaimDecode(t *testing.T) {
	var claims map[string]any
	require.NoError(t, json.Unmarshal(
		[]byte(`{"exp":1755590400,"repository_id":42,"repository":"org/repo"}`), &claims))

	assert.Equal(t, "1755590400", utils.FormatClaimValue(claims["exp"]))
	assert.Equal(t, "42", utils.FormatClaimValue(claims["repository_id"]))
	assert.Equal(t, "org/repo", utils.FormatClaimValue(claims["repository"]))
}
