package utils_test

import (
	"encoding/json"
	"log/slog"
	"math"
	"os"
	"regexp"
	"strconv"
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

type namedString string

func TestFormatClaimValue(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  any
		want string
	}{
		{"epoch second", float64(1755590400), "1755590400"},
		{"small integral number", float64(42), "42"},
		{"zero", float64(0), "0"},
		{"negative integral", float64(-7), "-7"},
		{"fractional stays fractional", 1.5, "1.5"},
		{"negative fractional", -0.25, "-0.25"},
		{"string", "org/repo", "org/repo"},
		{"empty string", "", ""},
		{"bool", true, "true"},
		{"at exact integer bound", float64(1 << 53), "9007199254740992"},
		{"negative exact integer bound", float64(-(1 << 53)), "-9007199254740992"},
		{"just past old exact-integer bound", float64(1<<53) + 2, "9007199254740994"},
		// Digits aren't the exact binary value of 1<<60: past 2^53, FormatFloat's
		// shortest round-trip decimal need not match the truncated integer.
		{"beyond exact integer range", float64(1 << 60), "1152921504606847000"},
		{"just below 1e21 boundary", math.Nextafter(1e21, 0), "999999999999999900000"},
		{"1e21 stays decimal rather than exponent form", 1e21, "1000000000000000000000"},
		{"negative 1e21 stays decimal", -1e21, "-1000000000000000000000"},
		{"1e30 stays decimal", 1e30, "1000000000000000000000000000000"},
		{"positive infinity", math.Inf(1), "+Inf"},
		{"negative infinity", math.Inf(-1), "-Inf"},
		{"NaN", math.NaN(), "NaN"},
		{"int", 42, "42"},
		{"int64", int64(42), "42"},
		{"nil", nil, "<nil>"},
		{"slice", []string{"a", "b"}, "[a b]"},
		{"any slice", []any{"a", float64(2), true}, "[a 2 true]"},
		{"string with percent and braces", "100% {x} %v", "100% {x} %v"},
		{"unicode string", "é世界", "é世界"},
		{"named string type", namedString("n"), "n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, utils.FormatClaimValue(tc.raw))
		})
	}
}

func TestFormatClaimValue_ExactIntegerRangeUnchanged(t *testing.T) {
	for _, f := range []float64{
		0, 1, -1, 42, -42, 1 << 53, -(1 << 53),
		12345, -12345, 1 << 20, -(1 << 20), 9007199254740991, -9007199254740991,
	} {
		want := strconv.FormatInt(int64(f), 10)
		t.Run(want, func(t *testing.T) {
			assert.Equal(t, want, utils.FormatClaimValue(f))
		})
	}
}

// A none_of written in decimal must be able to match a huge integral claim:
// exponent form would render a text no operator writes and disarm the veto.
func TestFormatClaimValue_NoExponentFormForIntegralFloats(t *testing.T) {
	for _, f := range []float64{1e21, -1e21, 1e30, 1e100, math.MaxFloat64} {
		got := utils.FormatClaimValue(f)
		if strings.ContainsAny(got, "eE") {
			t.Errorf("FormatClaimValue(%v) = %q, want full decimal with no exponent", f, got)
		}
	}
}

func TestFormatClaimValue_RoundTripsRealClaimDecode(t *testing.T) {
	var claims map[string]any
	require.NoError(t, json.Unmarshal(
		[]byte(`{"exp":1755590400,"repository_id":42,"repository":"org/repo"}`), &claims))

	assert.Equal(t, "1755590400", utils.FormatClaimValue(claims["exp"]))
	assert.Equal(t, "42", utils.FormatClaimValue(claims["repository_id"]))
	assert.Equal(t, "org/repo", utils.FormatClaimValue(claims["repository"]))
}

func TestSanitizeSTSName(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"slash", "org/repo", "org=repo"},
		{"subject", "repo:myorg/api:ref:refs/heads/main", "repo=myorg=api=ref=refs=heads=main"},
		{"space and star", "a b*c", "a=b=c"},
		{"plus replaced", "ok+=,.@-_1", "ok==,.@-_1"},
		{"empty", "", ""},
		{"long input keeps length", strings.Repeat("a/", 100), strings.Repeat("a=", 100)},
		{"forged hash tail", strings.Repeat("a", 47) + "+" + strings.Repeat("0", 16), strings.Repeat("a", 47) + "=" + strings.Repeat("0", 16)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, utils.SanitizeSTSName(tt.in))
		})
	}
}

func TestFitSTSName(t *testing.T) {
	validName := regexp.MustCompile(`^[\w+=,.@-]{2,64}$`)

	t.Run("exactly 64 unchanged", func(t *testing.T) {
		in := strings.Repeat("a", 64)
		assert.Equal(t, in, utils.FitSTSName(in))
	})
	t.Run("65 is capped with hash tail", func(t *testing.T) {
		in := strings.Repeat("a", 65)
		got := utils.FitSTSName(in)
		assert.Len(t, got, utils.MaxSTSNameLen)
		assert.Equal(t, in[:47]+"+", got[:48])
	})
	t.Run("deterministic", func(t *testing.T) {
		in := strings.Repeat("b", 80)
		assert.Equal(t, utils.FitSTSName(in), utils.FitSTSName(in))
	})
	t.Run("same prefix different tail NotEqual", func(t *testing.T) {
		prefix := strings.Repeat("a", 47) + strings.Repeat("c", 20)
		assert.NotEqual(t, utils.FitSTSName(prefix+"x"), utils.FitSTSName(prefix+"y"))
	})
	t.Run("multibyte input yields a valid name", func(t *testing.T) {
		assert.Regexp(t, validName, utils.FitSTSName(strings.Repeat("é/", 60)))
	})
}

func TestFitSanitizedSTSName(t *testing.T) {
	t.Run("plus in short input survives", func(t *testing.T) {
		in := strings.Repeat("a", 13) + "+" + strings.Repeat("0", 16)
		assert.Equal(t, in, utils.FitSanitizedSTSName(in))
	})
	t.Run("over 64 is capped", func(t *testing.T) {
		assert.Len(t, utils.FitSanitizedSTSName(strings.Repeat("a", 100)), utils.MaxSTSNameLen)
	})
}

func TestReadAllCapped(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{"under cap", 9, false},
		{"at cap", 10, false},
		{"over cap", 11, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := utils.ReadAllCapped(strings.NewReader(strings.Repeat("a", tt.size)), 10, "doc")
			if tt.wantErr {
				require.ErrorContains(t, err, "doc exceeds 10 bytes")
				assert.Nil(t, data)
				return
			}
			require.NoError(t, err)
			assert.Len(t, data, tt.size)
		})
	}
}

func TestValidSTSName(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"ab", true},
		{"a", false},
		{strings.Repeat("a", 64), true},
		{strings.Repeat("a", 65), false},
		{"user+tag=v,x.y@z-w_1", true},
		{"owner/repo", false},
		{"has space", false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, utils.ValidSTSName(tt.in), tt.in)
	}
}

func TestValidSTSSessionSecs(t *testing.T) {
	for secs, want := range map[int32]bool{899: false, 900: true, 43200: true, 43201: false, 0: false} {
		assert.Equal(t, want, utils.ValidSTSSessionSecs(secs), secs)
	}
}
