package utils_test

import (
	"encoding/json"
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
