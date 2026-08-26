package utils

import (
	"fmt"
	"log/slog"
	"math"
	"os"
	"strconv"
	"strings"
)

// FormatClaimValue renders a verified JWT claim value as the string recorded
// in an audit record or attached as an STS session tag.
//
// It exists because claims are decoded into map[string]any, so every JSON
// number arrives as a float64 — and fmt's default float verb (%g) renders a
// 10-digit epoch second as "1.7555904e+09". Scientific notation is not
// something a human reads as a timestamp or a SIEM parses as a number, so an
// integral float64 is rendered as an integer instead. Everything else falls
// through to %v unchanged, so string claims (the common case) are untouched.
//
// Both call sites — handler.auditClaims and aws.BuildSessionTags — must go
// through this. The audit trail documents that a claim reported in `claims`
// and the same claim attached as a session tag can never disagree, and two
// different number formatters would break exactly that.
func FormatClaimValue(raw any) string {
	// The 1<<53 bound is float64's exact-integer range; past it the int64
	// conversion would print a value the token never carried. 2^53 itself is
	// exactly representable, so the bound is inclusive — an exclusive test
	// pushed that one value into %g and printed "9.007199254740992e+15".
	if f, ok := raw.(float64); ok && f == math.Trunc(f) && math.Abs(f) <= 1<<53 {
		return strconv.FormatInt(int64(f), 10)
	}
	return fmt.Sprintf("%v", raw)
}

// ExtractBranchFromRef reduces a Git ref to its short branch name,
// e.g. "refs/heads/main" -> "main". Any ref that is not a branch ref — a tag
// ref, or an issuer whose `ref` claim carries something else entirely — is
// returned unchanged, so callers that compare against both forms (tag-auth's
// `branch` dimension) still work for a non-GitHub issuer.
func ExtractBranchFromRef(ref string) string {
	if strings.HasPrefix(ref, "refs/heads/") {
		return strings.TrimPrefix(ref, "refs/heads/")
	}
	return ref
}

// GetEnv returns the value of the environment variable key, or fallback when
// the variable is unset. An explicitly empty variable is a set variable and
// wins over fallback.
func GetEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// ParseLogLevel converts a level name to an slog.Level, case-insensitively.
// "warn" and "warning" are both accepted; anything else is an error rather
// than a silent fallback to info.
func ParseLogLevel(level string) (slog.Level, error) {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.Level(0), fmt.Errorf("invalid log level: %s", level)
	}
}

// RedactToken redacts a token string for safe logging, preserving only the
// first firstN and last lastN bytes. A token too short to survive that split is
// masked entirely, so the function never reveals more of a short token than of
// a long one. The counts are byte offsets, not runes: a multi-byte token can be
// cut mid-rune, which is acceptable for an opaque credential that is never
// rendered as text.
//
// Every count is clamped — negatives to zero, oversized ones to the token
// length. Neither can arise from a current caller, since the pipeline keeps
// token material out of logs entirely rather than logging it redacted and this
// has no callers by design. Both are still clamped because either one would
// otherwise panic inside a log call, which is the one place a redaction helper
// must not fail: a negative slices out of range directly, and an oversized pair
// overflows int when summed, wrapping negative so the too-short guard below is
// skipped and the slice panics anyway.
func RedactToken(token string, firstN, lastN int) string {
	if token == "" {
		return ""
	}
	if firstN < 0 {
		firstN = 0
	}
	if lastN < 0 {
		lastN = 0
	}

	tokenLen := len(token)

	// Clamp each count to the token length *before* summing them: firstN+lastN
	// overflows for adversarially large counts and the comparison below would
	// then be against a negative number.
	if firstN > tokenLen {
		firstN = tokenLen
	}
	if lastN > tokenLen {
		lastN = tokenLen
	}

	// If token is shorter than firstN + lastN, just mask it all
	if tokenLen <= firstN+lastN {
		return strings.Repeat("*", tokenLen)
	}

	// Otherwise, keep firstN and lastN characters visible
	return token[:firstN] + "..." + token[tokenLen-lastN:]
}
