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
	// conversion would print a value the token never carried.
	if f, ok := raw.(float64); ok && f == math.Trunc(f) && math.Abs(f) < 1<<53 {
		return strconv.FormatInt(int64(f), 10)
	}
	return fmt.Sprintf("%v", raw)
}

// extractBranchFromRef extracts the branch name from a GitHub ref
// e.g., "refs/heads/main" -> "main"
func ExtractBranchFromRef(ref string) string {
	if strings.HasPrefix(ref, "refs/heads/") {
		return strings.TrimPrefix(ref, "refs/heads/")
	}
	return ref
}

func GetEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// parseLogLevel converts a string to an slog.Level.
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

// RedactToken redacts a token string for safe logging, preserving only the first and last N characters
func RedactToken(token string, firstN, lastN int) string {
	if token == "" {
		return ""
	}

	tokenLen := len(token)

	// If token is shorter than firstN + lastN, just mask it all
	if tokenLen <= firstN+lastN {
		return strings.Repeat("*", tokenLen)
	}

	// Otherwise, keep firstN and lastN characters visible
	first := token[:firstN]
	last := token[tokenLen-lastN:]
	middle := "..." // strings.Repeat("*", tokenLen-firstN-lastN)

	return first + middle + last
}
