package utils

import (
	"fmt"
	"log/slog"
	"math"
	"os"
	"strconv"
	"strings"
)

// FormatClaimValue renders a verified JWT claim value as the string used in
// audit records, STS session tags, and condition/tag comparisons. Integral
// floats above 2^53 lose precision at JSON-decode time (float64), so two
// distinct claim values can render identically; this function can't recover
// that.
func FormatClaimValue(raw any) string {
	// IsInf guard: +Inf/-Inf satisfy f == Trunc(f). 1e21 cutoff matches where
	// %v itself switches to exponent form.
	if f, ok := raw.(float64); ok && !math.IsInf(f, 0) && !math.IsNaN(f) &&
		f == math.Trunc(f) && math.Abs(f) < 1e21 {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	return fmt.Sprintf("%v", raw)
}

// ExtractBranchFromRef reduces a branch ref to its short name
// ("refs/heads/main" -> "main"). Anything else is returned unchanged.
func ExtractBranchFromRef(ref string) string {
	if b, ok := strings.CutPrefix(ref, "refs/heads/"); ok {
		return b
	}
	return ref
}

// GetEnv returns the environment variable key, or fallback when it is unset.
// An explicitly empty variable is set, and wins over fallback.
func GetEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// ParseLogLevel converts a level name to an slog.Level, case-insensitively.
// An unknown name is an error, not a silent fallback to info.
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

// RedactToken keeps the first firstN and last lastN bytes of a token and masks
// the rest; a token too short to survive the split is masked entirely.
// Has no callers by design — the pipeline keeps tokens out of logs entirely.
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

	// Clamp before summing: firstN+lastN overflows for large counts.
	if firstN > tokenLen {
		firstN = tokenLen
	}
	if lastN > tokenLen {
		lastN = tokenLen
	}

	if tokenLen <= firstN+lastN {
		return strings.Repeat("*", tokenLen)
	}

	return token[:firstN] + "..." + token[tokenLen-lastN:]
}
