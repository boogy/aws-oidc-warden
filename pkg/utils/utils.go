package utils

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

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

// TruncateString truncates a string to the specified length and adds an ellipsis if truncated
func TruncateString(s string, maxLength int) string {
	if len(s) <= maxLength {
		return s
	}

	return s[:maxLength-3] + "..."
}
