package logevent

import (
	"io"
	"log/slog"

	"github.com/boogy/aws-oidc-warden/internal/version"
)

// Setup installs and returns the default JSON logger carrying the base schema attrs.
func Setup(w io.Writer, level slog.Leveler, adapter string) *slog.Logger {
	h := NewHandler(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level}))
	logger := slog.New(h).With(
		slog.String(keyService, serviceName),
		slog.String(keyVersion, version.Version),
		slog.String(keyAdapter, adapter),
		slog.Int(keySchemaVersion, schemaVersion),
	)
	slog.SetDefault(logger)
	return logger
}
