package logevent

import (
	"context"
	"log/slog"
	"runtime"
	"time"
)

// Debug logs e at Debug level; eventType, eventCategory and outcome precede attrs.
func Debug(ctx context.Context, l *slog.Logger, e Event, msg string, attrs ...slog.Attr) {
	logEvent(ctx, l, slog.LevelDebug, e, msg, attrs...)
}

// Info logs e at Info level; see Debug.
func Info(ctx context.Context, l *slog.Logger, e Event, msg string, attrs ...slog.Attr) {
	logEvent(ctx, l, slog.LevelInfo, e, msg, attrs...)
}

// Warn logs e at Warn level; see Debug.
func Warn(ctx context.Context, l *slog.Logger, e Event, msg string, attrs ...slog.Attr) {
	logEvent(ctx, l, slog.LevelWarn, e, msg, attrs...)
}

// Error logs e at Error level; see Debug.
func Error(ctx context.Context, l *slog.Logger, e Event, msg string, attrs ...slog.Attr) {
	logEvent(ctx, l, slog.LevelError, e, msg, attrs...)
}

// logEvent builds the record itself so source points at the caller; a nil l uses slog.Default().
func logEvent(ctx context.Context, l *slog.Logger, level slog.Level, e Event, msg string, attrs ...slog.Attr) {
	if l == nil {
		l = slog.Default()
	}
	if !l.Enabled(ctx, level) {
		return
	}

	var pcs [1]uintptr
	runtime.Callers(3, pcs[:]) // skip [Callers, logEvent, Debug/Info/Warn/Error]
	r := slog.NewRecord(time.Now(), level, msg, pcs[0])

	base := make([]slog.Attr, 0, len(attrs)+3)
	base = append(base, slog.String(keyEventType, e.typ), slog.String(keyEventCategory, e.Category()))
	if e.outcome != "" {
		base = append(base, slog.String(keyOutcome, e.outcome))
	}
	r.AddAttrs(append(base, attrs...)...)

	_ = l.Handler().Handle(ctx, r)
}
