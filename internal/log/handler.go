// Package log provides the slog handler that automatically tags every
// log record with the correlation_id from context.
//
// Wiring: main.go wraps slog.NewJSONHandler in CorrelationHandler and
// installs it as the default logger. After that, every
// slog.InfoContext(ctx, ...) call carries the correlation_id without the
// caller having to add it manually.
//
// Spec: app/specs/system/correlation.spec.yaml AC-12, AC-13.
package log

import (
	"context"
	"log/slog"

	"github.com/Hanalyx/openwatch/internal/correlation"
)

// CorrelationHandler wraps another slog.Handler. On every record, it
// inspects the supplied context for a correlation ID and, when present,
// adds it as a top-level attribute on the record before delegating.
//
// When the context carries no ID (e.g., a slog.Info call without ctx, or
// a ctx that never went through the HTTP middleware), the wrapper does
// nothing — the record is emitted without correlation_id. The forbidigo
// lint rule (active from Day 4) flags non-Context slog calls so this
// situation is rare and intentional (boot-time only).
type CorrelationHandler struct {
	inner slog.Handler
}

// NewCorrelationHandler wraps the inner handler. The inner handler does
// the actual writing; this wrapper just tags records.
func NewCorrelationHandler(inner slog.Handler) *CorrelationHandler {
	return &CorrelationHandler{inner: inner}
}

// Enabled delegates to the inner handler.
func (h *CorrelationHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle adds correlation_id (when present) and delegates.
func (h *CorrelationHandler) Handle(ctx context.Context, r slog.Record) error {
	if id, ok := correlation.From(ctx); ok {
		r.AddAttrs(slog.String("correlation_id", id))
	}
	return h.inner.Handle(ctx, r)
}

// WithAttrs preserves the chain. The wrapper itself doesn't hold state;
// the inner handler's WithAttrs is honored.
func (h *CorrelationHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &CorrelationHandler{inner: h.inner.WithAttrs(attrs)}
}

// WithGroup preserves the chain.
func (h *CorrelationHandler) WithGroup(name string) slog.Handler {
	return &CorrelationHandler{inner: h.inner.WithGroup(name)}
}
