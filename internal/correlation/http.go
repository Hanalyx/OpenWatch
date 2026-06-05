package correlation

import (
	"context"
	"log/slog"
	"net/http"
)

// HeaderName is the HTTP header carrying the correlation ID.
const HeaderName = "X-Correlation-Id"

// HTTPMiddleware extracts (or generates) a correlation ID for every
// incoming request, places it on the request context, and echoes it back
// in the response header.
//
// It MUST be mounted before any other middleware that emits logs or audit
// events. Per correlation.spec.yaml AC-9..AC-11 and the design in
// app/docs/correlation_id_propagation.md §5.1.
//
// Rejected client headers (charset/length/reserved-prefix violations) are
// replaced with a freshly-generated req- ID; a warn-level log records the
// rejection with a truncated preview of the bad value.
func HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		client := r.Header.Get(HeaderName)
		id, regenerated := SanitizeOrGenerate(client)

		if regenerated {
			slog.WarnContext(r.Context(), "rejected client correlation id; regenerated",
				slog.String("rejected_preview", truncate(client, 16)),
				slog.String("correlation_id", id),
				slog.String("remote_addr", r.RemoteAddr),
				slog.String("path", r.URL.Path),
			)
		}

		// Set response header BEFORE handler runs; downstream may set its
		// own headers but we own this one.
		w.Header().Set(HeaderName, id)

		ctx := Set(r.Context(), id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// truncate returns s up to max chars with an ellipsis if it was cut.
// Used to keep rejected-header previews bounded in log lines.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// MustFrom is a test/diagnostic helper that returns the correlation ID
// from ctx or panics if missing. Intended for code paths that should
// never run without a correlation ID (e.g., post-middleware handlers).
//
// Not part of the public contract — exists so tests don't have to thread
// ok-checks. Production code should use From and handle the missing case.
func MustFrom(ctx context.Context) string {
	id, ok := From(ctx)
	if !ok {
		panic("correlation.MustFrom: no correlation id on context")
	}
	return id
}
