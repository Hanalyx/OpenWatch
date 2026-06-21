package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/google/uuid"
)

// Package-level writer state. Init wires it; Shutdown drains it.
// The intent is that main() sets up one global emitter at boot and every
// foundation/handler calls audit.Emit() without threading a writer
// around.
var (
	pkgMu     sync.RWMutex
	pkgWriter *Writer

	// Counters surfaced via metrics (Day 5b will hook real Prometheus or
	// equivalent). Tests read these directly.
	pkgDropped            atomic.Int64 // events dropped due to channel overflow
	pkgMissingCorrelation atomic.Int64 // events emitted with no correlation_id on ctx
	pkgWriteFailures      atomic.Int64 // events whose flush returned an error
)

// Init starts the package-level writer. Must be called once at boot,
// before any handler emits. Idempotent: a second call is a no-op (the
// existing writer is retained).
func Init(storage Storage, opts WriterOptions) {
	pkgMu.Lock()
	defer pkgMu.Unlock()
	if pkgWriter != nil {
		return
	}
	pkgWriter = NewWriter(storage, opts)
	pkgWriter.Start()
}

// Shutdown stops the package-level writer, draining pending events.
// Returns once all in-flight events have flushed or the given deadline
// passes. Called from main() during graceful shutdown.
func Shutdown(deadline time.Duration) {
	pkgMu.Lock()
	w := pkgWriter
	pkgWriter = nil
	pkgMu.Unlock()
	if w == nil {
		return
	}
	w.Stop(deadline)
}

// Counters returns the current values of the metric counters. Test/
// diagnostic only; production code observes via the metrics exporter.
func Counters() (dropped, missingCorr, writeFail int64) {
	return pkgDropped.Load(), pkgMissingCorrelation.Load(), pkgWriteFailures.Load()
}

// resetCountersForTest is only used by tests to isolate counter state
// between test functions.
func resetCountersForTest() {
	pkgDropped.Store(0)
	pkgMissingCorrelation.Store(0)
	pkgWriteFailures.Store(0)
}

// Emit enqueues an audit event for asynchronous persistence. Returns
// immediately; the channel send is the only blocking work on the caller.
//
// Fills in defaults: ID (UUIDv7), OccurredAt (now), CorrelationID (from
// ctx), Severity (from registry if zero). Redaction is performed by the
// writer goroutine before insertion to keep this path fast.
//
// Per spec AC-4, AC-5.
func Emit(ctx context.Context, code Code, ev Event) {
	prepared := prepareEvent(ctx, code, ev)

	pkgMu.RLock()
	w := pkgWriter
	pkgMu.RUnlock()
	if w == nil {
		// No writer wired — log and drop. Should only happen during very
		// early boot (before Init) or in tests that didn't call Init.
		slog.WarnContext(ctx, "audit.Emit called before Init; event dropped",
			slog.String("action", string(code)))
		pkgDropped.Add(1)
		return
	}

	select {
	case w.ch <- prepared:
	default:
		pkgDropped.Add(1)
		slog.WarnContext(ctx, "audit channel overflow; event dropped",
			slog.String("action", string(code)),
			slog.Int64("dropped_total", pkgDropped.Load()),
		)
	}
}

// EmitSync persists an event synchronously, blocking until the row is
// committed. Reserved for events that must be durable before the request
// returns: license install, system.startup/shutdown, suspected tampering.
//
// Per spec AC-6, AC-7.
func EmitSync(ctx context.Context, code Code, ev Event) error {
	prepared := prepareEvent(ctx, code, ev)
	prepared.Detail, prepared.Redactions = Redact(prepared.Detail)

	pkgMu.RLock()
	w := pkgWriter
	pkgMu.RUnlock()
	if w == nil {
		return fmt.Errorf("audit: EmitSync called before Init")
	}

	// Respect caller's deadline if one is already set; only impose a
	// 1-second budget when ctx has no deadline of its own. Avoids
	// silently overriding a shorter caller-supplied timeout.
	syncCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		syncCtx, cancel = context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
	}
	if err := w.storage.InsertEvent(syncCtx, prepared); err != nil {
		pkgWriteFailures.Add(1)
		return fmt.Errorf("audit: EmitSync: %w", err)
	}
	return nil
}

// prepareEvent fills caller-omitted fields and stamps server-side
// defaults. Does NOT redact (writer does that just before INSERT to
// minimize the time between sensitive value present and scrubbed).
//
// EmitSync calls Redact explicitly because it skips the writer queue.
func prepareEvent(ctx context.Context, code Code, ev Event) *Event {
	if ev.ID == uuid.Nil {
		ev.ID = uuid.Must(uuid.NewV7())
	}
	if ev.OccurredAt.IsZero() {
		ev.OccurredAt = time.Now().UTC()
	}
	if ev.Action == "" {
		ev.Action = code
	}
	if ev.Severity == "" {
		if meta, ok := Metadata[code]; ok {
			ev.Severity = meta.Severity
		}
	}
	if ev.CorrelationID == "" {
		if id, ok := correlation.From(ctx); ok {
			ev.CorrelationID = id
		} else {
			pkgMissingCorrelation.Add(1)
		}
	}
	return &ev
}

// MaxDetailFieldLen bounds an attacker-influenced free-text string (a
// submitted username, a User-Agent header) recorded in audit detail.
const MaxDetailFieldLen = 256

// ClipDetail bounds an attacker-influenced string placed in audit detail:
// it truncates to MaxDetailFieldLen runes and replaces control characters
// with spaces. This stops an oversized header/field from bloating the
// audit_events.detail JSONB and neutralizes control-character log forging if
// the detail is ever rendered in a raw (non-escaping) context. It is NOT a
// substitute for key-name redaction (Redact), which scrubs secret values.
func ClipDetail(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= MaxDetailFieldLen {
			break
		}
		if r < 0x20 || r == 0x7f {
			r = ' '
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// jsonRawCopy is a small helper for callers that build details via map.
// audit.MakeDetail(map[string]any{"foo":"bar"}) → json.RawMessage.
// Provided here so handlers don't have to import encoding/json directly.
func MakeDetail(v interface{}) json.RawMessage {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}
