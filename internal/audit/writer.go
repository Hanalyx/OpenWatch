package audit

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// WriterOptions configures the batched writer. Defaults are set in
// DefaultWriterOptions; production callers tune as needed.
type WriterOptions struct {
	// ChannelBuffer is the size of the in-flight queue. Overflow drops
	// events (Emit returns immediately) and increments pkgDropped.
	// Default: 1024 per app/specs/system/audit-emission.spec.yaml.
	ChannelBuffer int

	// BatchSize caps how many events the writer flushes in one DB INSERT
	// transaction. Smaller = lower latency-per-event, more round-trips;
	// larger = fewer round-trips, more memory + risk on crash.
	// Default: 100.
	BatchSize int

	// FlushInterval caps how long an event waits in the queue before its
	// batch flushes. The writer flushes at min(BatchSize, FlushInterval).
	// Default: 100ms.
	FlushInterval time.Duration
}

// DefaultWriterOptions matches the spec's locked values.
func DefaultWriterOptions() WriterOptions {
	return WriterOptions{
		ChannelBuffer: 1024,
		BatchSize:     100,
		FlushInterval: 100 * time.Millisecond,
	}
}

// Writer drains the audit channel, batches events, and persists them via
// the storage layer. One Writer per process; Init() owns the singleton.
type Writer struct {
	storage Storage
	opts    WriterOptions

	ch chan *Event

	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// NewWriter constructs a Writer. Call Start to begin the drain goroutine.
func NewWriter(storage Storage, opts WriterOptions) *Writer {
	if opts.ChannelBuffer <= 0 {
		opts.ChannelBuffer = 1024
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 100
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = 100 * time.Millisecond
	}
	return &Writer{
		storage: storage,
		opts:    opts,
		ch:      make(chan *Event, opts.ChannelBuffer),
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}
}

// Start launches the drain goroutine. Safe to call once; subsequent calls
// panic (programming error — only Init should call Start).
func (w *Writer) Start() {
	go w.run()
}

// Stop signals shutdown and waits up to deadline for the drain to
// complete. Pending events are flushed even after Stop is called, as long
// as the deadline allows.
func (w *Writer) Stop(deadline time.Duration) {
	w.stopOnce.Do(func() {
		close(w.stopCh)
	})

	timer := time.NewTimer(deadline)
	defer timer.Stop()
	select {
	case <-w.doneCh:
	case <-timer.C:
		// Shutdown path has no per-request ctx — use Background and let the
		// CorrelationHandler emit without a correlation_id attribute.
		slog.WarnContext(context.Background(),
			"audit writer: drain deadline exceeded; some events may be lost")
	}
}

// run is the writer goroutine. It batches up to BatchSize events or
// FlushInterval (whichever comes first) and flushes via Storage.
func (w *Writer) run() {
	defer close(w.doneCh)

	batch := make([]*Event, 0, w.opts.BatchSize)
	ticker := time.NewTicker(w.opts.FlushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		// Redact each event right before write. Per spec: minimize the
		// window where sensitive data sits unredacted in memory.
		for _, ev := range batch {
			ev.Detail, ev.Redactions = Redact(ev.Detail)
			if ev.RecordedAt.IsZero() {
				ev.RecordedAt = time.Now().UTC()
			}
		}
		flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := w.flushBatch(flushCtx, batch); err != nil {
			pkgWriteFailures.Add(int64(len(batch)))
			slog.ErrorContext(flushCtx, "audit writer: flush failed",
				slog.Int("batch_size", len(batch)),
				slog.String("error", err.Error()),
			)
		}
		cancel()
		batch = batch[:0]
	}

	for {
		select {
		case <-w.stopCh:
			// Bounded final drain. Read all currently-buffered events.
			// Late producers that fire concurrent with shutdown either
			// land in this window OR get dropped via the select-default
			// fast path in Emit (channel-full). We do NOT close w.ch
			// because closing creates panic risk for goroutines already
			// past their pkgMu.RUnlock that may still send.
			drainDeadline := time.After(100 * time.Millisecond)
			draining := true
			for draining {
				select {
				case ev := <-w.ch:
					batch = append(batch, ev)
					if len(batch) >= w.opts.BatchSize {
						flush()
					}
				case <-drainDeadline:
					draining = false
				}
			}
			flush()
			return

		case ev := <-w.ch:
			batch = append(batch, ev)
			if len(batch) >= w.opts.BatchSize {
				flush()
			}

		case <-ticker.C:
			flush()
		}
	}
}

// flushBatch is the storage call. Wrapped so tests can inject a Storage
// implementation that captures events without DB access.
func (w *Writer) flushBatch(ctx context.Context, batch []*Event) error {
	if bs, ok := w.storage.(batchStorage); ok {
		return bs.InsertBatch(ctx, batch)
	}
	// Fallback for storage implementations without batch support:
	// per-row inserts. Slower; production pgStore always implements
	// batchStorage so this path is test-only.
	for _, ev := range batch {
		if err := w.storage.InsertEvent(ctx, ev); err != nil {
			return err
		}
	}
	return nil
}

// batchStorage is the optional batch-insert capability. pgStore
// implements it; mock stores in tests may not.
type batchStorage interface {
	InsertBatch(ctx context.Context, events []*Event) error
}
