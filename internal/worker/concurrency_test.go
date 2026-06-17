// @spec system-job-queue
//
// Bounded-concurrency drain: the in-process worker runs up to N claim/process
// loops at once so a fleet of queued jobs does not drain one at a time. SKIP
// LOCKED gives each loop a disjoint job; the per-host advisory lock (covered by
// scan_worker_test.go) still serializes same-host scans.

package worker

import (
	"context"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/Hanalyx/openwatch/internal/queue"
	"github.com/google/uuid"
)

// blockingDiscovery signals each invocation on started, then blocks until
// release is closed. host.discovery is a convenient vehicle: it has no per-host
// lock, so it isolates the worker's fan-out from the scan path's serialization.
type blockingDiscovery struct {
	started chan struct{}
	release chan struct{}
}

func (b *blockingDiscovery) RunDiscovery(_ context.Context, _ uuid.UUID) error {
	b.started <- struct{}{}
	<-b.release
	return nil
}

// @ac AC-12
// AC-12: with WithConcurrency(N) and N+1 blocking jobs, exactly N run at once
// and the (N+1)th waits for a free loop.
func TestWorker_BoundedConcurrency(t *testing.T) {
	t.Run("system-job-queue/AC-12", func(t *testing.T) {
		pool := dbtest.Pool(t)
		const n = 3
		d := &blockingDiscovery{started: make(chan struct{}, 16), release: make(chan struct{})}
		w := New(pool).WithDiscovery(d).WithConcurrency(n)

		// Enqueue N+1 host.discovery jobs for distinct hosts.
		for i := 0; i < n+1; i++ {
			ctx := correlation.Set(context.Background(), correlation.Generate("test"))
			// Pass the map directly — Enqueue marshals it (passing pre-marshaled
			// bytes would double-encode into a JSON string).
			body := map[string]string{"host_id": uuid.NewString()}
			if _, err := queue.Enqueue(ctx, pool, "host.discovery", body); err != nil {
				t.Fatalf("enqueue %d: %v", i, err)
			}
		}

		w.Start(context.Background())
		defer w.Stop()

		// Exactly N jobs enter RunDiscovery concurrently.
		for i := 0; i < n; i++ {
			select {
			case <-d.started:
			case <-time.After(5 * time.Second):
				t.Fatalf("only %d/%d jobs started concurrently", i, n)
			}
		}
		// The (N+1)th must NOT have started — fan-out is bounded at N.
		select {
		case <-d.started:
			t.Fatal("more than N jobs ran at once — concurrency not bounded")
		case <-time.After(400 * time.Millisecond):
			// good: bounded
		}

		// Free the in-flight loops; the (N+1)th now claims a freed loop.
		close(d.release)
		select {
		case <-d.started:
		case <-time.After(5 * time.Second):
			t.Fatal("the (N+1)th job never ran after release — a freed loop did not pick it up")
		}
	})
}

// @ac AC-12
// AC-12 (clamp): a concurrency < 1 clamps to 1 so the default worker stays
// strictly serial; a positive value is kept.
func TestWorker_WithConcurrencyClamps(t *testing.T) {
	t.Run("system-job-queue/AC-12", func(t *testing.T) {
		cases := map[int]int{0: 1, -5: 1, 1: 1, 8: 8}
		for in, want := range cases {
			if got := New(nil).WithConcurrency(in).concurrency; got != want {
				t.Errorf("WithConcurrency(%d) = %d, want %d", in, got, want)
			}
		}
		// New defaults to serial.
		if got := New(nil).concurrency; got != 1 {
			t.Errorf("New default concurrency = %d, want 1", got)
		}
	})
}
