// Package cron is the minimal Stage-0 cron scheduler. A single Scheduler
// fires a Tick function at a fixed interval. Each tick produces a fresh
// cron- correlation_id; jobs enqueued during the tick share that ID.
//
// Real distributed scheduling (leader election, missed-tick recovery)
// lands in Stage 2 when the first real scheduled consumer arrives.
//
// Spec: app/specs/system/job-queue.spec.yaml AC-09.
package cron

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/Hanalyx/openwatch/internal/correlation"
)

// TickFunc is the user-supplied tick body. Receives a context carrying a
// fresh cron- correlation_id. Returning an error logs but does not stop
// the scheduler.
type TickFunc func(ctx context.Context) error

// Scheduler runs a single TickFunc at a fixed interval until Stop is
// called. Safe to construct via New; not goroutine-safe to mutate after Run.
type Scheduler struct {
	interval time.Duration
	tick     TickFunc
	stop     chan struct{}
	wg       sync.WaitGroup
}

// New constructs a Scheduler. interval must be > 0; tick must be non-nil.
func New(interval time.Duration, tick TickFunc) *Scheduler {
	return &Scheduler{
		interval: interval,
		tick:     tick,
		stop:     make(chan struct{}),
	}
}

// Start runs the scheduler loop until Stop is called or ctx is canceled.
// Returns immediately; the loop runs on a background goroutine.
func (s *Scheduler) Start(ctx context.Context) {
	s.wg.Add(1)
	go s.loop(ctx)
}

// Stop signals the loop to exit and waits for the in-flight tick (if any)
// to complete. Idempotent; safe to call multiple times via t.Cleanup.
func (s *Scheduler) Stop() {
	select {
	case <-s.stop:
		// Already stopped.
	default:
		close(s.stop)
	}
	s.wg.Wait()
}

func (s *Scheduler) loop(parentCtx context.Context) {
	defer s.wg.Done()
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-parentCtx.Done():
			return
		case <-s.stop:
			return
		case <-t.C:
			// Fresh per-tick correlation_id (spec system-job-queue AC-09).
			tickCtx := correlation.Set(parentCtx, correlation.Generate(correlation.PrefixCron))
			if err := s.tick(tickCtx); err != nil {
				slog.WarnContext(tickCtx, "cron tick failed",
					slog.String("err", err.Error()))
			}
		}
	}
}
