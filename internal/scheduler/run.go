package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/Hanalyx/openwatch/internal/cron"
)

// DefaultTickInterval is the production cron tick cadence. Spec C-02
// fixes this at 60 seconds; finer cadence offers no improvement and
// adds dispatcher contention. Constant rather than configurable so
// tests can source-inspect the value.
const DefaultTickInterval = 60 * time.Second

// Run wires the scheduler to a fixed-interval cron tick.
//
// Spec ACs satisfied here:
//
//   - AC-03 (C-02): the cron tick fires at DefaultTickInterval (60s in
//     production). The internal/cron package's TickFunc-based loop has
//     a fresh correlation_id per tick; multiple consecutive ticks that
//     find nothing due (because Dispatch already advanced
//     next_scheduled_scan) are a no-op, so "missed tick" recovery never
//     produces double-dispatch.
//
// interval defaults to DefaultTickInterval when 0; tests can override
// to a sub-second cadence so the test doesn't block for a minute.
func (s *Service) Run(ctx context.Context, interval time.Duration) *cron.Scheduler {
	if interval == 0 {
		interval = DefaultTickInterval
	}
	tick := cron.New(interval, func(ctx context.Context) error {
		if _, err := s.Dispatch(ctx); err != nil {
			slog.ErrorContext(ctx, "scheduler tick: dispatch failed", "err", err)
			return err
		}
		return nil
	})
	tick.Start(ctx)
	return tick
}
