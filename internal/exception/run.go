// Background expiry sweep, wired in serve. Mirrors posture.Run: an
// immediate pass at boot plus an hourly tick.
//
// Spec: api-compliance-exceptions v1.0.0 (C-06).
package exception

import (
	"context"
	"log/slog"
	"time"

	"github.com/Hanalyx/openwatch/internal/cron"
)

// Run starts the expiry sweep on a cron tick with one immediate pass.
func (s *Service) Run(ctx context.Context, interval time.Duration) *cron.Scheduler {
	if interval == 0 {
		interval = ExpirySweepInterval
	}
	if n, err := s.ExpireSweep(ctx); err != nil {
		slog.WarnContext(ctx, "exception boot expiry sweep failed", "err", err)
	} else if n > 0 {
		slog.InfoContext(ctx, "exception expiry sweep", "expired", n)
	}
	tick := cron.New(interval, func(ctx context.Context) error {
		n, err := s.ExpireSweep(ctx)
		if err != nil {
			slog.ErrorContext(ctx, "exception expiry sweep failed", "err", err)
			return err
		}
		if n > 0 {
			slog.InfoContext(ctx, "exception expiry sweep", "expired", n)
		}
		return nil
	})
	tick.Start(ctx)
	return tick
}
