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
	s.sweepOnce(ctx, "boot ")
	tick := cron.New(interval, func(ctx context.Context) error {
		s.sweepOnce(ctx, "")
		return nil
	})
	tick.Start(ctx)
	return tick
}

// sweepOnce runs both expiry passes: flip lapsed exceptions to expired (and
// notify), then warn approvers about those expiring soon. Both are best-effort
// for notifications; a hard ExpireSweep error is logged but does not stop the
// tick (the next pass retries).
func (s *Service) sweepOnce(ctx context.Context, phase string) {
	if n, err := s.ExpireSweep(ctx); err != nil {
		slog.WarnContext(ctx, "exception "+phase+"expiry sweep failed", "err", err)
	} else if n > 0 {
		slog.InfoContext(ctx, "exception expiry sweep", "expired", n)
	}
	if n, err := s.ExpiringSoonSweep(ctx); err != nil {
		slog.WarnContext(ctx, "exception "+phase+"expiring-soon sweep failed", "err", err)
	} else if n > 0 {
		slog.InfoContext(ctx, "exception expiring-soon sweep", "warned", n)
	}
}
