// Background password-expiry sweep, wired in serve. Mirrors
// exception.Service.Run: an immediate pass at boot plus a daily tick.
//
// Spec: system-account-policy v1.0.0 C-04.
package accountpolicy

import (
	"context"
	"log/slog"
	"time"

	"github.com/Hanalyx/openwatch/internal/cron"
)

// Run starts the expiry sweep on a cron tick with one immediate pass.
func (s *Service) Run(ctx context.Context, interval time.Duration) *cron.Scheduler {
	if interval == 0 {
		interval = SweepInterval
	}
	s.sweepOnceLogged(ctx, "boot ")
	tick := cron.New(interval, func(ctx context.Context) error {
		s.sweepOnceLogged(ctx, "")
		return nil
	})
	tick.Start(ctx)
	return tick
}

// sweepOnceLogged runs one pass, logging the outcome. A sweep error is logged
// but never stops the tick (the next pass retries).
func (s *Service) sweepOnceLogged(ctx context.Context, phase string) {
	if n, err := s.SweepOnce(ctx); err != nil {
		slog.WarnContext(ctx, "accountpolicy "+phase+"expiry sweep failed", "err", err.Error())
	} else if n > 0 {
		slog.InfoContext(ctx, "accountpolicy expiry sweep", "notified", n)
	}
}
