// Config bridge — systemconfig.ScanConfig → TierLadder.
//
// v3.0.0: the tier ladder is operator-editable systemconfig (scan plan
// decision #4, resolved 2026-06-12). The v2 signed schedules-policy
// file is no longer the ladder source; the HMAC job-payload signing
// (hmac.go) is unrelated and stays.
//
// Spec: system-scheduler v3.0.0 C-01.

package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/Hanalyx/openwatch/internal/cron"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
)

// LoadFromConfig converts the systemconfig scan config into a clamped
// LoadResult via the same LoadIntervals path the v2 policy loader
// used, so the floor/ceiling clamps (C-08/C-04) apply identically.
//
// The PolicyVersion snapshot is derived from the ladder values
// themselves ("cfg-<minutes joined>") rather than a signed policy
// version: it changes exactly when an operator edit changes the
// effective cadence, which is what the in-flight-snapshot constraint
// (C-06) actually protects.
func LoadFromConfig(cfg systemconfig.ScanConfig) LoadResult {
	return LoadIntervals(PolicyTiers{
		Version: fmt.Sprintf("cfg-%d-%d-%d-%d-%d-%d",
			cfg.UnknownMins, cfg.CriticalMins, cfg.NonCompliantMins,
			cfg.PartialMins, cfg.MostlyCompliantMins, cfg.CompliantMins),
		IntervalMins: map[ComplianceState]int{
			StateUnknown:         cfg.UnknownMins,
			StateCritical:        cfg.CriticalMins,
			StateNonCompliant:    cfg.NonCompliantMins,
			StatePartial:         cfg.PartialMins,
			StateMostlyCompliant: cfg.MostlyCompliantMins,
			StateCompliant:       cfg.CompliantMins,
		},
	})
}

// RunManaged wires the scheduler to the production cron tick with a
// config refresh before every Dispatch: each tick reloads the scan
// config from systemconfig, swaps the ladder/rate-limit/pause flag via
// Reload, then dispatches. Operator edits to /system/scan/config take
// effect within one tick; Enabled=false or MaintenanceGlobal=true
// pause dispatch without stopping the loop.
//
// A config load failure logs and keeps the last-known-good ladder —
// a transient DB blip must not freeze scanning on stale-but-sane
// settings or, worse, un-pause a paused fleet.
func (s *Service) RunManaged(ctx context.Context, interval time.Duration, store *systemconfig.Store) *cron.Scheduler {
	if interval == 0 {
		interval = DefaultTickInterval
	}
	tick := cron.New(interval, func(ctx context.Context) error {
		cfg, err := store.LoadScan(ctx)
		if err != nil {
			slog.ErrorContext(ctx, "scheduler tick: scan config load failed; keeping last ladder", "err", err)
		} else {
			s.Reload(LoadFromConfig(cfg), cfg.RateLimit, !cfg.Enabled || cfg.MaintenanceGlobal)
		}
		if _, err := s.Dispatch(ctx); err != nil {
			slog.ErrorContext(ctx, "scheduler tick: dispatch failed", "err", err)
			return err
		}
		return nil
	})
	tick.Start(ctx)
	return tick
}
