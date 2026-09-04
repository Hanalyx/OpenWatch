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
	"log/slog"
	"strconv"
	"strings"
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
	res := LoadIntervals(PolicyTiers{
		// Version is derived from the EFFECTIVE ladder below, not from these
		// raw values, so this placeholder is overwritten before returning.
		Version: "",
		IntervalMins: map[ComplianceState]int{
			// An unassessable host is not less urgent than one known to be
			// failing, so unknown is clamped to critical when an operator has
			// configured it slower. The shipped defaults were unknown 360 and
			// critical 240, so before bugs/OW-024 fixing the fabricated zero
			// would have moved those hosts from a 4-hour re-check to a 6-hour
			// one: a correction that quietly reduced monitoring.
			StateUnknown:         minInt(cfg.UnknownMins, cfg.CriticalMins),
			StateCritical:        cfg.CriticalMins,
			StateNonCompliant:    cfg.NonCompliantMins,
			StatePartial:         cfg.PartialMins,
			StateMostlyCompliant: cfg.MostlyCompliantMins,
			StateCompliant:       cfg.CompliantMins,
		},
	})
	res.PolicyVersion = policyVersionFromLadder(res.Ladder)
	return res
}

// policyVersionFromLadder derives the version snapshot from the six EFFECTIVE
// intervals, in canonical state order.
//
// AC-01 promises that two configurations producing the same ladder produce the
// same version, and building the string from raw config values broke that
// wherever a clamp applied. Raw 1 minute and raw 5 minutes both land on the
// 5-minute floor; raw 100 hours and raw 48 hours both land on the ceiling; and
// unknown=360/critical=240 now lands on the same ladder as unknown=240. Each
// produced a different version for an identical cadence, and the version is what
// the in-flight-snapshot constraint compares.
//
// Deriving from the ladder makes the contract structural rather than a thing
// two expressions have to be kept in agreement about.
func policyVersionFromLadder(l TierLadder) string {
	order := []ComplianceState{
		StateUnknown, StateCritical, StateNonCompliant,
		StatePartial, StateMostlyCompliant, StateCompliant,
	}
	parts := make([]string, 0, len(order))
	for _, st := range order {
		parts = append(parts, strconv.Itoa(int(l[st]/time.Minute)))
	}
	return "cfg-" + strings.Join(parts, "-")
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

// minInt clamps the unknown cadence. Kept explicit rather than inlined so the
// invariant "unknown is never slower than critical" has one place to read.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
