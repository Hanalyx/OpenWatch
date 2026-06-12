// PersistAfterScan + runtime Reload — the DB-integration half of the
// post-scan schedule update (the pure half is UpdateAfterScan).
//
// Spec: system-scheduler v3.0.0.

package scheduler

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ladderMu guards the Service fields the cron tick rewrites on config
// reload (ladder, policyVersion, rate limit, pause flag). Dispatch and
// PersistAfterScan read under the same lock.
//
// A plain mutex (not RWMutex): contention is one tick + one scan
// completion at a time — never hot.
var ladderMu sync.Mutex

// Reload swaps the active ladder + policy version snapshot and the
// per-tick rate limit / pause flag from a freshly-loaded config. Called
// by the cron tick before every Dispatch so operator edits to
// /system/scan/config take effect within one tick (60s) without a
// process restart.
//
// Spec v3.0.0 AC-10 (config reload replaces the v2 signed-policy
// reload): in-flight scans keep their enqueued policy_version snapshot;
// only future dispatches see the new ladder.
func (s *Service) Reload(load LoadResult, rateLimit int, paused bool) {
	ladderMu.Lock()
	defer ladderMu.Unlock()
	s.ladder = load.Ladder
	s.policyVersion = load.PolicyVersion
	if rateLimit < 1 {
		rateLimit = 1
	}
	if rateLimit > dispatchBatchSize {
		rateLimit = dispatchBatchSize
	}
	s.rateLimit = rateLimit
	s.paused = paused
}

// snapshot returns the reload-guarded fields consistently.
func (s *Service) snapshot() (TierLadder, string, int, bool) {
	ladderMu.Lock()
	defer ladderMu.Unlock()
	limit := s.rateLimit
	if limit == 0 {
		limit = dispatchBatchSize // NewService without Reload: legacy full batch
	}
	return s.ladder, s.policyVersion, limit, s.paused
}

// PersistAfterScan recomputes a host's compliance state from a
// completed scan's outcome and UPSERTs host_compliance_schedule.
// Called by the scan worker after every COMPLETED scan, scheduler-
// dispatched or on-demand: a fresh result is fresh compliance data
// either way, and re-anchoring next_scheduled_scan to "just scanned"
// prevents a pointless back-to-back auto scan after a manual one
// (v3.0.0 revision of the v2 "manual scans never touch the row" rule —
// manual scans still bypass dispatch-time row locks and advancement).
//
// Emits scheduler.schedule.updated with prior/new state (C-09).
func (s *Service) PersistAfterScan(ctx context.Context, hostID uuid.UUID, score float64, hasCritical bool, completedAt time.Time) (ScanResult, error) {
	ladder, _, _, _ := s.snapshot()
	res := UpdateAfterScan(score, hasCritical, completedAt, ladder)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return res, fmt.Errorf("scheduler: persist begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Read the prior row (if any) for the audit prior/new pair.
	priorNext := time.Time{}
	_ = tx.QueryRow(ctx, `
		SELECT next_scheduled_scan FROM host_compliance_schedule
		 WHERE host_id = $1 FOR UPDATE`, hostID).Scan(&priorNext)

	if _, err := tx.Exec(ctx, `
		INSERT INTO host_compliance_schedule
			(host_id, compliance_state, compliance_score, has_critical_findings,
			 current_interval_minutes, next_scheduled_scan, last_scan_completed_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, now())
		ON CONFLICT (host_id) DO UPDATE
		   SET compliance_state         = EXCLUDED.compliance_state,
		       compliance_score         = EXCLUDED.compliance_score,
		       has_critical_findings    = EXCLUDED.has_critical_findings,
		       current_interval_minutes = EXCLUDED.current_interval_minutes,
		       next_scheduled_scan      = EXCLUDED.next_scheduled_scan,
		       last_scan_completed_at   = EXCLUDED.last_scan_completed_at,
		       updated_at               = now()`,
		hostID, string(res.State), score, hasCritical,
		int(ladderInterval(ladder, res.State)/time.Minute), res.NextScheduled, completedAt,
	); err != nil {
		return res, fmt.Errorf("scheduler: persist after scan %s: %w", hostID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return res, fmt.Errorf("scheduler: persist commit: %w", err)
	}

	s.emitScheduleUpdated(ctx, hostID, "scan_completed", priorNext, res.NextScheduled)
	return res, nil
}

// ladderInterval is ladder[state] with the same shortest-known
// fallback NextScanFor uses, so the persisted current_interval_minutes
// never reads zero for an unmapped state.
func ladderInterval(ladder TierLadder, state ComplianceState) time.Duration {
	if d, ok := ladder[state]; ok {
		return d
	}
	return shortestInterval(ladder)
}
