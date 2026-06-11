package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/queue"
)

// Service is the live scheduler. Constructed once at boot via NewService,
// held for the process lifetime. Owns the cron tick (driven externally
// via internal/cron) and the dispatcher pass.
type Service struct {
	pool          *pgxpool.Pool
	ladder        TierLadder
	policyVersion string
	hmacKey       []byte
	emit          EmitFunc
	metrics       *Metrics

	// Now is the wall-clock function used by Dispatch. Defaults to
	// time.Now; tests override with a deterministic clock.
	Now func() time.Time
}

// NewService wires the scheduler. The pool is the shared application
// pgxpool; load carries the clamped ladder + snapshotted policy_version;
// hmacKey is the DeriveQueueKey-derived HMAC key; emit is audit.Emit in
// production (or a fake in tests).
//
// v2.0.0 breaking change: the defaultFramework parameter is removed.
// Per the framework-at-query-time architecture, the scheduler does
// not carry a framework — the executor scans the full applicable
// rule corpus and framework slicing is a query-time projection.
func NewService(pool *pgxpool.Pool, load LoadResult, hmacKey []byte, emit EmitFunc) *Service {
	return &Service{
		pool:          pool,
		ladder:        load.Ladder,
		policyVersion: load.PolicyVersion,
		hmacKey:       hmacKey,
		emit:          emit,
		metrics:       NewMetrics(),
		Now:           time.Now,
	}
}

// Metrics returns the runtime metrics handle (read-only via Snapshot).
func (s *Service) Metrics() *Metrics { return s.metrics }

// dueRow is one host_compliance_schedule row claimed by the dispatcher
// in its FOR UPDATE SKIP LOCKED pass.
type dueRow struct {
	HostID   uuid.UUID
	State    ComplianceState
	NextScan time.Time
}

// dispatchBatchSize caps the number of hosts a single Dispatch pass will
// claim. 100 is large enough that small fleets drain in one tick and
// small enough that concurrent ticks can each find something to do.
const dispatchBatchSize = 100

// Dispatch performs one dispatcher pass.
//
// Steps:
//  1. BEGIN transaction
//  2. SELECT host_compliance_schedule ... FOR UPDATE SKIP LOCKED LIMIT N
//     (filtered to rows where next_scheduled_scan <= now() and
//     maintenance_mode = false)
//  3. For each claimed row: build JobPayload, HMAC-sign, queue.Enqueue
//     under job_type "scan", UPDATE next_scheduled_scan forward, emit
//     scheduler.schedule.updated.
//  4. COMMIT
//  5. Emit scheduler.tick.dispatched with the per-tick counters.
//
// Returns the number of hosts dispatched.
//
// Spec ACs satisfied:
//
//   - AC-04 (C-03): FOR UPDATE SKIP LOCKED. Two concurrent Dispatch
//     calls (from two workers or two ticks) claim disjoint rows.
//   - AC-05 (C-05): maintenance_mode = true rows are excluded from the
//     SELECT and so never dispatched.
//   - AC-06 (C-06, C-12): each job payload carries host_id,
//     policy_version, enqueued_at; all HMAC-signed.
//   - AC-13 (C-09): every UPDATE to host_compliance_schedule emits
//     scheduler.schedule.updated.
func (s *Service) Dispatch(ctx context.Context) (int, error) {
	now := s.Now()
	s.metrics.SetLastTick(now)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("scheduler: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const selectStmt = `
		SELECT host_id, compliance_state, next_scheduled_scan
		  FROM host_compliance_schedule
		 WHERE next_scheduled_scan <= $1
		   AND maintenance_mode = false
		 ORDER BY next_scheduled_scan
		 FOR UPDATE SKIP LOCKED
		 LIMIT $2`

	rows, err := tx.Query(ctx, selectStmt, now, dispatchBatchSize)
	if err != nil {
		return 0, fmt.Errorf("scheduler: select due: %w", err)
	}
	var due []dueRow
	for rows.Next() {
		var r dueRow
		if err := rows.Scan(&r.HostID, &r.State, &r.NextScan); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scheduler: scan due row: %w", err)
		}
		due = append(due, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("scheduler: iterate due rows: %w", err)
	}

	s.metrics.DueCount.Add(int64(len(due)))

	dispatched := 0
	for _, r := range due {
		payload := JobPayload{
			HostID:        r.HostID,
			PolicyVersion: s.policyVersion,
			EnqueuedAt:    now,
		}
		tag := Sign(s.hmacKey, payload)

		// JobPayload encoded into JSONB. host_id is a string for
		// JSON-friendly storage; the HMAC tag is hex for the same.
		// v2.0.0 — no framework_id key (per system-scheduler v2 C-12).
		body := map[string]any{
			"host_id":        payload.HostID.String(),
			"policy_version": payload.PolicyVersion,
			"enqueued_at":    payload.EnqueuedAt.UTC().Format(time.RFC3339Nano),
			"hmac":           fmt.Sprintf("%x", tag[:]),
		}
		if _, err := queue.Enqueue(ctx, s.pool, "scan", body); err != nil {
			return dispatched, fmt.Errorf("scheduler: enqueue %s: %w", r.HostID, err)
		}

		// Move next_scheduled_scan forward so a subsequent tick before
		// the scan completes does not re-dispatch. Real recompute (from
		// the scan result) happens later in UpdateAfterScan.
		newNext := now.Add(s.ladder[r.State])
		if _, err := tx.Exec(ctx, `
			UPDATE host_compliance_schedule
			   SET next_scheduled_scan = $1, updated_at = now()
			 WHERE host_id = $2`,
			newNext, r.HostID); err != nil {
			return dispatched, fmt.Errorf("scheduler: update schedule %s: %w", r.HostID, err)
		}
		s.emitScheduleUpdated(ctx, r.HostID, "next_scan_advanced", r.NextScan, newNext)
		dispatched++
	}
	s.metrics.DispatchedCount.Add(int64(dispatched))

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("scheduler: commit: %w", err)
	}

	s.emit(ctx, audit.SchedulerTickDispatched, audit.Event{
		ActorType: "system",
		Detail: mustJSON(map[string]any{
			"due_count":        len(due),
			"dispatched_count": dispatched,
		}),
	})

	return dispatched, nil
}

// emitScheduleUpdated produces a scheduler.schedule.updated audit event
// for a single row mutation. Detail.prior / Detail.new are kept minimal
// (next_scheduled_scan only) for now; the change_kind enum tells consumers
// which mutation occurred.
func (s *Service) emitScheduleUpdated(ctx context.Context, hostID uuid.UUID, kind string, priorNext, newNext time.Time) {
	s.emit(ctx, audit.SchedulerScheduleUpdated, audit.Event{
		ActorType: "system",
		Detail: mustJSON(map[string]any{
			"host_id":     hostID.String(),
			"change_kind": kind,
			"prior":       map[string]any{"next_scheduled_scan": priorNext.UTC().Format(time.RFC3339Nano)},
			"new":         map[string]any{"next_scheduled_scan": newNext.UTC().Format(time.RFC3339Nano)},
		}),
	})
}

// mustJSON marshals v to JSON. Marshal of map[string]any never returns
// an error for scalar values; defensively swallow any future failure.
func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
