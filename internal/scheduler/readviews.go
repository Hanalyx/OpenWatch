// Read-only projections over host_compliance_schedule for the HTTP
// surface (api-system-scan-config). They live HERE because this
// package owns the table (spec C-07 / AC-07: nothing under
// internal/server may reference host_compliance_schedule, reads
// included — the guard test enforces it by filename sweep).
//
// Spec: system-scheduler v3.0.0 + api-system-scan-config v1.0.0.

package scheduler

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// StateCount is one fleet-states row: a compliance state and the count
// of live hosts in it.
type StateCount struct {
	State     ComplianceState
	HostCount int
}

// FleetStateCounts returns one entry per ComplianceState in ladder
// order (AllStates), zero-count states included. Soft-deleted hosts
// never count; a live host without a schedule row counts as unknown.
func FleetStateCounts(ctx context.Context, pool *pgxpool.Pool) ([]StateCount, error) {
	const q = `
		SELECT COALESCE(s.compliance_state, 'unknown') AS state, COUNT(*)::bigint
		  FROM hosts h
		  LEFT JOIN host_compliance_schedule s ON s.host_id = h.id
		 WHERE h.deleted_at IS NULL
		 GROUP BY 1`
	rows, err := pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("scheduler: fleet state counts: %w", err)
	}
	defer rows.Close()

	counts := map[string]int{}
	for rows.Next() {
		var state string
		var n int64
		if err := rows.Scan(&state, &n); err != nil {
			return nil, fmt.Errorf("scheduler: scan state count: %w", err)
		}
		counts[state] = int(n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scheduler: iterate state counts: %w", err)
	}

	out := make([]StateCount, 0, len(AllStates()))
	for _, st := range AllStates() {
		out = append(out, StateCount{State: st, HostCount: counts[string(st)]})
	}
	return out, nil
}

// SchedulePreview is the 24h forward projection consumed by the
// Settings schedule strip. Buckets always has exactly 24 entries
// (index == hours from now).
type SchedulePreview struct {
	NextScanAt *time.Time
	DueNow     int
	Buckets    [24]int
}

// PreviewSchedule projects host_compliance_schedule forward 24 hours:
// the soonest FUTURE next_scheduled_scan, the already-due backlog, and
// per-hour due counts. Maintenance-mode rows and soft-deleted hosts
// are excluded from every figure. Read-only — never a dry-run dispatch.
func PreviewSchedule(ctx context.Context, pool *pgxpool.Pool, now time.Time) (SchedulePreview, error) {
	var p SchedulePreview

	if err := pool.QueryRow(ctx, `
		SELECT MIN(s.next_scheduled_scan) FILTER (WHERE s.next_scheduled_scan > $1),
		       COUNT(*) FILTER (WHERE s.next_scheduled_scan <= $1)
		  FROM host_compliance_schedule s
		  JOIN hosts h ON h.id = s.host_id AND h.deleted_at IS NULL
		 WHERE s.maintenance_mode = false`, now,
	).Scan(&p.NextScanAt, &p.DueNow); err != nil {
		return p, fmt.Errorf("scheduler: preview aggregates: %w", err)
	}

	rows, err := pool.Query(ctx, `
		SELECT FLOOR(EXTRACT(EPOCH FROM (s.next_scheduled_scan - $1)) / 3600)::int AS hour_offset,
		       COUNT(*)::bigint
		  FROM host_compliance_schedule s
		  JOIN hosts h ON h.id = s.host_id AND h.deleted_at IS NULL
		 WHERE s.maintenance_mode = false
		   AND s.next_scheduled_scan > $1
		   AND s.next_scheduled_scan <= $1 + interval '24 hours'
		 GROUP BY 1`, now)
	if err != nil {
		return p, fmt.Errorf("scheduler: preview buckets: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var offset int
		var n int64
		if err := rows.Scan(&offset, &n); err != nil {
			return p, fmt.Errorf("scheduler: scan preview bucket: %w", err)
		}
		if offset >= 0 && offset < 24 {
			p.Buckets[offset] = int(n)
		}
	}
	if err := rows.Err(); err != nil {
		return p, fmt.Errorf("scheduler: iterate preview buckets: %w", err)
	}
	return p, nil
}
