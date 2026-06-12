// Package posture maintains daily per-host compliance posture
// snapshots and serves the trend reads built on them.
//
// The rollup runs on an hourly cron tick (plus once at boot): it
// UPSERTs today's row per scanned host from the live host_rule_state
// aggregate. Intra-day re-scans refresh today's numbers; the row
// freezes when the date rolls over. History therefore accumulates
// going forward - there is no retroactive reconstruction from the
// transactions log.
//
// score_pct matches the compliance lens formula (passing / total over
// ALL statuses) so the trend line and the Compliance tab headline
// never disagree.
//
// Spec: system-posture-snapshots v1.0.0.
package posture

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/cron"
)

// RollupInterval is the production cadence of the snapshot rollup.
// Hourly is plenty: the row only needs to be right by midnight, and
// each pass is one aggregate UPSERT over a bounded table.
const RollupInterval = time.Hour

// Rollup UPSERTs today's snapshot row for every live host that has
// host_rule_state rows (a never-scanned host has no posture to
// record). Returns the number of host rows written.
func Rollup(ctx context.Context, pool *pgxpool.Pool, asOf time.Time) (int, error) {
	tag, err := pool.Exec(ctx, `
		INSERT INTO posture_snapshots
			(host_id, snapshot_date, passing, failing, skipped, error, total,
			 score_pct, has_critical_findings, updated_at)
		SELECT s.host_id,
		       $1::date,
		       COUNT(*) FILTER (WHERE s.current_status = 'pass'),
		       COUNT(*) FILTER (WHERE s.current_status = 'fail'),
		       COUNT(*) FILTER (WHERE s.current_status = 'skipped'),
		       COUNT(*) FILTER (WHERE s.current_status = 'error'),
		       COUNT(*),
		       ROUND((COUNT(*) FILTER (WHERE s.current_status = 'pass'))::numeric
		             / COUNT(*) * 1000) / 10,
		       BOOL_OR(s.current_status = 'fail' AND s.severity = 'critical'),
		       now()
		  FROM host_rule_state s
		  JOIN hosts h ON h.id = s.host_id AND h.deleted_at IS NULL
		 GROUP BY s.host_id
		ON CONFLICT (host_id, snapshot_date) DO UPDATE
		   SET passing               = EXCLUDED.passing,
		       failing               = EXCLUDED.failing,
		       skipped               = EXCLUDED.skipped,
		       error                 = EXCLUDED.error,
		       total                 = EXCLUDED.total,
		       score_pct             = EXCLUDED.score_pct,
		       has_critical_findings = EXCLUDED.has_critical_findings,
		       updated_at            = now()`,
		asOf.UTC())
	if err != nil {
		return 0, fmt.Errorf("posture: rollup: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// Run wires the rollup to an hourly cron tick, with one immediate
// pass at start so a fresh boot (or fresh install) has today's row
// without waiting an hour. Mirrors the scheduler's Run shape.
func Run(ctx context.Context, pool *pgxpool.Pool, interval time.Duration) *cron.Scheduler {
	if interval == 0 {
		interval = RollupInterval
	}
	// Immediate first pass: the ticker's first fire is one full
	// interval out, and a fresh boot should have today's row now.
	if n, err := Rollup(ctx, pool, time.Now()); err != nil {
		slog.WarnContext(ctx, "posture boot rollup failed", "err", err)
	} else {
		slog.InfoContext(ctx, "posture rollup started", "hosts", n,
			"interval", interval.String())
	}
	tick := cron.New(interval, func(ctx context.Context) error {
		n, err := Rollup(ctx, pool, time.Now())
		if err != nil {
			slog.ErrorContext(ctx, "posture rollup failed", "err", err)
			return err
		}
		slog.DebugContext(ctx, "posture rollup", "hosts", n)
		return nil
	})
	tick.Start(ctx)
	return tick
}

// DayPoint is one day of a host's trend.
type DayPoint struct {
	Date     time.Time
	ScorePct float64
	Passing  int
	Failing  int
	Total    int
}

// HostTrend returns the host's snapshots over the trailing N days
// (today inclusive), oldest first. Days without a snapshot are simply
// absent - the chart renders the gaps.
func HostTrend(ctx context.Context, pool *pgxpool.Pool, hostID uuid.UUID, days int) ([]DayPoint, error) {
	rows, err := pool.Query(ctx, `
		SELECT snapshot_date, score_pct, passing, failing, total
		  FROM posture_snapshots
		 WHERE host_id = $1
		   AND snapshot_date > current_date - $2::int
		 ORDER BY snapshot_date`, hostID, days)
	if err != nil {
		return nil, fmt.Errorf("posture: host trend: %w", err)
	}
	defer rows.Close()
	var out []DayPoint
	for rows.Next() {
		var p DayPoint
		if err := rows.Scan(&p.Date, &p.ScorePct, &p.Passing, &p.Failing, &p.Total); err != nil {
			return nil, fmt.Errorf("posture: scan trend row: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// FleetDayPoint is one day of the fleet trend.
type FleetDayPoint struct {
	Date          time.Time
	AvgScorePct   float64
	Hosts         int
	Failing       int
	CriticalHosts int
}

// FleetTrend returns per-day fleet aggregates over the trailing N
// days, oldest first: average score across snapshotted hosts, host
// count, total failing rules, and hosts carrying critical findings.
// Soft-deleted hosts are excluded even when their snapshots linger.
func FleetTrend(ctx context.Context, pool *pgxpool.Pool, days int) ([]FleetDayPoint, error) {
	rows, err := pool.Query(ctx, `
		SELECT p.snapshot_date,
		       ROUND(AVG(p.score_pct)::numeric * 10) / 10,
		       COUNT(*)::int,
		       COALESCE(SUM(p.failing), 0)::int,
		       COUNT(*) FILTER (WHERE p.has_critical_findings)::int
		  FROM posture_snapshots p
		  JOIN hosts h ON h.id = p.host_id AND h.deleted_at IS NULL
		 WHERE p.snapshot_date > current_date - $1::int
		 GROUP BY p.snapshot_date
		 ORDER BY p.snapshot_date`, days)
	if err != nil {
		return nil, fmt.Errorf("posture: fleet trend: %w", err)
	}
	defer rows.Close()
	var out []FleetDayPoint
	for rows.Next() {
		var p FleetDayPoint
		if err := rows.Scan(&p.Date, &p.AvgScorePct, &p.Hosts, &p.Failing, &p.CriticalHosts); err != nil {
			return nil, fmt.Errorf("posture: scan fleet row: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
