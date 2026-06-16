// @spec system-posture-snapshots
//
// AC traceability (DSN-gated):
//
//	AC-01  TestRollup_UpsertCountsAndExclusions
//	AC-02  TestTrends_WindowOrderingAndFleetAggregates
package posture

import (
	"context"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()
	for _, stmt := range []string{
		"TRUNCATE TABLE posture_snapshots CASCADE",
		"TRUNCATE TABLE host_rule_state CASCADE",
		"TRUNCATE TABLE hosts CASCADE",
		"TRUNCATE TABLE users CASCADE",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Logf("truncate (ok if benign): %v", err)
		}
	}
	return pool
}

func seedUser(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (id, username, email, password_hash)
		 VALUES ($1, $2, $3, $4)`,
		id, "posture-test-user", "ptu@example.com", "argon2id$dummy") // pragma: allowlist secret
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

func seedHost(t *testing.T, pool *pgxpool.Pool, createdBy uuid.UUID) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO hosts (id, hostname, ip_address, created_by)
		 VALUES ($1, $2, '192.0.2.20'::inet, $3)`,
		id, "posture-"+id.String(), createdBy)
	if err != nil {
		t.Fatalf("seed host: %v", err)
	}
	return id
}

func seedRuleState(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, ruleID, status string, severity any) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO host_rule_state
			(host_id, rule_id, current_status, severity, last_checked_at,
			 check_count, last_scan_id, first_seen_at, last_changed_at)
		VALUES ($1, $2, $3, $4, now(), 1, $5, now(), now())`,
		hostID, ruleID, status, severity, uuid.Must(uuid.NewV7()))
	if err != nil {
		t.Fatalf("seed rule state: %v", err)
	}
}

// seedSnapshot writes a snapshot row directly for trend-read tests.
func seedSnapshot(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, daysAgo int, score float64, failing int, critical bool) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO posture_snapshots
			(host_id, snapshot_date, passing, failing, skipped, error, total,
			 score_pct, has_critical_findings)
		VALUES ($1, current_date - $2::int, 10, $3, 0, 0, 10 + $3, $4, $5)`,
		hostID, daysAgo, failing, score, critical)
	if err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}
}

// @ac AC-01
// AC-01: one row per scanned host with lens-formula score and the
// critical flag; same-day re-run UPDATEs; never-scanned and
// soft-deleted hosts produce no row.
func TestRollup_UpsertCountsAndExclusions(t *testing.T) {
	t.Run("system-posture-snapshots/AC-01", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		user := seedUser(t, pool)

		scanned := seedHost(t, pool, user)
		// 2 pass, 1 critical fail, 1 skipped => total 4, score 50.0.
		seedRuleState(t, pool, scanned, "r1", "pass", "low")
		seedRuleState(t, pool, scanned, "r2", "pass", "high")
		seedRuleState(t, pool, scanned, "r3", "fail", "critical")
		seedRuleState(t, pool, scanned, "r4", "skipped", nil)

		_ = seedHost(t, pool, user) // never scanned

		deleted := seedHost(t, pool, user)
		seedRuleState(t, pool, deleted, "r1", "fail", "high")
		if _, err := pool.Exec(ctx, `UPDATE hosts SET deleted_at = now() WHERE id = $1`, deleted); err != nil {
			t.Fatalf("soft delete: %v", err)
		}

		n, err := Rollup(ctx, pool, time.Now())
		if err != nil {
			t.Fatalf("Rollup: %v", err)
		}
		if n != 1 {
			t.Errorf("rollup rows = %d, want 1 (never-scanned + deleted excluded)", n)
		}

		var passing, failing, skipped, total int
		var score float64
		var critical bool
		err = pool.QueryRow(ctx, `
			SELECT passing, failing, skipped, total, score_pct, has_critical_findings
			  FROM posture_snapshots WHERE host_id = $1 AND snapshot_date = current_date`,
			scanned).Scan(&passing, &failing, &skipped, &total, &score, &critical)
		if err != nil {
			t.Fatalf("read snapshot: %v", err)
		}
		if passing != 2 || failing != 1 || skipped != 1 || total != 4 || score != 50.0 || !critical {
			t.Errorf("snapshot = %d/%d/%d total %d score %v critical %v, want 2/1/1 4 50 true",
				passing, failing, skipped, total, score, critical)
		}

		// Same-day re-run after a fix: UPDATE, not a duplicate.
		if _, err := pool.Exec(ctx, `
			UPDATE host_rule_state SET current_status = 'pass' WHERE host_id = $1 AND rule_id = 'r3'`,
			scanned); err != nil {
			t.Fatalf("flip rule: %v", err)
		}
		if _, err := Rollup(ctx, pool, time.Now()); err != nil {
			t.Fatalf("second Rollup: %v", err)
		}
		var rows int
		var score2 float64
		_ = pool.QueryRow(ctx, `
			SELECT COUNT(*), MAX(score_pct) FROM posture_snapshots WHERE host_id = $1`,
			scanned).Scan(&rows, &score2)
		if rows != 1 || score2 != 75.0 {
			t.Errorf("after re-run: rows=%d score=%v, want 1 row at 75", rows, score2)
		}
	})
}

// @ac AC-02
// AC-02: trend reads window + order correctly; fleet aggregates per
// day and drops soft-deleted hosts.
func TestTrends_WindowOrderingAndFleetAggregates(t *testing.T) {
	t.Run("system-posture-snapshots/AC-02", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		user := seedUser(t, pool)

		a := seedHost(t, pool, user)
		b := seedHost(t, pool, user)
		seedSnapshot(t, pool, a, 0, 80, 2, false)
		seedSnapshot(t, pool, a, 1, 70, 3, true)
		seedSnapshot(t, pool, a, 40, 10, 30, true) // outside a 30-day window
		seedSnapshot(t, pool, b, 0, 60, 5, false)

		// Soft-deleted host's snapshots vanish from the fleet view.
		ghost := seedHost(t, pool, user)
		seedSnapshot(t, pool, ghost, 0, 0, 99, true)
		if _, err := pool.Exec(ctx, `UPDATE hosts SET deleted_at = now() WHERE id = $1`, ghost); err != nil {
			t.Fatalf("soft delete: %v", err)
		}

		points, err := HostTrend(ctx, pool, a, 30)
		if err != nil {
			t.Fatalf("HostTrend: %v", err)
		}
		if len(points) != 2 {
			t.Fatalf("host points = %d, want 2 (40-day-old row excluded)", len(points))
		}
		if !(points[0].ScorePct == 70 && points[1].ScorePct == 80) {
			t.Errorf("ordering wrong: %v then %v, want 70 then 80 (oldest first)",
				points[0].ScorePct, points[1].ScorePct)
		}

		fleet, err := FleetTrend(ctx, pool, 30)
		if err != nil {
			t.Fatalf("FleetTrend: %v", err)
		}
		if len(fleet) != 2 {
			t.Fatalf("fleet days = %d, want 2", len(fleet))
		}
		today := fleet[len(fleet)-1]
		if today.Hosts != 2 || today.AvgScorePct != 70.0 || today.Failing != 7 || today.CriticalHosts != 0 {
			t.Errorf("today = %+v, want hosts 2 avg 70 failing 7 critical 0 (ghost dropped)", today)
		}
		yesterday := fleet[0]
		if yesterday.Hosts != 1 || yesterday.AvgScorePct != 70.0 || yesterday.CriticalHosts != 1 {
			t.Errorf("yesterday = %+v, want hosts 1 avg 70 critical 1", yesterday)
		}
	})
}
