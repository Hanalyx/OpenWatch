// @spec system-posture-snapshots
//
// AC traceability (DSN-gated):
//
//	AC-01  TestRollup_UpsertCountsAndExclusions
//	AC-02  TestTrends_WindowOrderingAndFleetAggregates
//	AC-03  TestRollup_PerFamilyOSResolvedSeries
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
			  FROM posture_snapshots WHERE host_id = $1 AND snapshot_date = current_date AND framework = ''`,
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
			SELECT COUNT(*), MAX(score_pct) FROM posture_snapshots WHERE host_id = $1 AND framework = ''`,
			scanned).Scan(&rows, &score2)
		if rows != 1 || score2 != 75.0 {
			t.Errorf("after re-run: rows=%d score=%v, want 1 row at 75", rows, score2)
		}
	})
}

// seedRuleStateFW seeds a host_rule_state row with a framework_refs JSONB
// literal (e.g. `{"stig_rhel9":["V-1"]}`).
func seedRuleStateFW(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, ruleID, status, refs string) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO host_rule_state
			(host_id, rule_id, current_status, severity, last_checked_at,
			 check_count, last_scan_id, framework_refs, first_seen_at, last_changed_at)
		VALUES ($1, $2, $3, 'medium', now(), 1, $4, $5::jsonb, now(), now())`,
		hostID, ruleID, status, uuid.Must(uuid.NewV7()), refs)
	if err != nil {
		t.Fatalf("seed rule state fw: %v", err)
	}
}

// @ac AC-03
// AC-03: the rollup writes a per-FAMILY series, OS-RESOLVED — a RHEL 9
// host's "stig" row scores stig_rhel9 only (a stig_rhel10 rule it carries
// is excluded), OS-neutral families resolve via the bare key, and the ”
// all-rules series counts everything. HostTrend reads the requested lens
// series and normalizes a specific key to its family.
func TestRollup_PerFamilyOSResolvedSeries(t *testing.T) {
	t.Run("system-posture-snapshots/AC-03", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		user := seedUser(t, pool)

		h := seedHost(t, pool, user)
		if _, err := pool.Exec(ctx,
			`UPDATE hosts SET os_family='rhel', os_version='9.6' WHERE id=$1`, h); err != nil {
			t.Fatalf("set os: %v", err)
		}
		// STIG: stig_rhel9 (1 pass, 1 fail) + stig_rhel10 (1 pass, wrong OS).
		seedRuleStateFW(t, pool, h, "s9.pass", "pass", `{"stig_rhel9":["V-1"]}`)
		seedRuleStateFW(t, pool, h, "s9.fail", "fail", `{"stig_rhel9":["V-2"]}`)
		seedRuleStateFW(t, pool, h, "s10.pass", "pass", `{"stig_rhel10":["V-1"]}`)
		// CIS (OS-specific) + NIST (OS-neutral).
		seedRuleStateFW(t, pool, h, "c9.pass", "pass", `{"cis_rhel9":["1.1"]}`)
		seedRuleStateFW(t, pool, h, "n.pass", "pass", `{"nist_800_53":["AC-1"]}`)

		if _, err := Rollup(ctx, pool, time.Now()); err != nil {
			t.Fatalf("Rollup: %v", err)
		}

		read := func(fw string) (passing, total int, score float64) {
			err := pool.QueryRow(ctx, `
				SELECT passing, total, score_pct FROM posture_snapshots
				 WHERE host_id=$1 AND snapshot_date=current_date AND framework=$2`,
				h, fw).Scan(&passing, &total, &score)
			if err != nil {
				t.Fatalf("read framework %q: %v", fw, err)
			}
			return
		}

		// STIG resolves to stig_rhel9 ONLY: 1 pass / 2 total (stig_rhel10 excluded).
		if p, tot, sc := read("stig"); p != 1 || tot != 2 || sc != 50.0 {
			t.Errorf("stig series = %d/%d score %v, want 1/2 50 (stig_rhel10 excluded)", p, tot, sc)
		}
		// CIS (cis_rhel9): 1/1. NIST (bare key): 1/1.
		if p, tot, _ := read("cis"); p != 1 || tot != 1 {
			t.Errorf("cis series = %d/%d, want 1/1", p, tot)
		}
		if p, tot, _ := read("nist_800_53"); p != 1 || tot != 1 {
			t.Errorf("nist_800_53 series = %d/%d, want 1/1", p, tot)
		}
		// All-rules ('' series): everything = 4 pass / 5 total.
		if p, tot, _ := read(""); p != 4 || tot != 5 {
			t.Errorf("all-rules series = %d/%d, want 4/5", p, tot)
		}

		// HostTrend reads the lens series; a specific key normalizes to family.
		fam, err := HostTrend(ctx, pool, h, 30, "stig")
		if err != nil || len(fam) != 1 || fam[0].ScorePct != 50.0 {
			t.Errorf("HostTrend(stig) = %+v err=%v, want one point at 50", fam, err)
		}
		key, _ := HostTrend(ctx, pool, h, 30, "stig_rhel9")
		if len(key) != 1 || key[0].ScorePct != 50.0 {
			t.Errorf("HostTrend(stig_rhel9) = %+v, want the stig series (50)", key)
		}
		all, _ := HostTrend(ctx, pool, h, 30, "")
		if len(all) != 1 || all[0].ScorePct != 80.0 {
			t.Errorf("HostTrend('') = %+v, want all-rules (80)", all)
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

		points, err := HostTrend(ctx, pool, a, 30, "")
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

		fleet, err := FleetTrend(ctx, pool, 30, "")
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
