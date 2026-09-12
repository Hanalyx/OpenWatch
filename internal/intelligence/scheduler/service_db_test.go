// @spec system-intelligence-scheduler
//
// AC traceability (this file):
//
//	AC-06  TestListIntelTargets_FilterSemantics
//	AC-08  TestRecordSuccess_AdvancesNextIntelligenceAt
//	AC-09  TestRecordFailure_UpsertsIntelBackoff
//	AC-11  TestRecordFailure_DoesNotTouchScanBackoff

package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func freshDBScheduler(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()
	// CASCADE: hosts is referenced by 11 child tables (alerts,
	// credentials, host_backoff_state, host_compliance_schedule,
	// host_intelligence_*, host_liveness, host_monitoring_history,
	// host_rule_state, host_system_info, transactions). Maintaining
	// a hand-rolled child-truncate list per test file broke every
	// time a new FK was added — TRUNCATE…CASCADE delegates to the
	// schema instead.
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE hosts CASCADE")
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE users CASCADE")
	createdBy, _ := uuid.NewV7()
	hash, _ := identity.HashPassword("seed-pw-12345-aa")
	_, _ = pool.Exec(ctx,
		`INSERT INTO users (id, username, email, password_hash) VALUES ($1, $2, $3, $4)`,
		createdBy, "sched-creator", "sched@example.com", hash)
	return pool
}

func insertSchedHost(t *testing.T, pool *pgxpool.Pool, name string) uuid.UUID {
	t.Helper()
	var creator uuid.UUID
	_ = pool.QueryRow(context.Background(), `SELECT id FROM users LIMIT 1`).Scan(&creator)
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO hosts (id, hostname, ip_address, created_by)
		 VALUES ($1, $2, $3::inet, $4)`,
		id, name, "192.0.2.50", creator)
	if err != nil {
		t.Fatalf("seed host %s: %v", name, err)
	}
	return id
}

// @ac AC-06
// AC-06: listIntelTargets returns only H1 (next NULL) and H2 (next in
// past); skips H3 (next in future), H4 (per-host maintenance), H5 (intel
// backoff active), H6 (per-group maintenance). H4 and H6 together prove
// both maintenance scopes resolve through host_effective_maintenance.
func TestListIntelTargets_FilterSemantics(t *testing.T) {
	t.Run("system-intelligence-scheduler/AC-06", func(t *testing.T) {
		pool := freshDBScheduler(t)
		ctx := context.Background()

		h1 := insertSchedHost(t, pool, "h1-null-next")
		h2 := insertSchedHost(t, pool, "h2-past-next")
		h3 := insertSchedHost(t, pool, "h3-future-next")
		h4 := insertSchedHost(t, pool, "h4-maintenance")
		h5 := insertSchedHost(t, pool, "h5-backoff")
		h6 := insertSchedHost(t, pool, "h6-group-maintenance")

		// h1: row absent → NULL next → due.
		// h2: row present with past next.
		_, err := pool.Exec(ctx,
			`INSERT INTO host_intelligence_state (host_id, snapshot, collected_at, next_intelligence_at)
			 VALUES ($1, '{}'::jsonb, now() - interval '1 hour', now() - interval '5 minutes')`,
			h2)
		if err != nil {
			t.Fatalf("seed h2 state: %v", err)
		}
		// h3: row present with future next → skipped.
		_, _ = pool.Exec(ctx,
			`INSERT INTO host_intelligence_state (host_id, snapshot, collected_at, next_intelligence_at)
			 VALUES ($1, '{}'::jsonb, now() - interval '1 hour', now() + interval '30 minutes')`,
			h3)
		// h4: NULL next but per-host maintenance_mode=true.
		_, _ = pool.Exec(ctx, `UPDATE hosts SET maintenance_mode = true WHERE id = $1`, h4)
		// h5: backoff suppress_until in future.
		_, _ = pool.Exec(ctx, `
			INSERT INTO host_backoff_state (host_id, probe_type, consecutive_failures, suppress_until)
			VALUES ($1, 'intel', 3, now() + interval '1 hour')`,
			h5)
		// h6: NULL next but a member of a maintenance group (per-group scope).
		gid, _ := uuid.NewV7()
		if _, err := pool.Exec(ctx,
			`INSERT INTO groups (id, name, kind, membership, maintenance)
			 VALUES ($1, $2, 'site', 'manual', true)`, gid, "maint-"+gid.String()); err != nil {
			t.Fatalf("seed maintenance group: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO group_members (group_id, host_id) VALUES ($1, $2)`, gid, h6); err != nil {
			t.Fatalf("seed group member: %v", err)
		}

		svc := NewService(pool, nil)
		got, err := svc.listIntelTargets(ctx)
		if err != nil {
			t.Fatalf("listIntelTargets: %v", err)
		}
		seen := map[uuid.UUID]bool{}
		for _, id := range got {
			seen[id] = true
		}
		// h1 and h2 are due; h3, h4, h5 are not.
		if !seen[h1] {
			t.Errorf("h1 (NULL next) missing from due list")
		}
		if !seen[h2] {
			t.Errorf("h2 (past next) missing from due list")
		}
		if seen[h3] {
			t.Errorf("h3 (future next) wrongly included")
		}
		if seen[h4] {
			t.Errorf("h4 (per-host maintenance) wrongly included")
		}
		if seen[h5] {
			t.Errorf("h5 (intel backoff) wrongly included")
		}
		if seen[h6] {
			t.Errorf("h6 (per-group maintenance) wrongly included")
		}
	})
}

// @ac AC-08
// AC-08: successful RunCycle bumps next_intelligence_at by IntervalSec.
func TestRecordSuccess_AdvancesNextIntelligenceAt(t *testing.T) {
	t.Run("system-intelligence-scheduler/AC-08", func(t *testing.T) {
		pool := freshDBScheduler(t)
		ctx := context.Background()
		h := insertSchedHost(t, pool, "h-success")

		runner := &stubRunner{run: func(_ context.Context, _ uuid.UUID) error { return nil }}
		cfg := systemconfig.IntelligenceConfig{IntervalSec: 1800, RateLimit: 10}
		svc := NewService(pool, runner).WithConfigLoader(func(context.Context) (systemconfig.IntelligenceConfig, error) {
			return cfg, nil
		})

		svc.dispatchHost(ctx, h)

		var next *time.Time
		err := pool.QueryRow(ctx,
			`SELECT next_intelligence_at FROM host_intelligence_state WHERE host_id = $1`,
			h).Scan(&next)
		if err != nil {
			t.Fatalf("read next: %v", err)
		}
		if next == nil {
			t.Fatal("next_intelligence_at is NULL after successful cycle")
		}
		// Expect ~1800s in the future.
		delta := time.Until(*next).Seconds()
		if delta < 1500 || delta > 1900 {
			t.Errorf("next_intelligence_at delta=%.0fs, want ~1800", delta)
		}
	})
}

// @ac AC-09
// AC-09: failing RunCycle UPSERTs host_backoff_state with probe_type='intel'.
func TestRecordFailure_UpsertsIntelBackoff(t *testing.T) {
	t.Run("system-intelligence-scheduler/AC-09", func(t *testing.T) {
		pool := freshDBScheduler(t)
		ctx := context.Background()
		h := insertSchedHost(t, pool, "h-fail")

		runner := &stubRunner{run: func(_ context.Context, _ uuid.UUID) error {
			return errors.New("simulated probe failure")
		}}
		svc := NewService(pool, runner)
		svc.dispatchHost(ctx, h)

		var (
			probeType string
			consec    int
			suppress  *time.Time
		)
		err := pool.QueryRow(ctx,
			`SELECT probe_type, consecutive_failures, suppress_until
			   FROM host_backoff_state WHERE host_id = $1`, h,
		).Scan(&probeType, &consec, &suppress)
		if err != nil {
			t.Fatalf("read backoff: %v", err)
		}
		if probeType != "intel" {
			t.Errorf("probe_type=%q, want 'intel'", probeType)
		}
		if consec != 1 {
			t.Errorf("consecutive_failures=%d, want 1", consec)
		}
		if suppress == nil || time.Until(*suppress) <= 0 {
			t.Errorf("suppress_until=%v, want future timestamp", suppress)
		}
	})
}

// seedScanBackoff writes a scan backoff row directly. The intelligence
// path must never read or write it.
func seedScanBackoff(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, suppressUntil time.Time) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO host_backoff_state
			(host_id, probe_type, consecutive_failures, suppress_until, last_error_code, last_failure_at, updated_at)
		VALUES ($1, 'scan', 4, $2, 'kensa_error', now(), now())`,
		hostID, suppressUntil)
	if err != nil {
		t.Fatalf("seed scan backoff: %v", err)
	}
}

func readProbeRow(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, probe string) (present bool, consec int, suppress *time.Time, errCode *string) {
	t.Helper()
	err := pool.QueryRow(context.Background(), `
		SELECT consecutive_failures, suppress_until, last_error_code
		  FROM host_backoff_state WHERE host_id = $1 AND probe_type = $2`,
		hostID, probe).Scan(&consec, &suppress, &errCode)
	if err != nil {
		return false, 0, nil, nil
	}
	return true, consec, suppress, errCode
}

// @ac AC-11
// AC-11: a failing intel cycle does NOT touch (host_id, probe_type='scan').
//
// This used to be a source-inspection substitute. It grepped recordFailure
// for a `WHERE host_backoff_state.probe_type = 'intel'` guard, and its own
// comment explained why: the table was keyed on host_id alone, so a host
// could not hold both rows and the behavior could not be observed.
//
// The guard it asserted was worse than untested, it was harmful. With a
// single key, that WHERE turned the conflict into a silent no-op whenever a
// scan row already existed, so an intelligence failure on a host that had
// ever failed a scan recorded no backoff at all. Migration 0064 keys the
// table on (host_id, probe_type) and the guard is gone, so the real
// behavior is now observable and is what this asserts.
func TestRecordFailure_DoesNotTouchScanBackoff(t *testing.T) {
	t.Run("system-intelligence-scheduler/AC-11", func(t *testing.T) {
		pool := freshDBScheduler(t)
		ctx := context.Background()
		h := insertSchedHost(t, pool, "h-scan-protected")
		scanUntil := time.Now().UTC().Add(6 * time.Hour).Truncate(time.Microsecond)
		seedScanBackoff(t, pool, h, scanUntil)

		runner := &stubRunner{run: func(_ context.Context, _ uuid.UUID) error {
			return errors.New("simulated probe failure")
		}}
		svc := NewService(pool, runner)
		svc.dispatchHost(ctx, h)

		var n int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM host_backoff_state WHERE host_id = $1`, h).Scan(&n); err != nil {
			t.Fatalf("count rows: %v", err)
		}
		if n != 2 {
			t.Fatalf("host carries %d backoff rows, want 2. The intelligence failure either "+
				"overwrote the scan row or was discarded.", n)
		}

		okIntel, intelConsec, intelSuppress, _ := readProbeRow(t, pool, h, "intel")
		if !okIntel {
			t.Fatal("no intel row after a failing intel cycle: the write was discarded")
		}
		if intelConsec != 1 || intelSuppress == nil || time.Until(*intelSuppress) <= 0 {
			t.Errorf("intel row consec=%d suppress=%v, want 1 and a future timestamp",
				intelConsec, intelSuppress)
		}

		okScan, scanConsec, scanSuppress, scanErr := readProbeRow(t, pool, h, "scan")
		if !okScan {
			t.Fatal("the scan row is gone after an intelligence failure")
		}
		if scanConsec != 4 {
			t.Errorf("scan consecutive_failures moved 4 -> %d on an INTEL failure", scanConsec)
		}
		if scanSuppress == nil || !scanSuppress.Equal(scanUntil) {
			t.Errorf("scan suppress_until moved %v -> %v on an INTEL failure", scanUntil, scanSuppress)
		}
		if scanErr == nil || *scanErr != "kensa_error" {
			t.Errorf("scan last_error_code = %v, want the seeded scan value", scanErr)
		}
	})
}

// @ac AC-11
// A successful intel cycle clears the intel ladder and only that one.
func TestRecordSuccess_ClearsOnlyIntelBackoff(t *testing.T) {
	t.Run("system-intelligence-scheduler/AC-11", func(t *testing.T) {
		pool := freshDBScheduler(t)
		ctx := context.Background()
		h := insertSchedHost(t, pool, "h-intel-success")
		scanUntil := time.Now().UTC().Add(6 * time.Hour).Truncate(time.Microsecond)
		seedScanBackoff(t, pool, h, scanUntil)

		fail := &stubRunner{run: func(_ context.Context, _ uuid.UUID) error {
			return errors.New("simulated probe failure")
		}}
		svc := NewService(pool, fail)
		svc.dispatchHost(ctx, h)
		if ok, _, _, _ := readProbeRow(t, pool, h, "intel"); !ok {
			t.Fatal("no intel backoff to clear")
		}

		okRunner := &stubRunner{run: func(_ context.Context, _ uuid.UUID) error { return nil }}
		cfg := systemconfig.IntelligenceConfig{IntervalSec: 1800, RateLimit: 10}
		svcOK := NewService(pool, okRunner).WithConfigLoader(func(context.Context) (systemconfig.IntelligenceConfig, error) {
			return cfg, nil
		})
		svcOK.dispatchHost(ctx, h)

		if ok, _, _, _ := readProbeRow(t, pool, h, "intel"); ok {
			t.Error("the intel backoff row survived a successful intel cycle")
		}
		okScan, scanConsec, scanSuppress, _ := readProbeRow(t, pool, h, "scan")
		if !okScan || scanConsec != 4 || scanSuppress == nil || !scanSuppress.Equal(scanUntil) {
			t.Errorf("scan row present=%v consec=%d suppress=%v, want it untouched at 4 with its "+
				"suppression intact. A successful intelligence cycle must not lift a scan "+
				"suppression.", okScan, scanConsec, scanSuppress)
		}
	})
}

// small in-test helper to keep imports minimal.
func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
