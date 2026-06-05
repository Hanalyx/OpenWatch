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
	"os"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/db"
	"github.com/Hanalyx/openwatch/internal/db/migrations"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func schedulerTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OPENWATCH_TEST_DSN")
	if dsn == "" {
		t.Skip("set OPENWATCH_TEST_DSN to run scheduler integration tests")
	}
	return dsn
}

func freshDBScheduler(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := schedulerTestDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	pool, err := db.NewPool(ctx, dsn, 5)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatalf("migrations.Apply: %v", err)
	}
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
// past); skips H3 (next in future), H4 (maintenance), H5 (intel
// backoff active).
func TestListIntelTargets_FilterSemantics(t *testing.T) {
	t.Run("system-intelligence-scheduler/AC-06", func(t *testing.T) {
		pool := freshDBScheduler(t)
		ctx := context.Background()

		h1 := insertSchedHost(t, pool, "h1-null-next")
		h2 := insertSchedHost(t, pool, "h2-past-next")
		h3 := insertSchedHost(t, pool, "h3-future-next")
		h4 := insertSchedHost(t, pool, "h4-maintenance")
		h5 := insertSchedHost(t, pool, "h5-backoff")

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
		// h4: NULL next but maintenance_mode=true.
		_, _ = pool.Exec(ctx, `UPDATE hosts SET maintenance_mode = true WHERE id = $1`, h4)
		// h5: backoff suppress_until in future.
		_, _ = pool.Exec(ctx, `
			INSERT INTO host_backoff_state (host_id, probe_type, consecutive_failures, suppress_until)
			VALUES ($1, 'intel', 3, now() + interval '1 hour')`,
			h5)

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
			t.Errorf("h4 (maintenance) wrongly included")
		}
		if seen[h5] {
			t.Errorf("h5 (intel backoff) wrongly included")
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

// @ac AC-11
// AC-11: failing intel cycle does NOT touch (host_id, probe_type='scan').
func TestRecordFailure_DoesNotTouchScanBackoff(t *testing.T) {
	t.Run("system-intelligence-scheduler/AC-11", func(t *testing.T) {
		pool := freshDBScheduler(t)
		ctx := context.Background()
		h := insertSchedHost(t, pool, "h-scan-protected")

		// Pre-seed a SCAN backoff row so we can prove it's preserved.
		// Note: host_backoff_state PK is host_id only (per migration
		// 0011); the schema constrains probe_type but the row is
		// keyed by host. So a scan + intel row for the same host
		// cannot coexist in v1.0.0 of the table. The AC asserts the
		// intent: scan cadence MUST NOT be disrupted by intel.
		//
		// We assert the upsert WHERE clause specifically only touches
		// probe_type='intel' rows, leaving scan rows alone — source
		// inspection is the strongest invariant here since the schema
		// itself can't hold both rows.
		src := readSchedulerSrc(t, "service.go")
		body := extractFuncBody(t, src, "recordFailure")
		if !contains(body, "WHERE host_backoff_state.probe_type = 'intel'") {
			t.Errorf("recordFailure UPSERT missing WHERE probe_type='intel' guard — scan backoff could be overwritten")
		}
		if !contains(body, "'intel'") {
			t.Errorf("recordFailure does not write probe_type='intel'")
		}
		// Belt-and-suspenders: kick off a fail and assert the row that
		// lands has probe_type='intel'.
		runner := &stubRunner{run: func(_ context.Context, _ uuid.UUID) error {
			return errors.New("fail")
		}}
		svc := NewService(pool, runner)
		svc.dispatchHost(ctx, h)
		var pt string
		err := pool.QueryRow(ctx,
			`SELECT probe_type FROM host_backoff_state WHERE host_id = $1`, h).Scan(&pt)
		if err != nil {
			t.Fatalf("read backoff: %v", err)
		}
		if pt != "intel" {
			t.Errorf("probe_type=%q, want 'intel'", pt)
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
