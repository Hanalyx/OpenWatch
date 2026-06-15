// @spec system-scan-results-store
//
// AC traceability (this file):
//   AC-01  TestPersist_WritesAllRows_OneTransaction
//   AC-02  TestPersist_IdenticalEvidence_DedupedAcrossScans
//   AC-03  TestPersist_EmptyEvidence_NullHash
//   AC-04  TestPersist_OversizeEvidence_RejectedBeforeInsert
//   AC-05  TestPersist_SameScanID_Idempotent
//   AC-06  TestPersist_MissingScanRun_FKViolation
//   AC-07  TestPersist_InvalidStatus_RejectedBeforeInsert

package scanresult

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/db"
	"github.com/Hanalyx/openwatch/internal/db/migrations"
)

// ---------------------------------------------------------------------
// Test scaffolding (mirrors internal/transactionlog/writer_test.go)
// ---------------------------------------------------------------------

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OPENWATCH_TEST_DSN")
	if dsn == "" {
		t.Skip("set OPENWATCH_TEST_DSN to run scanresult integration tests")
	}
	return dsn
}

func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := testDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	pool, err := db.NewPool(ctx, dsn, 5)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatalf("migrations.Apply: %v", err)
	}
	for _, stmt := range []string{
		"TRUNCATE TABLE scan_results CASCADE",
		"TRUNCATE TABLE scan_evidence CASCADE",
		"TRUNCATE TABLE scan_runs CASCADE",
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
		id, "sr-user-"+id.String(), id.String()+"@example.com", "argon2id$dummy") // pragma: allowlist secret
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
		 VALUES ($1, $2, $3::inet, $4)`,
		id, "host-"+id.String(), "192.0.2.10", createdBy)
	if err != nil {
		t.Fatalf("seed host: %v", err)
	}
	return id
}

// seedScanRun inserts a minimal scan_runs row so scan_results' FK is
// satisfiable (mirrors what scanruns.MarkRunning does in production).
func seedScanRun(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO scan_runs (id, host_id, trigger_source, status)
		 VALUES ($1, $2, 'on_demand', 'running')`,
		id, hostID)
	if err != nil {
		t.Fatalf("seed scan_run: %v", err)
	}
	return id
}

func passResult(ruleID string, evidence []byte) Result {
	return Result{
		RuleID:        ruleID,
		Status:        StatusPass,
		Severity:      "medium",
		Evidence:      evidence,
		FrameworkRefs: map[string][]string{"cis_rhel9_v2": {"1.1.1"}},
	}
}

func countRows(t *testing.T, pool *pgxpool.Pool, query string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count (%s): %v", query, err)
	}
	return n
}

// ---------------------------------------------------------------------
// AC-01 — atomic batch, all rows written
// ---------------------------------------------------------------------

// @ac AC-01
func TestPersist_WritesAllRows_OneTransaction(t *testing.T) {
	pool := freshPool(t)
	w := NewWriter(pool)
	ctx := context.Background()

	u := seedUser(t, pool)
	h := seedHost(t, pool, u)
	scan := seedScanRun(t, pool, h)

	batch := PersistBatch{ScanID: scan, HostID: h, Results: []Result{
		passResult("rule-a", []byte(`{"detail":"a ok"}`)),
		passResult("rule-b", []byte(`{"detail":"b ok"}`)),
		{RuleID: "rule-c", Status: StatusFail, Severity: "high", Evidence: []byte(`{"detail":"c failed"}`)},
	}}
	if err := w.Persist(ctx, batch); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	t.Run("system-scan-results-store/AC-01", func(t *testing.T) {
		if got := countRows(t, pool, `SELECT count(*) FROM scan_results WHERE scan_id=$1`, scan); got != 3 {
			t.Errorf("scan_results rows = %d, want 3", got)
		}
		if got := countRows(t, pool, `SELECT count(*) FROM scan_evidence`); got != 3 {
			t.Errorf("scan_evidence rows = %d, want 3 (distinct evidence)", got)
		}
	})
}

// ---------------------------------------------------------------------
// AC-02 — content-addressed dedup across scans, stable first_seen_at
// ---------------------------------------------------------------------

// @ac AC-02
func TestPersist_IdenticalEvidence_DedupedAcrossScans(t *testing.T) {
	pool := freshPool(t)
	w := NewWriter(pool)
	ctx := context.Background()

	u := seedUser(t, pool)
	h := seedHost(t, pool, u)
	ev := []byte(`{"detail":"unchanged pass","checks":[{"method":"sysctl_value","exit_code":0}]}`)

	scan1 := seedScanRun(t, pool, h)
	if err := w.Persist(ctx, PersistBatch{ScanID: scan1, HostID: h, Results: []Result{passResult("rule-x", ev)}}); err != nil {
		t.Fatalf("Persist scan1: %v", err)
	}

	var firstSeen1 time.Time
	hash := sha256.Sum256(ev)
	if err := pool.QueryRow(ctx, `SELECT first_seen_at FROM scan_evidence WHERE evidence_hash=$1`, hash[:]).Scan(&firstSeen1); err != nil {
		t.Fatalf("read first_seen_at: %v", err)
	}

	// Second scan, byte-identical evidence for the same rule.
	scan2 := seedScanRun(t, pool, h)
	if err := w.Persist(ctx, PersistBatch{ScanID: scan2, HostID: h, Results: []Result{passResult("rule-x", ev)}}); err != nil {
		t.Fatalf("Persist scan2: %v", err)
	}

	t.Run("system-scan-results-store/AC-02", func(t *testing.T) {
		if got := countRows(t, pool, `SELECT count(*) FROM scan_evidence`); got != 1 {
			t.Errorf("scan_evidence rows = %d, want 1 (deduped)", got)
		}
		if got := countRows(t, pool, `SELECT count(*) FROM scan_results`); got != 2 {
			t.Errorf("scan_results rows = %d, want 2 (one per scan)", got)
		}
		var firstSeen2 time.Time
		if err := pool.QueryRow(ctx, `SELECT first_seen_at FROM scan_evidence WHERE evidence_hash=$1`, hash[:]).Scan(&firstSeen2); err != nil {
			t.Fatalf("read first_seen_at again: %v", err)
		}
		if !firstSeen1.Equal(firstSeen2) {
			t.Errorf("first_seen_at changed: %v -> %v (ON CONFLICT DO NOTHING must preserve it)", firstSeen1, firstSeen2)
		}
	})
}

// ---------------------------------------------------------------------
// AC-03 — empty evidence => NULL hash
// ---------------------------------------------------------------------

// @ac AC-03
func TestPersist_EmptyEvidence_NullHash(t *testing.T) {
	pool := freshPool(t)
	w := NewWriter(pool)
	ctx := context.Background()

	u := seedUser(t, pool)
	h := seedHost(t, pool, u)
	scan := seedScanRun(t, pool, h)

	if err := w.Persist(ctx, PersistBatch{ScanID: scan, HostID: h, Results: []Result{
		{RuleID: "rule-empty", Status: StatusSkipped, Evidence: nil},
	}}); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	t.Run("system-scan-results-store/AC-03", func(t *testing.T) {
		if got := countRows(t, pool, `SELECT count(*) FROM scan_results WHERE scan_id=$1 AND evidence_hash IS NULL`, scan); got != 1 {
			t.Errorf("null-hash scan_results rows = %d, want 1", got)
		}
		if got := countRows(t, pool, `SELECT count(*) FROM scan_evidence`); got != 0 {
			t.Errorf("scan_evidence rows = %d, want 0 (empty evidence stores no blob)", got)
		}
	})
}

// ---------------------------------------------------------------------
// AC-04 — oversize evidence rejected before insert
// ---------------------------------------------------------------------

// @ac AC-04
func TestPersist_OversizeEvidence_RejectedBeforeInsert(t *testing.T) {
	pool := freshPool(t)
	w := NewWriter(pool)
	ctx := context.Background()

	u := seedUser(t, pool)
	h := seedHost(t, pool, u)
	scan := seedScanRun(t, pool, h)

	oversize := bytes.Repeat([]byte("x"), MaxEvidenceBytes+1)
	err := w.Persist(ctx, PersistBatch{ScanID: scan, HostID: h, Results: []Result{
		passResult("rule-ok", []byte(`{"detail":"ok"}`)),
		{RuleID: "rule-big", Status: StatusFail, Evidence: oversize},
	}})

	t.Run("system-scan-results-store/AC-04", func(t *testing.T) {
		if !errors.Is(err, ErrEvidenceOversize) {
			t.Fatalf("Persist err = %v, want ErrEvidenceOversize", err)
		}
		if got := countRows(t, pool, `SELECT count(*) FROM scan_results WHERE scan_id=$1`, scan); got != 0 {
			t.Errorf("scan_results rows = %d, want 0 (whole batch rejected)", got)
		}
		if got := countRows(t, pool, `SELECT count(*) FROM scan_evidence`); got != 0 {
			t.Errorf("scan_evidence rows = %d, want 0", got)
		}
	})
}

// ---------------------------------------------------------------------
// AC-05 — idempotent on scan_id
// ---------------------------------------------------------------------

// @ac AC-05
func TestPersist_SameScanID_Idempotent(t *testing.T) {
	pool := freshPool(t)
	w := NewWriter(pool)
	ctx := context.Background()

	u := seedUser(t, pool)
	h := seedHost(t, pool, u)
	scan := seedScanRun(t, pool, h)
	batch := PersistBatch{ScanID: scan, HostID: h, Results: []Result{
		passResult("rule-a", []byte(`{"detail":"a"}`)),
		passResult("rule-b", []byte(`{"detail":"b"}`)),
	}}

	if err := w.Persist(ctx, batch); err != nil {
		t.Fatalf("Persist #1: %v", err)
	}
	if err := w.Persist(ctx, batch); err != nil {
		t.Fatalf("Persist #2 (re-apply): %v", err)
	}

	t.Run("system-scan-results-store/AC-05", func(t *testing.T) {
		if got := countRows(t, pool, `SELECT count(*) FROM scan_results WHERE scan_id=$1`, scan); got != 2 {
			t.Errorf("scan_results rows = %d, want 2 (re-apply is a no-op)", got)
		}
	})
}

// ---------------------------------------------------------------------
// AC-06 — FK to scan_runs enforced
// ---------------------------------------------------------------------

// @ac AC-06
func TestPersist_MissingScanRun_FKViolation(t *testing.T) {
	pool := freshPool(t)
	w := NewWriter(pool)
	ctx := context.Background()

	u := seedUser(t, pool)
	h := seedHost(t, pool, u)
	orphanScan, _ := uuid.NewV7() // no scan_runs row

	err := w.Persist(ctx, PersistBatch{ScanID: orphanScan, HostID: h, Results: []Result{
		passResult("rule-a", []byte(`{"detail":"a"}`)),
	}})

	t.Run("system-scan-results-store/AC-06", func(t *testing.T) {
		if err == nil {
			t.Fatal("Persist err = nil, want FK violation")
		}
		if got := countRows(t, pool, `SELECT count(*) FROM scan_results WHERE scan_id=$1`, orphanScan); got != 0 {
			t.Errorf("scan_results rows = %d, want 0", got)
		}
	})
}

// ---------------------------------------------------------------------
// AC-07 — invalid status rejected before insert
// ---------------------------------------------------------------------

// @ac AC-07
func TestPersist_InvalidStatus_RejectedBeforeInsert(t *testing.T) {
	pool := freshPool(t)
	w := NewWriter(pool)
	ctx := context.Background()

	u := seedUser(t, pool)
	h := seedHost(t, pool, u)
	scan := seedScanRun(t, pool, h)

	err := w.Persist(ctx, PersistBatch{ScanID: scan, HostID: h, Results: []Result{
		{RuleID: "rule-bad", Status: Status("bogus"), Evidence: []byte(`{"detail":"x"}`)},
	}})

	t.Run("system-scan-results-store/AC-07", func(t *testing.T) {
		if !errors.Is(err, ErrInvalidStatus) {
			t.Fatalf("Persist err = %v, want ErrInvalidStatus", err)
		}
		if got := countRows(t, pool, `SELECT count(*) FROM scan_results WHERE scan_id=$1`, scan); got != 0 {
			t.Errorf("scan_results rows = %d, want 0", got)
		}
	})
}
