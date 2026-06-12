// @spec system-transaction-log-writer
//
// AC traceability (this file):
//   AC-01  TestApply_SingleTransaction_RegardlessOfN
//   AC-02  TestApply_FirstScan_InsertsAllFirstSeen
//   AC-03  TestApply_IdenticalRescan_ZeroTransactions
//   AC-04  TestApply_OneStateChange_InsertsOneTransaction
//   AC-05  TestApply_SameScanID_Idempotent
//   AC-06  TestApply_FKViolation_RollsBackEntireBatch
//   AC-07  TestDeleteHosts_WithExtantTransactions_Fails
//   AC-08  (skipped — KensaEvidence OpenAPI schema lands in B.1c follow-up)
//   AC-09  TestApply_FindingPersistedCount_EqualsTransactionsRowCount
//   AC-10  TestApply_1000Rules_Under2Seconds
//   AC-11  TestApply_ConcurrentDistinctScans_NoDeadlock
//   AC-14  TestApply_OversizeEvidence_RejectedBeforeInsert
//   AC-15  TestApply_FKViolation_EmitsWriterApplyFailedAudit

package transactionlog

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/db"
	"github.com/Hanalyx/openwatch/internal/db/migrations"
)

// ---------------------------------------------------------------------
// Test scaffolding
// ---------------------------------------------------------------------

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OPENWATCH_TEST_DSN")
	if dsn == "" {
		t.Skip("set OPENWATCH_TEST_DSN to run transactionlog integration tests")
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
		"TRUNCATE TABLE transactions CASCADE",
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
		id, "tlog-user", "tlog@example.com", "argon2id$dummy") // pragma: allowlist secret
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

// emitCall captures an audit emission.
type emitCall struct {
	Code  audit.Code
	Event audit.Event
}

func fakeEmitter(mu *sync.Mutex, calls *[]emitCall) EmitFunc {
	return func(ctx context.Context, code audit.Code, ev audit.Event) {
		mu.Lock()
		defer mu.Unlock()
		*calls = append(*calls, emitCall{Code: code, Event: ev})
	}
}

func emissionsByCode(mu *sync.Mutex, calls *[]emitCall, code audit.Code) int {
	mu.Lock()
	defer mu.Unlock()
	n := 0
	for _, c := range *calls {
		if c.Code == code {
			n++
		}
	}
	return n
}

// makeResults returns N pass-status results with the given rule prefix.
func makeResults(n int, rulePrefix string) []Result {
	out := make([]Result, n)
	for i := 0; i < n; i++ {
		out[i] = Result{
			RuleID:   rulePrefix + "-" + uuid.NewString()[:8],
			Status:   StatusPass,
			Severity: "medium",
			Evidence: []byte(`{}`),
			// Multi-valued on purpose: one rule satisfying several
			// controls in the same framework must round-trip intact
			// (spec system-kensa-executor v2.1.0 C-14).
			FrameworkRefs: map[string][]string{
				"cis_rhel9_v2":   {"5.1.1"},
				"nist_800_53_r5": {"AC-6(2)", "AC-17(2)"},
			},
		}
	}
	return out
}

func countRows(t *testing.T, pool *pgxpool.Pool, table string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		"SELECT count(*) FROM "+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// ---------------------------------------------------------------------
// AC tests
// ---------------------------------------------------------------------

// @ac AC-01
// AC-01: writer.Apply runs exactly one DB transaction regardless of N.
// We can't directly observe BEGIN/COMMIT from outside but we can
// observe atomicity: all-or-nothing on failure (covered by AC-06).
// As a structural check, we count pg_stat queries: a single Apply call
// for 50 rules produces 1 commit, not 50.
func TestApply_SingleTransaction_RegardlessOfN(t *testing.T) {
	t.Run("system-transaction-log-writer/AC-01", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		var mu sync.Mutex
		var calls []emitCall
		w := NewWriter(pool, fakeEmitter(&mu, &calls))

		scanID, _ := uuid.NewV7()
		batch := ApplyBatch{ScanID: scanID, HostID: hostID, Results: makeResults(50, "r")}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Capture commit count before / after.
		var commitsBefore, commitsAfter int
		_ = pool.QueryRow(ctx,
			`SELECT xact_commit FROM pg_stat_database WHERE datname = current_database()`).
			Scan(&commitsBefore)

		if err := w.Apply(ctx, batch); err != nil {
			t.Fatalf("Apply: %v", err)
		}

		_ = pool.QueryRow(ctx,
			`SELECT xact_commit FROM pg_stat_database WHERE datname = current_database()`).
			Scan(&commitsAfter)

		// commitsAfter - commitsBefore should be small (around 1-3:
		// our explicit BEGIN/COMMIT + maybe the idempotency-check
		// implicit transaction + the pg_stat read itself). The exact
		// number drifts with Postgres internals, but it must be << 50.
		delta := commitsAfter - commitsBefore
		if delta > 10 {
			t.Errorf("commit delta = %d after Apply with 50 rules; want ≤ 10 (AC-01: single tx per Apply)", delta)
		}

		// And actually: all 50 rows landed.
		if got := countRows(t, pool, "host_rule_state"); got != 50 {
			t.Errorf("host_rule_state count = %d, want 50", got)
		}
	})
}

// @ac AC-02
// AC-02: first scan against a host writes N host_rule_state rows AND
// N transactions rows, all change_kind='first_seen'.
func TestApply_FirstScan_InsertsAllFirstSeen(t *testing.T) {
	t.Run("system-transaction-log-writer/AC-02", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		var mu sync.Mutex
		var calls []emitCall
		w := NewWriter(pool, fakeEmitter(&mu, &calls))

		const N = 10
		scanID, _ := uuid.NewV7()
		batch := ApplyBatch{ScanID: scanID, HostID: hostID, Results: makeResults(N, "r")}

		if err := w.Apply(context.Background(), batch); err != nil {
			t.Fatalf("Apply: %v", err)
		}

		if got := countRows(t, pool, "host_rule_state"); got != N {
			t.Errorf("host_rule_state = %d, want %d", got, N)
		}
		if got := countRows(t, pool, "transactions"); got != N {
			t.Errorf("transactions = %d, want %d", got, N)
		}

		// Every transactions row is first_seen.
		var allFirstSeen bool
		_ = pool.QueryRow(context.Background(),
			`SELECT bool_and(change_kind = 'first_seen') FROM transactions`).
			Scan(&allFirstSeen)
		if !allFirstSeen {
			t.Error("not every transactions row is change_kind='first_seen'")
		}
	})
}

// @ac AC-03
// AC-03: a second Apply with identical results writes 0 new transactions
// rows. host_rule_state rows update (last_checked_at moves, check_count++).
func TestApply_IdenticalRescan_ZeroTransactions(t *testing.T) {
	t.Run("system-transaction-log-writer/AC-03", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		var mu sync.Mutex
		var calls []emitCall
		w := NewWriter(pool, fakeEmitter(&mu, &calls))

		const N = 5
		results := makeResults(N, "r")

		// First scan.
		scan1, _ := uuid.NewV7()
		if err := w.Apply(context.Background(), ApplyBatch{ScanID: scan1, HostID: hostID, Results: results}); err != nil {
			t.Fatalf("first Apply: %v", err)
		}
		txnsAfterFirst := countRows(t, pool, "transactions")
		if txnsAfterFirst != N {
			t.Fatalf("post-first transactions = %d, want %d", txnsAfterFirst, N)
		}

		// Second scan: identical results, different scan_id.
		scan2, _ := uuid.NewV7()
		if err := w.Apply(context.Background(), ApplyBatch{ScanID: scan2, HostID: hostID, Results: results}); err != nil {
			t.Fatalf("second Apply: %v", err)
		}

		// Zero new transactions rows.
		if got := countRows(t, pool, "transactions"); got != N {
			t.Errorf("post-second transactions = %d, want %d (no new rows)", got, N)
		}

		// host_rule_state.check_count = 2 for every row.
		var minCount, maxCount int
		_ = pool.QueryRow(context.Background(),
			`SELECT min(check_count), max(check_count) FROM host_rule_state`).
			Scan(&minCount, &maxCount)
		if minCount != 2 || maxCount != 2 {
			t.Errorf("check_count min=%d max=%d, want 2/2 (UPSERT incremented)", minCount, maxCount)
		}
	})
}

// @ac AC-04
// AC-04: a second scan where exactly one rule flipped pass→fail
// writes exactly 1 new transactions row with change_kind='state_changed'.
func TestApply_OneStateChange_InsertsOneTransaction(t *testing.T) {
	t.Run("system-transaction-log-writer/AC-04", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		var mu sync.Mutex
		var calls []emitCall
		w := NewWriter(pool, fakeEmitter(&mu, &calls))

		results := makeResults(3, "r")

		// First scan.
		scan1, _ := uuid.NewV7()
		if err := w.Apply(context.Background(), ApplyBatch{ScanID: scan1, HostID: hostID, Results: results}); err != nil {
			t.Fatalf("first: %v", err)
		}
		if got := countRows(t, pool, "transactions"); got != 3 {
			t.Fatalf("post-first transactions = %d, want 3", got)
		}

		// Second scan: same rules, but rule 1 flipped to fail.
		results[1].Status = StatusFail
		scan2, _ := uuid.NewV7()
		if err := w.Apply(context.Background(), ApplyBatch{ScanID: scan2, HostID: hostID, Results: results}); err != nil {
			t.Fatalf("second: %v", err)
		}

		if got := countRows(t, pool, "transactions"); got != 4 {
			t.Errorf("transactions after one flip = %d, want 4 (3 first_seen + 1 state_changed)", got)
		}

		var stateChangedCount int
		_ = pool.QueryRow(context.Background(),
			`SELECT count(*) FROM transactions WHERE change_kind = 'state_changed'`).
			Scan(&stateChangedCount)
		if stateChangedCount != 1 {
			t.Errorf("state_changed count = %d, want 1", stateChangedCount)
		}
	})
}

// @ac AC-05
// AC-05: re-applying the same scan_id is a no-op.
func TestApply_SameScanID_Idempotent(t *testing.T) {
	t.Run("system-transaction-log-writer/AC-05", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		var mu sync.Mutex
		var calls []emitCall
		w := NewWriter(pool, fakeEmitter(&mu, &calls))

		const N = 5
		batch := ApplyBatch{HostID: hostID, Results: makeResults(N, "r")}
		batch.ScanID, _ = uuid.NewV7()

		if err := w.Apply(context.Background(), batch); err != nil {
			t.Fatalf("first: %v", err)
		}
		firstHRS := countRows(t, pool, "host_rule_state")
		firstTxns := countRows(t, pool, "transactions")

		// Replay with the same scan_id.
		if err := w.Apply(context.Background(), batch); err != nil {
			t.Errorf("replay returned error: %v (idempotent replay should succeed silently)", err)
		}
		if countRows(t, pool, "host_rule_state") != firstHRS {
			t.Errorf("host_rule_state row count changed on replay (was %d)", firstHRS)
		}
		if countRows(t, pool, "transactions") != firstTxns {
			t.Errorf("transactions row count changed on replay (was %d)", firstTxns)
		}
	})
}

// @ac AC-06
// AC-06: a simulated DB error mid-Apply rolls back the entire batch.
// We trigger this by passing a host_id that violates the FK constraint
// (no matching hosts(id) row).
func TestApply_FKViolation_RollsBackEntireBatch(t *testing.T) {
	t.Run("system-transaction-log-writer/AC-06", func(t *testing.T) {
		pool := freshPool(t)
		// Don't seed user/host — the FK violation is the test.

		var mu sync.Mutex
		var calls []emitCall
		w := NewWriter(pool, fakeEmitter(&mu, &calls))

		nonExistentHost, _ := uuid.NewV7()
		batch := ApplyBatch{HostID: nonExistentHost, Results: makeResults(20, "r")}
		batch.ScanID, _ = uuid.NewV7()

		err := w.Apply(context.Background(), batch)
		if err == nil {
			t.Fatal("Apply with non-existent host_id succeeded; expected FK violation error")
		}

		// Zero rows persisted across BOTH tables.
		if got := countRows(t, pool, "host_rule_state"); got != 0 {
			t.Errorf("host_rule_state = %d after FK violation; want 0 (full rollback)", got)
		}
		if got := countRows(t, pool, "transactions"); got != 0 {
			t.Errorf("transactions = %d after FK violation; want 0 (full rollback)", got)
		}
	})
}

// @ac AC-07
// AC-07: DELETE on hosts with extant transactions rows fails — the FK
// uses ON DELETE RESTRICT.
func TestDeleteHosts_WithExtantTransactions_Fails(t *testing.T) {
	t.Run("system-transaction-log-writer/AC-07", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		var mu sync.Mutex
		var calls []emitCall
		w := NewWriter(pool, fakeEmitter(&mu, &calls))

		batch := ApplyBatch{HostID: hostID, Results: makeResults(2, "r")}
		batch.ScanID, _ = uuid.NewV7()
		if err := w.Apply(context.Background(), batch); err != nil {
			t.Fatalf("Apply: %v", err)
		}

		_, err := pool.Exec(context.Background(), `DELETE FROM hosts WHERE id = $1`, hostID)
		if err == nil {
			t.Error("DELETE on hosts with extant transactions succeeded; AC-07 requires FK RESTRICT to block it")
		}
	})
}

// @ac AC-09
// AC-09: the count of finding.persisted audit events for a scan equals
// the count of transactions rows inserted by that scan.
func TestApply_FindingPersistedCount_EqualsTransactionsRowCount(t *testing.T) {
	t.Run("system-transaction-log-writer/AC-09", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		var mu sync.Mutex
		var calls []emitCall
		w := NewWriter(pool, fakeEmitter(&mu, &calls))

		// First scan: 4 first_seen rows → 4 audit events.
		batch1 := ApplyBatch{HostID: hostID, Results: makeResults(4, "r")}
		batch1.ScanID, _ = uuid.NewV7()
		if err := w.Apply(context.Background(), batch1); err != nil {
			t.Fatalf("first: %v", err)
		}
		if got := emissionsByCode(&mu, &calls, audit.FindingPersisted); got != 4 {
			t.Errorf("after first scan finding.persisted = %d, want 4", got)
		}

		// Second scan, identical results: zero new transactions, zero new audits.
		batch2 := ApplyBatch{HostID: hostID, Results: batch1.Results}
		batch2.ScanID, _ = uuid.NewV7()
		if err := w.Apply(context.Background(), batch2); err != nil {
			t.Fatalf("second: %v", err)
		}
		if got := emissionsByCode(&mu, &calls, audit.FindingPersisted); got != 4 {
			t.Errorf("after identical rescan finding.persisted = %d, want 4 (no new emissions)", got)
		}
	})
}

// @ac AC-10
// AC-10: 1000-rule Apply completes in ≤ 2 seconds wall-clock against
// shared-CI Postgres. Mirrors system-audit-emission AC-05 budget.
func TestApply_1000Rules_Under2Seconds(t *testing.T) {
	t.Run("system-transaction-log-writer/AC-10", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		var mu sync.Mutex
		var calls []emitCall
		w := NewWriter(pool, fakeEmitter(&mu, &calls))

		batch := ApplyBatch{HostID: hostID, Results: makeResults(1000, "r")}
		batch.ScanID, _ = uuid.NewV7()

		start := time.Now()
		if err := w.Apply(context.Background(), batch); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		elapsed := time.Since(start)

		if elapsed > 2*time.Second {
			t.Errorf("1000-rule Apply took %v, budget 2s", elapsed)
		}
		t.Logf("1000-rule Apply: %v", elapsed)

		if got := countRows(t, pool, "transactions"); got != 1000 {
			t.Errorf("transactions = %d, want 1000", got)
		}
	})
}

// @ac AC-11
// AC-11: concurrent Apply calls for distinct scan_ids on distinct hosts
// complete without deadlock under -race.
func TestApply_ConcurrentDistinctScans_NoDeadlock(t *testing.T) {
	t.Run("system-transaction-log-writer/AC-11", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)

		var mu sync.Mutex
		var calls []emitCall
		w := NewWriter(pool, fakeEmitter(&mu, &calls))

		const N = 50
		hosts := make([]uuid.UUID, N)
		for i := range hosts {
			hosts[i] = seedHost(t, pool, user)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		var wg sync.WaitGroup
		errs := make(chan error, N)
		for _, h := range hosts {
			wg.Add(1)
			go func(host uuid.UUID) {
				defer wg.Done()
				batch := ApplyBatch{HostID: host, Results: makeResults(10, "r")}
				batch.ScanID, _ = uuid.NewV7()
				if err := w.Apply(ctx, batch); err != nil {
					errs <- err
				}
			}(h)
		}
		wg.Wait()
		close(errs)

		for err := range errs {
			t.Errorf("concurrent Apply: %v", err)
		}

		if got := countRows(t, pool, "transactions"); got != N*10 {
			t.Errorf("transactions = %d, want %d", got, N*10)
		}
	})
}

// @ac AC-14
// AC-14: per-rule evidence > 256 KB is rejected BEFORE any INSERT.
// Tests both the typed-error return and the no-partial-writes guarantee.
func TestApply_OversizeEvidence_RejectedBeforeInsert(t *testing.T) {
	t.Run("system-transaction-log-writer/AC-14", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		var mu sync.Mutex
		var calls []emitCall
		w := NewWriter(pool, fakeEmitter(&mu, &calls))

		// Build a batch where rule #5 (of 10) has oversize evidence.
		results := makeResults(10, "r")
		results[5].Evidence = make([]byte, MaxEvidenceBytes+1)

		batch := ApplyBatch{HostID: hostID, Results: results}
		batch.ScanID, _ = uuid.NewV7()

		err := w.Apply(context.Background(), batch)
		if err == nil {
			t.Fatal("Apply with oversize evidence succeeded; AC-14 requires rejection")
		}

		// Nothing persisted from this batch.
		if got := countRows(t, pool, "host_rule_state"); got != 0 {
			t.Errorf("host_rule_state = %d after oversize rejection; want 0 (rejected BEFORE INSERT)", got)
		}
		if got := countRows(t, pool, "transactions"); got != 0 {
			t.Errorf("transactions = %d after oversize rejection; want 0", got)
		}
	})
}

// @ac AC-15
// AC-15: a DB error during Apply emits writer.apply.failed with the
// classified reason. Triggered here via FK violation (no matching host).
func TestApply_FKViolation_EmitsWriterApplyFailedAudit(t *testing.T) {
	t.Run("system-transaction-log-writer/AC-15", func(t *testing.T) {
		pool := freshPool(t)

		var mu sync.Mutex
		var calls []emitCall
		w := NewWriter(pool, fakeEmitter(&mu, &calls))

		nonExistentHost, _ := uuid.NewV7()
		batch := ApplyBatch{HostID: nonExistentHost, Results: makeResults(3, "r")}
		batch.ScanID, _ = uuid.NewV7()

		_ = w.Apply(context.Background(), batch)

		if got := emissionsByCode(&mu, &calls, audit.WriterApplyFailed); got != 1 {
			t.Errorf("writer.apply.failed count = %d, want 1", got)
		}

		// detail.reason should classify the FK violation.
		mu.Lock()
		var failureDetail map[string]any
		for _, c := range calls {
			if c.Code == audit.WriterApplyFailed {
				_ = json.Unmarshal(c.Event.Detail, &failureDetail)
				break
			}
		}
		mu.Unlock()
		if got, _ := failureDetail["reason"].(string); got != string(ReasonFKViolation) {
			t.Errorf("Detail.reason = %v, want %q", failureDetail["reason"], ReasonFKViolation)
		}
		if got, _ := failureDetail["rule_count_attempted"].(float64); got != 3 {
			t.Errorf("Detail.rule_count_attempted = %v, want 3", failureDetail["rule_count_attempted"])
		}
	})
}

// AC-14 with oversize-evidence audit (negative companion to AC-14):
// also verify writer.apply.failed fires with reason=evidence_oversize.
func TestApply_OversizeEvidence_EmitsAuditWithReason(t *testing.T) {
	t.Run("system-transaction-log-writer/AC-14", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		var mu sync.Mutex
		var calls []emitCall
		w := NewWriter(pool, fakeEmitter(&mu, &calls))

		results := makeResults(3, "r")
		results[0].Evidence = make([]byte, MaxEvidenceBytes+1)
		batch := ApplyBatch{HostID: hostID, Results: results}
		batch.ScanID, _ = uuid.NewV7()

		_ = w.Apply(context.Background(), batch)

		var failureDetail map[string]any
		mu.Lock()
		for _, c := range calls {
			if c.Code == audit.WriterApplyFailed {
				_ = json.Unmarshal(c.Event.Detail, &failureDetail)
				break
			}
		}
		mu.Unlock()
		if got, _ := failureDetail["reason"].(string); got != string(ReasonEvidenceOversize) {
			t.Errorf("Detail.reason = %v, want %q", failureDetail["reason"], ReasonEvidenceOversize)
		}
	})
}

// @ac AC-08
// AC-08: evidence that isn't a JSON object is rejected before INSERT
// with a typed error. The full KensaEvidence-schema check (required
// fields) lands when the openapi.yaml KensaEvidence schema commits.
func TestApply_NonJSONEvidence_RejectedBeforeInsert(t *testing.T) {
	t.Run("system-transaction-log-writer/AC-08", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		var mu sync.Mutex
		var calls []emitCall
		w := NewWriter(pool, fakeEmitter(&mu, &calls))

		cases := []struct {
			name     string
			evidence []byte
		}{
			{"not valid JSON", []byte("not even JSON")},
			{"JSON array (not object)", []byte(`[1,2,3]`)},
			{"JSON scalar (not object)", []byte(`42`)},
			{"JSON string (not object)", []byte(`"hello"`)},
		}

		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				results := makeResults(3, "r")
				results[1].Evidence = c.evidence
				batch := ApplyBatch{HostID: hostID, Results: results}
				batch.ScanID, _ = uuid.NewV7()

				err := w.Apply(context.Background(), batch)
				if err == nil {
					t.Errorf("Apply with %s succeeded; AC-08 requires rejection", c.name)
				}
			})
		}

		// And nothing persisted across all the rejection attempts.
		if got := countRows(t, pool, "host_rule_state"); got != 0 {
			t.Errorf("host_rule_state = %d after invalid-evidence rejections; want 0", got)
		}
	})
}
