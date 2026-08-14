// @spec system-current-corpus
//
// AC traceability (DSN-gated):
//
//	AC-13  TestWritePath_SeesRowsOutsideTheCorpus
//	AC-15  TestSyntheticWrite_WithNoPriorRowLandsOutsideTheCorpus
//	AC-21  TestChange_CannotLandHalfApplied

package worker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/transactionlog"
)

// @ac AC-13
// AC-13: the write path still sees EVERY row, current or not.
//
// This is the concrete damage a scoped prior-state read would do. The
// writer reads the prior host_rule_state row to decide change_kind. If
// that read went through the view, a rule outside the host's current
// corpus would look absent, the writer would call the result first_seen,
// and it would append a false transactions row on every scan of every
// rule that one run happened to skip. The transaction log is the audit
// record, so those rows are not a cosmetic error.
func TestWritePath_SeesRowsOutsideTheCorpus(t *testing.T) {
	t.Run("system-current-corpus/AC-13", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)
		const rule = "sshd-permit-root-no"

		rec := &emitRecorder{}
		writer := transactionlog.NewWriter(pool, rec.writerEmit())

		// Scan 1 evaluates the rule and finds it failing.
		scan1 := seedCompletedScanRun(t, pool, hostID, time.Now().Add(-3*time.Hour))
		if err := writer.Apply(ctx, transactionlog.ApplyBatch{
			ScanID: scan1, HostID: hostID, Origin: transactionlog.OriginScan,
			Results: []transactionlog.Result{{
				RuleID: rule, Status: transactionlog.StatusFail, Severity: "high",
				Evidence: scanEvidence, FrameworkRefs: scanFrameworkRefs,
			}},
		}); err != nil {
			t.Fatalf("scan 1: %v", err)
		}

		// Scan 2 does NOT evaluate it, so the rule leaves the corpus.
		scan2 := seedCompletedScanRun(t, pool, hostID, time.Now().Add(-2*time.Hour))
		if err := writer.Apply(ctx, transactionlog.ApplyBatch{
			ScanID: scan2, HostID: hostID, Origin: transactionlog.OriginScan,
			Results: []transactionlog.Result{{
				RuleID: "other-rule", Status: transactionlog.StatusPass,
				Evidence: scanEvidence, FrameworkRefs: scanFrameworkRefs,
			}},
		}); err != nil {
			t.Fatalf("scan 2: %v", err)
		}

		// Precondition: the rule really is out of the corpus, or this
		// test is exercising an ordinary rescan.
		var inCorpus int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM host_rule_state_current WHERE host_id = $1 AND rule_id = $2`,
			hostID, rule).Scan(&inCorpus); err != nil {
			t.Fatalf("check corpus: %v", err)
		}
		if inCorpus != 0 {
			t.Fatalf("%s is still in the corpus after a scan that did not evaluate it; "+
				"the fixture does not describe the case under test", rule)
		}

		// Scan 3 evaluates it again, and it now passes.
		scan3 := seedCompletedScanRun(t, pool, hostID, time.Now().Add(-time.Hour))
		if err := writer.Apply(ctx, transactionlog.ApplyBatch{
			ScanID: scan3, HostID: hostID, Origin: transactionlog.OriginScan,
			Results: []transactionlog.Result{{
				RuleID: rule, Status: transactionlog.StatusPass, Severity: "high",
				Evidence: scanEvidence, FrameworkRefs: scanFrameworkRefs,
			}},
		}); err != nil {
			t.Fatalf("scan 3: %v", err)
		}

		var kind string
		if err := pool.QueryRow(ctx,
			`SELECT change_kind FROM transactions WHERE scan_id = $1 AND rule_id = $2`,
			scan3, rule).Scan(&kind); err != nil {
			t.Fatalf("read scan 3 transaction: %v", err)
		}
		if kind != "state_changed" {
			t.Errorf("scan 3 classified %s as %q, want state_changed. The rule was outside the "+
				"host's current corpus and its row still existed, so a prior-state read that "+
				"went through the view would have found nothing and called this first_seen, "+
				"appending a false row to the audit record", rule, kind)
		}

		// And exactly one transactions row per scan that changed it: two,
		// not three. A first_seen on scan 3 would still be one row, so
		// the count alone cannot catch this; the kind above is what does.
		var total int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM transactions WHERE host_id = $1 AND rule_id = $2`,
			hostID, rule).Scan(&total); err != nil {
			t.Fatalf("count transactions: %v", err)
		}
		if total != 2 {
			t.Errorf("transactions for %s = %d, want 2 (first_seen on scan 1, state_changed on scan 3)",
				rule, total)
		}
	})
}

// @ac AC-15
// AC-15: a synthetic write with NO prior row lands outside the corpus.
//
// The INSERT arm has no prior value to preserve, so the row takes the
// synthetic id and belongs to no corpus. That is the honest answer
// rather than a gap: no scan has ever evaluated that rule on that host,
// so it should score nothing. The row still exists and a later scan
// picks it up.
func TestSyntheticWrite_WithNoPriorRowLandsOutsideTheCorpus(t *testing.T) {
	t.Run("system-current-corpus/AC-15", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)
		const never = "never-scanned-rule"

		// The host has a real completed scan, so it HAS a corpus. Without
		// this the row would be outside the corpus for the trivial reason
		// that the host has none, and the test would pass on a host that
		// proves nothing.
		scanID := seedCompletedScanRun(t, pool, hostID, time.Now().Add(-time.Hour))
		rec := &emitRecorder{}
		writer := transactionlog.NewWriter(pool, rec.writerEmit())
		if err := writer.Apply(ctx, transactionlog.ApplyBatch{
			ScanID: scanID, HostID: hostID, Origin: transactionlog.OriginScan,
			Results: []transactionlog.Result{{
				RuleID: "scanned-rule", Status: transactionlog.StatusPass,
				Evidence: scanEvidence, FrameworkRefs: scanFrameworkRefs,
			}},
		}); err != nil {
			t.Fatalf("seed scan: %v", err)
		}

		requestID, _ := uuid.NewV7()
		if err := writer.Apply(ctx, transactionlog.ApplyBatch{
			ScanID: requestID, HostID: hostID, Origin: transactionlog.OriginRemediation,
			Results: []transactionlog.Result{{
				RuleID: never, Status: transactionlog.StatusPass, Evidence: scanEvidence,
			}},
		}); err != nil {
			t.Fatalf("synthetic apply: %v", err)
		}

		// The row exists and carries the synthetic id.
		var stamped uuid.UUID
		if err := pool.QueryRow(ctx,
			`SELECT last_scan_id FROM host_rule_state WHERE host_id = $1 AND rule_id = $2`,
			hostID, never).Scan(&stamped); err != nil {
			t.Fatalf("the synthetic write inserted no row: %v", err)
		}
		if stamped != requestID {
			t.Errorf("last_scan_id = %s, want the synthetic id %s. On the INSERT arm there is no "+
				"prior value to preserve, so the synthetic id is what the row carries", stamped, requestID)
		}

		// And the view does not return it, while the scanned rule is there.
		var inCorpus []string
		rows, err := pool.Query(ctx,
			`SELECT rule_id FROM host_rule_state_current WHERE host_id = $1 ORDER BY rule_id`, hostID)
		if err != nil {
			t.Fatalf("query view: %v", err)
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatalf("scan: %v", err)
			}
			inCorpus = append(inCorpus, id)
		}
		rows.Close()
		if len(inCorpus) != 1 || inCorpus[0] != "scanned-rule" {
			t.Errorf("current corpus = %v, want [scanned-rule] only. A rule whose only row was "+
				"ever written by a remediation has been evaluated by no scan, so it must score "+
				"nothing rather than count as a free pass", inCorpus)
		}
	})
}

// @ac AC-21
// AC-21: the change cannot land half-applied.
//
// Scoping the reads without the writer rule makes a remediated rule
// vanish from the score the moment it is fixed, so the surface meant to
// reward the operator punishes them instead. Adding the view without the
// guard leaves the twelfth read site unfound. This asserts the three
// halves together and names which one is missing, so the pieces cannot
// be split across two pull requests with a release in between.
//
// It reads SOURCE rather than behavior on purpose: the behavioral tests
// elsewhere each pass if their own half landed, and this is the one that
// fails when only some did.
func TestChange_CannotLandHalfApplied(t *testing.T) {
	t.Run("system-current-corpus/AC-21", func(t *testing.T) {
		root, err := filepath.Abs(filepath.Join("..", ".."))
		if err != nil {
			t.Fatalf("resolve module root: %v", err)
		}

		// 1. A migration creates the view.
		migrations, err := os.ReadDir(filepath.Join(root, "internal", "db", "migrations"))
		if err != nil {
			t.Fatalf("read migrations: %v", err)
		}
		viewCreated := false
		for _, m := range migrations {
			if !strings.HasSuffix(m.Name(), ".sql") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(root, "internal", "db", "migrations", m.Name()))
			if err != nil {
				t.Fatalf("read %s: %v", m.Name(), err)
			}
			if strings.Contains(string(raw), "CREATE VIEW host_rule_state_current") {
				viewCreated = true
				break
			}
		}
		if !viewCreated {
			t.Error("MISSING: no migration creates host_rule_state_current. The reads have " +
				"nothing to move to")
		}

		// 2. ApplyBatch carries an origin.
		types, err := os.ReadFile(filepath.Join(root, "internal", "transactionlog", "types.go"))
		if err != nil {
			t.Fatalf("read types.go: %v", err)
		}
		if !strings.Contains(string(types), "Origin Origin") {
			t.Error("MISSING: transactionlog.ApplyBatch carries no Origin field. Without it a " +
				"synthetic write cannot be told from a scan, and a remediated rule drops out of " +
				"the score the moment an operator fixes it")
		}

		// 3. The UPSERT preserves all three columns for a non-scan origin.
		src, err := os.ReadFile(filepath.Join(root, "internal", "transactionlog", "writer.go"))
		if err != nil {
			t.Fatalf("read writer.go: %v", err)
		}
		body := string(src)
		for _, col := range []string{"last_scan_id", "severity", "framework_refs"} {
			// The preserving form assigns the column from host_rule_state
			// rather than from EXCLUDED on the synthetic branch.
			if !strings.Contains(body, "host_rule_state."+col+"\n") {
				t.Errorf("MISSING: the UPSERT does not preserve %s for a non-scan origin. "+
					"A synthetic write reports one thing, that the rule now passes, and must "+
					"overwrite nothing else the scan recorded", col)
			}
		}
	})
}
