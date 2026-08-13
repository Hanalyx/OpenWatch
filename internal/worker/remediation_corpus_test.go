// @spec system-current-corpus
//
// AC traceability (DSN-gated):
//
//	AC-14  TestRemediationWorker_RemediatedRuleStaysInCurrentCorpus
//	AC-14  TestWriter_OriginRules
//	AC-16  TestRemediationWorker_RemediatedRuleKeepsItsFrameworkRefs
//
// PARTIAL COVERAGE, recorded here rather than in a report nobody reads
// next to the code:
//
//   - AC-16 also requires asserting that current_status, evidence,
//     last_checked_at and check_count DID move, which the test below
//     does not yet check. The separate repair for rows an earlier flip
//     already damaged is AC-23, which needs a migration that does not
//     exist.
//
// Current-corpus scoping: the remediation path.
//
// WHY THIS FILE EXISTS. Scoping a current score to "rows whose
// last_scan_id equals the host's most recent completed scan" is correct
// for a scan, and it is a trap for a remediation. flipRuleToPass applies
// a transaction-log batch keyed on the remediation request id as a
// SYNTHETIC scan id, so the writer's scan_id idempotency makes a
// re-delivered job a no-op. That id names no scan_runs row. If it
// reached host_rule_state.last_scan_id, the remediated rule would stop
// matching the host's latest scan and would drop out of every current
// score the moment an operator fixed it. Fixing a finding would raise
// the score by deleting the rule from the denominator, which is the
// opposite of what an operator is told the number means.
//
// The two assertions below are deliberately independent:
//
//   - last_scan_id in the database is read directly. It holds whatever
//     the shared read predicate turns out to be, and it is the assertion
//     that goes red when the synthetic id leaks.
//   - the posture rollup is a real current-score surface, so the same
//     defect is also caught in the shape an operator would see.
//
// Fixture rule, and it is load-bearing: NO scan_runs row is seeded for
// the remediation request id. The leak is only detectable because the
// request id matches no completed scan. A fixture that inserted one
// would let the mutation stay green.

package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/fleetrollup"
	"github.com/Hanalyx/openwatch/internal/kensa"
	"github.com/Hanalyx/openwatch/internal/posture"
	"github.com/Hanalyx/openwatch/internal/queue"
	"github.com/Hanalyx/openwatch/internal/transactionlog"

	"sync/atomic"
)

// scanEvidence is the minimal non-empty evidence object the transactions
// table requires (its evidence column is NOT NULL).
var scanEvidence = []byte(`{"command":"test"}`)

// scanFrameworkRefs keeps framework_refs a JSON OBJECT. A nil map
// marshals to null, and the posture rollup calls jsonb_object_keys on
// the column, which rejects a scalar.
var scanFrameworkRefs = map[string][]string{"cis": {"1.1"}}

// seedCompletedScanRun inserts a completed scan_runs row for hostID and
// returns its id. finishedAt drives BOTH queued_at and finished_at so a
// fixture is unambiguous under either ordering column.
func seedCompletedScanRun(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, finishedAt time.Time) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO scan_runs
			(id, host_id, trigger_source, status, queued_at, started_at, finished_at)
		VALUES ($1, $2, 'on_demand', 'completed', $3, $3, $3)`,
		id, hostID, finishedAt)
	if err != nil {
		t.Fatalf("seed completed scan_run: %v", err)
	}
	return id
}

// lastScanIDOf reads host_rule_state.last_scan_id for one rule.
func lastScanIDOf(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, ruleID string) uuid.UUID {
	t.Helper()
	var got uuid.UUID
	err := pool.QueryRow(context.Background(),
		`SELECT last_scan_id FROM host_rule_state WHERE host_id = $1 AND rule_id = $2`,
		hostID, ruleID).Scan(&got)
	if err != nil {
		t.Fatalf("read last_scan_id for rule %s: %v", ruleID, err)
	}
	return got
}

// fleetScore reads the unfiltered fleet compliance score, which is a
// real current-score surface over host_rule_state.
//
// Unfiltered is the deliberate choice. With no framework argument
// FleetComplianceScore's OS-resolved predicate short-circuits to TRUE
// and never touches framework_refs, so this surface measures corpus
// membership and nothing else. The framework_refs defect recorded in
// TestRemediationWorker_RemediatedRuleKeepsItsFrameworkRefs is a
// separate failure with a separate cause, and mixing the two would
// leave a red test that names neither.
//
// TotalEvaluations counts rows with current_status in (pass, fail), so
// it is the size of the corpus the score is computed over.
func fleetScore(t *testing.T, pool *pgxpool.Pool) fleetrollup.Score {
	t.Helper()
	sc, err := fleetrollup.NewService(pool).FleetComplianceScore(context.Background())
	if err != nil {
		t.Fatalf("fleet compliance score: %v", err)
	}
	return sc
}

// TestRemediationWorker_RemediatedRuleStaysInCurrentCorpus pins the
// property that fixing a finding moves the rule from fail to pass
// WITHOUT removing it from the corpus the score is computed over.
//
// The control rule matters. Asserting only that the remediated rule
// passes cannot distinguish "one rule, and it passes" from "two rules,
// one of which passes": both read as 100 percent. Asserting the TOTAL is
// what separates them, so the sizes below are chosen to make every
// wrong answer a different number.
// @ac AC-14
func TestRemediationWorker_RemediatedRuleStaysInCurrentCorpus(t *testing.T) {
	t.Run("system-current-corpus/AC-14", testRemediatedRuleStaysInCurrentCorpus)
}

func testRemediatedRuleStaysInCurrentCorpus(t *testing.T) {
	pool := freshPool(t)
	ctx := context.Background()
	user := seedUser(t, pool)
	hostID := seedHost(t, pool, user)

	const fixed = "sshd-permit-root-no" // the rule the operator remediates
	const control = "sshd-protocol-2"   // untouched, proves the corpus survived
	const retired = "shell-timeout-600" // dropped from the corpus before this scan

	// An older completed scan that evaluated a rule the current corpus no
	// longer ships. Its row freezes at fail forever: no scan clears it,
	// and no remediation fixes it, because the engine has no handler for
	// a rule it no longer ships. It must count toward nothing.
	oldScanID := seedCompletedScanRun(t, pool, hostID, time.Now().Add(-3*time.Hour))
	// One real completed scan carrying both live rules: fixed fails, control passes.
	scanID := seedCompletedScanRun(t, pool, hostID, time.Now().Add(-time.Hour))

	rec := &emitRecorder{}
	writer := transactionlog.NewWriter(pool, rec.writerEmit())
	if err := writer.Apply(ctx, transactionlog.ApplyBatch{
		ScanID: oldScanID,
		HostID: hostID,
		Origin: transactionlog.OriginScan,
		Results: []transactionlog.Result{
			{RuleID: retired, Status: transactionlog.StatusFail, Severity: "high",
				Evidence: scanEvidence, FrameworkRefs: scanFrameworkRefs},
		},
	}); err != nil {
		t.Fatalf("seed old scan via writer.Apply: %v", err)
	}
	if err := writer.Apply(ctx, transactionlog.ApplyBatch{
		ScanID: scanID,
		HostID: hostID,
		Origin: transactionlog.OriginScan,
		Results: []transactionlog.Result{
			{RuleID: fixed, Status: transactionlog.StatusFail, Severity: "high",
				Evidence: scanEvidence, FrameworkRefs: scanFrameworkRefs},
			{RuleID: control, Status: transactionlog.StatusPass, Severity: "low",
				Evidence: scanEvidence, FrameworkRefs: scanFrameworkRefs},
		},
	}); err != nil {
		t.Fatalf("seed scan via writer.Apply: %v", err)
	}

	// Before: 2 rules evaluated, half passing. The retired rule is on disk
	// and failing, so a score of 2 evaluations is also the assertion that
	// the surface scopes to the current corpus at all. Unscoped it reads 3
	// evaluations and a third of them passing.
	//
	// If this is already wrong the assertions after remediation prove
	// nothing, so it is checked rather than assumed.
	if before := fleetScore(t, pool); before.TotalEvaluations != 2 || before.PassingFraction != 0.5 {
		t.Fatalf("pre-remediation score = %+v, want {PassingFraction:0.5 TotalEvaluations:2}. "+
			"The host carries 3 rows and only 2 are in the current corpus; a total of 3 means "+
			"the retired rule %q is still being scored", before, retired)
	}
	// The retired row is on disk. The corpus argument only holds if
	// nothing was deleted to achieve it.
	var retiredStatus string
	if err := pool.QueryRow(ctx,
		`SELECT current_status FROM host_rule_state WHERE host_id = $1 AND rule_id = $2`,
		hostID, retired).Scan(&retiredStatus); err != nil {
		t.Fatalf("the retired row is gone: %v; scoping a read must never delete a row", err)
	}
	if retiredStatus != "fail" {
		t.Errorf("retired rule reads %q, want fail; its historical verdict must survive", retiredStatus)
	}

	// Remediate `fixed` through the real worker path.
	svc := recordingSvc(pool, rec)
	reqID := seedApprovedRequest(t, pool, svc, hostID, fixed)

	var calls atomic.Int64
	exec := kensa.NewExecutor(stubBridge{plain: []byte("x")}, rec.executorEmit()).
		WithRemediateFunc(fakeRemediate("committed", &calls), noopRollback())
	key := remediationKey(t)
	rw := NewRemediationWorker(RemediationConfig{
		Pool:     pool,
		Executor: exec,
		Service:  svc,
		Writer:   writer,
		QueueKey: key,
		Emit:     rec.Emit(),
	})
	enqueueRemediationJob(t, pool, key, reqID, hostID, fixed)
	job, jobCtx, err := queue.Dequeue(ctx, pool)
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}
	rw.ProcessJob(jobCtx, job)

	if calls.Load() != 1 {
		t.Fatalf("remediate calls = %d, want 1; the worker did not run the path under test", calls.Load())
	}
	if st, ok := ruleStateStatus(t, pool, hostID, fixed); !ok || st != "pass" {
		t.Fatalf("host_rule_state[%s] = (%q, %v), want (pass, true); "+
			"the remediation did not apply, so the corpus assertions below would be vacuous", fixed, st, ok)
	}

	// The fixture's own precondition. The request id must name no
	// scan_runs row, because that absence is the only reason a leaked
	// synthetic id is detectable at all.
	var runsForRequest int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM scan_runs WHERE id = $1`, reqID).Scan(&runsForRequest); err != nil {
		t.Fatalf("count scan_runs for request id: %v", err)
	}
	if runsForRequest != 0 {
		t.Fatalf("the remediation request id %s names %d scan_runs rows, want 0. "+
			"A synthetic id that happens to name a real scan makes this test unable to fail",
			reqID, runsForRequest)
	}

	// ASSERTION 1. The synthetic write did not overwrite last_scan_id.
	// This is the one that goes red if flipRuleToPass ever carries its
	// request id into the column the read predicate matches on.
	if got := lastScanIDOf(t, pool, hostID, fixed); got != scanID {
		extra := ""
		if got == reqID {
			extra = " That is the remediation request id: the synthetic scan id reached last_scan_id, " +
				"so this rule no longer matches the host's latest completed scan and drops out of every current score."
		}
		t.Errorf("after remediation, host_rule_state[%s].last_scan_id = %s, want the real scan id %s.%s",
			fixed, got, scanID, extra)
	}
	// The control rule was never rewritten, so its id pins that the
	// comparison above is against a value the scan really wrote.
	if got := lastScanIDOf(t, pool, hostID, control); got != scanID {
		t.Errorf("control rule %s last_scan_id = %s, want %s; the seeding scan did not write what this test assumes",
			control, got, scanID)
	}

	// ASSERTION 2. The same property through a current-score surface.
	// Both rules are still counted and both now pass. Under the leak the
	// remediated rule is gone and this reads
	// {PassingFraction:1 TotalEvaluations:1}, which is 100 percent computed
	// over half the corpus. Checking the fraction alone cannot tell those
	// apart: both read 1. TotalEvaluations is the assertion that can.
	after := fleetScore(t, pool)
	if after.TotalEvaluations != 2 {
		t.Errorf("post-remediation corpus size = %d, want 2. Remediating a rule must not remove it "+
			"from the corpus the score is computed over; got %+v", after.TotalEvaluations, after)
	}
	if after.PassingFraction != 1 {
		t.Errorf("post-remediation passing fraction = %v, want 1 (both rules pass); got %+v",
			after.PassingFraction, after)
	}
}

// TestRemediationWorker_RemediatedRuleKeepsItsFrameworkRefs pins a
// SEPARATE defect found while building the test above, kept separate so
// each failure names one cause.
//
// flipRuleToPass builds a transactionlog.Result carrying only RuleID,
// Status and Evidence. FrameworkRefs is a nil map, which marshals to the
// JSON scalar null, and the UPSERT assigns framework_refs =
// EXCLUDED.framework_refs unconditionally. JSON null is not SQL NULL, so
// the column's NOT NULL DEFAULT '{}' does not stop it. severity is
// cleared the same way.
//
// Two consequences. The posture rollup calls jsonb_object_keys over
// every live host in ONE statement, so a single scalar row aborts the
// whole INSERT and no host gets a snapshot. And a rule with no framework
// refs falls out of every framework-scoped score, which is this story's
// own defect arriving through a different column: scoping last_scan_id
// correctly does not put the rule back into the lens.
//
// Reported to coder8. This test does not assume a particular fix, only
// that a remediation stops destroying data the scan wrote.
// @ac AC-16
func TestRemediationWorker_RemediatedRuleKeepsItsFrameworkRefs(t *testing.T) {
	t.Run("system-current-corpus/AC-16", testRemediatedRuleKeepsItsFrameworkRefs)
}

func testRemediatedRuleKeepsItsFrameworkRefs(t *testing.T) {
	pool := freshPool(t)
	ctx := context.Background()
	user := seedUser(t, pool)
	hostID := seedHost(t, pool, user)
	const ruleID = "sshd-permit-root-no"

	scanID := seedCompletedScanRun(t, pool, hostID, time.Now().Add(-time.Hour))
	rec := &emitRecorder{}
	writer := transactionlog.NewWriter(pool, rec.writerEmit())
	if err := writer.Apply(ctx, transactionlog.ApplyBatch{
		ScanID: scanID,
		HostID: hostID,
		Origin: transactionlog.OriginScan,
		Results: []transactionlog.Result{{
			RuleID: ruleID, Status: transactionlog.StatusFail, Severity: "critical",
			Evidence: scanEvidence, FrameworkRefs: scanFrameworkRefs,
		}},
	}); err != nil {
		t.Fatalf("seed scan via writer.Apply: %v", err)
	}

	svc := recordingSvc(pool, rec)
	reqID := seedApprovedRequest(t, pool, svc, hostID, ruleID)
	var calls atomic.Int64
	exec := kensa.NewExecutor(stubBridge{plain: []byte("x")}, rec.executorEmit()).
		WithRemediateFunc(fakeRemediate("committed", &calls), noopRollback())
	key := remediationKey(t)
	rw := NewRemediationWorker(RemediationConfig{
		Pool: pool, Executor: exec, Service: svc, Writer: writer,
		QueueKey: key, Emit: rec.Emit(),
	})
	enqueueRemediationJob(t, pool, key, reqID, hostID, ruleID)
	job, jobCtx, err := queue.Dequeue(ctx, pool)
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}
	rw.ProcessJob(jobCtx, job)
	if calls.Load() != 1 {
		t.Fatalf("remediate calls = %d, want 1; the worker did not run the path under test", calls.Load())
	}

	// The column must still hold a JSON OBJECT. Asserting the type rather
	// than the exact refs is the honest assertion: whether the fix
	// preserves the prior refs or rewrites them, a scalar is always wrong.
	var refsType, refs string
	var severity *string
	if err := pool.QueryRow(ctx, `
		SELECT jsonb_typeof(framework_refs), framework_refs::text, severity
		  FROM host_rule_state WHERE host_id = $1 AND rule_id = $2`,
		hostID, ruleID).Scan(&refsType, &refs, &severity); err != nil {
		t.Fatalf("read remediated row: %v", err)
	}
	if refsType != "object" {
		t.Errorf("after remediation, framework_refs is jsonb %s (%s), want an object. "+
			"The scan wrote %v and the remediation replaced it, so this rule now maps to no "+
			"framework and drops out of every framework-scoped score",
			refsType, refs, scanFrameworkRefs)
	}
	if severity == nil || *severity != "critical" {
		got := "NULL"
		if severity != nil {
			got = *severity
		}
		t.Errorf("after remediation, severity = %s, want critical. The scan recorded the "+
			"severity and the remediation erased it", got)
	}

	// The fleet-wide effect, asserted through the surface that breaks.
	// posture.Rollup is one statement over every live host, so this is not
	// a per-host failure.
	if _, err := posture.Rollup(ctx, pool, time.Now()); err != nil {
		t.Errorf("posture rollup failed after ONE remediation: %v. "+
			"Rollup is a single INSERT over every live host, so one scalar framework_refs "+
			"row stops the daily snapshot for the whole fleet, not just this host", err)
	}
}

// @ac AC-14
// @spec system-transaction-log-writer
// @ac AC-16
// TestWriter_OriginRules covers the two halves of AC-14 that the origin
// value makes testable: re-applying a synthetic batch stays a no-op, and
// an Apply with no origin is refused before it writes anything.
//
// The refusal case is the one worth the most. C-06 requires the zero
// value to be invalid rather than to mean either thing, because a
// default that means scan lets a future synthetic caller reintroduce the
// original defect by forgetting a field, and a default that means
// preserve stops a scan advancing the corpus. Asserting the typed error
// without also asserting that NOTHING was written would pass against an
// implementation that rejected the batch after a partial write.
func TestWriter_OriginRules(t *testing.T) {
	t.Run("system-current-corpus/AC-14", func(t *testing.T) {
		t.Log("system-transaction-log-writer/AC-16")
		pool := freshPool(t)
		ctx := context.Background()
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)
		const ruleID = "sshd-permit-root-no"

		scanID := seedCompletedScanRun(t, pool, hostID, time.Now().Add(-time.Hour))
		rec := &emitRecorder{}
		writer := transactionlog.NewWriter(pool, rec.writerEmit())
		if err := writer.Apply(ctx, transactionlog.ApplyBatch{
			ScanID: scanID, HostID: hostID, Origin: transactionlog.OriginScan,
			Results: []transactionlog.Result{{
				RuleID: ruleID, Status: transactionlog.StatusFail, Severity: "high",
				Evidence: scanEvidence, FrameworkRefs: scanFrameworkRefs,
			}},
		}); err != nil {
			t.Fatalf("seed scan: %v", err)
		}

		t.Run("a synthetic re-apply is still a no-op", func(t *testing.T) {
			requestID, _ := uuid.NewV7()
			synthetic := transactionlog.ApplyBatch{
				ScanID: requestID, HostID: hostID, Origin: transactionlog.OriginRemediation,
				Results: []transactionlog.Result{{
					RuleID: ruleID, Status: transactionlog.StatusPass, Evidence: scanEvidence,
				}},
			}
			if err := writer.Apply(ctx, synthetic); err != nil {
				t.Fatalf("first synthetic apply: %v", err)
			}
			before := txnCount(t, pool, hostID, ruleID)
			afterFirst := lastScanIDOf(t, pool, hostID, ruleID)

			// The SAME batch again. Idempotency keys on scan_id, and the
			// origin change must not have disturbed it.
			if err := writer.Apply(ctx, synthetic); err != nil {
				t.Fatalf("re-apply: %v", err)
			}
			if got := txnCount(t, pool, hostID, ruleID); got != before {
				t.Errorf("transactions rows went %d -> %d on re-apply, want no change. "+
					"A re-delivered remediation job must stay a no-op", before, got)
			}
			if got := lastScanIDOf(t, pool, hostID, ruleID); got != afterFirst {
				t.Errorf("last_scan_id moved on re-apply: %s -> %s", afterFirst, got)
			}
			if st, _ := ruleStateStatus(t, pool, hostID, ruleID); st != "pass" {
				t.Errorf("status after re-apply = %q, want pass", st)
			}
			// The synthetic id never reached the column the corpus reads.
			if afterFirst != scanID {
				t.Errorf("last_scan_id = %s, want the real scan id %s", afterFirst, scanID)
			}
		})

		t.Run("an unset origin is refused before anything is written", func(t *testing.T) {
			hrsBefore, txnBefore := rowCounts(t, pool, hostID)
			orphan, _ := uuid.NewV7()
			err := writer.Apply(ctx, transactionlog.ApplyBatch{
				ScanID: orphan, HostID: hostID, // Origin deliberately unset
				Results: []transactionlog.Result{{
					RuleID: "brand-new-rule", Status: transactionlog.StatusPass,
					Evidence: scanEvidence,
				}},
			})
			if err == nil {
				t.Fatal("Apply with no origin returned nil. The zero value must be invalid: a " +
					"default meaning scan lets a synthetic caller reintroduce the defect by " +
					"forgetting a field, and a default meaning preserve stops a scan advancing " +
					"the corpus")
			}
			if !errors.Is(err, transactionlog.ErrMissingOrigin) {
				t.Errorf("Apply error = %v, want ErrMissingOrigin; callers classify with errors.Is", err)
			}
			// The refusal is audited. writer.apply.failed with
			// reason=missing_origin is the only trace an operator gets
			// of a caller that forgot the field, and a FailureReason
			// constant nothing emits is this repo's characteristic
			// defect: a declared surface carrying nothing.
			if rec.Count(audit.WriterApplyFailed) == 0 {
				t.Error("a refused Apply emitted no writer.apply.failed audit. The typed error " +
					"reaches the caller; the audit is the only thing that reaches an operator")
			}

			// Refused BEFORE writing, not after. A partial write would
			// satisfy the error assertion above and still be wrong.
			hrsAfter, txnAfter := rowCounts(t, pool, hostID)
			if hrsAfter != hrsBefore || txnAfter != txnBefore {
				t.Errorf("rows changed on a refused Apply: host_rule_state %d -> %d, "+
					"transactions %d -> %d; the batch must be rejected before any write",
					hrsBefore, hrsAfter, txnBefore, txnAfter)
			}
		})
	})
}

// txnCount counts transactions rows for one (host, rule).
func txnCount(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, ruleID string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM transactions WHERE host_id = $1 AND rule_id = $2`,
		hostID, ruleID).Scan(&n); err != nil {
		t.Fatalf("count transactions: %v", err)
	}
	return n
}

// rowCounts returns the host's host_rule_state and transactions row counts.
func rowCounts(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID) (hrs, txn int) {
	t.Helper()
	ctx := context.Background()
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM host_rule_state WHERE host_id = $1`, hostID).Scan(&hrs); err != nil {
		t.Fatalf("count host_rule_state: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM transactions WHERE host_id = $1`, hostID).Scan(&txn); err != nil {
		t.Fatalf("count transactions: %v", err)
	}
	return hrs, txn
}
