// @spec system-drift-detector
//
// AC traceability (this file):
//   AC-08  TestDetectForScan_FirstEverScan_ReturnsStable
//   AC-09  TestDetectForScan_PopulatesSeverityTransitionCounts
//   AC-10  TestDetectForScan_MajorWorsening_EmitsAuditWithDelta
//   AC-11  TestDetectForScan_Stable_EmitsNoAudit

package drift

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/db/dbtest"
)

func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()
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
		id, "drift-user", "drift@example.com", "argon2id$dummy") // pragma: allowlist secret
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

func countEmissions(mu *sync.Mutex, calls *[]emitCall, code audit.Code) int {
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

// seedRuleState inserts a host_rule_state row directly. Used to set up
// "prior" state without running the writer through a full scan.
func seedRuleState(t *testing.T, pool *pgxpool.Pool, hostID, scanID uuid.UUID, ruleID, status, severity string) {
	t.Helper()
	now := time.Now()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO host_rule_state
			(host_id, rule_id, current_status, severity, last_checked_at,
			 check_count, last_scan_id, evidence, framework_refs,
			 first_seen_at, last_changed_at)
		VALUES ($1, $2, $3, $4, $5, 1, $6, '{}'::jsonb, '{}'::jsonb, $5, $5)`,
		hostID, ruleID, status, severity, now, scanID)
	if err != nil {
		t.Fatalf("seed rule state: %v", err)
	}
}

// seedTransaction inserts a transactions row directly. status and
// change_kind drive the prior-reconstruction logic.
func seedTransaction(t *testing.T, pool *pgxpool.Pool, hostID, scanID uuid.UUID, ruleID, status, severity, changeKind string) {
	t.Helper()
	txnID, _ := uuid.NewV7()
	now := time.Now()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO transactions
			(id, host_id, rule_id, scan_id, status, severity,
			 change_kind, evidence, framework_refs, occurred_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, '{}'::jsonb, '{}'::jsonb, $8)`,
		txnID, hostID, ruleID, scanID, status, severity, changeKind, now)
	if err != nil {
		t.Fatalf("seed transaction: %v", err)
	}
}

// @ac AC-08
// AC-08: a host with all first_seen transactions (no prior baseline)
// returns DriftStable with HasPriorBaseline=false. No audit emission.
func TestDetectForScan_FirstEverScan_ReturnsStable(t *testing.T) {
	t.Run("system-drift-detector/AC-08", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)
		scanID, _ := uuid.NewV7()

		// Seed 5 rules, all first_seen on this scan.
		for i, st := range []string{"pass", "pass", "fail", "pass", "fail"} {
			ruleID := "rule-" + string(rune('a'+i))
			seedRuleState(t, pool, hostID, scanID, ruleID, st, "high")
			seedTransaction(t, pool, hostID, scanID, ruleID, st, "high", "first_seen")
		}

		var mu sync.Mutex
		var calls []emitCall
		svc := NewService(pool, fakeEmitter(&mu, &calls), DefaultThresholds(), nil)

		report, err := svc.DetectForScan(context.Background(), hostID, scanID)
		if err != nil {
			t.Fatalf("DetectForScan: %v", err)
		}
		if report.Kind != DriftStable {
			t.Errorf("Kind = %q, want %q (first-ever scan)", report.Kind, DriftStable)
		}
		if report.HasPriorBaseline {
			t.Error("HasPriorBaseline = true; expected false (all transactions are first_seen)")
		}
		if got := countEmissions(&mu, &calls, audit.ComplianceDriftDetected); got != 0 {
			t.Errorf("audit emissions = %d, want 0 (stable doesn't emit)", got)
		}
	})
}

// @ac AC-09
// AC-09: per-severity transition counts populated correctly. We seed:
//   - rule-A: critical, prior=pass, current=fail (state_changed)
//   - rule-B: high, prior=pass, current=fail (state_changed)
//   - rule-C: high, prior=pass, current=fail (state_changed)
//   - rule-D: medium, prior=fail, current=pass (state_changed)
//
// The report should reflect: critical_became_failing=1,
// high_became_failing=2, medium_became_passing=1, others=0.
func TestDetectForScan_PopulatesSeverityTransitionCounts(t *testing.T) {
	t.Run("system-drift-detector/AC-09", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)
		scanID, _ := uuid.NewV7()

		// Set up CURRENT state (post-Apply): the 4 rules above.
		seedRuleState(t, pool, hostID, scanID, "rule-A", "fail", "critical")
		seedRuleState(t, pool, hostID, scanID, "rule-B", "fail", "high")
		seedRuleState(t, pool, hostID, scanID, "rule-C", "fail", "high")
		seedRuleState(t, pool, hostID, scanID, "rule-D", "pass", "medium")

		// 4 transitions for this scan.
		seedTransaction(t, pool, hostID, scanID, "rule-A", "fail", "critical", "state_changed")
		seedTransaction(t, pool, hostID, scanID, "rule-B", "fail", "high", "state_changed")
		seedTransaction(t, pool, hostID, scanID, "rule-C", "fail", "high", "state_changed")
		seedTransaction(t, pool, hostID, scanID, "rule-D", "pass", "medium", "state_changed")

		var mu sync.Mutex
		var calls []emitCall
		svc := NewService(pool, fakeEmitter(&mu, &calls), DefaultThresholds(), nil)

		report, err := svc.DetectForScan(context.Background(), hostID, scanID)
		if err != nil {
			t.Fatalf("DetectForScan: %v", err)
		}

		if report.CriticalBecameFailing != 1 {
			t.Errorf("CriticalBecameFailing = %d, want 1", report.CriticalBecameFailing)
		}
		if report.HighBecameFailing != 2 {
			t.Errorf("HighBecameFailing = %d, want 2", report.HighBecameFailing)
		}
		if report.MediumBecamePassing != 1 {
			t.Errorf("MediumBecamePassing = %d, want 1", report.MediumBecamePassing)
		}
		// Negative cases.
		if report.LowBecameFailing != 0 {
			t.Errorf("LowBecameFailing = %d, want 0", report.LowBecameFailing)
		}
	})
}

// @ac AC-10
// AC-10: major worsening emits exactly one compliance.drift.detected
// audit with detail.drift_type="major" and detail.score_delta = the
// negative delta. We construct a scenario:
//
//	Prior: 10 rules, all passing → score=100
//	Current: 10 rules, 8 passing 2 failing → score=80
//	Delta: -20pp → DriftMajorWorsening
func TestDetectForScan_MajorWorsening_EmitsAuditWithDelta(t *testing.T) {
	t.Run("system-drift-detector/AC-10", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)
		scanID, _ := uuid.NewV7()

		// Current state: 8 pass + 2 fail.
		for i := 0; i < 8; i++ {
			seedRuleState(t, pool, hostID, scanID, "pass-rule-"+string(rune('a'+i)), "pass", "high")
		}
		for i := 0; i < 2; i++ {
			seedRuleState(t, pool, hostID, scanID, "fail-rule-"+string(rune('a'+i)), "fail", "high")
		}
		// Both fails were previously passing (state_changed). Others
		// have no transactions for this scan (steady-state pass).
		seedTransaction(t, pool, hostID, scanID, "fail-rule-a", "fail", "high", "state_changed")
		seedTransaction(t, pool, hostID, scanID, "fail-rule-b", "fail", "high", "state_changed")

		var mu sync.Mutex
		var calls []emitCall
		svc := NewService(pool, fakeEmitter(&mu, &calls), DefaultThresholds(), nil)

		report, err := svc.DetectForScan(context.Background(), hostID, scanID)
		if err != nil {
			t.Fatalf("DetectForScan: %v", err)
		}
		if report.Kind != DriftMajorWorsening {
			t.Errorf("Kind = %q, want %q (prior 100 → current 80 = -20pp)",
				report.Kind, DriftMajorWorsening)
		}
		if report.ScoreDelta >= 0 {
			t.Errorf("ScoreDelta = %v, want negative (worsening)", report.ScoreDelta)
		}

		emissions := countEmissions(&mu, &calls, audit.ComplianceDriftDetected)
		if emissions != 1 {
			t.Fatalf("compliance.drift.detected emissions = %d, want 1", emissions)
		}

		// Inspect emission detail.
		mu.Lock()
		var detail map[string]any
		for _, c := range calls {
			if c.Code == audit.ComplianceDriftDetected {
				_ = json.Unmarshal(c.Event.Detail, &detail)
				break
			}
		}
		mu.Unlock()
		if got := detail["drift_type"]; got != "major" {
			t.Errorf("Detail.drift_type = %v, want %q", got, "major")
		}
		// score_delta is JSON number → float64.
		delta, _ := detail["score_delta"].(float64)
		if delta >= 0 {
			t.Errorf("Detail.score_delta = %v, want negative", delta)
		}
	})
}

// @ac AC-11
// AC-11: a stable scan emits zero audits. Same scenario as AC-10 but
// with only 1 of 10 rules failing → delta is -10pp from 100 to 90 →
// major. So we use a different scenario: 1 fail → delta -10pp = major.
// For stable: prior=90, current=90 → no change.
//
// We seed: 9 pass + 1 fail in current. Only the 1 fail has a
// state_changed transaction with kind that reverses to "prior was
// failing" — so prior was also 9 pass + 1 fail (delta 0).
// Actually that's complex. Simpler: use one scan where only one rule
// changed severity (severity_changed change_kind). The score doesn't
// move.
func TestDetectForScan_Stable_EmitsNoAudit(t *testing.T) {
	t.Run("system-drift-detector/AC-11", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)
		scanID, _ := uuid.NewV7()

		// 9 passing + 1 failing in current. The 1 failing had a
		// severity reclassification (severity_changed) — status didn't
		// flip. Prior score = current score = 90.
		for i := 0; i < 9; i++ {
			seedRuleState(t, pool, hostID, scanID, "pass-r-"+string(rune('a'+i)), "pass", "high")
		}
		seedRuleState(t, pool, hostID, scanID, "fail-r-a", "fail", "high")
		seedTransaction(t, pool, hostID, scanID, "fail-r-a", "fail", "high", "severity_changed")

		var mu sync.Mutex
		var calls []emitCall
		svc := NewService(pool, fakeEmitter(&mu, &calls), DefaultThresholds(), nil)

		report, err := svc.DetectForScan(context.Background(), hostID, scanID)
		if err != nil {
			t.Fatalf("DetectForScan: %v", err)
		}
		if report.Kind != DriftStable {
			t.Errorf("Kind = %q, want %q", report.Kind, DriftStable)
		}
		if got := countEmissions(&mu, &calls, audit.ComplianceDriftDetected); got != 0 {
			t.Errorf("emissions = %d, want 0 (stable doesn't emit)", got)
		}
	})
}

// @spec system-current-corpus
// @ac AC-08
// AC-08: drift scopes to the scan it was HANDED, not to the host's
// latest completed run, and retired rows appear in neither its counts
// nor its total.
//
// WHY THIS IS THE SHARP ONE. DetectForScan runs inside the scan job,
// after writer.Apply and before scanruns.MarkCompleted. In that window
// host_rule_state already carries the new scan id on every rule the scan
// evaluated, while the latest COMPLETED run is still the previous one.
// A current-corpus read there does not return a slightly stale answer:
// it returns exactly the rules this scan did NOT evaluate.
//
// The consequence is silent. Drift would compute its "current" counts
// from the retired set, find them unchanged scan after scan, and report
// stable forever. Nothing errors, nothing logs, and a compliance
// regression that should page someone simply never fires. This test is
// what makes that visible, and it is written so the retired rows would
// have to change the numbers if they leaked in.
func TestDetectForScan_ScopedToTheScanNotTheCorpus(t *testing.T) {
	t.Run("system-current-corpus/AC-08", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		// A previous run, COMPLETED, carrying rules the new scan no
		// longer ships. These are the retired rows, and they are all
		// failing, so leaking them in moves every number.
		previousScanID, _ := uuid.NewV7()
		seedCompletedRun(t, pool, hostID, previousScanID, time.Now().Add(-3*time.Hour))
		for i := 0; i < 5; i++ {
			seedRuleState(t, pool, hostID, previousScanID,
				"retired."+uuid.NewString()[:8], "fail", "critical")
		}

		// The new run: rows written, NOT yet marked completed. This is
		// the exact state the worker produces when it calls drift.
		currentScanID, _ := uuid.NewV7()
		seedRunningRun(t, pool, hostID, currentScanID, time.Now().Add(-time.Minute))
		for i := 0; i < 6; i++ {
			r := "now.fail." + uuid.NewString()[:8]
			seedRuleState(t, pool, hostID, currentScanID, r, "fail", "high")
			seedTransaction(t, pool, hostID, currentScanID, r, "fail", "high", "state_changed")
		}
		for i := 0; i < 2; i++ {
			seedRuleState(t, pool, hostID, currentScanID,
				"now.pass."+uuid.NewString()[:8], "pass", "high")
		}

		var mu sync.Mutex
		var calls []emitCall
		svc := NewService(pool, fakeEmitter(&mu, &calls), DefaultThresholds(), nil)
		report, err := svc.DetectForScan(ctx, hostID, currentScanID)
		if err != nil {
			t.Fatalf("DetectForScan: %v", err)
		}

		// The numbers are computed over THIS scan's eight rules: 2 of 8
		// passing now, 8 of 8 before the six flips. Both are asserted,
		// because a read that fell back to the corpus would produce a
		// current score of 0 (five retired rows, all failing) and the
		// prior reconstruction would then have nothing to flip.
		if report.CurrentScore != 25 {
			t.Errorf("CurrentScore = %v, want 25 (2 passing of the 8 rules THIS scan evaluated).\n"+
				"A score of 0 means the read fell back to the host's latest COMPLETED run, which "+
				"in this window is the previous one, so it counted the 5 retired failing rules and "+
				"none of the 8 this scan actually evaluated.", report.CurrentScore)
		}
		if report.PriorScore != 100 {
			t.Errorf("PriorScore = %v, want 100 (all 8 were passing before the flips)", report.PriorScore)
		}
		if !report.HasPriorBaseline {
			t.Error("HasPriorBaseline = false; this is a rescan of rules the host already carried, " +
				"so a baseline exists. Reading it as a first-ever scan forces Kind to stable and " +
				"silences the regression")
		}
		if report.Kind != DriftMajorWorsening {
			t.Errorf("Kind = %q, want major_worsening. A 75-point drop that reports stable is the "+
				"failure mode this AC exists to catch, and it is silent: nothing errors and nothing logs",
				report.Kind)
		}
		// The severity transitions come from the same scan-scoped read.
		// The retired rows are critical; if any leaked in they would land
		// here as critical transitions.
		if report.HighBecameFailing != 6 {
			t.Errorf("HighBecameFailing = %d, want 6", report.HighBecameFailing)
		}
		if report.CriticalBecameFailing != 0 {
			t.Errorf("CriticalBecameFailing = %d, want 0. The only critical rows on this host are "+
				"the retired ones, so any count here is those rows leaking into a scan-scoped read",
				report.CriticalBecameFailing)
		}
	})
}

// seedCompletedRun inserts a completed scan_runs row.
func seedCompletedRun(t *testing.T, pool *pgxpool.Pool, hostID, runID uuid.UUID, finishedAt time.Time) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO scan_runs (id, host_id, trigger_source, status, queued_at, started_at, finished_at)
		VALUES ($1, $2, 'scheduled', 'completed', $3, $3, $3)`, runID, hostID, finishedAt)
	if err != nil {
		t.Fatalf("seed completed run: %v", err)
	}
}

// seedRunningRun inserts a scan_runs row that has started and not
// finished, which is the state drift runs in.
func seedRunningRun(t *testing.T, pool *pgxpool.Pool, hostID, runID uuid.UUID, startedAt time.Time) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO scan_runs (id, host_id, trigger_source, status, queued_at, started_at)
		VALUES ($1, $2, 'scheduled', 'running', $3, $3)`, runID, hostID, startedAt)
	if err != nil {
		t.Fatalf("seed running run: %v", err)
	}
}
