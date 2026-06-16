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
