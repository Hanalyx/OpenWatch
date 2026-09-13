// @spec system-fleet-rollup
//
// AC traceability (this file):
//   AC-01  TestFleetComplianceScore_EqualHostMeanNotPooled
//   AC-02  TestFleetComplianceScore_EmptyFleetIsAbsentNotZero
//   AC-03  TestFleetComplianceScore_SkipsAndErrorsExcluded
//   AC-14  TestFleetComplianceScore_ParticipationCounts
//   AC-04  TestFleetLiveness_FourBucketsSumToActiveHosts
//   AC-05  TestTopFailingRules_OrderedDescByCount
//   AC-06  TestTopFailingRules_ZeroLimit_EmptySlice
//   AC-07  TestTopFailingHosts_OrderedDescByCount
//   AC-08  TestRecentChanges_SinceCursorFilters_OrderDesc
//   AC-09  TestEveryMethod_RespectsContextCancellation
//   AC-10  TestLimitClamping_NegativeAndOverflow

package fleetrollup

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/db/corpustest"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/Hanalyx/openwatch/internal/specfixture"
)

// ---------------------------------------------------------------------
// Test scaffolding
// ---------------------------------------------------------------------

func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()
	for _, stmt := range []string{
		"TRUNCATE TABLE transactions CASCADE",
		"TRUNCATE TABLE host_rule_state CASCADE",
		"TRUNCATE TABLE host_liveness CASCADE",
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
		id, "rollup-user", "rollup@example.com", "argon2id$dummy") // pragma: allowlist secret
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

// seedRuleState inserts a host_rule_state row with the given status.
func seedRuleState(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, ruleID, status string) {
	t.Helper()
	now := time.Now().UTC()
	scanID := corpustest.CurrentRun(t, pool, hostID)
	_, err := pool.Exec(context.Background(), `
		INSERT INTO host_rule_state
			(host_id, rule_id, current_status, severity,
			 last_checked_at, check_count, last_scan_id, evidence,
			 framework_refs, first_seen_at, last_changed_at)
		VALUES ($1, $2, $3, 'medium', $4, 1, $5, '{}'::jsonb, '{}'::jsonb, $4, $4)`,
		hostID, ruleID, status, now, scanID,
	)
	if err != nil {
		t.Fatalf("seed rule_state: %v", err)
	}
}

// seedLiveness inserts a host_liveness row with the given status.
func seedLiveness(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, status string) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO host_liveness (host_id, reachability_status, last_probe_at)
		VALUES ($1, $2, now())`, hostID, status)
	if err != nil {
		t.Fatalf("seed liveness: %v", err)
	}
}

// seedTransaction inserts a transactions row.
func seedTransaction(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, ruleID, status, changeKind string, occurredAt time.Time) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	scanID, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO transactions
			(id, host_id, rule_id, scan_id, status, severity,
			 change_kind, evidence, occurred_at)
		VALUES ($1, $2, $3, $4, $5, 'medium', $6, '{}'::jsonb, $7)`,
		id, hostID, ruleID, scanID, status, changeKind, occurredAt,
	)
	if err != nil {
		t.Fatalf("seed transaction: %v", err)
	}
	return id
}

// rollupCriteria loads this spec's fixtures.
func rollupCriteria(t *testing.T) map[string]specfixture.Criterion {
	t.Helper()
	return specfixture.Load(t, "../../specs/system/fleet-rollup.spec.yaml", "system-fleet-rollup")
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

// @ac AC-01
// AC-01: the fleet score is the equal-host mean, not a pooled ratio.
func TestFleetComplianceScore_EqualHostMeanNotPooled(t *testing.T) {
	t.Run("system-fleet-rollup/AC-01", func(t *testing.T) {
		pool := freshPool(t)
		svc := NewService(pool)
		user := seedUser(t, pool)
		ac := specfixture.Get(t, rollupCriteria(t), "AC-01")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		// Two hosts with DIFFERENT rule counts. Equal counts make the pooled
		// ratio and the equal-host mean agree, so the fixture would prove
		// nothing: host A carries five times host B's rules on purpose.
		for _, h := range in.MapList("hosts") {
			id := seedHost(t, pool, user)
			// The label is read unconditionally. A host with no rules at all
			// would otherwise never touch it, and the fixture's own id would go
			// unconsumed on exactly the host this criterion is about.
			label := h.Str("id")
			for i := 0; i < h.Int("pass"); i++ {
				seedRuleState(t, pool, id, fmt.Sprintf("%s.p%d", label, i), "pass")
			}
			for i := 0; i < h.Int("fail"); i++ {
				seedRuleState(t, pool, id, fmt.Sprintf("%s.f%d", label, i), "fail")
			}
			if h.Has("skipped") {
				for i := 0; i < h.Int("skipped"); i++ {
					seedRuleState(t, pool, id, fmt.Sprintf("%s.s%d", label, i), "skipped")
				}
			}
			h.AllConsumed()
		}

		score, err := svc.FleetComplianceScore(context.Background())
		if err != nil {
			t.Fatalf("FleetComplianceScore: %v", err)
		}
		got, ok := score.Score.Rounded()
		if !ok {
			t.Fatal("fleet score absent, but two hosts produced verdicts")
		}
		if want := exp.Num("score_pct"); got != want {
			t.Errorf("score = %v, want %v (equal-host mean)", got, want)
		}
		// The discriminating assertions. Pooling every rule row weights host A
		// five to one over host B; averaging the unscored host in as zero pulls
		// the mean down by a third.
		if bad := exp.Num("forbidden_pooled_score_pct"); got == bad {
			t.Errorf("score = %v, the POOLED answer; a host with more rules must not "+
				"outweigh one with fewer", bad)
		}
		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-14
// AC-14: the participation counts are reported and differ from each other.
func TestFleetComplianceScore_ParticipationCounts(t *testing.T) {
	t.Run("system-fleet-rollup/AC-14", func(t *testing.T) {
		pool := freshPool(t)
		svc := NewService(pool)
		user := seedUser(t, pool)
		ac := specfixture.Get(t, rollupCriteria(t), "AC-14")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		for _, h := range in.MapList("hosts") {
			id := seedHost(t, pool, user)
			// The label is read unconditionally. A host with no rules at all
			// would otherwise never touch it, and the fixture's own id would go
			// unconsumed on exactly the host this criterion is about.
			label := h.Str("id")
			for i := 0; i < h.Int("pass"); i++ {
				seedRuleState(t, pool, id, fmt.Sprintf("%s.p%d", label, i), "pass")
			}
			for i := 0; i < h.Int("fail"); i++ {
				seedRuleState(t, pool, id, fmt.Sprintf("%s.f%d", label, i), "fail")
			}
			if h.Has("skipped") {
				for i := 0; i < h.Int("skipped"); i++ {
					seedRuleState(t, pool, id, fmt.Sprintf("%s.s%d", label, i), "skipped")
				}
			}
			h.AllConsumed()
		}

		score, err := svc.FleetComplianceScore(context.Background())
		if err != nil {
			t.Fatalf("FleetComplianceScore: %v", err)
		}
		if score.HostsScored != exp.Int("hosts_scored") {
			t.Errorf("HostsScored = %d, want %d", score.HostsScored, exp.Int("hosts_scored"))
		}
		if score.HostsWithoutScore != exp.Int("hosts_without_score") {
			t.Errorf("HostsWithoutScore = %d, want %d; the host that produced only skipped "+
				"rows is counted, not averaged in", score.HostsWithoutScore,
				exp.Int("hosts_without_score"))
		}
		if score.HostsTotal != exp.Int("hosts_total") {
			t.Errorf("HostsTotal = %d, want %d", score.HostsTotal, exp.Int("hosts_total"))
		}
		// The invariant. Host D has never been scanned and has no rule state, so
		// under the old query it fell out of the population entirely instead of
		// being counted as unscored.
		if score.HostsScored+score.HostsWithoutScore != score.HostsTotal {
			t.Errorf("%d scored + %d unscored != %d total; a host vanished from the population",
				score.HostsScored, score.HostsWithoutScore, score.HostsTotal)
		}
		got, ok := score.Score.Rounded()
		if !ok {
			t.Fatal("fleet score absent, but two hosts produced verdicts")
		}
		if want := exp.Num("score_pct"); got != want {
			t.Errorf("score = %v, want %v", got, want)
		}
		// Reading a forbidden value is not asserting it. Each is compared with
		// the actual result, so a regression to either aggregation is caught
		// here and not only in AC-01.
		if bad := exp.Num("forbidden_pooled_score_pct"); got == bad {
			t.Errorf("score = %v, the POOLED answer over every rule row", bad)
		}
		if bad := exp.Num("forbidden_zero_averaged_score_pct"); got == bad {
			t.Errorf("score = %v, the answer produced by averaging the unscored hosts in as zero", bad)
		}
		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-02
// AC-02: an empty fleet has NO score, and a fleet that failed everything has 0.
func TestFleetComplianceScore_EmptyFleetIsAbsentNotZero(t *testing.T) {
	t.Run("system-fleet-rollup/AC-02", func(t *testing.T) {
		pool := freshPool(t)
		svc := NewService(pool)

		score, err := svc.FleetComplianceScore(context.Background())
		if err != nil {
			t.Fatalf("FleetComplianceScore: %v", err)
		}
		if score.Score.Present() {
			pct, _ := score.Score.Value()
			t.Errorf("empty fleet scored %v; it must have no score at all", pct)
		}

		// The counterexample that makes the absence meaningful. A fleet whose
		// every evaluated rule failed scores 0, and under the old Score{0,0}
		// that was indistinguishable from the empty fleet above.
		user := seedUser(t, pool)
		h := seedHost(t, pool, user)
		seedRuleState(t, pool, h, "rule.a", "fail")
		seedRuleState(t, pool, h, "rule.b", "fail")

		failed, err := svc.FleetComplianceScore(context.Background())
		if err != nil {
			t.Fatalf("FleetComplianceScore: %v", err)
		}
		pct, ok := failed.Score.Rounded()
		if !ok {
			t.Fatal("a fleet that failed every rule has a real score of 0, not an absent one")
		}
		if pct != 0 {
			t.Errorf("all-failing fleet scored %v, want 0", pct)
		}
		if score.Score.Present() == failed.Score.Present() {
			t.Error("an empty fleet and an all-failing fleet are indistinguishable")
		}
	})
}

// @ac AC-03
// AC-03: skipped and error rows are excluded per host, and a host with only
// skipped rows has no score rather than a zero.
func TestFleetComplianceScore_SkipsAndErrorsExcluded(t *testing.T) {
	t.Run("system-fleet-rollup/AC-03", func(t *testing.T) {
		pool := freshPool(t)
		svc := NewService(pool)
		user := seedUser(t, pool)
		h := seedHost(t, pool, user)

		seedRuleState(t, pool, h, "rule.pass", "pass")
		seedRuleState(t, pool, h, "rule.fail", "fail")
		seedRuleState(t, pool, h, "rule.skipped", "skipped")
		seedRuleState(t, pool, h, "rule.error", "error")

		score, err := svc.FleetComplianceScore(context.Background())
		if err != nil {
			t.Fatalf("FleetComplianceScore: %v", err)
		}
		// The SCORE is what proves the exclusion. Two verdicts of four rows, one
		// passing, is 50; counting the skipped and errored rows would give 25.
		pct, ok := score.Score.Rounded()
		if !ok || pct != 50 {
			t.Errorf("score = %v present=%v, want 50", pct, ok)
		}

		// A host whose rows are ALL skipped produces no score, and is counted
		// rather than averaged in. Adding it must not move the mean.
		quiet := seedHost(t, pool, user)
		seedRuleState(t, pool, quiet, "rule.s1", "skipped")
		seedRuleState(t, pool, quiet, "rule.s2", "error")

		with, err := svc.FleetComplianceScore(context.Background())
		if err != nil {
			t.Fatalf("FleetComplianceScore: %v", err)
		}
		got, _ := with.Score.Rounded()
		if got != pct {
			t.Errorf("adding an unassessable host moved the mean from %v to %v", pct, got)
		}
		if with.HostsWithoutScore != 1 || with.HostsScored != 1 {
			t.Errorf("scored=%d unscored=%d, want 1 and 1",
				with.HostsScored, with.HostsWithoutScore)
		}
	})
}

// @ac AC-04
// AC-04: FleetLiveness returns four buckets summing to active hosts.
func TestFleetLiveness_FourBucketsSumToActiveHosts(t *testing.T) {
	t.Run("system-fleet-rollup/AC-04", func(t *testing.T) {
		pool := freshPool(t)
		svc := NewService(pool)
		user := seedUser(t, pool)

		hReach1 := seedHost(t, pool, user)
		hReach2 := seedHost(t, pool, user)
		hUnreach := seedHost(t, pool, user)
		hUnknown := seedHost(t, pool, user)
		// Three never-probed hosts (no host_liveness row).
		_ = seedHost(t, pool, user)
		_ = seedHost(t, pool, user)
		_ = seedHost(t, pool, user)

		seedLiveness(t, pool, hReach1, "reachable")
		seedLiveness(t, pool, hReach2, "reachable")
		seedLiveness(t, pool, hUnreach, "unreachable")
		seedLiveness(t, pool, hUnknown, "unknown")

		rollup, err := svc.FleetLiveness(context.Background())
		if err != nil {
			t.Fatalf("FleetLiveness: %v", err)
		}
		if rollup.Reachable != 2 {
			t.Errorf("Reachable = %d, want 2", rollup.Reachable)
		}
		if rollup.Unreachable != 1 {
			t.Errorf("Unreachable = %d, want 1", rollup.Unreachable)
		}
		if rollup.Unknown != 1 {
			t.Errorf("Unknown = %d, want 1", rollup.Unknown)
		}
		if rollup.NeverProbed != 3 {
			t.Errorf("NeverProbed = %d, want 3", rollup.NeverProbed)
		}
		if rollup.Total() != 7 {
			t.Errorf("Total = %d, want 7", rollup.Total())
		}
	})
}

// @ac AC-05
// AC-05: TopFailingRules ordered by FailingHostCount DESC.
func TestTopFailingRules_OrderedDescByCount(t *testing.T) {
	t.Run("system-fleet-rollup/AC-05", func(t *testing.T) {
		pool := freshPool(t)
		svc := NewService(pool)
		user := seedUser(t, pool)
		h1 := seedHost(t, pool, user)
		h2 := seedHost(t, pool, user)
		h3 := seedHost(t, pool, user)

		// rule.A fails on 3 hosts (top); rule.B fails on 2; rule.C fails on 1.
		seedRuleState(t, pool, h1, "rule.A", "fail")
		seedRuleState(t, pool, h2, "rule.A", "fail")
		seedRuleState(t, pool, h3, "rule.A", "fail")
		seedRuleState(t, pool, h1, "rule.B", "fail")
		seedRuleState(t, pool, h2, "rule.B", "fail")
		seedRuleState(t, pool, h1, "rule.C", "fail")
		// rule.D passes — must NOT appear.
		seedRuleState(t, pool, h1, "rule.D", "pass")

		out, err := svc.TopFailingRules(context.Background(), 10)
		if err != nil {
			t.Fatalf("TopFailingRules: %v", err)
		}
		if len(out) != 3 {
			t.Fatalf("len(out) = %d, want 3", len(out))
		}
		if out[0].RuleID != "rule.A" || out[0].FailingHostCount != 3 {
			t.Errorf("out[0] = %+v, want {rule.A,3}", out[0])
		}
		if out[1].RuleID != "rule.B" || out[1].FailingHostCount != 2 {
			t.Errorf("out[1] = %+v, want {rule.B,2}", out[1])
		}
		if out[2].RuleID != "rule.C" || out[2].FailingHostCount != 1 {
			t.Errorf("out[2] = %+v, want {rule.C,1}", out[2])
		}
		// Limit cap.
		limited, err := svc.TopFailingRules(context.Background(), 2)
		if err != nil {
			t.Fatalf("TopFailingRules limit=2: %v", err)
		}
		if len(limited) != 2 {
			t.Errorf("limit=2 returned %d rows", len(limited))
		}
	})
}

// @ac AC-06
// AC-06: limit=0 → empty slice, no error.
func TestTopFailingRules_ZeroLimit_EmptySlice(t *testing.T) {
	t.Run("system-fleet-rollup/AC-06", func(t *testing.T) {
		pool := freshPool(t)
		svc := NewService(pool)

		out, err := svc.TopFailingRules(context.Background(), 0)
		if err != nil {
			t.Fatalf("TopFailingRules(limit=0): %v", err)
		}
		if len(out) != 0 {
			t.Errorf("len(out) = %d, want 0", len(out))
		}
	})
}

// @ac AC-07
// AC-07: TopFailingHosts ordered by FailingRuleCount DESC.
func TestTopFailingHosts_OrderedDescByCount(t *testing.T) {
	t.Run("system-fleet-rollup/AC-07", func(t *testing.T) {
		pool := freshPool(t)
		svc := NewService(pool)
		user := seedUser(t, pool)
		hWorst := seedHost(t, pool, user)
		hMid := seedHost(t, pool, user)
		hBest := seedHost(t, pool, user)

		// hWorst fails 4 rules, hMid fails 2, hBest fails 1.
		seedRuleState(t, pool, hWorst, "rule.1", "fail")
		seedRuleState(t, pool, hWorst, "rule.2", "fail")
		seedRuleState(t, pool, hWorst, "rule.3", "fail")
		seedRuleState(t, pool, hWorst, "rule.4", "fail")
		seedRuleState(t, pool, hMid, "rule.1", "fail")
		seedRuleState(t, pool, hMid, "rule.2", "fail")
		seedRuleState(t, pool, hBest, "rule.1", "fail")
		// hBest passes rule.2 — does NOT count toward failing.
		seedRuleState(t, pool, hBest, "rule.2", "pass")

		out, err := svc.TopFailingHosts(context.Background(), 10)
		if err != nil {
			t.Fatalf("TopFailingHosts: %v", err)
		}
		if len(out) != 3 {
			t.Fatalf("len(out) = %d, want 3", len(out))
		}
		if out[0].HostID != hWorst || out[0].FailingRuleCount != 4 {
			t.Errorf("out[0] = %+v, want {%s,4}", out[0], hWorst)
		}
		if out[1].HostID != hMid || out[1].FailingRuleCount != 2 {
			t.Errorf("out[1] = %+v, want {%s,2}", out[1], hMid)
		}
		if out[2].HostID != hBest || out[2].FailingRuleCount != 1 {
			t.Errorf("out[2] = %+v, want {%s,1}", out[2], hBest)
		}
	})
}

// @ac AC-08
// AC-08: RecentChanges returns transactions DESC by occurred_at;
// since cursor filters strictly newer.
func TestRecentChanges_SinceCursorFilters_OrderDesc(t *testing.T) {
	t.Run("system-fleet-rollup/AC-08", func(t *testing.T) {
		pool := freshPool(t)
		svc := NewService(pool)
		user := seedUser(t, pool)
		h := seedHost(t, pool, user)

		t0 := time.Now().UTC().Truncate(time.Second)
		seedTransaction(t, pool, h, "rule.a", "fail", "state_changed", t0)
		seedTransaction(t, pool, h, "rule.b", "fail", "first_seen", t0.Add(1*time.Minute))
		seedTransaction(t, pool, h, "rule.c", "pass", "state_changed", t0.Add(2*time.Minute))

		// All three.
		all, err := svc.RecentChanges(context.Background(), time.Time{}, 10)
		if err != nil {
			t.Fatalf("RecentChanges all: %v", err)
		}
		if len(all) != 3 {
			t.Fatalf("len(all) = %d, want 3", len(all))
		}
		// Order: c (newest), b, a (oldest).
		if all[0].RuleID != "rule.c" {
			t.Errorf("all[0].RuleID = %q, want rule.c", all[0].RuleID)
		}
		if all[2].RuleID != "rule.a" {
			t.Errorf("all[2].RuleID = %q, want rule.a", all[2].RuleID)
		}

		// since cursor filtering — only strictly newer than t0.
		since, err := svc.RecentChanges(context.Background(), t0, 10)
		if err != nil {
			t.Fatalf("RecentChanges since=t0: %v", err)
		}
		if len(since) != 2 {
			t.Errorf("with since=t0, got %d rows, want 2 (b + c only)", len(since))
		}
	})
}

// @ac AC-09
// AC-09: every method respects context cancellation.
func TestEveryMethod_RespectsContextCancellation(t *testing.T) {
	t.Run("system-fleet-rollup/AC-09", func(t *testing.T) {
		pool := freshPool(t)
		svc := NewService(pool)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // cancel before calling

		if _, err := svc.FleetComplianceScore(ctx); err == nil {
			t.Error("FleetComplianceScore: expected error from canceled ctx, got nil")
		}
		if _, err := svc.FleetLiveness(ctx); err == nil {
			t.Error("FleetLiveness: expected error from canceled ctx, got nil")
		}
		if _, err := svc.TopFailingRules(ctx, 5); err == nil {
			t.Error("TopFailingRules: expected error from canceled ctx, got nil")
		}
		if _, err := svc.TopFailingHosts(ctx, 5); err == nil {
			t.Error("TopFailingHosts: expected error from canceled ctx, got nil")
		}
		if _, err := svc.RecentChanges(ctx, time.Time{}, 5); err == nil {
			t.Error("RecentChanges: expected error from canceled ctx, got nil")
		}
	})
}

// @ac AC-10
// AC-10: limit < 0 → 0; limit > MaxLimit → MaxLimit.
func TestLimitClamping_NegativeAndOverflow(t *testing.T) {
	t.Run("system-fleet-rollup/AC-10", func(t *testing.T) {
		// Pure-function check: clampLimit covers the AC.
		if got := clampLimit(-5); got != 0 {
			t.Errorf("clampLimit(-5) = %d, want 0", got)
		}
		if got := clampLimit(0); got != 0 {
			t.Errorf("clampLimit(0) = %d, want 0", got)
		}
		if got := clampLimit(500); got != 500 {
			t.Errorf("clampLimit(500) = %d, want 500", got)
		}
		if got := clampLimit(MaxLimit); got != MaxLimit {
			t.Errorf("clampLimit(MaxLimit) = %d, want MaxLimit", got)
		}
		if got := clampLimit(MaxLimit + 1); got != MaxLimit {
			t.Errorf("clampLimit(MaxLimit+1) = %d, want MaxLimit", got)
		}
		if got := clampLimit(1_000_000); got != MaxLimit {
			t.Errorf("clampLimit(1M) = %d, want MaxLimit", got)
		}

		// End-to-end on a populated fleet: ensure the LIMIT is respected.
		pool := freshPool(t)
		svc := NewService(pool)
		user := seedUser(t, pool)
		for i := 0; i < 5; i++ {
			h := seedHost(t, pool, user)
			seedRuleState(t, pool, h, "rule.shared", "fail")
		}
		// Negative limit on TopFailingRules → empty slice.
		out, err := svc.TopFailingRules(context.Background(), -1)
		if err != nil {
			t.Fatalf("TopFailingRules(-1): %v", err)
		}
		if len(out) != 0 {
			t.Errorf("TopFailingRules(-1) returned %d rows, want 0", len(out))
		}
	})
}
