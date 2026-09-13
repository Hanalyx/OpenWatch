// @spec system-drift-detector
//
// bugs/OW-023, end to end. The unit test in classify_test.go proves drift.Score
// reports absence; this proves DetectForScan acts on it: a real prior baseline
// plus an all-skipped current scan must classify stable, emit no audit event and
// publish nothing on the bus.
//
// Before the fix the Evaluate guard tested totalRows, which counts skipped rows,
// while the score's denominator counts only pass and fail. This scenario
// therefore passed the guard, scored a fabricated 0 against a real prior of 100,
// and emitted a major-worsening alert to Slack, webhook or email for a host
// nothing could assess.
package drift

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/eventbus"
	"github.com/Hanalyx/openwatch/internal/specfixture"
)

// @ac AC-19
// AC-19: an empty verdict denominator produces an absent score, and drift emits
// nothing for one.
func TestDetectForScan_AllSkippedCurrentScan_EmitsNothing(t *testing.T) {
	t.Run("system-drift-detector/AC-19", func(t *testing.T) {
		all := specfixture.Load(t, "../../specs/system/drift-detector.spec.yaml", "system-drift-detector")
		ac := specfixture.Get(t, all, "AC-19")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		counts := in.Map("counts")
		wantPassed, wantFailed, wantSkipped := counts.Int("passed"), counts.Int("failed"), counts.Int("skipped")
		wantPrior := in.Bool("has_prior_baseline")

		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)
		scanID, _ := uuid.NewV7()

		// Every rule the host already carried flips to skipped in this scan,
		// each with a state_changed transaction, so a prior baseline exists.
		// That is the condition the old guard let through.
		if wantPassed != 0 || wantFailed != 0 || wantSkipped <= 0 {
			t.Fatalf("AC-19 fixture is not an all-skipped scan: %d/%d/%d", wantPassed, wantFailed, wantSkipped)
		}
		for i := 0; i < wantSkipped; i++ {
			rule := "rule-" + string(rune('a'+i))
			seedRuleState(t, pool, hostID, scanID, rule, "skipped", "high")
			seedTransaction(t, pool, hostID, scanID, rule, "skipped", "high", "state_changed")
		}

		var mu sync.Mutex
		var calls []emitCall
		bus := eventbus.NewBus()
		defer bus.Shutdown()
		sub := bus.Subscribe(eventbus.SubscribeOptions{
			Kinds: []eventbus.EventKind{eventbus.EventKindDriftDetected},
		})
		defer sub.Unsubscribe()
		svc := NewService(pool, fakeEmitter(&mu, &calls), DefaultThresholds(), bus)

		report, err := svc.DetectForScan(context.Background(), hostID, scanID)
		if err != nil {
			t.Fatalf("DetectForScan: %v", err)
		}

		if got := exp.Bool("current_score_present"); report.CurrentScorePresent != got {
			t.Errorf("CurrentScorePresent = %v, want %v", report.CurrentScorePresent, got)
		}
		if got, want := string(report.Kind), exp.Str("drift_kind"); got != want {
			t.Errorf("Kind = %q, want %q; a host nothing could assess did not degrade", got, want)
		}
		wantEvents := exp.Int("audit_events_emitted")
		if got := len(calls); got != wantEvents {
			t.Errorf("audit emissions = %d, want %d", got, wantEvents)
		}
		wantBus := exp.Int("bus_events_published")
		gotBus := 0
		select {
		case e := <-sub.Events():
			gotBus++
			t.Errorf("event bus published %T, want nothing", e)
		default:
		}
		if gotBus != wantBus {
			t.Errorf("bus publications = %d, want %d", gotBus, wantBus)
		}
		if !report.HasPriorBaseline && wantPrior {
			t.Error("fixture expects a prior baseline but none was reconstructed; the guard would pass for the wrong reason")
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-21
// AC-21: absence is symmetric. A present current score with no reconstructible
// prior must not expose a plausible PriorScore of 0 or a ScoreDelta that no
// comparison produced.
func TestDetectForScan_PresentCurrentAbsentPrior_NoComparison(t *testing.T) {
	t.Run("system-drift-detector/AC-21", func(t *testing.T) {
		ac := specfixture.Get(t, driftCriteria(t), "AC-21")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		cur := in.Map("current")
		passed, failed := cur.Int("passed"), cur.Int("failed")
		newRules := in.Int("new_rules_first_seen")
		retained := in.Int("retained_skipped_rules")
		wantBaseline := in.Bool("has_prior_baseline")
		if newRules != passed+failed {
			t.Fatalf("AC-21 fixture: %d first_seen rules but %d scored, so the prior would not reduce to zero", newRules, passed+failed)
		}
		if retained < 1 {
			t.Fatal("AC-21 fixture needs a retained rule or no baseline exists")
		}

		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)
		scanID, _ := uuid.NewV7()

		// Every SCORED rule is new, so reconstructPriorCounts subtracts each
		// one and the prior reduces to 0 pass / 0 fail: absent. A retained
		// skipped rule keeps firstSeenCount below the rule total, so a baseline
		// still exists. That is the combination the presence flags exist for.
		n := 0
		for i := 0; i < passed; i++ {
			r := "p" + string(rune('a'+i))
			seedRuleState(t, pool, hostID, scanID, r, "pass", "high")
			seedTransaction(t, pool, hostID, scanID, r, "pass", "high", "first_seen")
			n++
		}
		for i := 0; i < failed; i++ {
			r := "f" + string(rune('a'+i))
			seedRuleState(t, pool, hostID, scanID, r, "fail", "high")
			seedTransaction(t, pool, hostID, scanID, r, "fail", "high", "first_seen")
			n++
		}
		for i := 0; i < retained; i++ {
			seedRuleState(t, pool, hostID, scanID, "s"+string(rune('a'+i)), "skipped", "high")
		}

		var mu sync.Mutex
		var calls []emitCall
		svc := NewService(pool, fakeEmitter(&mu, &calls), DefaultThresholds(), nil)
		report, err := svc.DetectForScan(context.Background(), hostID, scanID)
		if err != nil {
			t.Fatalf("DetectForScan: %v", err)
		}

		if wantBaseline && !report.HasPriorBaseline {
			t.Error("fixture expects a baseline; none was reconstructed")
		}
		if got, want := report.CurrentScorePresent, exp.Bool("current_score_present"); got != want {
			t.Errorf("CurrentScorePresent = %v, want %v", got, want)
		}
		if got, want := report.PriorScorePresent, exp.Bool("prior_score_present"); got != want {
			t.Errorf("PriorScorePresent = %v, want %v; HasPriorBaseline is a different fact", got, want)
		}
		if got, want := report.ComparisonPresent, exp.Bool("comparison_present"); got != want {
			t.Errorf("ComparisonPresent = %v, want %v", got, want)
		}
		if !report.ComparisonPresent && report.ScoreDelta != 0 {
			t.Errorf("ScoreDelta = %v with no comparison; it must stay the zero value", report.ScoreDelta)
		}
		if got, want := string(report.Kind), exp.Str("drift_kind"); got != want {
			t.Errorf("Kind = %q, want %q", got, want)
		}
		if got, want := len(calls), exp.Int("audit_events_emitted"); got != want {
			t.Errorf("audit emissions = %d, want %d", got, want)
		}

		cur.AllConsumed()
		in.AllConsumed()
		exp.AllConsumed()
	})
}
