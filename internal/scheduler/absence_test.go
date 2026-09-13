// @spec system-scheduler
//
// bugs/OW-024: an unassessable host must not be stored or reported as the worst
// compliance band. These cover the pure-logic half; the persisted-row repair is
// in the migration test.
package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/compliance"
	"github.com/Hanalyx/openwatch/internal/specfixture"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
)

// @ac AC-17
// AC-17: the unknown interval is never slower than the critical interval.
func TestLoadFromConfig_UnknownIsNeverSlowerThanCritical(t *testing.T) {
	t.Run("system-scheduler/AC-17", func(t *testing.T) {
		ac := specfixture.Get(t, schedulerCriteria(t), "AC-17")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		clamped := in.Map("clamped")
		cfg := systemconfig.DefaultScan()
		cfg.UnknownMins = clamped.Int("unknown_mins")
		cfg.CriticalMins = clamped.Int("critical_mins")
		load := LoadFromConfig(cfg)
		if got, want := load.Ladder[StateUnknown], time.Duration(exp.Int("clamped_ladder_unknown_mins"))*time.Minute; got != want {
			t.Errorf("ladder[unknown] = %v, want %v (clamped to critical)", got, want)
		}
		if got, want := load.Ladder[StateCritical], time.Duration(exp.Int("clamped_ladder_critical_mins"))*time.Minute; got != want {
			t.Errorf("ladder[critical] = %v, want %v", got, want)
		}

		// A faster operator setting is respected: the clamp is a ceiling, not a
		// fixed value.
		below := in.Map("below_clamp")
		cfg2 := systemconfig.DefaultScan()
		cfg2.UnknownMins = below.Int("unknown_mins")
		cfg2.CriticalMins = below.Int("critical_mins")
		if got, want := LoadFromConfig(cfg2).Ladder[StateUnknown], time.Duration(exp.Int("below_clamp_ladder_unknown_mins"))*time.Minute; got != want {
			t.Errorf("ladder[unknown] = %v, want %v (a value below the clamp is kept)", got, want)
		}
		clamped.AllConsumed()
		below.AllConsumed()
		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-18
// AC-18: an absent score selects unknown, not critical.
func TestStateFromScore_AbsentSelectsUnknown(t *testing.T) {
	t.Run("system-scheduler/AC-18", func(t *testing.T) {
		ac := specfixture.Get(t, schedulerCriteria(t), "AC-18")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)
		if in.Bool("score_present") {
			t.Fatal("AC-18 fixture must describe an absent score")
		}
		got := StateFromScore(compliance.AbsentScore(), in.Bool("has_critical_findings"))
		if string(got) == exp.Str("forbidden_state") {
			t.Fatal("absent score classified as critical; that is the bugs/OW-024 defect")
		}
		if want := exp.Str("state"); string(got) != want {
			t.Errorf("state = %q, want %q", got, want)
		}
		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-19
// AC-19: counterexample. A genuine zero percent is a verdict and stays critical,
// so absence and zero cannot be collapsed.
func TestStateFromScore_GenuineZeroStaysCritical(t *testing.T) {
	t.Run("system-scheduler/AC-19", func(t *testing.T) {
		ac := specfixture.Get(t, schedulerCriteria(t), "AC-19")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)
		zero := StateFromScore(mustScore(t, in.Num("score_pct")), in.Bool("has_critical_findings"))
		absent := StateFromScore(compliance.AbsentScore(), false)
		if want := exp.Str("state"); string(zero) != want {
			t.Errorf("genuine zero = %q, want %q; every evaluated rule failed", zero, want)
		}
		if exp.Bool("forbidden_same_as_absent") && zero == absent {
			t.Errorf("zero and absent both map to %q; they must stay distinguishable", zero)
		}
		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-20
// AC-20: an absent score is stored as NULL, never as 0. compliance_score is
// already a nullable REAL, so this needs no schema change; before bugs/OW-024
// the caller had no way to express absence and a fabricated 0 was written.
func TestPersistAfterScan_AbsentScoreStoresNull(t *testing.T) {
	t.Run("system-scheduler/AC-20", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		h := seedHost(t, pool, user)

		var calls []emitCall
		svc := NewService(pool, LoadFromConfig(systemconfig.DefaultScan()), testKey(), fakeEmitter(&calls))
		svc.Reload(LoadFromConfig(systemconfig.DefaultScan()), 25, false)

		ctx := withCorrelation(context.Background(), "ow024-null")
		completed := time.Now().UTC().Truncate(time.Second)
		ac := specfixture.Get(t, schedulerCriteria(t), "AC-20")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)
		if in.Bool("score_present") {
			t.Fatal("AC-20 fixture must describe an absent score")
		}
		res, err := svc.PersistAfterScan(ctx, h, compliance.AbsentScore(), false, completed)
		if err != nil {
			t.Fatalf("persist: %v", err)
		}
		if want := exp.Str("returned_state"); string(res.State) != want {
			t.Errorf("state = %q, want %q", res.State, want)
		}

		var state string
		var score *float64
		if err := pool.QueryRow(ctx, `
			SELECT compliance_state, compliance_score
			  FROM host_compliance_schedule WHERE host_id = $1`, h).Scan(&state, &score); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if want := exp.Str("stored_compliance_state"); state != want {
			t.Errorf("stored state = %q, want %q", state, want)
		}
		exp.IsNull("stored_compliance_score")
		if score != nil {
			t.Errorf("stored score = %v, want NULL; a fabricated 0 is what OW-024 wrote", *score)
		}
		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-22
// AC-22: the policy version is derived from the effective ladder.
func TestPolicyVersion_DerivedFromEffectiveLadder(t *testing.T) {
	t.Run("system-scheduler/AC-22", func(t *testing.T) {
		ac := specfixture.Get(t, schedulerCriteria(t), "AC-22")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		apply := func(base systemconfig.ScanConfig, over map[string]any) systemconfig.ScanConfig {
			for k, v := range over {
				n := v.(int)
				switch k {
				case "unknown_mins":
					base.UnknownMins = n
				case "critical_mins":
					base.CriticalMins = n
				case "partial_mins":
					base.PartialMins = n
				default:
					t.Fatalf("AC-22: unknown config key %q in fixture", k)
				}
			}
			return base
		}

		wantSame := exp.Bool("same_ladder_same_version")
		for _, raw := range in.List("same_ladder_pairs") {
			pair := raw.(map[string]any)
			a := LoadFromConfig(apply(systemconfig.DefaultScan(), pair["a"].(map[string]any)))
			b := LoadFromConfig(apply(systemconfig.DefaultScan(), pair["b"].(map[string]any)))
			same := a.PolicyVersion == b.PolicyVersion
			if same != wantSame {
				t.Errorf("%v: same version = %v, want %v (%q vs %q)",
					pair["why"], same, wantSame, a.PolicyVersion, b.PolicyVersion)
			}
		}

		diff := in.Map("different_ladder_pair")
		a := LoadFromConfig(apply(systemconfig.DefaultScan(), diff.Map("a").Raw()))
		b := LoadFromConfig(apply(systemconfig.DefaultScan(), diff.Map("b").Raw()))
		if wantDiff := exp.Bool("different_ladder_different_version"); (a.PolicyVersion != b.PolicyVersion) != wantDiff {
			t.Errorf("different ladder produced same version %q", a.PolicyVersion)
		}
		diff.AllConsumed()
		in.AllConsumed()
		exp.AllConsumed()
	})
}

// schedulerCriteria loads this spec's criteria once per test.
func schedulerCriteria(t *testing.T) map[string]specfixture.Criterion {
	t.Helper()
	return specfixture.Load(t, "../../specs/system/scheduler.spec.yaml", "system-scheduler")
}
