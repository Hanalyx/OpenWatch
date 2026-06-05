// @spec system-scheduler
//
// AC traceability (this file):
//   AC-08  TestStateFromScore_HasCriticalAlwaysCritical
//          TestStateFromScore_ScoreBuckets
//          TestUpdateAfterScan_CompliantScore_Schedules24h
//          TestUpdateAfterScan_HasCritical_Schedules1h
//          TestUpdateAfterScan_ZeroScore_TreatsAsCritical

package scheduler

import (
	"testing"
	"time"
)

// @ac AC-08
// AC-08 (override): hasCritical = true ALWAYS classifies as Critical,
// regardless of compliance_score. A single critical finding warrants
// the fastest re-check tier; the score-based bucketing is for cases
// where no critical finding triggered the override.
func TestStateFromScore_HasCriticalAlwaysCritical(t *testing.T) {
	t.Run("system-scheduler/AC-08", func(t *testing.T) {
		// 100% score + critical finding still means critical.
		if got := StateFromScore(100, true); got != StateCritical {
			t.Errorf("score=100, hasCritical=true: got %q, want %q", got, StateCritical)
		}
		// 0% score + critical finding obviously critical.
		if got := StateFromScore(0, true); got != StateCritical {
			t.Errorf("score=0, hasCritical=true: got %q, want %q", got, StateCritical)
		}
		// Mid-range score + critical: still critical.
		if got := StateFromScore(75.5, true); got != StateCritical {
			t.Errorf("score=75.5, hasCritical=true: got %q, want %q", got, StateCritical)
		}
	})
}

// @ac AC-08
// AC-08 (score bucketing): the threshold boundaries are tested at and
// just-below each cut-point. Half-open intervals are: [100, ∞)=Compliant,
// [80, 100)=Partial, [50, 80)=NonCompliant, (-∞, 50)=Critical.
func TestStateFromScore_ScoreBuckets(t *testing.T) {
	t.Run("system-scheduler/AC-08", func(t *testing.T) {
		cases := []struct {
			name  string
			score float64
			want  ComplianceState
		}{
			{"exactly 100 → Compliant", 100, StateCompliant},
			{"just below 100 → Partial", 99.999, StatePartial},
			{"exactly 80 → Partial", 80, StatePartial},
			{"just below 80 → NonCompliant", 79.999, StateNonCompliant},
			{"exactly 50 → NonCompliant", 50, StateNonCompliant},
			{"just below 50 → Critical", 49.999, StateCritical},
			{"0 → Critical", 0, StateCritical},
			{"negative (sanity) → Critical", -10, StateCritical},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				if got := StateFromScore(c.score, false); got != c.want {
					t.Errorf("score=%v: got %q, want %q", c.score, got, c.want)
				}
			})
		}
	})
}

// @ac AC-08
// AC-08 (end-to-end): a compliant scan produces State=Compliant and
// schedules the next scan at lastFinishedAt + ladder[Compliant].
func TestUpdateAfterScan_CompliantScore_Schedules24h(t *testing.T) {
	t.Run("system-scheduler/AC-08", func(t *testing.T) {
		ladder := LoadIntervals(validTiers()).Ladder
		completed := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)

		got := UpdateAfterScan(100, false, completed, ladder)

		if got.State != StateCompliant {
			t.Errorf("State = %q, want %q", got.State, StateCompliant)
		}
		want := completed.Add(24 * time.Hour)
		if !got.NextScheduled.Equal(want) {
			t.Errorf("NextScheduled = %v, want %v", got.NextScheduled, want)
		}
	})
}

// @ac AC-08
// AC-08 (critical override): hasCritical wins; mid-range score becomes
// Critical and schedules at the Critical tier (1h in validTiers()).
func TestUpdateAfterScan_HasCritical_Schedules1h(t *testing.T) {
	t.Run("system-scheduler/AC-08", func(t *testing.T) {
		ladder := LoadIntervals(validTiers()).Ladder
		completed := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)

		got := UpdateAfterScan(85, true, completed, ladder)

		if got.State != StateCritical {
			t.Errorf("State = %q, want %q (hasCritical overrides score)", got.State, StateCritical)
		}
		want := completed.Add(60 * time.Minute)
		if !got.NextScheduled.Equal(want) {
			t.Errorf("NextScheduled = %v, want %v", got.NextScheduled, want)
		}
	})
}

// @ac AC-08
// AC-08 (zero score): score = 0 without hasCritical still maps to
// Critical because the score itself is below the 50 threshold.
func TestUpdateAfterScan_ZeroScore_TreatsAsCritical(t *testing.T) {
	t.Run("system-scheduler/AC-08", func(t *testing.T) {
		ladder := LoadIntervals(validTiers()).Ladder
		completed := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)

		got := UpdateAfterScan(0, false, completed, ladder)

		if got.State != StateCritical {
			t.Errorf("State = %q, want %q (score < 50 with no override)", got.State, StateCritical)
		}
		want := completed.Add(60 * time.Minute)
		if !got.NextScheduled.Equal(want) {
			t.Errorf("NextScheduled = %v, want %v", got.NextScheduled, want)
		}
	})
}
