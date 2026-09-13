// Unit tests for the score constructors. No @ac annotations: these are the
// foundations the annotated criteria rest on, not criteria themselves.
package compliance

import (
	"math"
	"testing"
)

// ScoreFromPercent validates rather than trusting. An unvalidated constructor
// taking a float64 is a second way to fabricate a score, which would undo what
// the Score type is for.
func TestScoreFromPercent(t *testing.T) {
	valid := []float64{0, 0.1, 50, 99.9, 100}
	for _, pct := range valid {
		s, err := ScoreFromPercent(pct)
		if err != nil {
			t.Errorf("ScoreFromPercent(%v): %v", pct, err)
			continue
		}
		got, ok := s.Value()
		if !ok || got != pct {
			t.Errorf("ScoreFromPercent(%v) = %v present=%v", pct, got, ok)
		}
	}

	invalid := []struct {
		name string
		pct  float64
	}{
		{"NaN", math.NaN()},
		{"positive infinity", math.Inf(1)},
		{"negative infinity", math.Inf(-1)},
		{"below zero", -0.0001},
		{"well below zero", -10},
		{"above one hundred", 100.0001},
		{"well above one hundred", 1000},
	}
	for _, c := range invalid {
		t.Run(c.name, func(t *testing.T) {
			s, err := ScoreFromPercent(c.pct)
			if err == nil {
				t.Fatalf("ScoreFromPercent(%v) succeeded; none of these can be a percentage of rules that passed", c.pct)
			}
			// A rejected value must not leak a usable score either.
			if s.Present() {
				t.Error("rejected value returned a present score")
			}
		})
	}
}

// ScoreFromNullable is the bridge from a nullable column. NULL is absence, and a
// non-NULL value is validated the same way as any other.
func TestScoreFromNullable(t *testing.T) {
	t.Run("null becomes absent", func(t *testing.T) {
		s, err := ScoreFromNullable(nil)
		if err != nil {
			t.Fatalf("nil: %v", err)
		}
		if s.Present() {
			t.Error("NULL produced a present score")
		}
	})

	t.Run("valid value becomes present", func(t *testing.T) {
		v := 80.0
		s, err := ScoreFromNullable(&v)
		if err != nil {
			t.Fatalf("80: %v", err)
		}
		got, ok := s.Value()
		if !ok || got != 80 {
			t.Errorf("got %v present=%v, want 80 present", got, ok)
		}
	})

	t.Run("invalid stored value errors rather than loading", func(t *testing.T) {
		// A column holding something impossible is corruption, not absence.
		// Silently treating it as absent would hide the corruption; treating it
		// as a score would propagate it into an aggregate.
		for _, bad := range []float64{-1, 101, math.NaN()} {
			v := bad
			if _, err := ScoreFromNullable(&v); err == nil {
				t.Errorf("stored %v loaded without error", bad)
			}
		}
	})
}
