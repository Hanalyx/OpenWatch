// @spec system-drift-detector
//
// AC traceability (this file):
//   AC-01  TestClassify_10ppDrop_IsMajor
//   AC-02  TestClassify_4ppDrop_IsStable
//   AC-03  TestClassify_5ppDrop_IsMinor
//   AC-04  TestClassify_8ppGain_IsImprovement
//   AC-05  TestClassify_2ppSwing_IsStable
//   AC-06  TestClassify_UsesPassedThresholds
//   AC-07  TestValidateThresholds_RejectsOutOfRange
//          TestValidateThresholds_RejectsMajorBelowMinor
//          TestValidateThresholds_AcceptsValid
//   AC-13  TestKindEnum_HasExactlyFourValues
//   AC-14  TestScore_CountsOnlyConfirmedVerdicts
//   AC-20  TestScore_CountsOnlyConfirmedVerdicts (counterexample subtest)

package drift

import (
	"errors"
	"github.com/Hanalyx/openwatch/internal/specfixture"
	"testing"
)

// @ac AC-01
// AC-01: a 10pp drop at the major threshold value returns DriftMajorWorsening.
func TestClassify_10ppDrop_IsMajor(t *testing.T) {
	t.Run("system-drift-detector/AC-01", func(t *testing.T) {
		got := Classify(80, 70, DefaultThresholds())
		if got != DriftMajorWorsening {
			t.Errorf("Classify(80, 70) = %q, want %q", got, DriftMajorWorsening)
		}
	})
}

// @ac AC-02
// AC-02: a 4pp drop is BELOW the minor threshold (5pp) → DriftStable.
// The spec phrasing was slightly off; the actual semantic is: 4pp is
// below minor.
func TestClassify_4ppDrop_IsStable(t *testing.T) {
	t.Run("system-drift-detector/AC-02", func(t *testing.T) {
		got := Classify(80, 76, DefaultThresholds())
		if got != DriftStable {
			t.Errorf("Classify(80, 76) = %q, want %q (4pp drop is below minor 5pp threshold)",
				got, DriftStable)
		}
	})
}

// @ac AC-03
// AC-03: a 5pp drop hits the minor threshold exactly → DriftMinorWorsening.
func TestClassify_5ppDrop_IsMinor(t *testing.T) {
	t.Run("system-drift-detector/AC-03", func(t *testing.T) {
		got := Classify(80, 75, DefaultThresholds())
		if got != DriftMinorWorsening {
			t.Errorf("Classify(80, 75) = %q, want %q", got, DriftMinorWorsening)
		}
	})
}

// @ac AC-04
// AC-04: an 8pp gain (≥ ImprovementPP 5) → DriftImprovement.
func TestClassify_8ppGain_IsImprovement(t *testing.T) {
	t.Run("system-drift-detector/AC-04", func(t *testing.T) {
		got := Classify(70, 78, DefaultThresholds())
		if got != DriftImprovement {
			t.Errorf("Classify(70, 78) = %q, want %q", got, DriftImprovement)
		}
	})
}

// @ac AC-05
// AC-05: a 2pp positive swing is below all thresholds → DriftStable.
func TestClassify_2ppSwing_IsStable(t *testing.T) {
	t.Run("system-drift-detector/AC-05", func(t *testing.T) {
		got := Classify(80, 82, DefaultThresholds())
		if got != DriftStable {
			t.Errorf("Classify(80, 82) = %q, want %q", got, DriftStable)
		}
	})
}

// @ac AC-06
// AC-06: the function uses the input thresholds. Same prior/current
// produces different kinds depending on threshold config.
func TestClassify_UsesPassedThresholds(t *testing.T) {
	t.Run("system-drift-detector/AC-06", func(t *testing.T) {
		// 80 → 70 is a 10pp drop.
		strict := Thresholds{MajorWorseningPP: 5, MinorWorseningPP: 3, ImprovementPP: 5}
		relaxed := Thresholds{MajorWorseningPP: 20, MinorWorseningPP: 10, ImprovementPP: 10}

		gotStrict := Classify(80, 70, strict)
		gotRelaxed := Classify(80, 70, relaxed)

		if gotStrict != DriftMajorWorsening {
			t.Errorf("strict: got %q, want %q (10pp drop >> 5pp major)", gotStrict, DriftMajorWorsening)
		}
		// With major=20, 10pp is exactly the minor threshold → minor.
		if gotRelaxed != DriftMinorWorsening {
			t.Errorf("relaxed: got %q, want %q (10pp drop matches minor 10pp)", gotRelaxed, DriftMinorWorsening)
		}
	})
}

// @ac AC-07
// AC-07: ValidateThresholds rejects any value ≤ 0 or > 100.
func TestValidateThresholds_RejectsOutOfRange(t *testing.T) {
	t.Run("system-drift-detector/AC-07", func(t *testing.T) {
		cases := []Thresholds{
			{MajorWorseningPP: 0, MinorWorseningPP: 5, ImprovementPP: 5},
			{MajorWorseningPP: -1, MinorWorseningPP: 5, ImprovementPP: 5},
			{MajorWorseningPP: 101, MinorWorseningPP: 5, ImprovementPP: 5},
			{MajorWorseningPP: 10, MinorWorseningPP: 0, ImprovementPP: 5},
			{MajorWorseningPP: 10, MinorWorseningPP: 5, ImprovementPP: -2},
			{MajorWorseningPP: 10, MinorWorseningPP: 5, ImprovementPP: 200},
		}
		for i, t1 := range cases {
			err := ValidateThresholds(t1)
			if err == nil {
				t.Errorf("case %d: ValidateThresholds(%+v) = nil, want ErrInvalidThresholds", i, t1)
			} else if !errors.Is(err, ErrInvalidThresholds) {
				t.Errorf("case %d: err = %v, want errors.Is ErrInvalidThresholds", i, err)
			}
		}
	})
}

// @ac AC-07
// AC-07: ValidateThresholds rejects configs where major < minor.
func TestValidateThresholds_RejectsMajorBelowMinor(t *testing.T) {
	t.Run("system-drift-detector/AC-07", func(t *testing.T) {
		t1 := Thresholds{MajorWorseningPP: 3, MinorWorseningPP: 5, ImprovementPP: 5}
		if err := ValidateThresholds(t1); err == nil {
			t.Error("ValidateThresholds with major < minor: nil error")
		}
	})
}

// @ac AC-07
// AC-07: ValidateThresholds accepts valid configs (including the default).
func TestValidateThresholds_AcceptsValid(t *testing.T) {
	t.Run("system-drift-detector/AC-07", func(t *testing.T) {
		if err := ValidateThresholds(DefaultThresholds()); err != nil {
			t.Errorf("DefaultThresholds rejected: %v", err)
		}
		alt := Thresholds{MajorWorseningPP: 20, MinorWorseningPP: 10, ImprovementPP: 8}
		if err := ValidateThresholds(alt); err != nil {
			t.Errorf("alt rejected: %v", err)
		}
	})
}

// @ac AC-13
// AC-13: the Kind enum has exactly 4 values and AllKinds lists them.
func TestKindEnum_HasExactlyFourValues(t *testing.T) {
	t.Run("system-drift-detector/AC-13", func(t *testing.T) {
		if len(AllKinds) != 4 {
			t.Errorf("AllKinds = %d, want 4", len(AllKinds))
		}
		// Set-membership check: every expected value is in the slice.
		expected := map[Kind]bool{
			DriftStable: false, DriftMinorWorsening: false,
			DriftMajorWorsening: false, DriftImprovement: false,
		}
		for _, k := range AllKinds {
			expected[k] = true
		}
		for k, seen := range expected {
			if !seen {
				t.Errorf("AllKinds missing %q", k)
			}
		}
	})
}

// @ac AC-14
// @ac AC-20
// AC-14 is the formula. AC-20 is the counterexample: a host that failed every
// evaluated rule has a real zero and must stay distinguishable from a host that
// produced no verdict. AC-19, the no-emission half, is covered end to end in
// ow023_test.go, because asserting it here would report coverage for behavior
// this file cannot reach.
//
// Both fixtures come from the spec; nothing below restates a number.
func TestScore_CountsOnlyConfirmedVerdicts(t *testing.T) {
	all := driftCriteria(t)

	t.Run("system-drift-detector/AC-14", func(t *testing.T) {
		ac := specfixture.Get(t, all, "AC-14")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)
		counts := in.Map("counts")

		got, ok := Score(counts.Int("passed"), counts.Int("failed")).Value()
		if want := exp.Bool("score_present"); ok != want {
			t.Errorf("score present = %v, want %v", ok, want)
		}
		if want := exp.Num("score_pct"); ok && got != want {
			t.Errorf("score_pct = %v, want %v", got, want)
		}
		counts.AllConsumed()
		in.AllConsumed()
		exp.AllConsumed()
	})

	t.Run("unit-partial/absent-score", func(t *testing.T) {
		// Not annotated: the absence half belongs to AC-19, whose no-emission
		// requirement only DetectForScan can satisfy.
		if _, ok := Score(0, 0).Value(); ok {
			t.Error("Score(0, 0) reports a value; an empty denominator has no score")
		}
	})

	t.Run("system-drift-detector/AC-20", func(t *testing.T) {
		ac := specfixture.Get(t, all, "AC-20")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)
		counts := in.Map("counts")

		zero, ok := Score(counts.Int("passed"), counts.Int("failed")).Value()
		if want := exp.Bool("score_present"); ok != want {
			t.Errorf("score present = %v, want %v", ok, want)
		}
		if want := exp.Num("score_pct"); zero != want {
			t.Errorf("score_pct = %v, want %v", zero, want)
		}
		// The discriminating assertion: collapsing these two is what let an
		// unassessable host alert as a compliance collapse.
		if Score(0, 0).Present() == ok {
			t.Error("absent and genuine-zero are indistinguishable")
		}
		counts.AllConsumed()
		in.AllConsumed()
		exp.AllConsumed()
	})
}

// driftCriteria loads this spec's criteria.
func driftCriteria(t *testing.T) map[string]specfixture.Criterion {
	t.Helper()
	return specfixture.Load(t, "../../specs/system/drift-detector.spec.yaml", "system-drift-detector")
}
