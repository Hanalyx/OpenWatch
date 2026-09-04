// @spec system-compliance-scoring
//
// Assessment coverage: when a percentage exists, when it is withheld, and
// what stays visible while it is withheld.
//
// Coverage and score answer different questions. The score says how the
// rules that ran came out; coverage says how much of the intended rule set
// ran at all. A host can score 100 on the eight rules it evaluated while
// five more were never assessed, which is why withholding one must not
// withhold the other.
package compliance

import (
	"testing"

	"github.com/Hanalyx/openwatch/internal/specfixture"
)

// readCounts reads a fixture's counts block, consuming every key.
func readCounts(t *testing.T, in *specfixture.Fields) Counts {
	t.Helper()
	c := in.Map("counts")
	out := Counts{Pass: c.Int("pass"), Fail: c.Int("fail"), Skipped: c.Int("skipped")}
	if c.Has("error") {
		out.Error = c.Int("error")
	}
	c.AllConsumed()
	return out
}

// readSkipsTyped reads the flag that says which world the fixture is in.
//
// It defaults to false rather than being assumed, because false is the only
// value any deployment has until KN-OW-021 ships and a test that silently
// assumed it would stop meaning anything the day that changes.
func readSkipsTyped(in *specfixture.Fields) bool {
	if in.Has("skip_reasons_typed") {
		return in.Bool("skip_reasons_typed")
	}
	return false
}

// @ac AC-12
// AC-12: coverage is computable when nothing was skipped. With no skipped
// outcomes there is no unclassified reason to block on.
func TestCoverage_ComputableWhenNothingSkipped(t *testing.T) {
	t.Run("system-compliance-scoring/AC-12", func(t *testing.T) {
		ac := loadScoringAC(t, "AC-12")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		if lens := in.Str("lens"); lens == "" {
			t.Fatal("fixture states no lens; a percentage that names no lens cannot be reconciled")
		}
		counts := readCounts(t, in)
		cov := AssessmentCoverage(counts, readSkipsTyped(in))

		if string(cov.Status) != exp.Str("coverage_status") {
			t.Errorf("coverage_status = %q, want %q", cov.Status, exp.Str("coverage_status"))
		}
		got, ok := cov.Pct.Rounded()
		if !ok {
			t.Fatalf("coverage is absent with %d skipped outcomes; there is no unclassified "+
				"reason to withhold it for", counts.Skipped)
		}
		if got != exp.Num("assessment_coverage_pct") {
			t.Errorf("assessment_coverage_pct = %v, want %v; the denominator is pass plus fail "+
				"plus error, so the two error outcomes are in scope and unmet",
				got, exp.Num("assessment_coverage_pct"))
		}
		// The score alongside it. Coverage below 100 must not drag the score
		// down: the errored rules are missing from the numerator of coverage
		// and from both sides of the score.
		score := HostScore(counts)
		gotScore, present := score.Rounded()
		if !present {
			t.Fatal("score is absent although ten rules produced a verdict")
		}
		if gotScore != exp.Num("score_pct") {
			t.Errorf("score_pct = %v, want %v", gotScore, exp.Num("score_pct"))
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-14
// AC-14: coverage is withheld rather than guessed while any skip is untyped.
// OpenWatch cannot tell an inapplicable rule from an unevaluated one, so it
// publishes no number instead of a wrong one.
func TestCoverage_WithheldWhileSkipsAreUntyped(t *testing.T) {
	t.Run("system-compliance-scoring/AC-14", func(t *testing.T) {
		ac := loadScoringAC(t, "AC-14")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		if lens := in.Str("lens"); lens == "" {
			t.Fatal("fixture states no lens")
		}
		counts := readCounts(t, in)
		typed := readSkipsTyped(in)
		if typed {
			t.Fatal("fixture must describe the untyped world; that is the whole subject")
		}
		cov := AssessmentCoverage(counts, typed)

		if string(cov.Status) != exp.Str("coverage_status") {
			t.Errorf("coverage_status = %q, want %q", cov.Status, exp.Str("coverage_status"))
		}
		exp.IsNull("assessment_coverage_pct")
		if pct, ok := cov.Pct.Rounded(); ok {
			t.Errorf("assessment_coverage_pct = %v; with %d untyped skips both answers are "+
				"wrong, so neither may be published", pct, counts.Skipped)
		}
		// Withholding coverage must not withhold the score. They are separate
		// questions and the score's inputs are complete.
		gotScore, present := HostScore(counts).Rounded()
		if !present {
			t.Fatal("the score was withheld along with coverage; ten rules produced a verdict " +
				"and that number is knowable")
		}
		if gotScore != exp.Num("score_pct") {
			t.Errorf("score_pct = %v, want %v", gotScore, exp.Num("score_pct"))
		}

		// The counterexample that makes the flag load-bearing. Typed skips over
		// the SAME counts must produce a number: without this the assertion
		// above would also pass on a coverage function that never published
		// anything at all.
		if typedCov := AssessmentCoverage(counts, true); typedCov.Status != CoverageAvailable {
			t.Errorf("with typed skips the same counts still yield %q; the withholding is "+
				"unconditional rather than a consequence of untyped reasons", typedCov.Status)
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-15
// AC-15: withholding coverage does not withhold the counts. A reader must
// still see that five rules produced no verdict, even when the product
// cannot say why.
func TestCoverage_CountsSurviveWithheldCoverage(t *testing.T) {
	t.Run("system-compliance-scoring/AC-15", func(t *testing.T) {
		ac := loadScoringAC(t, "AC-15")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		if lens := in.Str("lens"); lens == "" {
			t.Fatal("fixture states no lens")
		}
		counts := readCounts(t, in)
		cov := AssessmentCoverage(counts, readSkipsTyped(in))

		// The precondition. If coverage were published these assertions would
		// still pass while proving nothing about the case the criterion names.
		if cov.Pct.Present() {
			t.Fatal("coverage was published; this criterion is about what survives when it is not")
		}
		if counts.Skipped != exp.Int("skipped") {
			t.Errorf("skipped = %d, want %d; the raw count is knowable even when its meaning "+
				"is not, and hiding it leaves the operator with no signal at all",
				counts.Skipped, exp.Int("skipped"))
		}
		if counts.Error != exp.Int("error") {
			t.Errorf("error = %d, want %d", counts.Error, exp.Int("error"))
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}
