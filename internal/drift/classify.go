package drift

import "github.com/Hanalyx/openwatch/internal/compliance"

// Classify maps a score delta to a Kind given the active
// thresholds. Pure function — no I/O, no side effects, deterministic.
//
// Spec ACs satisfied here:
//
//   - AC-01 (C-01, C-02, C-03): pure-function classifier returning a
//     closed-enum Kind from percentage-point math.
//   - AC-05 (C-04): scores within all thresholds return DriftStable.
//   - AC-06 (C-05): the function uses the passed thresholds, NOT
//     hardcoded values.
//
// Math:
//
//	delta := current - prior   (positive = improvement, negative = worsening)
//	if delta >= ImprovementPP                                  → Improvement
//	if delta <= -MajorWorseningPP                              → MajorWorsening
//	if delta <= -MinorWorseningPP (and not major)              → MinorWorsening
//	otherwise                                                  → Stable
//
// Comparisons use >= / <= so the threshold value itself fires the
// classification (a 5pp gain matches Improvement when ImprovementPP=5).
func Classify(prior, current float64, t Thresholds) Kind {
	delta := current - prior

	// Improvement: large positive delta.
	if delta >= t.ImprovementPP {
		return DriftImprovement
	}

	// Worsening: large negative delta. Check major first because the
	// major threshold is >= the minor threshold (validator enforces).
	if delta <= -t.MajorWorseningPP {
		return DriftMajorWorsening
	}
	if delta <= -t.MinorWorseningPP {
		return DriftMinorWorsening
	}

	return DriftStable
}

// Score returns the host's compliance score from confirmed verdicts, or an
// absent score when nothing produced one.
//
// It delegates to internal/compliance so drift and every other surface share
// one definition. Skipped and error outcomes are excluded from the denominator,
// which the old doc comment said only of skipped.
//
// This replaced ComplianceScore, which returned 0 for an empty denominator and
// called it a "conservative default". It was not conservative: 0 is a real
// verdict meaning every evaluated rule failed, so a host nothing could assess
// was indistinguishable from a host that failed everything, and the difference
// was a major-drift alert routed to an operator (bugs/OW-023).
func Score(passed, failed int) compliance.Score {
	return compliance.HostScore(compliance.Counts{Pass: passed, Fail: failed})
}
