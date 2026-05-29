package drift

// Classify maps a score delta to a DriftKind given the active
// thresholds. Pure function — no I/O, no side effects, deterministic.
//
// Spec ACs satisfied here:
//
//   - AC-01 (C-01, C-02, C-03): pure-function classifier returning a
//     closed-enum DriftKind from percentage-point math.
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
func Classify(prior, current float64, t Thresholds) DriftKind {
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

// ComplianceScore returns the percentage of (passed / (passed + failed))
// — skipped rules are excluded from the denominator. Spec AC-14.
//
// Edge cases:
//   - passed + failed == 0  → 0 (no scored rules; conservative default)
func ComplianceScore(passed, failed int) float64 {
	denom := passed + failed
	if denom == 0 {
		return 0
	}
	return (float64(passed) / float64(denom)) * 100
}
