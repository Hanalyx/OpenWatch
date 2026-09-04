package compliance

// CoverageStatus says whether an assessment-coverage percentage exists, and
// when it does not, why.
//
// A null coverage with no stated reason is the defect this vocabulary exists to
// prevent. "No number" can mean the lens matched nothing, or that OpenWatch
// cannot yet classify what was skipped. Those call for different operator
// responses, and a bare null tells them apart for nobody.
type CoverageStatus string

const (
	// CoverageAvailable means every in-scope rule is accounted for and the
	// percentage is published.
	CoverageAvailable CoverageStatus = "available"

	// CoverageUnavailableUnclassifiedSkips means at least one skipped outcome
	// carries no typed reason, so OpenWatch cannot tell an inapplicable rule
	// from an unevaluated one. It withholds the number rather than guessing.
	//
	// Guessing in either direction is worse than silence. Treating every skip as
	// inapplicable reports full coverage on a host with real gaps. Treating
	// every skip as unevaluated reported the development fleet at 62.4 percent
	// mean coverage when the honest figure, once reasons are typed, is 97.8.
	//
	// Resolved by features/KN-OW-021.
	CoverageUnavailableUnclassifiedSkips CoverageStatus = "unavailable_unclassified_skips"

	// CoverageUnavailableNoOutcomes means the lens produced no outcomes at all.
	//
	// The name is deliberately not "no in-scope rules". Zero counts cannot tell
	// "no rule applies to this host" from "never scanned" from "the scan
	// aborted". Naming it out-of-scope would assert what the counts do not
	// prove; that distinction is gated on KN-OW-021 with the rest of the reason
	// vocabulary.
	CoverageUnavailableNoOutcomes CoverageStatus = "unavailable_no_outcomes"
)

// Coverage is the fraction of in-scope rules that produced a verdict, with the
// status that says whether the fraction exists.
type Coverage struct {
	Pct    Score
	Status CoverageStatus
}

// AssessmentCoverage derives coverage from counts.
//
// skipReasonsTyped reports whether every skipped outcome carries a machine
// readable reason. It is false for every deployment until KN-OW-021 ships, and
// the parameter exists rather than being assumed so the call site states which
// world it is in.
func AssessmentCoverage(c Counts, skipReasonsTyped bool) Coverage {
	if c.Skipped > 0 && !skipReasonsTyped {
		return Coverage{Pct: AbsentScore(), Status: CoverageUnavailableUnclassifiedSkips}
	}
	inScope := c.InScope()
	if inScope == 0 {
		return Coverage{Pct: AbsentScore(), Status: CoverageUnavailableNoOutcomes}
	}
	return Coverage{
		Pct:    newScore(float64(c.Executed()) / float64(inScope) * 100),
		Status: CoverageAvailable,
	}
}
