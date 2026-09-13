// Package compliance owns the single definition of a compliance score.
//
// Before this package the product computed a score in five places with three
// formulas. The host lens divided passing by every outcome, so a rule that did
// not apply to the host counted as a failure. The fleet rollup pooled pass and
// fail rows across the estate, so a host with 700 rules outvoted one with 50.
// The posture snapshot used a third formula and the fleet trend averaged it, so
// the live fleet number and its own trend line disagreed by about 20
// percentage points on the development fleet.
//
// One definition lives here. A host score under one lens is passing over
// passing plus failing. A fleet or group score is the equal-host mean of
// eligible member scores. Query layers produce counts and call this package;
// nothing else computes a percentage.
//
// The package is pure. It imports no HTTP, no database driver, no Kensa, and
// no other internal package, so every rule in it is testable without a server
// or a schema. Spec: specs/system/compliance-scoring.spec.yaml.
//
// # Why Score is a struct and not a float64
//
// A bare float64 cannot say "there is no score". That is not a style
// preference: it is the shape behind two shipped defects. drift.ComplianceScore
// returned 0 for an empty denominator and a host that could not be assessed
// alerted as a compliance collapse (OW-023). internal/worker divided by every
// outcome and the same host was stored and reported as critically
// non-compliant (OW-024). Two independent code paths, one missing type.
//
// Zero percent is a real verdict meaning every evaluated rule failed. It has to
// stay distinguishable from "nothing was evaluated", so absence is a state of
// the type rather than a value a caller has to remember to check.
package compliance

import "math"

// Counts is one host's outcome tally under one lens.
//
// Skipped is carried separately from NotApplicable and NotAssessed on purpose.
// Until Kensa supplies a typed skip reason (features/KN-OW-021) OpenWatch
// cannot tell an inapplicable rule from an unevaluated one, so a skipped
// outcome is reported as a raw count and classified nowhere. NotApplicable and
// NotAssessed stay zero in that period and become meaningful in v1.1.0.
type Counts struct {
	Pass          int
	Fail          int
	Skipped       int
	NotApplicable int
	NotAssessed   int
	Error         int
}

// Executed is the score denominator: outcomes that produced a verdict.
func (c Counts) Executed() int { return c.Pass + c.Fail }

// InScope is the coverage denominator: rules that should have produced a
// verdict, whether or not they did. Skipped is excluded because an unclassified
// skip may or may not be in scope, which is the question KN-OW-021 answers.
func (c Counts) InScope() int { return c.Pass + c.Fail + c.NotAssessed + c.Error }

// Score is a compliance percentage that may be absent.
//
// The zero value is the absent score, so a Score that nobody set cannot be
// mistaken for zero percent. Callers reach the number through Value, which
// returns the presence flag beside it, or through Rounded, which does the same
// for the one-decimal presentation value. There is no accessor that hands back
// a number alone.
type Score struct {
	pct     float64
	present bool
}

// NewScore returns a present score. Callers inside this package only; a score
// is otherwise derived from counts.
func newScore(pct float64) Score { return Score{pct: pct, present: true} }

// AbsentScore is the explicit spelling of "no score", for callers that want to
// say so rather than rely on the zero value.
func AbsentScore() Score { return Score{} }

// Value returns the percentage and whether one exists. This is the accessor to
// prefer: the ok result makes the absent case impossible to ignore.
func (s Score) Value() (float64, bool) { return s.pct, s.present }

// Present reports whether a score exists.
func (s Score) Present() bool { return s.present }

// There is deliberately no Percent(fallback) accessor. It was written and
// removed: returning a bare float64 lets a caller collapse absence back into a
// number, which is the exact shape of OW-023 and OW-024 and what AC-04 forbids.
// Callers use Value or Rounded and handle the presence result.

// Rounded returns the canonical one-decimal presentation value and whether a
// score exists. Round once, at the boundary; aggregation uses the unrounded
// fraction.
func (s Score) Rounded() (float64, bool) {
	if !s.present {
		return 0, false
	}
	return Round1(s.pct), true
}

// ErrInvalidScore reports a percentage that cannot be a compliance score.
type ErrInvalidScore struct{ Reason string }

func (e ErrInvalidScore) Error() string { return "invalid compliance score: " + e.Reason }

// ScoreFromPercent wraps an already-computed percentage as a present score, or
// refuses.
//
// For values derived from counts somewhere else and being re-presented, such as
// a stored posture snapshot. It validates rather than trusting, because an
// unvalidated constructor taking a float64 is a second way to fabricate a score
// and would undo what the Score type is for. NaN, the infinities and anything
// outside 0 to 100 are rejected: none of them can be a percentage of rules that
// passed, so accepting one would put a number nobody can act on into signed
// evidence.
//
// Deriving a score from raw counts goes through HostScore, which is the only
// place the formula lives.
func ScoreFromPercent(pct float64) (Score, error) {
	if math.IsNaN(pct) {
		return Score{}, ErrInvalidScore{"not a number"}
	}
	if math.IsInf(pct, 0) {
		return Score{}, ErrInvalidScore{"infinite"}
	}
	if pct < 0 || pct > 100 {
		return Score{}, ErrInvalidScore{"outside 0 to 100"}
	}
	return newScore(pct), nil
}

// ScoreFromNullable bridges a nullable database column to a Score.
//
// A NULL column is an absent score and a non-NULL column is a present one,
// validated the same way as ScoreFromPercent. This is the shape posture
// snapshots and host_compliance_schedule need once score_pct is nullable, and
// having it here stops each caller reinventing the nil check and getting it
// wrong in one of them.
func ScoreFromNullable(pct *float64) (Score, error) {
	if pct == nil {
		return AbsentScore(), nil
	}
	return ScoreFromPercent(*pct)
}

// HostScore is the one formula: passing over passing plus failing.
//
// Skipped, not-applicable, not-assessed and error outcomes never enter the
// numerator or the denominator. An outcome that produced no verdict cannot
// argue either way about the host's posture.
//
// Zero executed outcomes returns an absent score, never zero percent.
func HostScore(c Counts) Score {
	executed := c.Executed()
	if executed == 0 {
		return AbsentScore()
	}
	return newScore(float64(c.Pass) / float64(executed) * 100)
}

// Aggregate is the result of averaging host scores, with the participation
// counts that make the average readable.
//
// HostsWithoutScore is not a footnote. An average over 2 of 200 hosts and an
// average over 200 of 200 are different claims, and a percentage alone cannot
// tell them apart.
type Aggregate struct {
	Score             Score
	HostsTotal        int
	HostsScored       int
	HostsWithoutScore int
}

// MeanOfHostScores averages the hosts that have a score, giving each one vote.
//
// This is the equal-host mean, not a pooled rule ratio. Pooling weights a host
// by how many rules it happens to carry, so a 700-rule host outvotes a 50-rule
// host fourteen to one and the number stops answering "how compliant is the
// average host". The two differ materially: nine-pass-one-fail with
// one-pass-one-fail is 70.0 by mean and 83.3 by pooling.
//
// A host without a score is omitted from the mean and counted, never averaged
// in as zero. Averaging it in would drag the fleet number down for a host
// nothing could measure.
//
// The mean is computed on unrounded fractions so rounding does not compound.
func MeanOfHostScores(scores []Score) Aggregate {
	agg := Aggregate{HostsTotal: len(scores)}
	var sum float64
	for _, s := range scores {
		pct, ok := s.Value()
		if !ok {
			agg.HostsWithoutScore++
			continue
		}
		agg.HostsScored++
		sum += pct
	}
	if agg.HostsScored == 0 {
		agg.Score = AbsentScore()
		return agg
	}
	agg.Score = newScore(sum / float64(agg.HostsScored))
	return agg
}

// Round1 rounds to one decimal place, half away from zero.
//
// The mode is named because it has to match PostgreSQL. A SQL aggregate may
// compute one exact numeric fraction per host and average them for scale, and
// ROUND(numeric, 1) in PostgreSQL is half away from zero. math.Round is too, so
// the two paths agree on a value that lands exactly on a half boundary. Banker's
// rounding here would disagree with the database on 6.25 and the disagreement
// would surface as two surfaces showing different numbers.
func Round1(pct float64) float64 {
	return math.Round(pct*10) / 10
}
