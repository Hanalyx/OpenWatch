package scheduler

import (
	"time"

	"github.com/Hanalyx/openwatch/internal/compliance"
)

// ScanResult is the output of UpdateAfterScan — what the scheduler row
// should look like after a scan completes. Service.PersistAfterScan
// (added in the DB-integration chunk) wraps this with the UPSERT to
// host_compliance_schedule and emits scheduler.schedule.updated audit.
type ScanResult struct {
	State         ComplianceState
	NextScheduled time.Time
}

// StateFromScore maps a (compliance_score, has_critical_findings) pair
// to a ComplianceState. The hasCritical override takes precedence over
// score-based classification because a single critical finding warrants
// the fastest re-check tier regardless of overall score.
//
// Score bands (v3.0.0 — the prototype's five bands, scan plan decision
// #5 resolved 2026-06-12):
//
//	hasCritical = true   → StateCritical
//	absent score         → StateUnknown (bugs/OW-024)
//	score >= 90          → StateCompliant
//	70 <= score < 90     → StateMostlyCompliant
//	50 <= score < 70     → StatePartial
//	20 <= score < 50     → StateNonCompliant
//	score < 20           → StateCritical
//
// Pure function: no I/O, no side effects.
func StateFromScore(score compliance.Score, hasCritical bool) ComplianceState {
	if hasCritical {
		return StateCritical
	}
	// An absent score is not a low score. Before bugs/OW-024 this function took
	// a bare float64, internal/worker divided passing by every outcome, and a
	// host whose scan produced no verdict arrived as 0.0 and fell through the
	// default branch to Critical. It was then stored and reported as the worst
	// compliance band for a scanning problem. StateUnknown is in the public API
	// enum and had no producer for exactly the case that needed it.
	pct, present := score.Value()
	if !present {
		return StateUnknown
	}
	switch {
	case pct >= 90:
		return StateCompliant
	case pct >= 70:
		return StateMostlyCompliant
	case pct >= 50:
		return StatePartial
	case pct >= 20:
		return StateNonCompliant
	default:
		return StateCritical
	}
}

// UpdateAfterScan computes the new schedule for a host given a completed
// scan's outcome.
//
// Spec ACs satisfied here:
//
//   - AC-08 (pure-logic core): given the resulting compliance_score,
//     has_critical_findings flag, the scan's completion time, and the
//     active tier ladder, returns the new ComplianceState and the
//     next_scheduled_scan time.
//
// Pure function — no DB write. Service.PersistAfterScan wraps this and
// performs the UPSERT + audit emission against host_compliance_schedule.
func UpdateAfterScan(score compliance.Score, hasCritical bool, scanCompletedAt time.Time, ladder TierLadder) ScanResult {
	state := StateFromScore(score, hasCritical)
	return ScanResult{
		State:         state,
		NextScheduled: NextScanFor(state, scanCompletedAt, ladder),
	}
}
