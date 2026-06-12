package scheduler

import "time"

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
//	score >= 90          → StateCompliant
//	70 <= score < 90     → StateMostlyCompliant
//	50 <= score < 70     → StatePartial
//	20 <= score < 50     → StateNonCompliant
//	score < 20           → StateCritical
//
// Pure function: no I/O, no side effects.
func StateFromScore(score float64, hasCritical bool) ComplianceState {
	if hasCritical {
		return StateCritical
	}
	switch {
	case score >= 90:
		return StateCompliant
	case score >= 70:
		return StateMostlyCompliant
	case score >= 50:
		return StatePartial
	case score >= 20:
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
func UpdateAfterScan(score float64, hasCritical bool, scanCompletedAt time.Time, ladder TierLadder) ScanResult {
	state := StateFromScore(score, hasCritical)
	return ScanResult{
		State:         state,
		NextScheduled: NextScanFor(state, scanCompletedAt, ladder),
	}
}
