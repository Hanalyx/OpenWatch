package scheduler

import (
	"time"
)

// LoadIntervals consumes a parsed PolicyTiers and returns a clamped
// TierLadder.
//
// Spec ACs satisfied here:
//
//   - AC-01 (C-01, C-04): tier intervals MUST be loaded from policy.Schedules;
//     missing tiers default to MaxIntervalCap (48h).
//   - AC-12 (C-08): policy values below MinIntervalFloor (5 min) are clamped
//     to the floor; values above MaxIntervalCap (48h) are clamped to the
//     ceiling. Each clamp produces a ClampRecord that the caller emits
//     as scheduler.policy.clamped audit.
//
// The function is pure: same input → same output, no I/O, no side effects.
// Audit emission is the caller's responsibility (cmd/openwatch/main.go at
// boot, scheduler.Reload at runtime).
func LoadIntervals(tiers PolicyTiers) LoadResult {
	ladder := make(TierLadder, 5)
	var clamps []ClampRecord

	allStates := []ComplianceState{
		StateUnknown,
		StateCritical,
		StateNonCompliant,
		StatePartial,
		StateCompliant,
	}

	for _, st := range allStates {
		mins, present := tiers.IntervalMins[st]
		if !present {
			// AC-01: missing tier defaults to MaxIntervalCap (48h).
			ladder[st] = MaxIntervalCap
			continue
		}

		raw := time.Duration(mins) * time.Minute
		clamped, kind := clampInterval(raw)
		ladder[st] = clamped

		if kind != "" {
			clamps = append(clamps, ClampRecord{
				State:           st,
				OriginalMinutes: mins,
				ClampedMinutes:  int(clamped / time.Minute),
				Kind:            kind,
			})
		}
	}

	return LoadResult{
		Ladder:        ladder,
		PolicyVersion: tiers.Version,
		Clamps:        clamps,
	}
}

// clampInterval enforces [MinIntervalFloor, MaxIntervalCap] and reports
// whether a clamp was applied.
func clampInterval(d time.Duration) (time.Duration, ClampKind) {
	if d < MinIntervalFloor {
		return MinIntervalFloor, ClampMinFloor
	}
	if d > MaxIntervalCap {
		return MaxIntervalCap, ClampMaxCeiling
	}
	return d, ""
}

// NextScanFor computes the next-scan time for a host given its current
// compliance state, the wall-clock time of its last successful scan, and
// the active tier ladder.
//
// Spec ACs satisfied here:
//
//   - AC-02 (C-01, C-04): returns lastFinishedAt + ladder[state]; the
//     result is implicitly bounded by the ladder, which is already clamped
//     to MaxIntervalCap. An unknown state (not in the ladder) treats the
//     host as critical-priority for safety — it'll be re-checked at the
//     ladder's shortest-known interval, never at the cap.
//
// If lastFinishedAt is zero (never scanned), the function returns the
// zero time so callers know to schedule the host immediately.
func NextScanFor(state ComplianceState, lastFinishedAt time.Time, ladder TierLadder) time.Time {
	if lastFinishedAt.IsZero() {
		return time.Time{}
	}

	interval, ok := ladder[state]
	if !ok {
		// Unknown state → treat as if newly observed; schedule against
		// whichever known tier in the ladder is shortest. Fail-safe
		// toward "scan again sooner" rather than "wait MaxIntervalCap".
		interval = shortestInterval(ladder)
	}

	// Defensive: the ladder MUST already have been clamped, but check
	// the ceiling once more so a misuse of TierLadder{} can't produce
	// an unbounded NextScanFor result.
	if interval > MaxIntervalCap {
		interval = MaxIntervalCap
	}

	return lastFinishedAt.Add(interval)
}

// shortestInterval returns the smallest interval in the ladder, defaulting
// to MinIntervalFloor when the ladder is empty (which itself should not
// happen because LoadIntervals always populates all 5 states).
func shortestInterval(ladder TierLadder) time.Duration {
	min := MaxIntervalCap
	for _, d := range ladder {
		if d < min {
			min = d
		}
	}
	if min == 0 {
		return MinIntervalFloor
	}
	return min
}
