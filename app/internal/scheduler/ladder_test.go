// @spec system-scheduler
//
// AC traceability (this file):
//   AC-01  TestLoadIntervals_TierLookup_Default48hForMissingTier
//   AC-02  TestNextScanFor_AddsLadderInterval
//          TestNextScanFor_ClampsToMaxIntervalCap
//          TestNextScanFor_ZeroLastFinishedAtMeansImmediate
//   AC-09  TestLoadIntervals_PolicyVersionSnapshotted
//   AC-12  TestLoadIntervals_ClampsBelow5MinToFloor
//          TestLoadIntervals_ClampsAbove48hToCeiling
//          TestLoadIntervals_NoClampForInBudgetValues

package scheduler

import (
	"reflect"
	"testing"
	"time"
)

// validTiers returns a PolicyTiers value that exercises every state with
// in-budget interval values. Used as the baseline input across tests.
func validTiers() PolicyTiers {
	return PolicyTiers{
		Version: "1.0.0",
		IntervalMins: map[ComplianceState]int{
			StateCritical:     60,   // 1h
			StateNonCompliant: 360,  // 6h
			StatePartial:      720,  // 12h
			StateCompliant:    1440, // 24h
			StateUnknown:      60,   // 1h — treat as critical until known
		},
	}
}

// @ac AC-01
// AC-01: missing tier defaults to MaxIntervalCap (48h) — the safety-floor
// guarantee that an under-specified policy can never produce a too-fast
// scan rate.
func TestLoadIntervals_TierLookup_Default48hForMissingTier(t *testing.T) {
	t.Run("system-scheduler/AC-01", func(t *testing.T) {
		tiers := PolicyTiers{
			Version: "1.0.0",
			IntervalMins: map[ComplianceState]int{
				StateCompliant: 1440, // only "compliant" defined
			},
		}

		result := LoadIntervals(tiers)

		// The 4 omitted states fall back to MaxIntervalCap.
		omitted := []ComplianceState{
			StateUnknown, StateCritical, StateNonCompliant, StatePartial,
		}
		for _, st := range omitted {
			got, ok := result.Ladder[st]
			if !ok {
				t.Errorf("state %q not present in ladder; LoadIntervals must populate every state", st)
				continue
			}
			if got != MaxIntervalCap {
				t.Errorf("state %q: got interval %v, want MaxIntervalCap %v", st, got, MaxIntervalCap)
			}
		}

		// The defined state survives at its policy value.
		if got, want := result.Ladder[StateCompliant], 24*time.Hour; got != want {
			t.Errorf("compliant: got %v, want %v", got, want)
		}
	})
}

// @ac AC-09
// AC-09: the result's PolicyVersion field matches the input PolicyTiers.Version,
// so callers can snapshot the version into the scan job payload (load-bearing
// for "policy reload mid-scan does not change in-flight scan's policy_version").
func TestLoadIntervals_PolicyVersionSnapshotted(t *testing.T) {
	t.Run("system-scheduler/AC-09", func(t *testing.T) {
		tiers := validTiers()
		tiers.Version = "2.4.1-rc.2"

		result := LoadIntervals(tiers)

		if result.PolicyVersion != "2.4.1-rc.2" {
			t.Errorf("PolicyVersion = %q, want %q", result.PolicyVersion, "2.4.1-rc.2")
		}
	})
}

// @ac AC-12
// AC-12: policy values below MinIntervalFloor (5 min) are clamped to the
// floor; a ClampRecord with kind=min_floor is produced for audit emission.
// Protects against scan-storm DoS via misconfigured policy.
func TestLoadIntervals_ClampsBelow5MinToFloor(t *testing.T) {
	t.Run("system-scheduler/AC-12", func(t *testing.T) {
		tiers := validTiers()
		tiers.IntervalMins[StateCritical] = 1 // 1 min — well below the 5-min floor

		result := LoadIntervals(tiers)

		if got := result.Ladder[StateCritical]; got != MinIntervalFloor {
			t.Errorf("clamped critical interval = %v, want %v", got, MinIntervalFloor)
		}

		// Exactly one clamp recorded, with the expected shape.
		clampForCritical := findClamp(result.Clamps, StateCritical)
		if clampForCritical == nil {
			t.Fatalf("no ClampRecord for StateCritical; got clamps = %#v", result.Clamps)
		}
		if clampForCritical.Kind != ClampMinFloor {
			t.Errorf("Clamp.Kind = %q, want %q", clampForCritical.Kind, ClampMinFloor)
		}
		if clampForCritical.OriginalMinutes != 1 {
			t.Errorf("Clamp.OriginalMinutes = %d, want 1", clampForCritical.OriginalMinutes)
		}
		if clampForCritical.ClampedMinutes != 5 {
			t.Errorf("Clamp.ClampedMinutes = %d, want 5", clampForCritical.ClampedMinutes)
		}
	})
}

// Same AC-12, ceiling side. A policy value above MaxIntervalCap (48h)
// is clamped to the ceiling with kind=max_ceiling.
func TestLoadIntervals_ClampsAbove48hToCeiling(t *testing.T) {
	t.Run("system-scheduler/AC-12", func(t *testing.T) {
		tiers := validTiers()
		tiers.IntervalMins[StateCompliant] = 7 * 24 * 60 // 7 days

		result := LoadIntervals(tiers)

		if got := result.Ladder[StateCompliant]; got != MaxIntervalCap {
			t.Errorf("clamped compliant interval = %v, want %v", got, MaxIntervalCap)
		}

		clampForCompliant := findClamp(result.Clamps, StateCompliant)
		if clampForCompliant == nil {
			t.Fatalf("no ClampRecord for StateCompliant; got clamps = %#v", result.Clamps)
		}
		if clampForCompliant.Kind != ClampMaxCeiling {
			t.Errorf("Clamp.Kind = %q, want %q", clampForCompliant.Kind, ClampMaxCeiling)
		}
	})
}

// Same AC-12, negative case. In-budget values do NOT produce a clamp.
func TestLoadIntervals_NoClampForInBudgetValues(t *testing.T) {
	t.Run("system-scheduler/AC-12", func(t *testing.T) {
		result := LoadIntervals(validTiers())

		if len(result.Clamps) != 0 {
			t.Errorf("expected zero clamps for in-budget tiers, got %d: %#v",
				len(result.Clamps), result.Clamps)
		}

		// Verify the ladder content matches the input verbatim.
		want := TierLadder{
			StateCritical:     60 * time.Minute,
			StateNonCompliant: 6 * time.Hour,
			StatePartial:      12 * time.Hour,
			StateCompliant:    24 * time.Hour,
			StateUnknown:      60 * time.Minute,
		}
		if !reflect.DeepEqual(result.Ladder, want) {
			t.Errorf("ladder mismatch:\n  got:  %v\n  want: %v", result.Ladder, want)
		}
	})
}

// @ac AC-02
// AC-02: NextScanFor returns lastFinishedAt + ladder[state]. Pure arithmetic.
func TestNextScanFor_AddsLadderInterval(t *testing.T) {
	t.Run("system-scheduler/AC-02", func(t *testing.T) {
		ladder := LoadIntervals(validTiers()).Ladder
		last := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)

		// Critical → +1h
		gotCritical := NextScanFor(StateCritical, last, ladder)
		wantCritical := last.Add(60 * time.Minute)
		if !gotCritical.Equal(wantCritical) {
			t.Errorf("critical: got %v, want %v", gotCritical, wantCritical)
		}

		// Compliant → +24h
		gotCompliant := NextScanFor(StateCompliant, last, ladder)
		wantCompliant := last.Add(24 * time.Hour)
		if !gotCompliant.Equal(wantCompliant) {
			t.Errorf("compliant: got %v, want %v", gotCompliant, wantCompliant)
		}
	})
}

// Same AC-02, clamping path. If a misuse ever produces a ladder entry above
// MaxIntervalCap, NextScanFor still clamps the result. Defensive belt-and-suspenders.
func TestNextScanFor_ClampsToMaxIntervalCap(t *testing.T) {
	t.Run("system-scheduler/AC-02", func(t *testing.T) {
		// Construct an INVALID ladder (skipping LoadIntervals) where one
		// entry exceeds MaxIntervalCap.
		ladder := TierLadder{
			StateCritical: 100 * time.Hour, // exceeds the 48h cap
		}
		last := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)

		got := NextScanFor(StateCritical, last, ladder)
		want := last.Add(MaxIntervalCap)
		if !got.Equal(want) {
			t.Errorf("got %v, want %v (clamp to MaxIntervalCap)", got, want)
		}
	})
}

// Same AC-02, zero-time edge case. A host that has never been scanned
// (lastFinishedAt = time.Time{}) gets the zero time back — signal to the
// dispatcher to schedule it immediately.
func TestNextScanFor_ZeroLastFinishedAtMeansImmediate(t *testing.T) {
	t.Run("system-scheduler/AC-02", func(t *testing.T) {
		ladder := LoadIntervals(validTiers()).Ladder

		got := NextScanFor(StateCompliant, time.Time{}, ladder)
		if !got.IsZero() {
			t.Errorf("got %v, want zero time (immediate schedule)", got)
		}
	})
}

// findClamp helper — small enough to inline but used in two AC-12 tests.
func findClamp(clamps []ClampRecord, state ComplianceState) *ClampRecord {
	for i := range clamps {
		if clamps[i].State == state {
			return &clamps[i]
		}
	}
	return nil
}
