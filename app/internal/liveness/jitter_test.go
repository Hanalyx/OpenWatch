// @spec system-liveness-loop
//
// AC traceability (this file):
//   AC-07  TestApplyJitter_Deterministic
//          TestApplyJitter_WithinBudget
//          TestApplyJitter_DistinctHostsDistinctValues
//   AC-08  TestClampInterval_BelowFloor
//          TestClampInterval_AboveCeiling
//          TestClampInterval_InRange
//          TestClampInterval_ZeroDefaults

package liveness

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// @ac AC-07
// AC-07: same (hostID, interval) → same jittered value across calls.
func TestApplyJitter_Deterministic(t *testing.T) {
	t.Run("system-liveness-loop/AC-07", func(t *testing.T) {
		hostID := uuid.MustParse("11111111-2222-3333-4444-555555555555")
		base := 5 * time.Minute

		a := ApplyJitter(base, hostID)
		b := ApplyJitter(base, hostID)
		if a != b {
			t.Errorf("ApplyJitter non-deterministic: %v vs %v", a, b)
		}
	})
}

// @ac AC-07
// AC-07: jittered value stays within [0.8×interval, 1.2×interval].
func TestApplyJitter_WithinBudget(t *testing.T) {
	t.Run("system-liveness-loop/AC-07", func(t *testing.T) {
		base := 5 * time.Minute
		min := time.Duration(float64(base) * (1 - JitterFactor))
		max := time.Duration(float64(base) * (1 + JitterFactor))

		// Sample 200 distinct hostIDs.
		for i := 0; i < 200; i++ {
			hostID := uuid.New()
			got := ApplyJitter(base, hostID)
			if got < min || got > max {
				t.Errorf("hostID=%s: jittered = %v, want in [%v, %v]", hostID, got, min, max)
			}
		}
	})
}

// @ac AC-07
// AC-07: distinct hostIDs produce distinct jittered values (no collisions
// across a sample of 100 hosts).
func TestApplyJitter_DistinctHostsDistinctValues(t *testing.T) {
	t.Run("system-liveness-loop/AC-07", func(t *testing.T) {
		base := 5 * time.Minute
		seen := make(map[time.Duration]struct{})

		for i := 0; i < 100; i++ {
			hostID := uuid.New()
			d := ApplyJitter(base, hostID)
			if _, dup := seen[d]; dup {
				// FNV-1a is a strong hash; with 100 hosts in a 2-minute
				// window of nanosecond-resolution durations, collisions
				// are vanishingly unlikely. If this fires, the jitter
				// math is degenerate.
				t.Errorf("collision on jitter value %v", d)
			}
			seen[d] = struct{}{}
		}
	})
}

// @ac AC-08
// AC-08: input below MinProbeInterval clamps to MinProbeInterval.
func TestClampInterval_BelowFloor(t *testing.T) {
	t.Run("system-liveness-loop/AC-08", func(t *testing.T) {
		cases := []time.Duration{
			1 * time.Second,
			30 * time.Second,
			59 * time.Second,
		}
		for _, in := range cases {
			if got := ClampInterval(in); got != MinProbeInterval {
				t.Errorf("ClampInterval(%v) = %v, want %v", in, got, MinProbeInterval)
			}
		}
	})
}

// @ac AC-08
// AC-08: input above MaxProbeInterval clamps to MaxProbeInterval.
func TestClampInterval_AboveCeiling(t *testing.T) {
	t.Run("system-liveness-loop/AC-08", func(t *testing.T) {
		cases := []time.Duration{
			61 * time.Minute,
			2 * time.Hour,
			24 * time.Hour,
		}
		for _, in := range cases {
			if got := ClampInterval(in); got != MaxProbeInterval {
				t.Errorf("ClampInterval(%v) = %v, want %v", in, got, MaxProbeInterval)
			}
		}
	})
}

// @ac AC-08
// AC-08: in-range values pass through unchanged.
func TestClampInterval_InRange(t *testing.T) {
	t.Run("system-liveness-loop/AC-08", func(t *testing.T) {
		cases := []time.Duration{
			60 * time.Second,
			5 * time.Minute,
			30 * time.Minute,
			60 * time.Minute,
		}
		for _, in := range cases {
			if got := ClampInterval(in); got != in {
				t.Errorf("ClampInterval(%v) = %v, want %v", in, got, in)
			}
		}
	})
}

// @ac AC-08
// AC-08: zero input means "policy did not set", so default applies.
func TestClampInterval_ZeroDefaults(t *testing.T) {
	t.Run("system-liveness-loop/AC-08", func(t *testing.T) {
		if got := ClampInterval(0); got != DefaultProbeInterval {
			t.Errorf("ClampInterval(0) = %v, want %v", got, DefaultProbeInterval)
		}
	})
}
