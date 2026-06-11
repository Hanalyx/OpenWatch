package liveness

import (
	"hash/fnv"
	"time"

	"github.com/google/uuid"
)

// ApplyJitter computes a per-host jittered probe interval in the range
// [(1-JitterFactor)×interval, (1+JitterFactor)×interval].
//
// Spec C-04 / AC-07: the jitter is deterministic for a given (hostID,
// interval) pair so the same host always lands at the same offset
// within the cadence — important for diagnosability (the operator
// can predict when host X probes).
//
// Distinct hostIDs at the same interval produce distinct jittered
// values, spreading the fleet's tick load over the interval window.
//
// Pure function. No randomness, no I/O.
func ApplyJitter(interval time.Duration, hostID uuid.UUID) time.Duration {
	if interval <= 0 {
		return 0
	}

	// FNV-1a hash over the 16 hostID bytes gives a stable per-host
	// uint64 offset. Distinct hostIDs are uncorrelated; same hostID
	// is identical across boot cycles.
	h := fnv.New64a()
	_, _ = h.Write(hostID[:])
	sum := h.Sum64()

	// Map sum into [-JitterFactor, +JitterFactor]. The math is:
	//   normalized = sum / maxUint64  ∈ [0, 1)
	//   centered   = (normalized - 0.5) * 2  ∈ [-1, 1)
	//   scaled     = centered * JitterFactor   ∈ [-JitterFactor, +JitterFactor)
	// Then apply to interval.
	normalized := float64(sum) / float64(^uint64(0))
	centered := (normalized - 0.5) * 2
	scaled := centered * JitterFactor

	delta := time.Duration(float64(interval) * scaled)
	return interval + delta
}

// ClampInterval enforces the [MinProbeInterval, MaxProbeInterval] safety
// range on a configured cadence value. Spec C-03 / AC-08.
//
//   - input  < MinProbeInterval → MinProbeInterval
//   - input  > MaxProbeInterval → MaxProbeInterval
//   - input == 0                → DefaultProbeInterval (treat as
//     "policy did not set; use default")
//   - otherwise                 → input unchanged
//
// Pure function.
func ClampInterval(d time.Duration) time.Duration {
	if d == 0 {
		return DefaultProbeInterval
	}
	if d < MinProbeInterval {
		return MinProbeInterval
	}
	if d > MaxProbeInterval {
		return MaxProbeInterval
	}
	return d
}
