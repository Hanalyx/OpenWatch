// @spec system-worker-subcommand
//
// AC traceability (this file):
//
//	AC-04  TestTransientBackoff_FirstFailure_OneMinute
//	AC-10  TestTransientBackoff_LadderAndCeiling

package worker

import (
	"testing"
	"time"
)

// AC-04 (pure function half): on the first transient failure,
// suppress_until = now + 1m. The DB integration half is in
// TestScanWorker_ErrHostBusy_BackoffUpsert.
func TestTransientBackoff_FirstFailure_OneMinute(t *testing.T) {
	t.Run("system-worker-subcommand/AC-04", func(t *testing.T) {
		got := transientBackoff(1)
		if got != 1*time.Minute {
			t.Errorf("transientBackoff(1) = %v, want 1m", got)
		}
	})
}

// AC-10: the full ladder is 1m, 2m, 4m, 8m, 16m for failures 1..5;
// failures >= 6 hit the 24h ceiling.
// @ac AC-10
func TestTransientBackoff_LadderAndCeiling(t *testing.T) {
	t.Run("system-worker-subcommand/AC-10", func(t *testing.T) {
		cases := []struct {
			failures int
			want     time.Duration
		}{
			{1, 1 * time.Minute},
			{2, 2 * time.Minute},
			{3, 4 * time.Minute},
			{4, 8 * time.Minute},
			{5, 16 * time.Minute},
			{6, 24 * time.Hour},
			{7, 24 * time.Hour},
			{100, 24 * time.Hour},
		}
		for _, c := range cases {
			got := transientBackoff(c.failures)
			if got != c.want {
				t.Errorf("transientBackoff(%d) = %v, want %v", c.failures, got, c.want)
			}
		}

		// Defensive: <= 0 should return 0 (no suppression).
		if got := transientBackoff(0); got != 0 {
			t.Errorf("transientBackoff(0) = %v, want 0", got)
		}
		if got := transientBackoff(-1); got != 0 {
			t.Errorf("transientBackoff(-1) = %v, want 0", got)
		}
	})
}
