// @spec system-scheduler
//
// AC traceability (this file):
//   AC-11  TestMetrics_ZeroState
//          TestMetrics_AllCountersIncrementAndRoundTrip
//          TestMetrics_LastTickSetAndGet
//          TestMetrics_ConcurrentIncrementsAreAtomic

package scheduler

import (
	"sync"
	"testing"
	"time"
)

// @ac AC-11
// AC-11 (zero state): NewMetrics returns counters all at zero and
// LastTickAt at the zero time.
func TestMetrics_ZeroState(t *testing.T) {
	t.Run("system-scheduler/AC-11", func(t *testing.T) {
		m := NewMetrics()
		snap := m.Snapshot()

		if snap.DueCount != 0 ||
			snap.DispatchedCount != 0 ||
			snap.SkippedMaintenanceCount != 0 ||
			snap.SkippedBackoffCount != 0 ||
			snap.RefuseCount != 0 ||
			snap.PolicyClampedCount != 0 ||
			snap.HMACRejectCount != 0 {
			t.Errorf("expected all-zero counters, got %+v", snap)
		}
		if !snap.LastTickAt.IsZero() {
			t.Errorf("LastTickAt = %v, want zero time", snap.LastTickAt)
		}
	})
}

// @ac AC-11
// AC-11 (round-trip): every counter named in the spec is incrementable
// and the Snapshot reflects the new value. Failure on this test means a
// renamed/missing counter field that the spec requires.
func TestMetrics_AllCountersIncrementAndRoundTrip(t *testing.T) {
	t.Run("system-scheduler/AC-11", func(t *testing.T) {
		m := NewMetrics()

		m.DueCount.Add(7)
		m.DispatchedCount.Add(5)
		m.SkippedMaintenanceCount.Add(2)
		m.SkippedBackoffCount.Add(1)
		m.RefuseCount.Add(1)
		m.PolicyClampedCount.Add(3)
		m.HMACRejectCount.Add(1)

		snap := m.Snapshot()

		if snap.DueCount != 7 {
			t.Errorf("DueCount = %d, want 7", snap.DueCount)
		}
		if snap.DispatchedCount != 5 {
			t.Errorf("DispatchedCount = %d, want 5", snap.DispatchedCount)
		}
		if snap.SkippedMaintenanceCount != 2 {
			t.Errorf("SkippedMaintenanceCount = %d, want 2", snap.SkippedMaintenanceCount)
		}
		if snap.SkippedBackoffCount != 1 {
			t.Errorf("SkippedBackoffCount = %d, want 1", snap.SkippedBackoffCount)
		}
		if snap.RefuseCount != 1 {
			t.Errorf("RefuseCount = %d, want 1", snap.RefuseCount)
		}
		if snap.PolicyClampedCount != 3 {
			t.Errorf("PolicyClampedCount = %d, want 3", snap.PolicyClampedCount)
		}
		if snap.HMACRejectCount != 1 {
			t.Errorf("HMACRejectCount = %d, want 1", snap.HMACRejectCount)
		}
	})
}

// @ac AC-11
// AC-11 (last_tick_at): SetLastTick stores; LastTick / Snapshot read.
// The round-trip preserves nanosecond precision.
func TestMetrics_LastTickSetAndGet(t *testing.T) {
	t.Run("system-scheduler/AC-11", func(t *testing.T) {
		m := NewMetrics()
		want := time.Date(2026, 5, 28, 12, 30, 45, 123456789, time.UTC)

		m.SetLastTick(want)

		if got := m.LastTick(); !got.Equal(want) {
			t.Errorf("LastTick() = %v, want %v", got, want)
		}
		if snap := m.Snapshot(); !snap.LastTickAt.Equal(want) {
			t.Errorf("Snapshot.LastTickAt = %v, want %v", snap.LastTickAt, want)
		}
	})
}

// @ac AC-11
// AC-11 (concurrency): atomic counters survive 100 parallel increments
// per counter without losing updates. -race build catches missing atomics.
func TestMetrics_ConcurrentIncrementsAreAtomic(t *testing.T) {
	t.Run("system-scheduler/AC-11", func(t *testing.T) {
		m := NewMetrics()
		const goroutines = 100

		var wg sync.WaitGroup
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				m.DueCount.Add(1)
				m.DispatchedCount.Add(1)
				m.PolicyClampedCount.Add(1)
				m.HMACRejectCount.Add(1)
			}()
		}
		wg.Wait()

		snap := m.Snapshot()
		if snap.DueCount != goroutines {
			t.Errorf("DueCount = %d, want %d", snap.DueCount, goroutines)
		}
		if snap.DispatchedCount != goroutines {
			t.Errorf("DispatchedCount = %d, want %d", snap.DispatchedCount, goroutines)
		}
		if snap.PolicyClampedCount != goroutines {
			t.Errorf("PolicyClampedCount = %d, want %d", snap.PolicyClampedCount, goroutines)
		}
		if snap.HMACRejectCount != goroutines {
			t.Errorf("HMACRejectCount = %d, want %d", snap.HMACRejectCount, goroutines)
		}
	})
}
