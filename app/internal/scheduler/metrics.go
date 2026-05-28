package scheduler

import (
	"sync/atomic"
	"time"
)

// Metrics holds the scheduler's runtime counters. Exposed (read-only)
// for ops visibility via the admin metrics endpoint.
//
// Spec AC-11: scheduler metrics expose last_tick_at, due_count,
// dispatched_count, skipped_maintenance_count, skipped_backoff_count,
// refuse_count, policy_clamped_count, hmac_reject_count counters.
//
// All fields are atomic; safe for concurrent read/write across the cron
// tick goroutine, the dispatcher, and the metrics-read handler.
type Metrics struct {
	// lastTickNanos holds the Unix-nano timestamp of the most recent
	// dispatcher tick. Stored as int64 (zero = no tick yet).
	lastTickNanos atomic.Int64

	// DueCount counts host_compliance_schedule rows where
	// next_scheduled_scan has passed at the time of the tick.
	DueCount atomic.Int64

	// DispatchedCount counts scan jobs successfully enqueued by ticks.
	DispatchedCount atomic.Int64

	// SkippedMaintenanceCount counts due rows that were skipped because
	// maintenance_mode = true (spec AC-05).
	SkippedMaintenanceCount atomic.Int64

	// SkippedBackoffCount counts due rows that were skipped because
	// host_backoff_state.suppress_until is in the future (spec C-11
	// on system-kensa-executor; the scheduler honors backoff at dispatch).
	SkippedBackoffCount atomic.Int64

	// RefuseCount counts hard failures that prevented the scheduler from
	// running (boot policy invalid, runtime reload rejected).
	RefuseCount atomic.Int64

	// PolicyClampedCount counts tier values that were clamped to the
	// safety floor/ceiling at LoadIntervals time (spec C-08, AC-12).
	PolicyClampedCount atomic.Int64

	// HMACRejectCount counts scan job payloads that failed HMAC
	// verification at dequeue (spec C-11, AC-15).
	HMACRejectCount atomic.Int64
}

// NewMetrics returns a fresh zero-valued Metrics. Inject this into
// NewService for tests; production code uses scheduler.New which
// constructs a Metrics internally.
func NewMetrics() *Metrics {
	return &Metrics{}
}

// SetLastTick records the time of the most recent dispatcher tick.
func (m *Metrics) SetLastTick(t time.Time) {
	m.lastTickNanos.Store(t.UnixNano())
}

// LastTick returns the most recently recorded tick time, or zero if no
// tick has fired yet.
func (m *Metrics) LastTick() time.Time {
	n := m.lastTickNanos.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

// MetricsSnapshot is a point-in-time copy of all counters, suitable for
// JSON serialization in the admin metrics handler.
type MetricsSnapshot struct {
	LastTickAt              time.Time `json:"last_tick_at"`
	DueCount                int64     `json:"due_count"`
	DispatchedCount         int64     `json:"dispatched_count"`
	SkippedMaintenanceCount int64     `json:"skipped_maintenance_count"`
	SkippedBackoffCount     int64     `json:"skipped_backoff_count"`
	RefuseCount             int64     `json:"refuse_count"`
	PolicyClampedCount      int64     `json:"policy_clamped_count"`
	HMACRejectCount         int64     `json:"hmac_reject_count"`
}

// Snapshot returns a point-in-time copy of all counter values. Caller
// observes a consistent view of each counter individually; counters are
// NOT mutually consistent (one counter may advance between two reads
// inside the snapshot). This is acceptable for ops-visibility metrics.
func (m *Metrics) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{
		LastTickAt:              m.LastTick(),
		DueCount:                m.DueCount.Load(),
		DispatchedCount:         m.DispatchedCount.Load(),
		SkippedMaintenanceCount: m.SkippedMaintenanceCount.Load(),
		SkippedBackoffCount:     m.SkippedBackoffCount.Load(),
		RefuseCount:             m.RefuseCount.Load(),
		PolicyClampedCount:      m.PolicyClampedCount.Load(),
		HMACRejectCount:         m.HMACRejectCount.Load(),
	}
}
