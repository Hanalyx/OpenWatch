package alertrouter

import "sync/atomic"

// Metrics holds the router's runtime counters. Spec AC-14.
type Metrics struct {
	// ReceivedCount is the count of bus events the router translated
	// into Alert values (pre-dedup).
	ReceivedCount atomic.Int64

	// RoutedCount is the count of (alert, channel) pairs where the
	// channel's tag filter matched and Send was invoked. Counts each
	// channel delivery for a fan-out alert.
	RoutedCount atomic.Int64

	// DedupedCount is the count of alerts skipped by the dedup gate.
	// Per Spec C-03, these never reach Channel.Send.
	DedupedCount atomic.Int64

	// ChannelFailureCount is the aggregate count of Channel.Send calls
	// that returned an error. Per-channel counters are tracked on
	// channelEntry.failureCount.
	ChannelFailureCount atomic.Int64
}

// NewMetrics returns a fresh Metrics.
func NewMetrics() *Metrics { return &Metrics{} }

// MetricsSnapshot is a JSON-friendly point-in-time snapshot.
type MetricsSnapshot struct {
	ReceivedCount       int64 `json:"received_count"`
	RoutedCount         int64 `json:"routed_count"`
	DedupedCount        int64 `json:"deduped_count"`
	ChannelFailureCount int64 `json:"channel_failure_count"`
}

// Snapshot returns a point-in-time copy of all counters.
func (m *Metrics) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{
		ReceivedCount:       m.ReceivedCount.Load(),
		RoutedCount:         m.RoutedCount.Load(),
		DedupedCount:        m.DedupedCount.Load(),
		ChannelFailureCount: m.ChannelFailureCount.Load(),
	}
}
