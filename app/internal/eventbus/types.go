package eventbus

import (
	"time"

	"github.com/google/uuid"
)

// EventKind is the closed enum classifying every event the bus carries.
// Spec C-02 / AC-07.
type EventKind string

const (
	// EventKindHeartbeatPulse is emitted by the B.2a liveness loop on
	// reachability state transitions (reachable ↔ unreachable).
	EventKindHeartbeatPulse EventKind = "heartbeat.pulse"

	// EventKindDriftDetected is emitted by the B.2b drift detector on
	// any non-stable scan outcome (major_worsening / minor_worsening /
	// improvement).
	EventKindDriftDetected EventKind = "drift.detected"

	// EventKindHostChanged is emitted by host CRUD handlers (create,
	// update, soft-delete, maintenance toggle) so the UI can refresh
	// the list/detail without polling. v1.3.0 (Track B SSE).
	EventKindHostChanged EventKind = "host.changed"

	// EventKindMonitoringBandChanged fires on multi-layer band
	// transitions (online → degraded, etc.). v1.3.0 (Track B SSE).
	// The HeartbeatPulse event predates the multi-layer model — this
	// new kind carries the richer band string so the UI can update
	// the StatusPill without re-fetching the host.
	EventKindMonitoringBandChanged EventKind = "monitoring.band.changed"
)

// AllEventKinds is the closed set, in registration order. Spec AC-07's
// reflection-style check counts this slice.
var AllEventKinds = []EventKind{
	EventKindHeartbeatPulse,
	EventKindDriftDetected,
	EventKindHostChanged,
	EventKindMonitoringBandChanged,
}

// Event is the contract every bus event satisfies. Implementations are
// typed structs (HeartbeatPulse, DriftDetected) — the interface lets
// the bus dispatch generically while preserving type information for
// subscribers via type assertion.
type Event interface {
	// Kind returns the EventKind. Used by the bus for filter matching.
	Kind() EventKind
	// Timestamp returns when the event was generated. The bus uses this
	// for ordering hints but doesn't enforce ordering.
	Timestamp() time.Time
}

// HeartbeatPulse is fired by the liveness loop on every state
// transition (reachable → unreachable, unreachable → reachable, or
// first-seen).
type HeartbeatPulse struct {
	HostID     uuid.UUID
	Reachable  bool
	OccurredAt time.Time

	// PriorReachable is the value before this transition.
	// Helps subscribers distinguish first-seen from recovery.
	PriorReachable bool

	// ResponseTimeMS is the probe's response time in milliseconds when
	// Reachable; zero when not.
	ResponseTimeMS int
}

// Kind satisfies Event.
func (h HeartbeatPulse) Kind() EventKind { return EventKindHeartbeatPulse }

// Timestamp satisfies Event.
func (h HeartbeatPulse) Timestamp() time.Time { return h.OccurredAt }

// DriftDetected is fired by the drift detector on every non-stable
// scan outcome. Carries the same payload shape as the audit event's
// detail for symmetry.
type DriftDetected struct {
	HostID       uuid.UUID
	ScanID       uuid.UUID
	OccurredAt   time.Time
	DriftType    string // "major" | "minor" | "improvement"
	PriorScore   float64
	CurrentScore float64
	ScoreDelta   float64 // negative on worsening

	// Per-severity transition counts. Lets alert routing rules filter
	// by severity without re-querying the transaction log.
	CriticalBecameFailing int
	HighBecameFailing     int
	MediumBecameFailing   int
	LowBecameFailing      int
	CriticalBecamePassing int
	HighBecamePassing     int
	MediumBecamePassing   int
	LowBecamePassing      int
}

// Kind satisfies Event.
func (d DriftDetected) Kind() EventKind { return EventKindDriftDetected }

// Timestamp satisfies Event.
func (d DriftDetected) Timestamp() time.Time { return d.OccurredAt }

// HostChangeKind classifies what happened to a host. Surfaces as the
// `change` field on the SSE payload so the UI can pick which TanStack
// Query keys to invalidate.
type HostChangeKind string

const (
	HostChangeCreated     HostChangeKind = "created"
	HostChangeUpdated     HostChangeKind = "updated"
	HostChangeDeleted     HostChangeKind = "deleted"
	HostChangeMaintenance HostChangeKind = "maintenance"
)

// HostChanged is fired on host CRUD events + maintenance toggle. The
// UI's useLiveEvents hook maps this to query invalidation: ['host', id]
// + ['hosts'] for create/update/delete; ['host', id] + ['hosts'] for
// maintenance (so badges flip in place).
type HostChanged struct {
	HostID     uuid.UUID
	Change     HostChangeKind
	OccurredAt time.Time
}

// Kind satisfies Event.
func (h HostChanged) Kind() EventKind { return EventKindHostChanged }

// Timestamp satisfies Event.
func (h HostChanged) Timestamp() time.Time { return h.OccurredAt }

// MonitoringBandChanged carries the v1.3.0 multi-layer band string
// (online/degraded/critical/down/maintenance/unknown). HeartbeatPulse
// stays as the legacy event for code that hasn't migrated; this is
// the richer per-band stream the SSE layer fans out.
type MonitoringBandChanged struct {
	HostID     uuid.UUID
	PriorBand  string
	NewBand    string
	OccurredAt time.Time
}

// Kind satisfies Event.
func (m MonitoringBandChanged) Kind() EventKind { return EventKindMonitoringBandChanged }

// Timestamp satisfies Event.
func (m MonitoringBandChanged) Timestamp() time.Time { return m.OccurredAt }

// DefaultBufferSize is the per-subscriber channel buffer when
// SubscribeOptions.BufferSize is zero. Spec C-04.
const DefaultBufferSize = 1024

// SubscribeOptions configures a subscriber registration.
type SubscribeOptions struct {
	// BufferSize overrides DefaultBufferSize. Useful for tests that
	// want to deterministically force drops with BufferSize = 1.
	BufferSize int

	// Kinds is the closed set of EventKinds this subscriber wants to
	// receive. An empty Kinds slice receives NOTHING (NOT all events) —
	// no wildcard subscription. Spec C-05.
	Kinds []EventKind
}
