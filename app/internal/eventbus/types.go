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
)

// AllEventKinds is the closed set, in registration order. Spec AC-07's
// reflection-style check counts this slice.
var AllEventKinds = []EventKind{
	EventKindHeartbeatPulse,
	EventKindDriftDetected,
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
