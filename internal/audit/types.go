// Package audit emits and stores audit events per the contract in
// app/docs/audit_event_taxonomy.md and app/specs/system/audit-emission.spec.yaml.
//
// Two emission paths:
//   - Emit  (async): channel + batched insert. ~5µs per call on the
//     producer side. Used for the vast majority of events.
//   - EmitSync:     blocks until the row is committed. Reserved for
//     license install, system.startup/shutdown, and other
//     audit-before-response operations.
//
// Pre-write redaction scrubs sensitive field names from the detail JSON.
// Event codes are typed constants from events.gen.go (registry-driven, no
// raw-string emissions allowed by lint).
//
// The package never blocks audit-emission paths on DB errors: failures
// during async write are counted via the metrics.dropped counter and
// logged; the originating request always succeeds.
package audit

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Outcome is the operational result encoded on the event row.
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeDenied  Outcome = "denied"
)

// Event is the canonical envelope persisted to audit_events. All fields
// except Action are optional from the caller's perspective; the emitter
// fills in defaults (ID, OccurredAt) and the writer fills in RecordedAt.
//
// Field semantics match audit_event_taxonomy.md §3 and the audit_events
// schema from migration 0002.
type Event struct {
	// Filled by Emit if unset; UUIDv7 for time-ordered PK.
	ID uuid.UUID

	// Filled by Emit from ctx.From if unset.
	CorrelationID string

	// Required. Typed Code from events.gen.go.
	Action Code

	// When the underlying event happened. Defaults to time.Now() at Emit.
	OccurredAt time.Time

	// Severity defaults to the registry's per-event severity if zero.
	Severity Severity

	// Outcome is operation-result; empty means "n/a" (read-only events).
	Outcome Outcome

	// Actor identification.
	ActorType      string // "user" | "system" | "api_key" | "agent"
	ActorID        string // UUID or stable identifier
	ActorLabel     string // human display (email, "system")
	ActorIP        string // request remote_addr
	ActorUserAgent string
	ActorSessionID *uuid.UUID

	// Resource targeted by the action.
	ResourceType string
	ResourceID   string

	// Optional parent for child events (e.g., scan jobs → host audits).
	ParentEventID *uuid.UUID

	// Policy version active at evaluation time (policy.applied events).
	PolicyVersion string

	// Free-form detail JSON. Redaction scrubs known-sensitive field
	// names before persistence; redactions is populated automatically.
	Detail json.RawMessage

	// Filled by the writer at INSERT time, never the caller.
	Redactions []string
	RecordedAt time.Time
}

// Storage is the persistence interface the writer needs. db.Pool wrapped
// at construction time satisfies this so tests can mock without pulling
// in a full pgxpool.
type Storage interface {
	InsertEvent(ctx Ctx, ev *Event) error
}

// Ctx is the minimal context surface the storage layer requires. Aliasing
// here keeps the storage interface independent of context.Context's full
// API; production code passes a real context.Context.
type Ctx = interface {
	Deadline() (time.Time, bool)
	Done() <-chan struct{}
	Err() error
	Value(key any) any
}
