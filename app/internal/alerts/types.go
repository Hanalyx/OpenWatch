package alerts

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// State is the closed-enum alert state.
type State string

const (
	StateActive       State = "active"
	StateAcknowledged State = "acknowledged"
	StateSilenced     State = "silenced"
	StateResolved     State = "resolved"
	StateDismissed    State = "dismissed"
)

// AllStates is the registration-order list.
var AllStates = []State{
	StateActive,
	StateAcknowledged,
	StateSilenced,
	StateResolved,
	StateDismissed,
}

// IsKnownState reports whether s is a valid State.
func IsKnownState(s string) bool {
	for _, k := range AllStates {
		if string(k) == s {
			return true
		}
	}
	return false
}

// Severity is the closed-enum severity (mirrors system-alert-router).
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// AllSeverities is the registration-order list.
var AllSeverities = []Severity{
	SeverityCritical,
	SeverityHigh,
	SeverityMedium,
	SeverityLow,
	SeverityInfo,
}

// IsKnownSeverity reports whether s is a valid Severity.
func IsKnownSeverity(s string) bool {
	for _, k := range AllSeverities {
		if string(k) == s {
			return true
		}
	}
	return false
}

// Alert is the persisted alert row + lifecycle metadata.
type Alert struct {
	ID         uuid.UUID
	DedupKey   string
	Type       string
	Severity   Severity
	HostID     uuid.UUID // uuid.Nil when no host (system alerts)
	RuleID     string
	Title      string
	Body       string
	Tags       map[string]string
	State      State
	OccurredAt time.Time

	// Lifecycle metadata — nil pointers when the corresponding
	// transition hasn't happened.
	AcknowledgedBy *uuid.UUID
	AcknowledgedAt *time.Time
	SilencedBy     *uuid.UUID
	SilencedUntil  *time.Time
	ResolvedBy     *uuid.UUID
	ResolvedAt     *time.Time
	DismissedBy    *uuid.UUID
	DismissedAt    *time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
}

// ListFilter narrows the List query.
type ListFilter struct {
	State    *string
	HostID   *uuid.UUID
	Severity *string
	Since    *time.Time
	Until    *time.Time

	Cursor string
	Limit  int
}

// Sentinel errors. Wrap with %w so callers can errors.Is them.
var (
	// ErrAlertNotFound is returned by Get and the lifecycle methods
	// when the id is unknown. Spec AC-14.
	ErrAlertNotFound = errors.New("alerts: not found")

	// ErrInvalidTransition is returned when the requested transition
	// is not allowed by the closed state machine (C-02).
	ErrInvalidTransition = errors.New("alerts: invalid state transition")

	// ErrInvalidSilenceWindow is returned by Silence when until is in
	// the past (C-03).
	ErrInvalidSilenceWindow = errors.New("alerts: silenced_until must be in the future")
)
