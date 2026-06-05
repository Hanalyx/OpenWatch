package activity

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Source classifies which underlying table produced a Row. Stored as
// the 'source' literal column in the UNION query.
type Source string

const (
	SourceAlert        Source = "alert"
	SourceTransaction  Source = "transaction"
	SourceIntelligence Source = "intelligence"
	SourceAudit        Source = "audit"
	// SourceMonitoring projects host_monitoring_history band-transition
	// rows into the unified feed. Spec system-activity v1.1.0 C-08.
	SourceMonitoring Source = "monitoring"
)

// AllSources is the registration-order list.
var AllSources = []Source{
	SourceAlert,
	SourceTransaction,
	SourceIntelligence,
	SourceAudit,
	SourceMonitoring,
}

// IsKnownSource reports whether s is in the closed Source enum.
func IsKnownSource(s string) bool {
	for _, k := range AllSources {
		if string(k) == s {
			return true
		}
	}
	return false
}

// Severity is the closed enum used by the union (info/low/medium/high/critical).
// Audit-event rows whose native severity is warning|error are mapped
// to medium|high in the SELECT to fit the closed set.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// AllSeverities is the registration-order list.
var AllSeverities = []Severity{
	SeverityInfo,
	SeverityLow,
	SeverityMedium,
	SeverityHigh,
	SeverityCritical,
}

// IsKnownSeverity reports whether s is in the closed Severity enum.
func IsKnownSeverity(s string) bool {
	for _, k := range AllSeverities {
		if string(k) == s {
			return true
		}
	}
	return false
}

// Row is one entry in the activity feed.
type Row struct {
	ID         uuid.UUID
	Source     Source
	Severity   Severity
	HostID     *uuid.UUID // nil for audit / system rows
	Title      string
	Summary    string
	OccurredAt time.Time
}

// Filter narrows the union query. Empty fields are wildcards.
type Filter struct {
	Source   string // "" or one of AllSources
	Severity string // "" or one of AllSeverities
	HostID   *uuid.UUID
	Since    *time.Time
	Until    *time.Time
	Cursor   string
	Limit    int
}

// Caller is the per-source permission gate. A caller without
// CanReadAlerts sees zero alert rows; etc. The activity service
// reports the count hidden by the gate so the UI can render an honest
// "N visible / M hidden" line.
type Caller struct {
	CanReadAlerts bool
	CanReadHosts  bool
	CanReadAudit  bool
}

// Sentinel errors.
var (
	// ErrInvalidLimit is returned when limit is outside [1, 200].
	ErrInvalidLimit = errors.New("activity: limit must be in [1, 200]")

	// ErrInvalidSource is returned when filter.Source is non-empty
	// and not in the closed enum.
	ErrInvalidSource = errors.New("activity: invalid source")

	// ErrInvalidSeverity is returned when filter.Severity is non-empty
	// and not in the closed enum.
	ErrInvalidSeverity = errors.New("activity: invalid severity")
)
