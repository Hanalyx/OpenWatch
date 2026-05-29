package alertrouter

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AlertType is the closed enum of alert types the router can emit.
// Spec C-01 / AC-01.
type AlertType string

const (
	// AlertTypeHostUnreachable is raised when the liveness loop
	// transitions a host from reachable to unreachable.
	AlertTypeHostUnreachable AlertType = "host_unreachable"

	// AlertTypeHostRecovered is raised when a previously unreachable
	// host becomes reachable again.
	AlertTypeHostRecovered AlertType = "host_recovered"

	// AlertTypeDriftMajor is raised when the drift detector classifies
	// a scan as a major worsening.
	AlertTypeDriftMajor AlertType = "drift_major"

	// AlertTypeDriftMinor is raised when the drift detector classifies
	// a scan as a minor worsening.
	AlertTypeDriftMinor AlertType = "drift_minor"

	// AlertTypeDriftImprovement is raised when the drift detector
	// classifies a scan as an improvement.
	AlertTypeDriftImprovement AlertType = "drift_improvement"
)

// AllAlertTypes is the closed set, in registration order. Spec AC-01's
// reflection-style check counts this slice.
var AllAlertTypes = []AlertType{
	AlertTypeHostUnreachable,
	AlertTypeHostRecovered,
	AlertTypeDriftMajor,
	AlertTypeDriftMinor,
	AlertTypeDriftImprovement,
}

// Severity is the closed enum of alert severities. Spec C-02 / AC-02.
type Severity string

const (
	// SeverityCritical is the highest severity. Used for pager-quality
	// events that must wake someone.
	SeverityCritical Severity = "critical"

	// SeverityHigh is one tier below Critical. Notifies via primary
	// channels (Slack #alerts, email).
	SeverityHigh Severity = "high"

	// SeverityMedium is the default for noteworthy-but-not-urgent
	// events.
	SeverityMedium Severity = "medium"

	// SeverityLow is informational with a slight nudge — surfaced in
	// digest channels.
	SeverityLow Severity = "low"

	// SeverityInfo is purely informational (e.g., a host recovered).
	SeverityInfo Severity = "info"
)

// AllSeverities is the closed set in descending order
// (critical → info). Spec AC-02.
var AllSeverities = []Severity{
	SeverityCritical,
	SeverityHigh,
	SeverityMedium,
	SeverityLow,
	SeverityInfo,
}

// SeverityOrder gives each severity a numeric rank for comparison.
// Lower number = higher severity (critical=0, info=4). Spec AC-02.
var SeverityOrder = map[Severity]int{
	SeverityCritical: 0,
	SeverityHigh:     1,
	SeverityMedium:   2,
	SeverityLow:      3,
	SeverityInfo:     4,
}

// defaultSeverityFor returns the Severity the router applies before
// channel routing for a given AlertType. Spec C-02.
func defaultSeverityFor(t AlertType) Severity {
	switch t {
	case AlertTypeHostUnreachable:
		return SeverityHigh
	case AlertTypeHostRecovered:
		return SeverityInfo
	case AlertTypeDriftMajor:
		return SeverityHigh
	case AlertTypeDriftMinor:
		return SeverityMedium
	case AlertTypeDriftImprovement:
		return SeverityInfo
	default:
		return SeverityMedium
	}
}

// Alert is a typed alert produced by the router from a bus event.
// Channel implementations receive Alert values; they may format with
// String() or render their own way from the structured fields.
type Alert struct {
	Type       AlertType
	Severity   Severity
	HostID     uuid.UUID
	RuleID     string // empty when not rule-scoped (host_unreachable, host_recovered)
	OccurredAt time.Time

	// Title is a one-line summary suitable for a channel header.
	Title string

	// Body carries human-readable detail. Channel implementations may
	// wrap this in their native format (Slack blocks, email body, etc.).
	Body string

	// Tags carries routable metadata. At minimum: severity + alert_type
	// + host_id (populated by the router). Spec C-06.
	Tags map[string]string
}

// DedupKey returns the (alert_type|host_id|rule_id) tuple used by the
// dedup gate. Spec C-03.
func (a Alert) DedupKey() string {
	return fmt.Sprintf("%s|%s|%s", a.Type, a.HostID, a.RuleID)
}

// String returns a single-line summary of the alert. Used by the
// stdout channel and as a fallback for channels without a custom
// renderer.
func (a Alert) String() string {
	return fmt.Sprintf("[%s] %s — %s", a.Severity, a.Type, a.Title)
}

// Channel is the contract every notification channel implements.
// Implementations (Slack, email, webhook) live in subpackages so the
// core router has no external SDK dependencies. Spec C-09.
type Channel interface {
	// Name returns the channel's identifier. Used in metrics + logs.
	Name() string

	// Send delivers the alert. An error increments the channel's
	// FailureCount but does not halt delivery to other channels for the
	// same alert. Spec C-07.
	Send(ctx context.Context, alert Alert) error
}

// ChannelRegistration binds a Channel to a tag filter.
type ChannelRegistration struct {
	// Channel is the implementation that receives matching alerts.
	Channel Channel

	// Tags is the required filter: every key/value pair must be present
	// in Alert.Tags for the channel to receive. An empty Tags map is a
	// wildcard (channel receives every alert). Spec C-05.
	Tags map[string]string
}

// matches reports whether the alert satisfies the channel's tag filter.
// Empty Tags = wildcard. Spec AC-08 / AC-09.
func (r ChannelRegistration) matches(alert Alert) bool {
	if len(r.Tags) == 0 {
		return true
	}
	for k, v := range r.Tags {
		if alert.Tags[k] != v {
			return false
		}
	}
	return true
}

// MinDedupTTL is the lower bound on the dedup TTL — anything shorter
// flattens the dedup gate to a no-op. Spec C-04.
const MinDedupTTL = 60 * time.Second

// MaxDedupTTL is the upper bound on the dedup TTL — anything longer is
// likely a misconfiguration that suppresses real recurrences. Spec C-04.
const MaxDedupTTL = 24 * time.Hour

// DefaultDedupTTL is the policy default when no explicit TTL is
// configured. Spec C-04.
const DefaultDedupTTL = 60 * time.Minute

// ErrDedupTTLOutOfRange is returned by ValidateDedupTTL when the
// configured TTL falls outside [MinDedupTTL, MaxDedupTTL]. Spec AC-15.
var ErrDedupTTLOutOfRange = errors.New("alertrouter: dedup TTL must be between 60s and 24h")

// ValidateDedupTTL enforces the policy range on the configurable dedup
// TTL. Spec AC-15 / C-04.
func ValidateDedupTTL(ttl time.Duration) error {
	if ttl < MinDedupTTL || ttl > MaxDedupTTL {
		return fmt.Errorf("%w: got %s", ErrDedupTTLOutOfRange, ttl)
	}
	return nil
}
