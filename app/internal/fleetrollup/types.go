package fleetrollup

import (
	"time"

	"github.com/google/uuid"
)

// MaxLimit is the hard upper bound on every paginated query. Per
// Spec C-03 / C-04, regardless of caller input.
const MaxLimit = 1000

// ReachabilityStatus is the closed enum FleetLiveness reports counts
// for. Mirrors host_liveness.reachability_status plus the synthesized
// "never_probed" bucket for hosts with no row in host_liveness yet.
type ReachabilityStatus string

const (
	StatusReachable   ReachabilityStatus = "reachable"
	StatusUnreachable ReachabilityStatus = "unreachable"
	StatusUnknown     ReachabilityStatus = "unknown"
	StatusNeverProbed ReachabilityStatus = "never_probed"
)

// AllReachabilityStatuses is the closed set in display order. Spec AC-04.
var AllReachabilityStatuses = []ReachabilityStatus{
	StatusReachable,
	StatusUnreachable,
	StatusUnknown,
	StatusNeverProbed,
}

// Score is the fleet-wide compliance summary. PassingFraction is 0..1;
// multiply by 100 for percentage at the UI. TotalEvaluations is the
// count of host_rule_state rows whose current_status is pass or fail
// (skipped / error rows are excluded). Spec AC-01 / AC-03.
type Score struct {
	PassingFraction  float64 `json:"passing_fraction"`
	TotalEvaluations int64   `json:"total_evaluations"`
}

// LivenessRollup is the host-count breakdown by reachability status.
// The four counts sum to len(hosts WHERE deleted_at IS NULL). Spec AC-04.
type LivenessRollup struct {
	Reachable   int64 `json:"reachable"`
	Unreachable int64 `json:"unreachable"`
	Unknown     int64 `json:"unknown"`
	NeverProbed int64 `json:"never_probed"`
}

// Total returns the sum of all four buckets. Convenience method for
// callers that want a denominator.
func (l LivenessRollup) Total() int64 {
	return l.Reachable + l.Unreachable + l.Unknown + l.NeverProbed
}

// RuleFailureRollup is one entry in TopFailingRules.
type RuleFailureRollup struct {
	RuleID           string `json:"rule_id"`
	FailingHostCount int64  `json:"failing_host_count"`
}

// HostFailureRollup is one entry in TopFailingHosts.
type HostFailureRollup struct {
	HostID           uuid.UUID `json:"host_id"`
	FailingRuleCount int64     `json:"failing_rule_count"`
}

// TransactionRollup is one entry in RecentChanges. Mirrors a
// transactions row plus the change_kind so the UI can render
// "first_seen", "state_changed", "severity_changed" distinctly.
type TransactionRollup struct {
	ID         uuid.UUID `json:"id"`
	HostID     uuid.UUID `json:"host_id"`
	RuleID     string    `json:"rule_id"`
	Status     string    `json:"status"`
	Severity   string    `json:"severity,omitempty"`
	ChangeKind string    `json:"change_kind"`
	OccurredAt time.Time `json:"occurred_at"`
}

// clampLimit enforces the hard upper bound + non-negative invariant.
// Spec AC-10.
func clampLimit(limit int) int {
	if limit <= 0 {
		return 0
	}
	if limit > MaxLimit {
		return MaxLimit
	}
	return limit
}
