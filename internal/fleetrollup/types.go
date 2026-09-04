package fleetrollup

import (
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/compliance"
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

// Score is the fleet-wide compliance summary.
//
// Score is the EQUAL-HOST MEAN of the per-host scores: every host counts once,
// whatever its rule count. It replaces a pooled ratio over every rule row, under
// which a host carrying 800 rules outweighed one carrying 40 by twenty to one
// and the "fleet score" was really a weighted average of rule counts.
//
// It can be absent. An empty fleet, or a fleet where no host produced a verdict,
// has no score, and the old Score{0, 0} reported that as zero percent compliant.
//
// HostsScored and HostsWithoutScore are the population the mean was taken over.
// A mean without its denominator cannot be told from a mean over every host.
//
// There is deliberately no rule-level evaluation count. It was the denominator
// of the pooled fraction this replaced, and it stopped meaning anything once the
// score became a mean over hosts. A caller that needs the size of the corpus a
// score was computed over counts host_rule_state_current, which is the thing
// itself rather than a number that used to imply it.
// Spec system-fleet-rollup C-05, AC-01 to AC-03.
type Score struct {
	Score compliance.Score
	// HostsScored + HostsWithoutScore == HostsTotal, always. HostsTotal is
	// every active host, so a host that was never scanned, produced nothing, or
	// carries no rule matching the lens is counted as unscored rather than
	// omitted from the population entirely.
	// Counts and Coverage come from the SAME query as Score. Read separately
	// they could describe a fleet one scan apart from the number they explain.
	Counts   compliance.Counts
	Coverage compliance.Coverage

	HostsScored       int
	HostsWithoutScore int
	HostsTotal        int

	// Lens is the single framework every host was scored against, as resolved
	// by the caller. It travels with the number because a percentage that
	// cannot name its rule set reconciles with nothing.
	Lens string

	// Engines are the engine versions that produced the contributing outcomes,
	// with how many SCORED hosts each covers, copied from each host's scan run.
	// HostsWithoutEngine counts the scored hosts whose run recorded none. The
	// two together are what let an aggregate say "partially identified" rather
	// than reporting one version as if everyone agreed.
	Engines            []compliance.EngineContributor
	HostsWithoutEngine int
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

// ConnectivityBreakdown is the 4-state per-host count breakdown for
// the Settings → Scanning & monitoring page. Spec
// api-fleet-connectivity-breakdown.
//
// Bands come from consecutive_failures hysteresis:
//
//	online       — reachable + consecutive_failures=0
//	degraded     — reachable + consecutive_failures>=1
//	critical     — unreachable + consecutive_failures<3
//	down         — consecutive_failures>=3 (regardless of status)
//	never_probed — no host_liveness row exists
//
// The five counts sum to the count of active hosts.
type ConnectivityBreakdown struct {
	Online      int64 `json:"online"`
	Degraded    int64 `json:"degraded"`
	Critical    int64 `json:"critical"`
	Down        int64 `json:"down"`
	NeverProbed int64 `json:"never_probed"`
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
