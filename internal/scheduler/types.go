// Package scheduler implements the adaptive compliance scan scheduler.
//
// Spec: specs/system/scheduler.spec.yaml (v3.0.0)
//
// Responsibilities:
//   - Load tier intervals from the operator-editable systemconfig scan
//     config (LoadFromConfig; scan plan decision #4 — the v2 signed
//     schedules-policy file is gone) and refresh them before every tick
//   - Run a 60-second cron tick that sweeps host_compliance_schedule for
//     hosts whose next_scheduled_scan has passed
//   - Dispatch scan jobs via internal/queue using SELECT ... FOR UPDATE
//     SKIP LOCKED so concurrent tick processes pick disjoint hosts
//   - Sign every dispatched job payload with an HMAC over the load-bearing
//     fields so post-enqueue tampering is caught at dequeue
//   - After each scan completes (scheduler-dispatched OR on-demand),
//     classify the result into one of the five score bands + unknown
//     and re-anchor next_scheduled_scan (PersistAfterScan)
//   - Respect maintenance mode (config-global and per-host) and the
//     config Enabled flag; per-host backoff after consecutive failures
//
// Architectural choices:
//   - host_compliance_schedule writes are scheduler-owned. The executor
//     never writes to this table; the worker reports back via
//     Service.PersistAfterScan.
//   - Per-host failure backoff lives in host_backoff_state (separate
//     table) so executor-domain writes don't touch scheduler-domain rows.
//   - Manual scans via POST /scans bypass DISPATCH (no schedule-row lock,
//     no dispatch-time advancement, no scheduler concurrency slot), but
//     their completion updates the row like any other scan — a manual
//     scan postpones the next auto scan instead of stacking onto it.
package scheduler

import (
	"context"
	"time"

	"github.com/Hanalyx/openwatch/internal/audit"
)

// ComplianceState classifies a host's overall compliance posture and
// is the input to the tier-interval lookup. The string values are
// persisted to host_compliance_schedule.compliance_state.
type ComplianceState string

const (
	StateUnknown         ComplianceState = "unknown"
	StateCritical        ComplianceState = "critical"
	StateNonCompliant    ComplianceState = "non_compliant"
	StatePartial         ComplianceState = "partial"
	StateMostlyCompliant ComplianceState = "mostly_compliant"
	StateCompliant       ComplianceState = "compliant"
)

// AllStates lists every ComplianceState in ladder order (riskiest
// first, unknown last). The five score bands match the prototype
// (scan plan decision #5, resolved 2026-06-12); unknown covers
// never-scanned hosts. Exported so the fleet-states endpoint and the
// Settings UI iterate the same canonical order.
func AllStates() []ComplianceState {
	return []ComplianceState{
		StateCritical,
		StateNonCompliant,
		StatePartial,
		StateMostlyCompliant,
		StateCompliant,
		StateUnknown,
	}
}

// Hard safety floors / ceilings — spec C-04, C-08. Independent of policy
// values; policy intervals are clamped into [MinIntervalFloor, MaxIntervalCap]
// at load time and the clamp is audited.
const (
	MinIntervalFloor = 5 * time.Minute
	MaxIntervalCap   = 48 * time.Hour
)

// TierLadder maps a ComplianceState to the interval between scans for
// hosts in that state. Populated by LoadIntervals via LoadFromConfig.
//
// Missing entries default to MaxIntervalCap rather than the policy's
// fallback so an under-specified policy can never produce a too-fast scan.
type TierLadder map[ComplianceState]time.Duration

// PolicyTiers is the input shape that LoadIntervals consumes — a flat
// map of state-name → minutes. v3.0.0: produced by LoadFromConfig from
// the systemconfig scan config; the name predates the config migration
// and is kept so the clamp pipeline (LoadIntervals) stays unchanged.
type PolicyTiers struct {
	Version      string                  // policy.Schedules.Version snapshot
	IntervalMins map[ComplianceState]int // tier → minutes
}

// LoadResult is what LoadIntervals returns: the clamped ladder plus a
// list of clamp events suitable for emitting as scheduler.policy.clamped
// audit events.
type LoadResult struct {
	Ladder        TierLadder
	PolicyVersion string
	Clamps        []ClampRecord
}

// ClampRecord describes a single tier value that was clamped. Emitted as
// detail in the scheduler.policy.clamped audit event.
type ClampRecord struct {
	State           ComplianceState
	OriginalMinutes int
	ClampedMinutes  int
	Kind            ClampKind
}

// ClampKind matches the detail.clamp_kind enum on scheduler.policy.clamped.
type ClampKind string

const (
	ClampMinFloor   ClampKind = "min_floor"
	ClampMaxCeiling ClampKind = "max_ceiling"
)

// EmitFunc is the audit-emission shape the scheduler depends on. Matches
// audit.Emit's signature so cmd/openwatch wires the real audit emitter
// in by passing audit.Emit directly; tests pass a fake that records calls.
type EmitFunc func(ctx context.Context, code audit.Code, ev audit.Event)
