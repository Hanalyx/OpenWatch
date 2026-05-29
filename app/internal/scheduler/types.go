// Package scheduler implements the adaptive compliance scan scheduler.
//
// Spec: specs/system/scheduler.spec.yaml
//
// Responsibilities:
//   - Load tier intervals from the Ed25519-signed schedules policy at boot
//     and verify on every runtime reload
//   - Run a 60-second cron tick that sweeps host_compliance_schedule for
//     hosts whose next_scheduled_scan has passed
//   - Dispatch scan jobs via internal/queue using SELECT ... FOR UPDATE
//     SKIP LOCKED so concurrent tick processes pick disjoint hosts
//   - Sign every dispatched job payload with an HMAC over the load-bearing
//     fields so post-enqueue tampering is caught at dequeue
//   - After each scan completes, compute the next-scan time from the
//     resulting compliance state
//   - Respect maintenance mode (system-wide and per-host) and per-host
//     backoff after consecutive failures
//
// Architectural choices:
//   - host_compliance_schedule writes are scheduler-owned. The executor
//     never writes to this table; it reports back via UpdateAfterScan.
//   - Per-host failure backoff lives in host_backoff_state (separate
//     table) so executor-domain writes don't touch scheduler-domain rows.
//   - Manual scans via POST /scans bypass the scheduler entirely — they
//     don't lock the schedule row, don't update next_scheduled_scan, and
//     don't consume the per-host concurrency slot at the scheduler tier
//     (the executor's in-memory sync.Map catches that).
package scheduler

import (
	"time"
)

// ComplianceState classifies a host's overall compliance posture and
// is the input to the tier-interval lookup. The string values are
// persisted to host_compliance_schedule.compliance_state.
type ComplianceState string

const (
	StateUnknown      ComplianceState = "unknown"
	StateCritical     ComplianceState = "critical"
	StateNonCompliant ComplianceState = "non_compliant"
	StatePartial      ComplianceState = "partial"
	StateCompliant    ComplianceState = "compliant"
)

// Hard safety floors / ceilings — spec C-04, C-08. Independent of policy
// values; policy intervals are clamped into [MinIntervalFloor, MaxIntervalCap]
// at load time and the clamp is audited.
const (
	MinIntervalFloor = 5 * time.Minute
	MaxIntervalCap   = 48 * time.Hour
)

// TierLadder maps a ComplianceState to the interval between scans for
// hosts in that state. Populated by LoadIntervals from policy.Schedules.
//
// Missing entries default to MaxIntervalCap rather than the policy's
// fallback so an under-specified policy can never produce a too-fast scan.
type TierLadder map[ComplianceState]time.Duration

// PolicyTiers is the input shape that LoadIntervals consumes — a flat
// map of state-name → minutes from the parsed schedules policy. This is
// intentionally decoupled from the policy package so tests in this
// package don't need a signed policy file; the real policy loader is
// wired in cmd/openwatch/main.go.
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
