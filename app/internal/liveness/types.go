package liveness

import (
	"errors"
	"time"
)

// Status classifies a host's current reachability. Stored as TEXT with a
// CHECK constraint in host_liveness.reachability_status.
type Status string

const (
	StatusUnknown     Status = "unknown"
	StatusReachable   Status = "reachable"
	StatusUnreachable Status = "unreachable"
)

// MonitoringState is the 5-band classification surfaced to the operator
// (v1.3.0). Derived from the multi-layer probe outcome: it tells the UI
// not just "up or down" but WHICH layer is failing.
//
//	online       — ping + SSH + privilege all OK
//	degraded     — ping + SSH OK, privilege (sudo) failing
//	critical     — ping OK, SSH/TCP-22 failing
//	down         — no ping; host is off the network
//	maintenance  — explicitly excluded from probes (per-host or global)
//	unknown      — added but not yet probed
//
// Stored as TEXT with a CHECK constraint in host_liveness.monitoring_state.
type MonitoringState string

const (
	StateOnline      MonitoringState = "online"
	StateDegraded    MonitoringState = "degraded"
	StateCritical    MonitoringState = "critical"
	StateDown        MonitoringState = "down"
	StateMaintenance MonitoringState = "maintenance"
	StateUnknown     MonitoringState = "unknown"
)

// FailedLayer names the lowest layer that failed in a multi-layer probe.
// Empty string when all layers passed. Surface for diagnostics and for
// the state machine's transition logic.
type FailedLayer string

const (
	LayerNone      FailedLayer = ""
	LayerPing      FailedLayer = "ping"
	LayerSSH       FailedLayer = "ssh"
	LayerPrivilege FailedLayer = "privilege"
)

// MultiLayerResult is the structured outcome of one multi-layer probe
// (ping → TCP/SSH banner → SSH auth + sudo). Each layer is short-circuit
// evaluated: if ping fails we don't try SSH; if SSH fails we don't try
// privilege. Per-layer fields stay zero when the layer wasn't attempted.
type MultiLayerResult struct {
	// PingOK is true when ICMP Echo Request received a matching reply
	// within the timeout. False on timeout, destination unreachable, or
	// socket error.
	PingOK  bool
	PingRTT time.Duration
	PingErr error

	// SSHOK is true when TCP-22 accepted a connection AND the server's
	// banner began with "SSH-". A non-SSH banner on port 22 is SSHOk=false.
	SSHOK        bool
	SSHRTT       time.Duration
	SSHBanner    []byte
	SSHErr       error
	SSHAttempted bool // true if ping succeeded so SSH was tried

	// PrivilegeOK is true when an SSH session authenticated successfully
	// AND `sudo -n true` returned exit 0. Skipped when SSH layer failed
	// or when no usable credential exists for the host.
	PrivilegeOK        bool
	PrivilegeRTT       time.Duration
	PrivilegeErr       error
	PrivilegeAttempted bool

	// TotalRTT is the wall-clock cost of the whole multi-layer probe.
	TotalRTT time.Duration

	// FirstFailedLayer names the lowest layer that failed. LayerNone
	// when every attempted layer passed. The state machine uses this
	// directly to pick the destination band.
	FirstFailedLayer FailedLayer
}

// Reachable reports whether the host satisfies the legacy "SSH banner"
// criterion. Used to map MultiLayerResult onto the existing
// host_liveness.reachability_status (3-value) enum so the v1.3.0
// rollout doesn't break callers that haven't migrated to the
// multi-layer view yet.
func (m MultiLayerResult) Reachable() bool { return m.SSHOK }

// AsProbeResult flattens a MultiLayerResult into the legacy ProbeResult
// shape so all the existing single-layer code paths (persist hysteresis
// against reachability_status, audit emission, etc.) keep working
// unchanged. Multi-layer fields live alongside it on the persisted row.
func (m MultiLayerResult) AsProbeResult() ProbeResult {
	r := ProbeResult{
		Reachable:    m.SSHOK,
		ResponseTime: m.TotalRTT,
		BannerSeen:   len(m.SSHBanner) > 0,
		Banner:       m.SSHBanner,
	}
	switch {
	case m.PingErr != nil && !m.PingOK:
		r.Error = m.PingErr
	case m.SSHErr != nil && !m.SSHOK:
		r.Error = m.SSHErr
	case m.PrivilegeErr != nil && !m.PrivilegeOK:
		r.Error = m.PrivilegeErr
	}
	return r
}

// Probe-cadence safety limits. Spec C-03 enforces the [60s, 3600s] range
// independent of policy.Liveness.IntervalSec. Defaults sized for typical
// fleet sizes (1000 hosts × 5 min cadence = ~3 probes/sec — trivial).
const (
	DefaultProbeInterval = 5 * time.Minute
	MinProbeInterval     = 60 * time.Second
	MaxProbeInterval     = 60 * time.Minute

	// DefaultProbeTimeout is the per-probe wall-clock budget. Spec C-02.
	// Net.DialTimeout returns within this window; the banner read uses
	// a deadline of (Now + timeout) so the whole probe stays bounded.
	DefaultProbeTimeout = 5 * time.Second

	// DefaultUnreachableThreshold is the consecutive-failure count
	// before flipping reachable→unreachable. Spec C-08.
	DefaultUnreachableThreshold = 2

	// JitterFactor is the ±20% probe-scheduling jitter. Spec C-04.
	JitterFactor = 0.20

	// MaxBannerBytes is the upper bound on banner-read length.
	// SSH banners are short (typically <100 bytes); 256 is plenty.
	MaxBannerBytes = 256
)

// ProbeResult is the structured outcome of one probe attempt.
// Spec AC-01: returned by liveness.Probe.
type ProbeResult struct {
	// Reachable is true when the probe established a TCP connection AND
	// (when banner is enabled) the server's banner began with "SSH-".
	Reachable bool

	// ResponseTime is the wall-clock elapsed time from dial start to
	// banner read completion (or connection close on failure). Always
	// populated; zero only on impossible-input errors.
	ResponseTime time.Duration

	// BannerSeen is true when at least one byte was read from the
	// server. A connect-success with no banner returned is BannerSeen=false.
	BannerSeen bool

	// Banner holds the bytes actually read (truncated at MaxBannerBytes).
	// Populated only on success or non-empty error. Empty on
	// dial-timeout / connection-refused.
	Banner []byte

	// Error classifies the failure mode. nil on success. The error's
	// type ladder maps to the host_liveness.last_error_type column:
	//   net.OpError (timeout) → "tcp_timeout"
	//   net.OpError (refused) → "connection_refused"
	//   "non-SSH banner"      → "banner_mismatch"
	Error error
}

// ErrProbeInFlight is returned by Service.ProbeHost when a probe for
// the same host_id is already running. Spec C-05.
var ErrProbeInFlight = errors.New("liveness: probe already in flight for this host")

// LastErrorType returns the spec-defined detail string for the
// host_liveness.last_error_type column. Used by Service.persist.
func (p ProbeResult) LastErrorType() string {
	if p.Error == nil {
		return ""
	}
	if isTimeoutError(p.Error) {
		return "tcp_timeout"
	}
	msg := p.Error.Error()
	if containsConnectionRefused(msg) {
		return "connection_refused"
	}
	if containsBannerMismatch(msg) {
		return "banner_mismatch"
	}
	return "tcp_error"
}

// Probe-classification helpers. Centralized here so tests can verify
// the exact substring rules without reaching into the probe package.

func containsConnectionRefused(s string) bool {
	return contains(s, "connection refused")
}

func containsBannerMismatch(s string) bool {
	return contains(s, "non-SSH banner")
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && stringContainsFold(haystack, needle)
}

// stringContainsFold is a lightweight strings.Contains so types.go has
// no imports beyond errors + time. Tests use strings.Contains directly.
func stringContainsFold(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// isTimeoutError is satisfied by net.Error implementations whose
// Timeout() returns true. Defined here as an interface-shaped check so
// callers don't need to import net for the type-assertion.
func isTimeoutError(err error) bool {
	type timeoutI interface {
		Timeout() bool
	}
	t, ok := err.(timeoutI)
	return ok && t.Timeout()
}
