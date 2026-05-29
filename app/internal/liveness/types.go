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
