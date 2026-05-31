// Multi-layer state machine. Translates a MultiLayerResult into the
// 5-band MonitoringState, advances the per-layer consecutive counters,
// and decides whether to emit a transition audit.
//
// Rules (v1.3.0, mirroring Python's HostMonitoringStateMachine):
//
//   - All three layers pass (ping + ssh + privilege)
//     → online, reset all counters
//   - ssh OK + privilege fails for ≥ degradeThreshold
//     → degraded
//   - ping OK + ssh fails for ≥ degradeThreshold
//     → critical
//   - ping fails for ≥ downThreshold
//     → down
//   - maintenance flag set
//     → maintenance (no probe even runs; included here for completeness)
//
// Below the threshold count we hold the prior band — hysteresis keeps a
// single transient blip from flipping the UI between online and down.

package liveness

// MultiLayerThresholds tunes how many consecutive failures move a host
// down a band. Set per-band so the operator can tell the loop "I want
// degraded after 1 sudo failure but critical after 2 SSH failures."
// Defaults match Python's StateTransitionConfig.
type MultiLayerThresholds struct {
	// PingFailuresToDown — consecutive ping failures before a host drops
	// from any state into 'down'.
	PingFailuresToDown int
	// SSHFailuresToCritical — consecutive ssh failures (with ping still OK)
	// before a host drops into 'critical'.
	SSHFailuresToCritical int
	// PrivilegeFailuresToDegraded — consecutive sudo failures (with SSH OK)
	// before a host drops into 'degraded'.
	PrivilegeFailuresToDegraded int
	// SuccessesToOnline — consecutive all-layer-pass results before a
	// host returns to 'online' from a degraded/critical/down band.
	SuccessesToOnline int
}

// DefaultMultiLayerThresholds returns the Python-equivalent defaults.
func DefaultMultiLayerThresholds() MultiLayerThresholds {
	return MultiLayerThresholds{
		PingFailuresToDown:          3,
		SSHFailuresToCritical:       2,
		PrivilegeFailuresToDegraded: 2,
		SuccessesToOnline:           3,
	}
}

// LayerCounters carries the six consecutive-counter values stored on
// host_liveness so we don't pass six ints around.
type LayerCounters struct {
	PingFail, PingOK            int
	SSHFail, SSHOK              int
	PrivilegeFail, PrivilegeOK  int
}

// AdvanceCounters returns the new counter values after one probe. Each
// layer's failure counter resets when the layer passes; the success
// counter resets when the layer fails. Layers not attempted (because a
// lower layer short-circuited) leave their counters unchanged — they
// neither pass nor fail.
func AdvanceCounters(prev LayerCounters, r MultiLayerResult) LayerCounters {
	next := prev

	// Ping layer.
	if r.PingOK {
		next.PingOK = prev.PingOK + 1
		next.PingFail = 0
	} else if r.PingErr != nil {
		next.PingFail = prev.PingFail + 1
		next.PingOK = 0
	}

	// SSH layer — only mutate when attempted.
	if r.SSHAttempted {
		if r.SSHOK {
			next.SSHOK = prev.SSHOK + 1
			next.SSHFail = 0
		} else {
			next.SSHFail = prev.SSHFail + 1
			next.SSHOK = 0
		}
	}

	// Privilege layer — only mutate when attempted.
	if r.PrivilegeAttempted {
		if r.PrivilegeOK {
			next.PrivilegeOK = prev.PrivilegeOK + 1
			next.PrivilegeFail = 0
		} else {
			next.PrivilegeFail = prev.PrivilegeFail + 1
			next.PrivilegeOK = 0
		}
	}

	return next
}

// DeriveMonitoringState picks the 5-band state given the new counters
// + the prior band. Hysteresis: a host stays in its current band until
// the relevant threshold is crossed. Maintenance is never picked here
// — the loop short-circuits on the maintenance flag before probing.
//
// `priorBand` lets us hold a host in its current state when the layer
// counters haven't crossed a threshold yet (avoids "flap to degraded
// on first probe after restart" UX glitch).
func DeriveMonitoringState(
	priorBand MonitoringState,
	c LayerCounters,
	t MultiLayerThresholds,
	r MultiLayerResult,
) MonitoringState {
	// Pure-pass path: all attempted layers passed.
	if r.FirstFailedLayer == LayerNone &&
		((r.SSHAttempted && r.SSHOK) || !r.SSHAttempted) {
		// Need enough consecutive successes to upgrade out of a bad band.
		if priorBand == StateOnline || priorBand == StateUnknown {
			return StateOnline
		}
		// Coming back from degraded/critical/down — wait for
		// SuccessesToOnline before declaring online.
		recoveryOK := c.PingOK >= t.SuccessesToOnline
		if r.SSHAttempted {
			recoveryOK = recoveryOK && c.SSHOK >= t.SuccessesToOnline
		}
		if r.PrivilegeAttempted {
			recoveryOK = recoveryOK && c.PrivilegeOK >= t.SuccessesToOnline
		}
		if recoveryOK {
			return StateOnline
		}
		return priorBand
	}

	// Failure path: pick the band from the failing layer + threshold.
	switch r.FirstFailedLayer {
	case LayerPing:
		if c.PingFail >= t.PingFailuresToDown {
			return StateDown
		}
		// Below threshold: hold prior band but step toward worse if
		// we were already healthy.
		if priorBand == StateOnline || priorBand == StateUnknown {
			return StateCritical
		}
		return priorBand
	case LayerSSH:
		if c.SSHFail >= t.SSHFailuresToCritical {
			return StateCritical
		}
		if priorBand == StateOnline || priorBand == StateUnknown {
			return StateDegraded
		}
		return priorBand
	case LayerPrivilege:
		if c.PrivilegeFail >= t.PrivilegeFailuresToDegraded {
			return StateDegraded
		}
		// Below threshold — privilege flaps shouldn't drop us out of
		// online. Stay where we were.
		return priorBand
	}
	return priorBand
}

// BandForMultiLayer is the convenience wrapper that combines
// AdvanceCounters + DeriveMonitoringState. Returns the next counters,
// the next band, and whether the band changed (the caller uses this
// flag to emit a transition audit).
func BandForMultiLayer(
	priorBand MonitoringState,
	prior LayerCounters,
	t MultiLayerThresholds,
	r MultiLayerResult,
) (LayerCounters, MonitoringState, bool) {
	next := AdvanceCounters(prior, r)
	band := DeriveMonitoringState(priorBand, next, t, r)
	return next, band, band != priorBand
}
