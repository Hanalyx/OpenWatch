// Multi-layer execution path for Service. When the operator wires
// a Pinger + credential resolver into the service (via WithPinger and
// WithCredentialResolver), tick uses the multi-layer probe and writes
// the v1.3.0 schema columns + appends a host_monitoring_history row.
//
// When no Pinger is configured (ICMP not permitted at boot, unit
// tests, …) tick falls back to the v1.2.x single-layer Probe path so
// the legacy AC tests keep running unchanged.

package liveness

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/Hanalyx/openwatch/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// WithPinger returns a new Service that uses the supplied Pinger for
// ICMP layer-1 probes. A nil pinger reverts to the legacy single-layer
// SSH-only path. The receiver is not mutated.
func (s *Service) WithPinger(p *Pinger) *Service {
	out := s.shallowCopy()
	out.pinger = p
	return out
}

// WithPrivilegeProbe returns a new Service that runs the supplied
// privilege check as layer 3 of every multi-layer probe. The function
// owns credential decryption + SSH dialing — keeps the liveness
// package credential-free. A nil func disables the privilege layer.
func (s *Service) WithPrivilegeProbe(fn PrivilegeProbeFunc) *Service {
	out := s.shallowCopy()
	out.privProbe = fn
	return out
}

// WithMultiLayerThresholds tunes per-layer hysteresis. Falls back to
// DefaultMultiLayerThresholds when zero values are supplied.
func (s *Service) WithMultiLayerThresholds(t MultiLayerThresholds) *Service {
	out := s.shallowCopy()
	if t.PingFailuresToDown == 0 {
		t.PingFailuresToDown = 3
	}
	if t.SSHFailuresToCritical == 0 {
		t.SSHFailuresToCritical = 2
	}
	if t.PrivilegeFailuresToDegraded == 0 {
		t.PrivilegeFailuresToDegraded = 2
	}
	if t.SuccessesToOnline == 0 {
		t.SuccessesToOnline = 3
	}
	out.multiThresholds = t
	return out
}

// WithMonitoringHistory toggles append-only host_monitoring_history
// inserts. Off by default — turning it on adds ~1 row per probe per
// host. Retention is operator-managed via the cleanup job; see
// system-liveness-loop C-19.
func (s *Service) WithMonitoringHistory(enabled bool) *Service {
	out := s.shallowCopy()
	out.historyEnabled = enabled
	return out
}

// shallowCopy duplicates the Service into a new instance preserving
// every field, so chaining With…() calls doesn't mutate the receiver
// and each chained Service owns its own inFlight set.
func (s *Service) shallowCopy() *Service {
	out := &Service{
		pool:            s.pool,
		emit:            s.emit,
		bus:             s.bus,
		probeFunc:       s.probeFunc,
		timeout:         s.timeout,
		threshold:       s.threshold,
		interval:        s.interval,
		metrics:         s.metrics,
		clock:           s.clock,
		cfgLoader:       s.cfgLoader,
		pinger:          s.pinger,
		privProbe:       s.privProbe,
		multiThresholds: s.multiThresholds,
		historyEnabled:  s.historyEnabled,
	}
	if p := s.cfgPtr.Load(); p != nil {
		out.cfgPtr.Store(p)
	}
	return out
}

// multiLayerEnabled reports whether the service has been configured
// with at least a Pinger or a privilege probe. When both are nil, the
// legacy single-layer path runs unchanged.
func (s *Service) multiLayerEnabled() bool {
	return s.pinger != nil || s.privProbe != nil
}

// probeMultiLayerHost runs one multi-layer probe and persists the
// result. Used by tickMultiLayer. Returns (newBand, priorBand,
// changed, err) so callers can audit + publish a transition event
// without re-reading the row.
func (s *Service) probeMultiLayerHost(ctx context.Context, hostID uuid.UUID, ip string, port int) (MonitoringState, MonitoringState, bool, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	mp := NewMultiLayerProbe(s.pinger, s.privProbe, s.effectiveTimeout())
	result := mp.Probe(ctx, HostID(hostID.String()), ip, addr)
	return s.persistMultiLayer(ctx, hostID, result)
}

// effectiveTimeout pulls the per-probe budget from the live config
// (TimeoutSec) or falls back to DefaultProbeTimeout.
func (s *Service) effectiveTimeout() time.Duration {
	cfg := s.readConfig()
	if cfg.TimeoutSec > 0 {
		return time.Duration(cfg.TimeoutSec) * time.Second
	}
	return DefaultProbeTimeout
}

// persistMultiLayer UPSERTs the new host_liveness columns + appends a
// history row (when enabled). Returns (newBand, priorBand, changed,
// err) — the caller decides whether to emit audit + bus events on a
// transition.
func (s *Service) persistMultiLayer(ctx context.Context, hostID uuid.UUID, r MultiLayerResult) (MonitoringState, MonitoringState, bool, error) {
	now := s.clock()

	// Read prior counters + band.
	var (
		priorBand string
		prev      LayerCounters
	)
	err := s.pool.QueryRow(ctx, `
		SELECT
			monitoring_state,
			ping_consecutive_failures, ping_consecutive_successes,
			ssh_consecutive_failures,  ssh_consecutive_successes,
			privilege_consecutive_failures, privilege_consecutive_successes
		FROM host_liveness
		WHERE host_id = $1`, hostID).Scan(
		&priorBand,
		&prev.PingFail, &prev.PingOK,
		&prev.SSHFail, &prev.SSHOK,
		&prev.PrivilegeFail, &prev.PrivilegeOK,
	)
	hasPrior := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return StateUnknown, StateUnknown, false, fmt.Errorf("read prior multilayer: %w", err)
	}
	if !hasPrior {
		priorBand = string(StateUnknown)
	}

	thresholds := s.multiThresholds
	if thresholds == (MultiLayerThresholds{}) {
		thresholds = DefaultMultiLayerThresholds()
	}
	next, band, changed := BandForMultiLayer(MonitoringState(priorBand), prev, thresholds, r)

	// Derive the legacy reachability_status (3-value) so v1.2.x callers
	// keep working. SSH-reachable → 'reachable'; everything else →
	// 'unreachable'; if SSH wasn't even attempted (ping failed) →
	// 'unreachable'.
	legacyStatus := StatusUnreachable
	if r.SSHOK {
		legacyStatus = StatusReachable
	}
	consec := totalFailures(next, r)

	// Adaptive next_probe_at — same band table the v1.2.x code uses,
	// but driven by the multi-layer band rather than (reachable + count).
	cfg := s.readConfig()
	nextProbeAt := now.Add(bandIntervalForMonitoringState(band, cfg))

	responseMS := nullableInt(int(r.TotalRTT / time.Millisecond))
	if r.FirstFailedLayer == LayerPing {
		responseMS = nil
	}
	lastErrType := nullableString(multiLayerErrorType(r))

	stateChangeAt := now
	if hasPrior && priorBand == string(band) {
		// Same band; preserve prior state-change time by passing the
		// existing value back through the UPSERT.
		stateChangeAt = now // we'll read+write below in a single statement
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO host_liveness
			(host_id, reachability_status, monitoring_state, last_probe_at,
			 last_response_ms, consecutive_failures,
			 last_state_change_at, last_error_type, next_probe_at, updated_at,
			 ping_consecutive_failures, ping_consecutive_successes,
			 ssh_consecutive_failures,  ssh_consecutive_successes,
			 privilege_consecutive_failures, privilege_consecutive_successes)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $4,
		        $10, $11, $12, $13, $14, $15)
		ON CONFLICT (host_id) DO UPDATE SET
			reachability_status            = EXCLUDED.reachability_status,
			monitoring_state               = EXCLUDED.monitoring_state,
			last_probe_at                  = EXCLUDED.last_probe_at,
			last_response_ms               = EXCLUDED.last_response_ms,
			consecutive_failures           = EXCLUDED.consecutive_failures,
			last_state_change_at           = CASE
				WHEN host_liveness.monitoring_state = EXCLUDED.monitoring_state
				THEN host_liveness.last_state_change_at
				ELSE EXCLUDED.last_state_change_at
			END,
			last_error_type                = EXCLUDED.last_error_type,
			next_probe_at                  = EXCLUDED.next_probe_at,
			updated_at                     = EXCLUDED.updated_at,
			ping_consecutive_failures      = EXCLUDED.ping_consecutive_failures,
			ping_consecutive_successes     = EXCLUDED.ping_consecutive_successes,
			ssh_consecutive_failures       = EXCLUDED.ssh_consecutive_failures,
			ssh_consecutive_successes      = EXCLUDED.ssh_consecutive_successes,
			privilege_consecutive_failures = EXCLUDED.privilege_consecutive_failures,
			privilege_consecutive_successes = EXCLUDED.privilege_consecutive_successes`,
		hostID, string(legacyStatus), string(band), now,
		responseMS, consec,
		stateChangeAt, lastErrType, nextProbeAt,
		next.PingFail, next.PingOK,
		next.SSHFail, next.SSHOK,
		next.PrivilegeFail, next.PrivilegeOK,
	)
	if err != nil {
		return band, MonitoringState(priorBand), false, fmt.Errorf("upsert multilayer: %w", err)
	}

	if s.historyEnabled {
		if err := s.appendHistory(ctx, hostID, now, band, MonitoringState(priorBand), changed, r); err != nil {
			// Diagnostic failure must not break the probe — log and move on.
			slog.WarnContext(ctx, "liveness: history append failed",
				slog.String("host_id", hostID.String()), slog.String("err", err.Error()))
		}
	}
	return band, MonitoringState(priorBand), changed, nil
}

// totalFailures projects layer-specific counters back onto the legacy
// host_liveness.consecutive_failures column so existing reads keep
// working. We sum failure counters across attempted layers; an empty
// (all-pass) probe contributes 0.
func totalFailures(c LayerCounters, _ MultiLayerResult) int {
	return c.PingFail + c.SSHFail + c.PrivilegeFail
}

// multiLayerErrorType maps the failing layer + low-level error onto
// the legacy last_error_type values for backwards compatibility.
func multiLayerErrorType(r MultiLayerResult) string {
	switch r.FirstFailedLayer {
	case LayerPing:
		if r.PingErr != nil && r.PingErr.Error() == "icmp_timeout" {
			return "icmp_timeout"
		}
		return "icmp_unreachable"
	case LayerSSH:
		if r.SSHErr != nil {
			pr := ProbeResult{Error: r.SSHErr}
			return pr.LastErrorType()
		}
		return "ssh_error"
	case LayerPrivilege:
		return "privilege_denied"
	}
	return ""
}

// bandIntervalForMonitoringState returns the per-host probe cadence
// for the given band, reading from the live ConnectivityConfig. Same
// table the v1.2.x code uses but indexed by the multi-layer band.
func bandIntervalForMonitoringState(band MonitoringState, cfg systemconfig.ConnectivityConfig) time.Duration {
	switch band {
	case StateOnline, StateUnknown:
		return time.Duration(cfg.OnlineSec) * time.Second
	case StateDegraded:
		return time.Duration(cfg.DegradedSec) * time.Second
	case StateCritical:
		return time.Duration(cfg.CriticalSec) * time.Second
	case StateDown:
		return time.Duration(cfg.DownSec) * time.Second
	case StateMaintenance:
		return time.Duration(cfg.MaintenanceSec) * time.Second
	}
	return time.Duration(cfg.OnlineSec) * time.Second
}

// appendHistory inserts one host_monitoring_history row.
func (s *Service) appendHistory(ctx context.Context, hostID uuid.UUID, when time.Time, band, prior MonitoringState, changed bool, r MultiLayerResult) error {
	var previousState any
	if changed {
		previousState = string(prior)
	}
	var failedLayer any
	if r.FirstFailedLayer != LayerNone {
		failedLayer = string(r.FirstFailedLayer)
	}
	var errMsg any
	if r.PingErr != nil {
		errMsg = r.PingErr.Error()
	} else if r.SSHErr != nil {
		errMsg = r.SSHErr.Error()
	} else if r.PrivilegeErr != nil {
		errMsg = r.PrivilegeErr.Error()
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO host_monitoring_history
			(host_id, check_time, monitoring_state, previous_state,
			 response_time_ms, ping_ok, ssh_ok, privilege_ok,
			 failed_layer, error_message, error_type)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		hostID, when, string(band), previousState,
		nullableInt(int(r.TotalRTT/time.Millisecond)),
		r.PingOK, r.SSHOK, r.PrivilegeOK,
		failedLayer, errMsg, multiLayerErrorType(r),
	)
	return err
}
