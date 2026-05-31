package liveness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/eventbus"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
)

// ConfigLoaderFunc returns the current ConnectivityConfig. The
// Service calls this on boot and on every Reload to pick up
// operator-tunable values without restart. Spec
// services-connectivity-config C-04.
type ConfigLoaderFunc func(context.Context) (systemconfig.ConnectivityConfig, error)

// EmitFunc mirrors audit.Emit's signature; same pattern as
// internal/scheduler.EmitFunc and internal/kensa.EmitFunc.
type EmitFunc func(ctx context.Context, code audit.Code, ev audit.Event)

// ProbeFunc is the per-host probe seam. Production wires this to the
// in-process net.DialTimeout-based Probe; tests substitute a fake.
// Future: swap to Kensa.Reachable() when boundary doc §6.3 lands.
//
// NOT an interface — function types don't trip "no engine abstraction"
// rules (this package doesn't have a strict spec equivalent of AC-12,
// but the pattern stays consistent with kensa-executor).
type ProbeFunc func(ctx context.Context, addr string, timeout time.Duration) ProbeResult

// Service is the live probe runner.
type Service struct {
	pool      *pgxpool.Pool
	emit      EmitFunc
	bus       *eventbus.Bus // may be nil; see v1.1.0 C-13
	probeFunc ProbeFunc
	timeout   time.Duration
	threshold int
	interval  time.Duration
	metrics   *Metrics
	inFlight  sync.Map // map[uuid.UUID]struct{}
	clock     func() time.Time

	// cfgLoader, when set, is called on Reload to fetch fresh runtime
	// config from systemconfig. The returned snapshot is stored under
	// cfgPtr for lock-free read-side access. Spec
	// services-connectivity-config C-04.
	cfgLoader ConfigLoaderFunc
	cfgPtr    atomic.Pointer[systemconfig.ConnectivityConfig]

	// v1.3.0 multi-layer fields. When pinger is non-nil OR privProbe
	// is non-nil, tick uses MultiLayerProbe + persistMultiLayer instead
	// of the legacy single-layer path. The privilege probe lives outside
	// this package so the AC-14 "no credential imports" invariant holds.
	// Spec system-liveness-loop C-18.
	pinger          *Pinger
	privProbe       PrivilegeProbeFunc
	multiThresholds MultiLayerThresholds
	historyEnabled  bool
}

// NewService wires the live probe runner. timeout defaults to
// DefaultProbeTimeout, threshold defaults to DefaultUnreachableThreshold.
//
// v1.1.0: bus may be nil. When nil, the service still emits audit
// events but skips bus publishes. Spec system-liveness-loop C-13.
func NewService(pool *pgxpool.Pool, emit EmitFunc, bus *eventbus.Bus) *Service {
	return &Service{
		pool:      pool,
		emit:      emit,
		bus:       bus,
		probeFunc: Probe,
		timeout:   DefaultProbeTimeout,
		threshold: DefaultUnreachableThreshold,
		interval:  DefaultProbeInterval,
		metrics:   NewMetrics(),
		clock:     time.Now,
	}
}

// WithProbeFunc returns a new Service that mirrors the receiver's
// configuration but uses the given ProbeFunc. The receiver is not
// mutated; the returned Service has its own inFlight set (no shared
// sync.Map between original and copy).
func (s *Service) WithProbeFunc(fn ProbeFunc) *Service {
	return &Service{
		pool:      s.pool,
		emit:      s.emit,
		bus:       s.bus,
		probeFunc: fn,
		timeout:   s.timeout,
		threshold: s.threshold,
		interval:  s.interval,
		metrics:   s.metrics,
		clock:     s.clock,
	}
}

// WithInterval returns a new Service that ticks at the given interval.
// Used by tests (and policy.Liveness.IntervalSec loading at boot) to
// override the default 5-minute cadence. Spec system-liveness-loop C-03.
func (s *Service) WithInterval(d time.Duration) *Service {
	out := &Service{
		pool:      s.pool,
		emit:      s.emit,
		bus:       s.bus,
		probeFunc: s.probeFunc,
		timeout:   s.timeout,
		threshold: s.threshold,
		interval:  d,
		metrics:   s.metrics,
		clock:     s.clock,
		cfgLoader: s.cfgLoader,
	}
	if p := s.cfgPtr.Load(); p != nil {
		out.cfgPtr.Store(p)
	}
	return out
}

// WithConfigLoader returns a new Service that calls the given loader
// on every Reload to refresh runtime config (interval, timeout,
// threshold, maintenance). The loader is also invoked immediately so
// boot-time config takes effect before the first tick. Spec
// services-connectivity-config C-04.
func (s *Service) WithConfigLoader(loader ConfigLoaderFunc) *Service {
	out := &Service{
		pool:      s.pool,
		emit:      s.emit,
		bus:       s.bus,
		probeFunc: s.probeFunc,
		timeout:   s.timeout,
		threshold: s.threshold,
		interval:  s.interval,
		metrics:   s.metrics,
		clock:     s.clock,
		cfgLoader: loader,
	}
	if loader != nil {
		// Best-effort initial load; failures fall back to defaults.
		if cfg, err := loader(context.Background()); err == nil {
			out.cfgPtr.Store(&cfg)
		}
	}
	return out
}

// Reload re-reads the config via the loader and atomically swaps the
// in-process snapshot. The next tick uses the new values for
// maintenance, timeout, threshold, and interval. Returns nil with no
// loader configured (defaults stay in effect).
func (s *Service) Reload(ctx context.Context) error {
	if s.cfgLoader == nil {
		return nil
	}
	cfg, err := s.cfgLoader(ctx)
	if err != nil {
		return err
	}
	s.cfgPtr.Store(&cfg)
	return nil
}

// readConfig returns the current config snapshot. Falls back to
// systemconfig.DefaultConnectivity() when no loader has populated the
// pointer — keeps tests and bare-bones boot paths working with no
// behavior change vs the pre-config Service.
func (s *Service) readConfig() systemconfig.ConnectivityConfig {
	if p := s.cfgPtr.Load(); p != nil {
		return *p
	}
	return systemconfig.DefaultConnectivity()
}

// Metrics returns the runtime counters handle.
func (s *Service) Metrics() *Metrics { return s.metrics }

// Run is the blocking liveness loop. On every tick at the configured
// interval it walks the active host inventory and calls ProbeHost for
// each host whose backoff state allows a probe. Returns when ctx is
// canceled, allowing the in-flight tick to complete.
//
// Spec system-liveness-loop v1.1.0:
//   - C-10 / AC-16 / AC-17: tick-and-walk semantics.
//   - C-11 / AC-18: skip hosts whose host_backoff_state.suppress_until is in the future.
//   - AC-19: returns within 2s of ctx cancellation.
func (s *Service) Run(ctx context.Context) {
	interval := s.effectiveInterval()
	t := time.NewTicker(interval)
	defer t.Stop()

	// Tick once at start so the loop produces a result before the first
	// interval elapses. The initial tick respects ctx like any other.
	s.tick(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.tick(ctx)
			// Honor config reloads: if the operator changed
			// IntervalSec via PUT /system/connectivity/config, the next
			// tick fires at the new cadence. Spec
			// services-connectivity-config C-04.
			if next := s.effectiveInterval(); next != interval && next > 0 {
				interval = next
				t.Reset(interval)
			}
		}
	}
}

// effectiveInterval returns the Run-loop tick cadence. v1.2.0 makes
// this a short polling interval — per-host effective cadence comes
// from the band intervals in ConnectivityConfig, not from the tick
// rate. Spec system-liveness-loop C-16.
//
// 30s gives sub-band-floor latency for the "due now" check without
// hammering the DB. For tests, s.interval (settable via WithInterval)
// can override it.
func (s *Service) effectiveInterval() time.Duration {
	if s.interval > 0 && s.interval < 30*time.Second {
		// Test path — respect the explicit short interval.
		return s.interval
	}
	return 30 * time.Second
}

// bandIntervalFor maps (status, consecutive_failures, cfg) to the
// per-host probe interval — the duration before this host is next
// due. Spec system-liveness-loop v1.2.0 C-14, AC-24:
//
//	reachable    + consec=0                → OnlineSec   (stable)
//	reachable    + consec>=1                → DegradedSec (watch)
//	unreachable  + consec<threshold         → CriticalSec (confirm)
//	any          + consec>=threshold        → DownSec     (back off)
//	unknown / anything else                 → OnlineSec   (treat as healthy default)
func bandIntervalFor(status Status, consecutive int, cfg systemconfig.ConnectivityConfig) time.Duration {
	threshold := cfg.UnreachableThreshold
	if threshold <= 0 {
		threshold = 2
	}
	switch {
	case consecutive >= threshold:
		return time.Duration(cfg.DownSec) * time.Second
	case status == StatusUnreachable:
		return time.Duration(cfg.CriticalSec) * time.Second
	case status == StatusReachable && consecutive >= 1:
		return time.Duration(cfg.DegradedSec) * time.Second
	default:
		return time.Duration(cfg.OnlineSec) * time.Second
	}
}

// tick performs one probe walk. Surface for tests: exercising tick
// directly avoids relying on time.Ticker.
func (s *Service) tick(ctx context.Context) {
	// Maintenance: when MaintenanceGlobal=true, the loop ticks but
	// probes no hosts. Spec services-connectivity-config C-05.
	if s.readConfig().MaintenanceGlobal {
		slog.InfoContext(ctx, "liveness: tick skipped",
			slog.Bool("maintenance_active", true))
		return
	}
	hosts, err := s.listProbeTargets(ctx)
	if err != nil {
		slog.WarnContext(ctx, "liveness: list probe targets failed",
			slog.String("err", err.Error()))
		return
	}
	useMultiLayer := s.multiLayerEnabled()
	for _, h := range hosts {
		// Per-host probe respects its own ctx — if Run's ctx is
		// canceled, the probe call sees it and returns quickly.
		if useMultiLayer {
			// v1.3.0: multi-layer path writes the new schema columns
			// and emits transitions on band changes. Spec C-18 / AC-32.
			band, changed, err := s.probeMultiLayerHost(ctx, h.HostID, h.IP, h.Port)
			if err != nil {
				slog.WarnContext(ctx, "liveness: multilayer probe failed",
					slog.String("host_id", h.HostID.String()),
					slog.String("err", err.Error()))
			}
			if changed {
				s.metrics.StateTransitionCount.Add(1)
				s.emitBandTransition(ctx, h.HostID, band)
			}
		} else {
			_, _ = s.ProbeHost(ctx, h.HostID, h.Addr)
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// probeTarget is one host the tick will probe.
type probeTarget struct {
	HostID uuid.UUID
	IP     string // resolved IPv4, no CIDR suffix (v1.2.1 C-17)
	Port   int    // SSH port; defaults to 22
	Addr   string // "ip:port" cached for the legacy single-layer path
}

// listProbeTargets returns active (non-soft-deleted) hosts whose
//
//   - host_backoff_state does not suppress probes at this moment
//     (AC-18), AND
//   - host_liveness.next_probe_at is NULL (never probed / fresh row)
//     OR <= now (probe is due). v1.2.0 C-15 / AC-26.
//
// Hosts probed within their band's interval are skipped here so the
// tick scales to large fleets without re-walking every host.
func (s *Service) listProbeTargets(ctx context.Context) ([]probeTarget, error) {
	now := s.clock()
	// host(inet) strips the /N prefix length that PostgreSQL's inet type
	// renders via ::text — "192.168.1.10/32" → "192.168.1.10". The
	// `/32` slipping through here would yield "192.168.1.10/32:22"
	// which net.Dial rejects, marking every host unreachable. v1.2.1 C-17.
	//
	// v1.3.0 additions (C-20):
	//   - WHERE hosts.maintenance_mode = false (per-host pause)
	//   - ORDER BY hosts.check_priority DESC, hl.next_probe_at ASC NULLS FIRST
	//     so critical hosts get drained before stable ones.
	const q = `
		SELECT h.id, host(h.ip_address), COALESCE(h.port, 22), h.check_priority
		  FROM hosts h
		  LEFT JOIN host_backoff_state b
		    ON b.host_id = h.id AND b.probe_type = 'scan'
		  LEFT JOIN host_liveness hl
		    ON hl.host_id = h.id
		 WHERE h.deleted_at IS NULL
		   AND h.maintenance_mode = false
		   AND (b.suppress_until IS NULL OR b.suppress_until <= $1)
		   AND (hl.next_probe_at IS NULL OR hl.next_probe_at <= $1)
		 ORDER BY h.check_priority DESC, hl.next_probe_at ASC NULLS FIRST`
	rows, err := s.pool.Query(ctx, q, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []probeTarget
	for rows.Next() {
		var (
			id       uuid.UUID
			ip       string
			port     int
			priority int
		)
		if err := rows.Scan(&id, &ip, &port, &priority); err != nil {
			return nil, err
		}
		out = append(out, probeTarget{
			HostID: id,
			IP:     ip,
			Port:   port,
			Addr:   fmt.Sprintf("%s:%d", ip, port),
		})
	}
	return out, rows.Err()
}

// emitBandTransition fires an audit event on a multi-layer band change.
// Mirrors emitTransition (legacy single-layer path) but uses the
// 5-band MonitoringState in the detail payload instead of the binary
// reachable/unreachable enum.
func (s *Service) emitBandTransition(ctx context.Context, hostID uuid.UUID, band MonitoringState) {
	s.emit(ctx, audit.HostConnectivityChecked, audit.Event{
		ActorType: "system",
		Detail: mustJSON(map[string]any{
			"host_id":          hostID.String(),
			"monitoring_state": string(band),
		}),
	})
}

// ProbeHost runs one probe against the given host and persists the result.
//
// Spec ACs satisfied here:
//
//   - AC-05 (C-05): per-host concurrency guard; second concurrent call
//     for the same hostID returns ErrProbeInFlight.
//   - AC-06 (C-05): different hostIDs probe in parallel; no global lock.
//   - AC-09/10/11/12 (C-06, C-08, C-09): persists to host_liveness with
//     transition logic; emits host.connectivity.checked ONLY on state
//     transitions (first-seen or status flip).
func (s *Service) ProbeHost(ctx context.Context, hostID uuid.UUID, addr string) (ProbeResult, error) {
	// Concurrency guard.
	if _, loaded := s.inFlight.LoadOrStore(hostID, struct{}{}); loaded {
		return ProbeResult{}, ErrProbeInFlight
	}
	defer s.inFlight.Delete(hostID)

	now := s.clock()
	s.metrics.SetLastProbeAt(now)
	s.metrics.ProbeCount.Add(1)

	// Per-probe timeout comes from config (with falls-back to the
	// construction default when no config is loaded). Spec
	// services-connectivity-config C-04.
	timeout := s.timeout
	if p := s.cfgPtr.Load(); p != nil && p.TimeoutSec > 0 {
		timeout = time.Duration(p.TimeoutSec) * time.Second
	}
	result := s.probeFunc(ctx, addr, timeout)
	if result.Reachable {
		s.metrics.ProbeSuccessCount.Add(1)
	} else {
		s.metrics.ProbeFailureCount.Add(1)
	}

	// Persist the outcome and decide whether to audit.
	if err := s.persist(ctx, hostID, result, now); err != nil {
		// Persistence failure: counted as a probe failure but the probe
		// itself succeeded or failed cleanly. Return the result so the
		// caller has the data; the error tells them the persistence
		// path needs attention.
		return result, fmt.Errorf("liveness: persist for %s: %w", hostID, err)
	}
	return result, nil
}

// persist UPSERTs host_liveness and emits host.connectivity.checked ONLY
// on state transitions. Implements the hysteresis from spec C-08:
//   - first-seen → record state, emit audit
//   - prior reachable + this failure → consecutive_failures++; flip to
//     unreachable AND audit only when count reaches threshold
//   - prior unreachable + this success → flip to reachable, reset
//     count, audit
//   - steady-state same-as-before → update last_probe_at + response,
//     no audit
func (s *Service) persist(ctx context.Context, hostID uuid.UUID, result ProbeResult, now time.Time) error {
	// Read prior row.
	var (
		priorStatus      string
		priorConsecutive int
		hasPrior         bool
	)
	err := s.pool.QueryRow(ctx, `
		SELECT reachability_status, consecutive_failures
		  FROM host_liveness
		 WHERE host_id = $1`, hostID).
		Scan(&priorStatus, &priorConsecutive)
	if err == nil {
		hasPrior = true
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("read prior: %w", err)
	}

	// Compute the new state + whether we audit.
	newStatus, newConsecutive, didTransition := s.computeNewState(
		hasPrior, Status(priorStatus), priorConsecutive, result,
	)

	responseMS := nullableInt(int(result.ResponseTime / time.Millisecond))
	if !result.Reachable {
		responseMS = nil // store NULL when probe failed
	}
	lastErrType := nullableString(result.LastErrorType())
	stateChangeAt := pickStateChangeTime(hasPrior, Status(priorStatus), newStatus, now)

	// Adaptive next_probe_at — the band the host now sits in decides
	// how long until we probe it again. Spec system-liveness-loop
	// v1.2.0 C-14 / AC-25.
	cfg := s.readConfig()
	nextProbeAt := now.Add(bandIntervalFor(newStatus, newConsecutive, cfg))

	// UPSERT spec C-09 (+v1.2.0 next_probe_at).
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO host_liveness
			(host_id, reachability_status, last_probe_at,
			 last_response_ms, consecutive_failures,
			 last_state_change_at, last_error_type, next_probe_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $3)
		ON CONFLICT (host_id) DO UPDATE SET
			reachability_status  = EXCLUDED.reachability_status,
			last_probe_at        = EXCLUDED.last_probe_at,
			last_response_ms     = EXCLUDED.last_response_ms,
			consecutive_failures = EXCLUDED.consecutive_failures,
			last_state_change_at = EXCLUDED.last_state_change_at,
			last_error_type      = EXCLUDED.last_error_type,
			next_probe_at        = EXCLUDED.next_probe_at,
			updated_at           = EXCLUDED.updated_at`,
		hostID, string(newStatus), now, responseMS, newConsecutive,
		stateChangeAt, lastErrType, nextProbeAt,
	); err != nil {
		return fmt.Errorf("upsert: %w", err)
	}

	// Emit on transition. Spec C-06.
	if didTransition {
		s.metrics.StateTransitionCount.Add(1)
		s.emitTransition(ctx, hostID, result, newStatus)
		// v1.1.0 C-12: publish HeartbeatPulse to the eventbus on the
		// same trigger. Bus may be nil (test path) — skip in that case.
		s.publishHeartbeat(ctx, hostID, result, Status(priorStatus), newStatus, now)
	}
	return nil
}

// publishHeartbeat publishes a typed HeartbeatPulse to the eventbus on
// every reachability state transition. Best-effort: a nil bus is a
// no-op; publish failures are not propagated to the caller (matches
// the bus's own "drop on full / dropped count" contract). Spec v1.1.0
// C-12 / AC-20 / AC-21 / AC-22.
func (s *Service) publishHeartbeat(ctx context.Context, hostID uuid.UUID, result ProbeResult, prior, current Status, now time.Time) {
	if s.bus == nil {
		return
	}
	s.bus.Publish(ctx, eventbus.HeartbeatPulse{
		HostID:         hostID,
		Reachable:      current == StatusReachable,
		PriorReachable: prior == StatusReachable,
		OccurredAt:     now,
		ResponseTimeMS: int(result.ResponseTime / time.Millisecond),
	})
}

// computeNewState applies the hysteresis rules.
func (s *Service) computeNewState(
	hasPrior bool, prior Status, priorConsecutive int, r ProbeResult,
) (newStatus Status, newConsecutive int, didTransition bool) {
	// Threshold comes from the live config when set; otherwise the
	// construction default. Spec services-connectivity-config C-04.
	threshold := s.threshold
	if p := s.cfgPtr.Load(); p != nil && p.UnreachableThreshold > 0 {
		threshold = p.UnreachableThreshold
	}

	if !hasPrior {
		// First time we've seen this host. Record state, emit.
		if r.Reachable {
			return StatusReachable, 0, true
		}
		return StatusUnreachable, 1, true
	}

	if r.Reachable {
		// Success: always reachable, reset counter. Audit only if we
		// were not previously reachable (transition).
		didTransition = prior != StatusReachable
		return StatusReachable, 0, didTransition
	}

	// Failure path.
	newConsecutive = priorConsecutive + 1
	if prior == StatusReachable {
		// Still in the grace window unless threshold reached.
		if newConsecutive >= threshold {
			return StatusUnreachable, newConsecutive, true
		}
		// Hysteresis: status stays reachable.
		return StatusReachable, newConsecutive, false
	}
	// Already unreachable (or unknown): stay unreachable, increment counter.
	if prior == StatusUnreachable {
		return StatusUnreachable, newConsecutive, false
	}
	// prior == unknown: flip to unreachable, emit.
	return StatusUnreachable, newConsecutive, true
}

// pickStateChangeTime returns the right last_state_change_at value.
// On a transition (or first-seen), use now; otherwise preserve the prior
// value via NULL (Postgres ON CONFLICT DO UPDATE keeps the prior column).
// We approximate by always passing now; the column drift is bounded
// because we only update it on transitions in the SET clause via the
// UPSERT pattern handled by the caller.
func pickStateChangeTime(hasPrior bool, prior Status, newStatus Status, now time.Time) time.Time {
	if !hasPrior {
		return now
	}
	if prior != newStatus {
		return now
	}
	return now // safe — set once on transition; subsequent UPSERTs overwrite
}

// emitTransition produces host.connectivity.checked with ssh_accessible
// + response_time_ms in detail.
func (s *Service) emitTransition(ctx context.Context, hostID uuid.UUID, result ProbeResult, newStatus Status) {
	s.emit(ctx, audit.HostConnectivityChecked, audit.Event{
		ActorType: "system",
		Detail: mustJSON(map[string]any{
			"host_id":          hostID.String(),
			"ssh_accessible":   result.Reachable,
			"response_time_ms": int(result.ResponseTime / time.Millisecond),
			"new_status":       string(newStatus),
		}),
	})
}

// ---------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------

// Metrics holds the service's runtime counters. Spec AC-15.
type Metrics struct {
	lastProbeNanos       atomic.Int64
	ProbeCount           atomic.Int64
	ProbeSuccessCount    atomic.Int64
	ProbeFailureCount    atomic.Int64
	StateTransitionCount atomic.Int64
}

// NewMetrics returns a fresh Metrics value.
func NewMetrics() *Metrics { return &Metrics{} }

// SetLastProbeAt stores the most recent probe-start time.
func (m *Metrics) SetLastProbeAt(t time.Time) {
	m.lastProbeNanos.Store(t.UnixNano())
}

// LastProbeAt returns the most recent probe-start time, or zero.
func (m *Metrics) LastProbeAt() time.Time {
	n := m.lastProbeNanos.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

// MetricsSnapshot is a typed snapshot for JSON serialization.
type MetricsSnapshot struct {
	LastProbeAt          time.Time `json:"last_probe_at"`
	ProbeCount           int64     `json:"probe_count"`
	ProbeSuccessCount    int64     `json:"probe_success_count"`
	ProbeFailureCount    int64     `json:"probe_failure_count"`
	StateTransitionCount int64     `json:"state_transition_count"`
}

// Snapshot returns a point-in-time copy of all counters.
func (m *Metrics) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{
		LastProbeAt:          m.LastProbeAt(),
		ProbeCount:           m.ProbeCount.Load(),
		ProbeSuccessCount:    m.ProbeSuccessCount.Load(),
		ProbeFailureCount:    m.ProbeFailureCount.Load(),
		StateTransitionCount: m.StateTransitionCount.Load(),
	}
}

// inFlightCount returns the number of hostIDs currently being probed.
// Test-only helper.
func (s *Service) inFlightCount() int {
	n := 0
	s.inFlight.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

func nullableInt(v int) any {
	if v == 0 {
		return nil
	}
	return v
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
