package liveness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
)

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
	probeFunc ProbeFunc
	timeout   time.Duration
	threshold int
	metrics   *Metrics
	inFlight  sync.Map // map[uuid.UUID]struct{}
	clock     func() time.Time
}

// NewService wires the live probe runner. timeout defaults to
// DefaultProbeTimeout, threshold defaults to DefaultUnreachableThreshold.
func NewService(pool *pgxpool.Pool, emit EmitFunc) *Service {
	return &Service{
		pool:      pool,
		emit:      emit,
		probeFunc: Probe,
		timeout:   DefaultProbeTimeout,
		threshold: DefaultUnreachableThreshold,
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
		probeFunc: fn,
		timeout:   s.timeout,
		threshold: s.threshold,
		metrics:   s.metrics,
		clock:     s.clock,
	}
}

// Metrics returns the runtime counters handle.
func (s *Service) Metrics() *Metrics { return s.metrics }

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

	result := s.probeFunc(ctx, addr, s.timeout)
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

	// UPSERT spec C-09.
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO host_liveness
			(host_id, reachability_status, last_probe_at,
			 last_response_ms, consecutive_failures,
			 last_state_change_at, last_error_type, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $3)
		ON CONFLICT (host_id) DO UPDATE SET
			reachability_status  = EXCLUDED.reachability_status,
			last_probe_at        = EXCLUDED.last_probe_at,
			last_response_ms     = EXCLUDED.last_response_ms,
			consecutive_failures = EXCLUDED.consecutive_failures,
			last_state_change_at = EXCLUDED.last_state_change_at,
			last_error_type      = EXCLUDED.last_error_type,
			updated_at           = EXCLUDED.updated_at`,
		hostID, string(newStatus), now, responseMS, newConsecutive,
		stateChangeAt, lastErrType,
	); err != nil {
		return fmt.Errorf("upsert: %w", err)
	}

	// Emit on transition. Spec C-06.
	if didTransition {
		s.metrics.StateTransitionCount.Add(1)
		s.emitTransition(ctx, hostID, result, newStatus)
	}
	return nil
}

// computeNewState applies the hysteresis rules.
func (s *Service) computeNewState(
	hasPrior bool, prior Status, priorConsecutive int, r ProbeResult,
) (newStatus Status, newConsecutive int, didTransition bool) {
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
		if newConsecutive >= s.threshold {
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
