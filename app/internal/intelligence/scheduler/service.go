package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/Hanalyx/openwatch/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Tick-rate safety bounds. Spec C-01 / AC-05.
const (
	DefaultTickInterval = 30 * time.Second
	MinTickInterval     = 5 * time.Second
	MaxTickInterval     = 5 * time.Minute
)

// DefaultRateLimit is the bounded-pool concurrency cap when
// IntelligenceConfig is unset. Matches systemconfig default. Spec C-07.
const DefaultRateLimit = 10

// RunCycleRunner is the seam between the scheduler and the OS
// Intelligence collector. The real implementation is
// internal/intelligence/collector.Service. Interface lives here so
// scheduler doesn't need to import collector for the test path (the
// test stub satisfies it directly).
type RunCycleRunner interface {
	RunCycle(ctx context.Context, hostID uuid.UUID) ([]any, error)
}

// ConfigLoaderFunc reads the current IntelligenceConfig. Production
// wires this to systemconfig.Store; tests pass a closure.
type ConfigLoaderFunc func(ctx context.Context) (systemconfig.IntelligenceConfig, error)

// Service runs the scheduler loop. Construct via NewService.
type Service struct {
	pool         *pgxpool.Pool
	runner       RunCycleRunner
	tickInterval time.Duration
	rateLimit    int
	cfgLoader    ConfigLoaderFunc

	// Bounded worker pool. Semaphore is a buffered channel of empty
	// structs; capacity == rateLimit. dispatchHostInPool acquires a
	// slot before running and releases after.
	sem  chan struct{}
	semO sync.Once

	stop       chan struct{}
	stopO      sync.Once
	inFlightWG sync.WaitGroup
}

// NewService constructs a Service. pool may be nil for tests that
// exercise only the in-process pool seam (RateLimit / Stop tests).
func NewService(pool *pgxpool.Pool, runner RunCycleRunner) *Service {
	return &Service{
		pool:   pool,
		runner: runner,
		stop:   make(chan struct{}),
	}
}

// WithTickInterval overrides the default tick rate (tests).
func (s *Service) WithTickInterval(d time.Duration) *Service {
	s.tickInterval = d
	return s
}

// WithRateLimit overrides the bounded-pool capacity (tests +
// runtime config when policy.Intelligence.RateLimit lands).
func (s *Service) WithRateLimit(n int) *Service {
	s.rateLimit = n
	// Reset the semaphore so the new cap takes effect even if Run
	// has not been called yet.
	s.semO = sync.Once{}
	s.sem = nil
	return s
}

// WithConfigLoader wires the systemconfig reader.
func (s *Service) WithConfigLoader(loader ConfigLoaderFunc) *Service {
	s.cfgLoader = loader
	return s
}

// effectiveInterval returns the actual tick interval, clamped to
// [MinTickInterval, MaxTickInterval]. Spec C-01.
func (s *Service) effectiveInterval() time.Duration {
	d := s.tickInterval
	if d <= 0 {
		d = DefaultTickInterval
	}
	if d < MinTickInterval {
		return MinTickInterval
	}
	if d > MaxTickInterval {
		return MaxTickInterval
	}
	return d
}

// rateLimitOrDefault returns the bounded-pool capacity, clamped to
// [1, 200]. Spec C-07.
func (s *Service) rateLimitOrDefault() int {
	n := s.rateLimit
	if n <= 0 {
		return DefaultRateLimit
	}
	if n > 200 {
		return 200
	}
	return n
}

// initSem lazy-initializes the bounded-pool semaphore.
func (s *Service) initSem() {
	s.semO.Do(func() {
		s.sem = make(chan struct{}, s.rateLimitOrDefault())
	})
}

// Run starts the scheduler loop. Blocks until ctx is canceled OR Stop
// is called. Safe to call once per Service.
func (s *Service) Run(ctx context.Context) error {
	s.initSem()
	t := time.NewTicker(s.effectiveInterval())
	defer t.Stop()

	slog.InfoContext(ctx, "intelligence scheduler started",
		slog.Duration("tick_interval", s.effectiveInterval()),
		slog.Int("rate_limit", s.rateLimitOrDefault()),
	)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.stop:
			return nil
		case <-t.C:
			s.tickOnce(ctx)
		}
	}
}

// Stop signals the loop to exit and waits for any in-flight RunCycles
// to complete. Idempotent.
func (s *Service) Stop() {
	s.stopO.Do(func() {
		close(s.stop)
	})
	s.inFlightWG.Wait()
}

// tickOnce reads the due-hosts list and dispatches them through the
// bounded pool.
func (s *Service) tickOnce(ctx context.Context) {
	if s.cfgLoader != nil {
		cfg, err := s.cfgLoader(ctx)
		if err == nil && cfg.MaintenanceGlobal {
			return // entire fleet paused
		}
	}
	hosts, err := s.listIntelTargets(ctx)
	if err != nil {
		slog.WarnContext(ctx, "intelligence scheduler: listIntelTargets failed",
			slog.String("err", err.Error()),
		)
		return
	}
	for _, h := range hosts {
		s.dispatchHostInPool(ctx, h)
	}
}

// listIntelTargets returns the host ids whose intelligence cycle is
// due. Spec C-02 + AC-06. Single SQL query (AC-07).
//
// Excludes: deleted hosts, maintenance hosts, hosts with future
// intel-backoff suppress_until, hosts with future next_intelligence_at.
func (s *Service) listIntelTargets(ctx context.Context) ([]uuid.UUID, error) {
	const q = `
		SELECT h.id
		  FROM hosts h
		  LEFT JOIN host_intelligence_state hi
		    ON hi.host_id = h.id
		  LEFT JOIN host_backoff_state b
		    ON b.host_id = h.id AND b.probe_type = 'intel'
		 WHERE h.deleted_at IS NULL
		   AND h.maintenance_mode = false
		   AND (b.suppress_until IS NULL OR b.suppress_until <= $1)
		   AND (hi.next_intelligence_at IS NULL OR hi.next_intelligence_at <= $1)
		 ORDER BY hi.next_intelligence_at ASC NULLS FIRST`
	rows, err := s.pool.Query(ctx, q, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// dispatchHostInPool acquires a bounded-pool slot then runs
// dispatchHost. Tests call this directly to assert rate-limit behavior.
func (s *Service) dispatchHostInPool(ctx context.Context, hostID uuid.UUID) {
	s.initSem()
	s.sem <- struct{}{} // blocks if pool is full
	s.inFlightWG.Add(1)
	go func() {
		defer func() {
			<-s.sem
			s.inFlightWG.Done()
		}()
		s.dispatchHost(ctx, hostID)
	}()
}

// dispatchHost takes the per-host advisory lock and runs RunCycle.
// Spec C-03 + AC-12 — pool.BeginTx → pg_advisory_xact_lock → RunCycle.
//
// On success advances host_intelligence_state.next_intelligence_at.
// On failure UPSERTs host_backoff_state(probe_type='intel') with
// exponential backoff. Spec C-04 + AC-09.
//
// When the pool is nil (unit tests of the bounded-pool / Stop seams),
// the lock + record paths are skipped but runner.RunCycle still runs —
// so concurrency tests can observe the in-flight cycle.
func (s *Service) dispatchHost(ctx context.Context, hostID uuid.UUID) {
	if s.pool == nil {
		// Pool-less path (tests). RunCycle still runs so the WaitGroup
		// reflects in-flight work for AC-14, AC-13.
		_, _ = s.runner.RunCycle(ctx, hostID)
		return
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Per-host advisory lock — hashtext to map UUID → int8.
	// pg_advisory_xact_lock (via the try variant) returns false when
	// another tx already holds the lock; we no-op in that case so two
	// scheduler processes don't stack up on the same host. Spec C-03.
	var locked bool
	if err := tx.QueryRow(ctx,
		`SELECT pg_try_advisory_xact_lock(hashtext($1)::int8)`,
		hostID.String(),
	).Scan(&locked); err != nil {
		return
	}
	if !locked {
		return // another scheduler claimed this host
	}

	cfg := systemconfig.DefaultIntelligence()
	if s.cfgLoader != nil {
		if loaded, err := s.cfgLoader(ctx); err == nil {
			cfg = loaded
		}
	}

	_, runErr := s.runner.RunCycle(ctx, hostID)
	if runErr != nil {
		// Backoff path. The collector already failed; we bump
		// host_backoff_state and advance next_intelligence_at past
		// the suppression window.
		if err := s.recordFailure(ctx, tx, hostID, runErr, cfg); err != nil {
			slog.WarnContext(ctx, "intelligence scheduler: recordFailure",
				slog.String("err", err.Error()))
		}
		_ = tx.Commit(ctx)
		return
	}

	// Success path: advance cadence + clear any prior backoff row.
	if err := s.recordSuccess(ctx, tx, hostID, cfg); err != nil {
		slog.WarnContext(ctx, "intelligence scheduler: recordSuccess",
			slog.String("err", err.Error()))
		return
	}
	_ = tx.Commit(ctx)
}

// recordSuccess advances next_intelligence_at and clears the intel
// backoff row. Spec C-04.
func (s *Service) recordSuccess(ctx context.Context, tx pgx.Tx, hostID uuid.UUID, cfg systemconfig.IntelligenceConfig) error {
	next := time.Now().UTC().Add(time.Duration(cfg.IntervalSec) * time.Second)
	if _, err := tx.Exec(ctx, `
		INSERT INTO host_intelligence_state (host_id, snapshot, collected_at, next_intelligence_at)
		VALUES ($1, '{}'::jsonb, now(), $2)
		ON CONFLICT (host_id) DO UPDATE SET
			next_intelligence_at = EXCLUDED.next_intelligence_at,
			updated_at           = now()`,
		hostID, next,
	); err != nil {
		return fmt.Errorf("scheduler: update next_intelligence_at: %w", err)
	}
	// Clear any prior intel backoff so the host returns to normal cadence.
	if _, err := tx.Exec(ctx,
		`DELETE FROM host_backoff_state WHERE host_id = $1 AND probe_type = 'intel'`,
		hostID,
	); err != nil {
		return fmt.Errorf("scheduler: clear intel backoff: %w", err)
	}
	return nil
}

// recordFailure UPSERTs host_backoff_state for probe_type='intel'.
// Spec C-05 + AC-09 + AC-11.
func (s *Service) recordFailure(ctx context.Context, tx pgx.Tx, hostID uuid.UUID, runErr error, cfg systemconfig.IntelligenceConfig) error {
	var prior int
	err := tx.QueryRow(ctx,
		`SELECT consecutive_failures FROM host_backoff_state WHERE host_id = $1 AND probe_type = 'intel'`,
		hostID).Scan(&prior)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("scheduler: read prior backoff: %w", err)
	}
	consec := prior + 1
	base := time.Duration(cfg.IntervalSec) * time.Second
	suppressFor := computeBackoff(consec, base, 24*time.Hour)
	suppressUntil := time.Now().UTC().Add(suppressFor)

	// Truncated error message for last_error_code.
	errCode := runErr.Error()
	if len(errCode) > 64 {
		errCode = errCode[:64]
	}

	// Spec C-05: UPSERT only the intel row. The (host_id,
	// probe_type='scan') row is left untouched — Spec AC-11.
	if _, err := tx.Exec(ctx, `
		INSERT INTO host_backoff_state
			(host_id, probe_type, consecutive_failures, suppress_until, last_error_code, last_failure_at, updated_at)
		VALUES ($1, 'intel', $2, $3, $4, now(), now())
		ON CONFLICT (host_id) DO UPDATE SET
			consecutive_failures = EXCLUDED.consecutive_failures,
			suppress_until       = EXCLUDED.suppress_until,
			last_error_code      = EXCLUDED.last_error_code,
			last_failure_at      = now(),
			updated_at           = now()
		WHERE host_backoff_state.probe_type = 'intel'`,
		hostID, consec, suppressUntil, errCode,
	); err != nil {
		return fmt.Errorf("scheduler: upsert intel backoff: %w", err)
	}
	return nil
}

// computeBackoff returns min(base * 2^(consec-1), cap) — capped
// exponential. Spec AC-10. consec=0 returns base (defensive).
func computeBackoff(consec int, base, maxBackoff time.Duration) time.Duration {
	if consec <= 1 {
		return clampDur(base, maxBackoff)
	}
	// Use float64 to avoid signed-int overflow at high consec values.
	mult := math.Pow(2, float64(consec-1))
	out := time.Duration(float64(base) * mult)
	return clampDur(out, maxBackoff)
}

func clampDur(d, maxBackoff time.Duration) time.Duration {
	if d > maxBackoff {
		return maxBackoff
	}
	return d
}
