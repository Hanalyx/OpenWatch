package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/Hanalyx/openwatch/internal/intelligence/discovery"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Tick-rate safety bounds. Spec C-01 / AC-04.
const (
	DefaultTickInterval = 60 * time.Second
	MinTickInterval     = 10 * time.Second
	MaxTickInterval     = 5 * time.Minute
)

// DefaultRateLimit is the per-tick enqueue cap when DiscoveryConfig is
// unset. Matches systemconfig default. Spec C-04.
const DefaultRateLimit = 25

// Enqueuer is the seam between the scheduler and the job queue. The
// real implementation calls queue.Enqueue; tests pass a stub that
// records calls and never touches the DB.
type Enqueuer interface {
	Enqueue(ctx context.Context, hostID uuid.UUID) (uuid.UUID, error)
}

// PoolEnqueuer adapts a *pgxpool.Pool into the Enqueuer interface
// using the production queue.Enqueue call. Production wires this; tests
// substitute a stub Enqueuer directly.
type PoolEnqueuer struct {
	Pool *pgxpool.Pool
	// Now is the clock backoff is compared against; nil means time.Now.
	Now func() time.Time
}

// Enqueue persists a host.discovery job whose payload carries hostID,
// through discovery.Enqueue, which inserts nothing when the host already
// has a pending or processing discovery job (bugs/OW-120). Adds a
// correlation_id to the context if one isn't already on it so the queue's
// correlation guard is satisfied. Spec C-03, C-09.
func (p PoolEnqueuer) Enqueue(ctx context.Context, hostID uuid.UUID) (uuid.UUID, error) {
	if _, ok := correlation.From(ctx); !ok {
		ctx = correlation.Set(ctx, correlation.Generate(correlation.PrefixCron))
	}
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	_, err := discovery.Enqueue(ctx, p.Pool, hostID, now())
	return uuid.Nil, err
}

// ConfigLoaderFunc reads the current DiscoveryConfig. Production wires
// this to systemconfig.Store.LoadDiscovery; tests pass a closure.
type ConfigLoaderFunc func(ctx context.Context) (systemconfig.DiscoveryConfig, error)

// Service runs the scheduler loop. Construct via NewService.
type Service struct {
	pool         *pgxpool.Pool
	enqueuer     Enqueuer
	tickInterval time.Duration
	cfgLoader    ConfigLoaderFunc
	now          func() time.Time

	stop       chan struct{}
	stopO      sync.Once
	inFlightWG sync.WaitGroup
}

// NewService constructs a Service. pool may be nil for tests that
// exercise only the in-process seam (config bound checks).
func NewService(pool *pgxpool.Pool) *Service {
	s := &Service{
		pool: pool,
		stop: make(chan struct{}),
		now:  time.Now,
	}
	// The enqueuer reads the scheduler's clock, so WithClock reaches it.
	s.enqueuer = PoolEnqueuer{Pool: pool, Now: func() time.Time { return s.now() }}
	return s
}

// WithClock overrides the clock the scheduler compares backoff against
// (tests). Spec C-11.
func (s *Service) WithClock(now func() time.Time) *Service {
	s.now = now
	return s
}

// WithTickInterval overrides the default tick rate (tests).
func (s *Service) WithTickInterval(d time.Duration) *Service {
	s.tickInterval = d
	return s
}

// WithEnqueuer overrides the production enqueuer (tests).
func (s *Service) WithEnqueuer(e Enqueuer) *Service {
	s.enqueuer = e
	return s
}

// WithConfigLoader wires the systemconfig reader.
func (s *Service) WithConfigLoader(loader ConfigLoaderFunc) *Service {
	s.cfgLoader = loader
	return s
}

// effectiveInterval returns the actual tick interval, clamped to
// [MinTickInterval, MaxTickInterval]. Spec C-01 / AC-04.
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

// loadConfig reads the current DiscoveryConfig. Falls back to defaults
// if no loader is wired (tests) or the loader returns an error.
func (s *Service) loadConfig(ctx context.Context) systemconfig.DiscoveryConfig {
	if s.cfgLoader == nil {
		return systemconfig.DefaultDiscovery()
	}
	cfg, err := s.cfgLoader(ctx)
	if err != nil {
		slog.WarnContext(ctx, "discovery scheduler: config load failed; using defaults",
			slog.String("err", err.Error()))
		return systemconfig.DefaultDiscovery()
	}
	return cfg
}

// Run starts the scheduler loop. Blocks until ctx is canceled OR Stop
// is called. Safe to call once per Service.
func (s *Service) Run(ctx context.Context) error {
	t := time.NewTicker(s.effectiveInterval())
	defer t.Stop()

	slog.InfoContext(ctx, "discovery scheduler started",
		slog.Duration("tick_interval", s.effectiveInterval()),
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

// Stop signals the loop to exit and waits for any in-flight tick to
// complete. Idempotent.
func (s *Service) Stop() {
	s.stopO.Do(func() {
		close(s.stop)
	})
	s.inFlightWG.Wait()
}

// tickOnce reads the due-hosts list and enqueues up to RateLimit
// host.discovery jobs. Spec C-04 / C-06 / AC-08 / AC-09.
func (s *Service) tickOnce(ctx context.Context) {
	s.inFlightWG.Add(1)
	defer s.inFlightWG.Done()

	cfg := s.loadConfig(ctx)
	if cfg.MaintenanceGlobal {
		return // entire fleet paused — short-circuit before any DB read
	}
	if s.pool == nil {
		return // tests without a pool
	}

	// Retire jobs whose claim has outlived StaleDeadline first, so their
	// hosts back off and stop holding the slot. Spec C-10.
	if n, err := discovery.RetireStaleJobs(ctx, s.pool, s.now()); err != nil {
		slog.WarnContext(ctx, "discovery scheduler: retire stale jobs failed",
			slog.String("err", err.Error()))
	} else if n > 0 {
		slog.InfoContext(ctx, "discovery scheduler: retired stale jobs", slog.Int("count", n))
	}

	hosts, err := s.listDiscoveryTargets(ctx, cfg.IntervalSec, s.now())
	if err != nil {
		slog.WarnContext(ctx, "discovery scheduler: listDiscoveryTargets failed",
			slog.String("err", err.Error()))
		return
	}

	limit := cfg.RateLimit
	if limit <= 0 {
		limit = DefaultRateLimit
	}
	if len(hosts) > limit {
		hosts = hosts[:limit]
	}

	for _, h := range hosts {
		if _, err := s.enqueuer.Enqueue(ctx, h); err != nil {
			slog.WarnContext(ctx, "discovery scheduler: enqueue failed",
				slog.String("host_id", h.String()),
				slog.String("err", err.Error()))
			// continue with the rest — one bad host doesn't poison the tick
		}
	}
}

// listDiscoveryTargets returns the host ids whose discovery is due. One
// SQL query (AC-06). Excludes deleted, maintenance, and hosts whose
// os_discovered_at is more recent than now() - intervalSec. Also excludes
// hosts that already have a pending or processing discovery job, so they
// do not use up the per-tick cap, and hosts backing off after a failure
// until their next_attempt_at, compared against now (spec C-11, C-12).
//
// Maintenance (per-host OR per-group) resolves via the
// host_effective_maintenance view (migration 0049), matching the scan
// scheduler and the other loops.
//
// NULL os_discovered_at is treated as due (never-discovered hosts go
// first via NULLS FIRST ordering). Spec C-02 / AC-05.
func (s *Service) listDiscoveryTargets(ctx context.Context, intervalSec int, now time.Time) ([]uuid.UUID, error) {
	const q = `
		SELECT h.id
		  FROM hosts h
		  JOIN host_effective_maintenance hem ON hem.host_id = h.id
		 WHERE h.deleted_at IS NULL
		   AND NOT hem.in_maintenance
		   AND (h.os_discovered_at IS NULL
		        OR h.os_discovered_at + make_interval(secs => $1) <= now())
		   AND NOT EXISTS (
		       SELECT 1 FROM job_queue jq
		        WHERE jq.job_type = 'host.discovery'
		          AND jq.status IN ('pending', 'processing')
		          AND jq.payload->>'host_id' = h.id::text)
		   AND NOT EXISTS (
		       SELECT 1 FROM host_discovery_backoff b
		        WHERE b.host_id = h.id AND b.next_attempt_at > $2)
		 ORDER BY h.os_discovered_at ASC NULLS FIRST`
	rows, err := s.pool.Query(ctx, q, intervalSec, now)
	if err != nil {
		return nil, fmt.Errorf("discovery scheduler: query targets: %w", err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("discovery scheduler: scan: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
