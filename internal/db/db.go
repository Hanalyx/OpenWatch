// Package db owns PostgreSQL connectivity for the openwatch binary.
//
// Day 3: pool helper + goose migration runner + audit_events / idempotency_keys
// queries. Day 4 onward consumes the pool from the server bootstrap.
package db

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPool returns a *pgxpool.Pool configured for the OpenWatch backend.
// The DSN, max-conns, and timeouts come from Config (Day 2).
//
// Caller MUST defer pool.Close().
//
// Validates connectivity with a Ping before returning; an unreachable DB
// fails fast at startup instead of producing confusing per-query errors.
func NewPool(ctx context.Context, dsn string, maxConns int) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("db: parse dsn: %w", err)
	}

	if maxConns > 0 {
		// Bound at math.MaxInt32 — a connection count above that is a
		// config bug, not a feature.
		if maxConns > math.MaxInt32 {
			maxConns = math.MaxInt32
		}
		cfg.MaxConns = int32(maxConns) //nolint:gosec // bounded above by MaxInt32 check
	}

	// Conservative defaults; tunable later if production observability shows
	// hot spots.
	cfg.MinConns = 1
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.MaxConnLifetime = 1 * time.Hour
	cfg.HealthCheckPeriod = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("db: create pool: %w", err)
	}

	// Fail fast on unreachable DB. Use a short timeout for the initial ping;
	// the caller's ctx may be Background() with no deadline.
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}

	return pool, nil
}
