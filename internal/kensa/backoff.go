package kensa

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// BackoffPolicy is the failure-count → suppress_until math. Defaults
// match spec AC-16: 3 consecutive failures double the next-attempt
// clock relative to the tier interval; the doubling chain caps at 24h.
type BackoffPolicy struct {
	// FailureThreshold is the number of consecutive failures before
	// the executor starts applying suppress_until. Default 3 per spec.
	FailureThreshold int
	// MaxSuppressDuration is the ceiling on suppress_until. Default
	// 24h per spec C-11.
	MaxSuppressDuration time.Duration
	// BaseInterval is the host's current tier interval — the value the
	// scheduler would use absent backoff. The doubling chain takes
	// (consecutive_failures - threshold + 1) doublings starting from
	// BaseInterval.
	BaseInterval time.Duration
}

// DefaultBackoffPolicy returns the spec-defined defaults.
func DefaultBackoffPolicy(baseInterval time.Duration) BackoffPolicy {
	return BackoffPolicy{
		FailureThreshold:    3,
		MaxSuppressDuration: 24 * time.Hour,
		BaseInterval:        baseInterval,
	}
}

// computeSuppressUntil returns the new suppress_until for the given
// post-failure counter. Returns the zero time when below the threshold
// (no suppression applied yet — let the scheduler dispatch normally).
//
// Doubling schedule (with default 3-fail threshold + 1h baseInterval):
//
//	failures = 1  → suppress_until = zero (no suppression)
//	failures = 2  → suppress_until = zero
//	failures = 3  → suppress_until = now + 2h   (1h × 2)
//	failures = 4  → suppress_until = now + 4h   (1h × 4)
//	failures = 5  → suppress_until = now + 8h   (1h × 8)
//	failures = 6+ → suppress_until = now + 24h  (capped)
//
// Pure function for unit-testability.
func (p BackoffPolicy) computeSuppressUntil(now time.Time, consecutiveFailures int) time.Time {
	if consecutiveFailures < p.FailureThreshold {
		return time.Time{}
	}
	// First time we hit the threshold, double once (×2). Each additional
	// failure doubles again. consecutive_failures = threshold → 1×double.
	doublings := consecutiveFailures - p.FailureThreshold + 1
	interval := p.BaseInterval
	for i := 0; i < doublings; i++ {
		interval *= 2
		if interval > p.MaxSuppressDuration {
			interval = p.MaxSuppressDuration
			break
		}
	}
	return now.Add(interval)
}

// RecordFailure increments host_backoff_state.consecutive_failures for
// the given host, recomputes suppress_until per BackoffPolicy, and
// writes back. On success returns the new (count, suppressUntil).
//
// Spec AC-16: the scheduler's dispatcher reads suppress_until via the
// idx_host_backoff_state_suppress index and skips hosts whose
// suppress_until is in the future. This method is the writer half of
// that contract.
//
// Uses an UPSERT so a brand-new host (no prior backoff row) gets one
// created at consecutive_failures = 1.
func (e *Executor) RecordFailure(ctx context.Context, pool *pgxpool.Pool, hostID uuid.UUID, policy BackoffPolicy, reason FailureReason) (int, time.Time, error) {
	now := e.clock()

	// UPSERT: increment if exists, insert at 1 if not.
	const stmt = `
		INSERT INTO host_backoff_state
			(host_id, probe_type, consecutive_failures, last_error_code, last_failure_at, updated_at)
		VALUES
			($1, 'scan', 1, $2, $3, $3)
		ON CONFLICT (host_id) DO UPDATE
		SET consecutive_failures = host_backoff_state.consecutive_failures + 1,
		    last_error_code = EXCLUDED.last_error_code,
		    last_failure_at = EXCLUDED.last_failure_at,
		    updated_at = EXCLUDED.updated_at
		RETURNING consecutive_failures`

	var newCount int
	if err := pool.QueryRow(ctx, stmt, hostID, string(reason), now).Scan(&newCount); err != nil {
		return 0, time.Time{}, fmt.Errorf("kensa: upsert backoff state: %w", err)
	}

	// Compute and persist suppress_until.
	suppressUntil := policy.computeSuppressUntil(now, newCount)
	if !suppressUntil.IsZero() {
		if _, err := pool.Exec(ctx, `
			UPDATE host_backoff_state
			   SET suppress_until = $1, updated_at = $2
			 WHERE host_id = $3`,
			suppressUntil, now, hostID); err != nil {
			return newCount, time.Time{}, fmt.Errorf("kensa: update suppress_until: %w", err)
		}
	}

	return newCount, suppressUntil, nil
}

// RecordSuccess resets host_backoff_state.consecutive_failures to 0 and
// clears suppress_until. A successful scan ends a failure streak.
//
// No-op (no error) if no prior backoff row exists for hostID.
func (e *Executor) RecordSuccess(ctx context.Context, pool *pgxpool.Pool, hostID uuid.UUID) error {
	_, err := pool.Exec(ctx, `
		UPDATE host_backoff_state
		   SET consecutive_failures = 0,
		       suppress_until = NULL,
		       last_error_code = NULL,
		       updated_at = $1
		 WHERE host_id = $2`,
		e.clock(), hostID)
	if err != nil {
		return fmt.Errorf("kensa: reset backoff state: %w", err)
	}
	return nil
}
