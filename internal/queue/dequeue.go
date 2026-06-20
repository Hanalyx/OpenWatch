package queue

import (
	"context"
	"errors"
	"fmt"

	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Dequeue claims one pending job atomically via SELECT ... FOR UPDATE
// SKIP LOCKED. Returns (job, workerCtx, nil) on success. workerCtx is
// a fresh context derived from context.Background() with the row's
// correlation_id set — the caller's ctx is NOT used as parent so the
// worker-loop's own correlation_id cannot leak into per-job execution
// (spec C-02).
//
// Returns ErrNoJob (sentinel) when nothing is pending. Caller should
// poll with a delay on this.
//
// Spec system-job-queue AC-03, AC-04, AC-05.
func Dequeue(ctx context.Context, pool *pgxpool.Pool) (*Job, context.Context, error) {
	// Single statement: claim and return the row. Reduces round-trips
	// and keeps the transactional boundary inside Postgres.
	const stmt = `
		UPDATE job_queue
		   SET status     = 'processing',
		       locked_at  = now(),
		       attempts   = attempts + 1
		 WHERE id = (
		     SELECT id FROM job_queue
		      WHERE status = 'pending' AND available_at <= now()
		      ORDER BY available_at, created_at
		      FOR UPDATE SKIP LOCKED
		      LIMIT 1
		 )
		 RETURNING id, job_type, payload, correlation_id, status, attempts,
		           COALESCE(last_error, ''), created_at, locked_at, completed_at`

	row := pool.QueryRow(ctx, stmt)
	var j Job
	if err := row.Scan(&j.ID, &j.JobType, &j.Payload, &j.CorrelationID, &j.Status,
		&j.Attempts, &j.LastError, &j.CreatedAt, &j.LockedAt, &j.CompletedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrNoJob
		}
		return nil, nil, fmt.Errorf("queue: dequeue: %w", err)
	}

	// Build a fresh worker context from Background, NOT from the caller's
	// ctx (spec C-02). The caller's ctx may carry the worker loop's own
	// correlation_id; we want per-job isolation.
	workerCtx := correlation.Set(context.Background(), j.CorrelationID)
	return &j, workerCtx, nil
}

// Complete marks a job as completed. Workers call this after the job
// runs successfully.
//
// Spec system-job-queue AC-06.
func Complete(ctx context.Context, pool *pgxpool.Pool, jobID uuid.UUID) error {
	const stmt = `
		UPDATE job_queue
		   SET status       = 'completed',
		       completed_at = now()
		 WHERE id = $1`
	_, err := pool.Exec(ctx, stmt, jobID)
	if err != nil {
		return fmt.Errorf("queue: complete: %w", err)
	}
	return nil
}

// Fail marks a job as failed and records the error message. Workers
// call this on terminal failure (after retry policy is exhausted, which
// the queue doesn't yet implement).
//
// Spec system-job-queue AC-07.
func Fail(ctx context.Context, pool *pgxpool.Pool, jobID uuid.UUID, errMsg string) error {
	const stmt = `
		UPDATE job_queue
		   SET status       = 'failed',
		       completed_at = now(),
		       last_error   = $2
		 WHERE id = $1`
	_, err := pool.Exec(ctx, stmt, jobID, errMsg)
	if err != nil {
		return fmt.Errorf("queue: fail: %w", err)
	}
	return nil
}
