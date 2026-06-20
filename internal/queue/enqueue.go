package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Enqueue persists a new job_queue row, immediately dequeuable. The caller's
// ctx MUST carry a correlation_id; this is a programming-error guard per spec
// C-01. The row's correlation_id pins the job to the originating intent across
// the async boundary.
//
// Returns the inserted job's ID. The job is in "pending" status with
// attempts=0 until a worker claims it via Dequeue.
//
// Spec system-job-queue AC-01.
func Enqueue(ctx context.Context, pool *pgxpool.Pool, jobType string, payload any) (uuid.UUID, error) {
	return EnqueueAfter(ctx, pool, jobType, payload, 0)
}

// EnqueueAfter is Enqueue with a delay: the job is not dequeuable until
// `delay` from now (available_at = now() + delay). A non-positive delay makes
// it immediately available, identical to Enqueue. Used to back off and requeue
// a job that can't run yet (e.g. the target host is busy) without a tight
// re-dequeue loop, since Dequeue skips not-yet-available rows.
//
// Spec system-job-queue AC-13 (delayed visibility).
func EnqueueAfter(ctx context.Context, pool *pgxpool.Pool, jobType string, payload any, delay time.Duration) (uuid.UUID, error) {
	corrID, ok := correlation.From(ctx)
	if !ok {
		return uuid.Nil, ErrMissingCorrelation
	}
	if jobType == "" {
		return uuid.Nil, fmt.Errorf("queue: jobType must not be empty")
	}

	var payloadJSON []byte
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return uuid.Nil, fmt.Errorf("queue: marshal payload: %w", err)
		}
		payloadJSON = raw
	} else {
		payloadJSON = []byte("{}")
	}

	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, fmt.Errorf("queue: uuid: %w", err)
	}

	// available_at is computed server-side (now() + interval) so it shares the
	// database clock that Dequeue compares against.
	secs := delay.Seconds()
	if secs < 0 {
		secs = 0
	}
	const stmt = `
		INSERT INTO job_queue (id, job_type, payload, correlation_id, status, attempts, available_at)
		VALUES ($1, $2, $3::jsonb, $4, 'pending', 0, now() + make_interval(secs => $5))`
	if _, err := pool.Exec(ctx, stmt, id, jobType, payloadJSON, corrID, secs); err != nil {
		return uuid.Nil, fmt.Errorf("queue: insert: %w", err)
	}
	return id, nil
}
