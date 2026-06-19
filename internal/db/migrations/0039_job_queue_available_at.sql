-- Delayed-visibility for the job queue. A pending job becomes dequeuable only
-- at or after available_at, which defaults to now() — so every existing enqueue
-- path (scans, diagnostics, etc.) is immediately visible and unchanged. The
-- remediation worker sets a future available_at to back off and requeue a job
-- whose target host is already being remediated, so concurrent "Fix" clicks on
-- one host serialize (queue) instead of colliding on the per-host SSH guard and
-- failing.
--
-- Spec: specs/system/job-queue.spec.yaml.

-- +goose Up
ALTER TABLE job_queue ADD COLUMN available_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- The dequeue hot path now filters and orders on availability. Replace the
-- status-only partial index so the claim query stays index-driven.
DROP INDEX IF EXISTS idx_job_queue_pending;
CREATE INDEX idx_job_queue_pending ON job_queue (available_at, created_at)
    WHERE status = 'pending';

-- +goose Down
DROP INDEX IF EXISTS idx_job_queue_pending;
CREATE INDEX idx_job_queue_pending ON job_queue (created_at)
    WHERE status = 'pending';
ALTER TABLE job_queue DROP COLUMN IF EXISTS available_at;
