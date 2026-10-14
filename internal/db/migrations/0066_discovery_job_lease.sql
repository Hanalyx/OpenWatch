-- +goose Up
-- Discovery job deduplication, leases and failure backoff (bugs/OW-120).
--
-- The discovery scheduler re-queued a failing host every 60 seconds and
-- queued a second job while the first was still pending, because a failure
-- recorded nothing and nothing checked for an active job. Three pieces:
--
--   1. job_queue.lease_token: a fresh token set each time a job is claimed.
--      Completing or failing a leased job, and writing its results, require
--      the current token, so a worker whose job was retired as stale cannot
--      finish it later.
--   2. A unique partial index: at most one pending or processing
--      host.discovery job per host. Enforced by the database, so every
--      enqueue path is covered, including ones added later.
--   3. host_discovery_backoff: per-host failure state that the scheduler
--      reads before choosing targets.

ALTER TABLE job_queue
    ADD COLUMN lease_token UUID;

-- Existing duplicates would make the unique index fail to build. Keep one
-- active discovery job per host and retire the rest as failed, with the
-- reason recorded. Nothing is deleted. The one kept is the most recently
-- claimed processing job if there is one, otherwise the oldest pending job.
WITH ranked AS (
    SELECT id,
           row_number() OVER (
               PARTITION BY payload->>'host_id'
               ORDER BY (status = 'processing') DESC,
                        locked_at DESC NULLS LAST,
                        created_at ASC,
                        id ASC
           ) AS rn
      FROM job_queue
     WHERE job_type = 'host.discovery'
       AND status IN ('pending', 'processing')
       AND payload ? 'host_id'
)
UPDATE job_queue
   SET status       = 'failed',
       last_error   = 'host.discovery: retired as a duplicate by migration 0066',
       completed_at = now()
 WHERE id IN (SELECT id FROM ranked WHERE rn > 1);

CREATE UNIQUE INDEX uq_job_queue_discovery_active
    ON job_queue ((payload->>'host_id'))
    WHERE job_type = 'host.discovery' AND status IN ('pending', 'processing');

CREATE TABLE host_discovery_backoff (
    host_id              UUID         PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    consecutive_failures INTEGER      NOT NULL CHECK (consecutive_failures > 0),
    last_failure_at      TIMESTAMPTZ  NOT NULL,
    next_attempt_at      TIMESTAMPTZ  NOT NULL,
    last_error           TEXT         NOT NULL DEFAULT ''
);

-- +goose Down
DROP TABLE IF EXISTS host_discovery_backoff;
DROP INDEX IF EXISTS uq_job_queue_discovery_active;
ALTER TABLE job_queue DROP COLUMN IF EXISTS lease_token;
