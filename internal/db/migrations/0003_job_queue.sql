-- Day-9 job queue. PostgreSQL-native (SKIP LOCKED). One row per queued
-- async unit. correlation_id is NOT NULL by the same contract that binds
-- audit_events: a job that lacks a correlation_id is a programming bug
-- at enqueue time and must be rejected before persistence.
--
-- Spec: app/specs/system/job-queue.spec.yaml AC-08.

-- +goose Up
CREATE TABLE job_queue (
    id              UUID         PRIMARY KEY,
    job_type        TEXT         NOT NULL,
    payload         JSONB        NOT NULL DEFAULT '{}'::jsonb,
    correlation_id  TEXT         NOT NULL,
    status          TEXT         NOT NULL DEFAULT 'pending',
    attempts        INTEGER      NOT NULL DEFAULT 0,
    last_error      TEXT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    locked_at       TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    CONSTRAINT job_queue_status_known CHECK (status IN ('pending','processing','completed','failed'))
);

-- Index for the hot path: SELECT pending row with FOR UPDATE SKIP LOCKED.
CREATE INDEX idx_job_queue_pending ON job_queue (created_at)
    WHERE status = 'pending';

-- Index to query by correlation_id (forensics).
CREATE INDEX idx_job_queue_correlation ON job_queue (correlation_id);

-- +goose Down
DROP TABLE IF EXISTS job_queue;
