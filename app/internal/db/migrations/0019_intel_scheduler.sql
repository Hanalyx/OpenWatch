-- PR 1.4 — recurring scheduler cadence column for OS Intelligence
-- (system-intelligence-scheduler v1.0.0).
--
-- Adds next_intelligence_at to host_intelligence_state so the
-- scheduler can read "due hosts" in one SQL query. NULL = "due
-- immediately" (mirrors host_liveness.next_probe_at convention).

-- +goose Up
ALTER TABLE host_intelligence_state
    ADD COLUMN next_intelligence_at TIMESTAMPTZ;

-- B-tree index ordered with NULLs first so the scheduler's
-- "due-hosts" query (WHERE next_intelligence_at IS NULL OR
-- next_intelligence_at <= $1) walks the leftmost slice and stops as
-- soon as it crosses the cutoff. A partial WHERE clause was tried but
-- rejected — Postgres requires predicate functions to be IMMUTABLE
-- and now() is STABLE, so a now()-based predicate fails with
-- SQLSTATE 42P17.
CREATE INDEX idx_intel_state_due
    ON host_intelligence_state (next_intelligence_at NULLS FIRST);

-- +goose Down
DROP INDEX IF EXISTS idx_intel_state_due;
ALTER TABLE host_intelligence_state DROP COLUMN IF EXISTS next_intelligence_at;
