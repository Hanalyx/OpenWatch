-- PR 1.4 — recurring scheduler cadence column for OS Intelligence
-- (system-intelligence-scheduler v1.0.0).
--
-- Adds next_intelligence_at to host_intelligence_state so the
-- scheduler can read "due hosts" in one SQL query. NULL = "due
-- immediately" (mirrors host_liveness.next_probe_at convention).

-- +goose Up
ALTER TABLE host_intelligence_state
    ADD COLUMN next_intelligence_at TIMESTAMPTZ;

-- Partial index: only the "due" rows. Scheduler tick reads with
-- WHERE next_intelligence_at IS NULL OR next_intelligence_at <= now().
CREATE INDEX idx_intel_state_due
    ON host_intelligence_state (next_intelligence_at NULLS FIRST)
    WHERE next_intelligence_at IS NULL OR next_intelligence_at <= now();

-- +goose Down
DROP INDEX IF EXISTS idx_intel_state_due;
ALTER TABLE host_intelligence_state DROP COLUMN IF EXISTS next_intelligence_at;
