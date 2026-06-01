-- PR 3 — alert lifecycle columns (system-alerts v1.0.0).
--
-- alerts.v1.1.0 (PR 2) shipped with state-only metadata. Lifecycle
-- (acknowledge / silence / resolve / dismiss) needs who-did-what-when
-- columns to satisfy AC-02 .. AC-07 + the auto-resolve hook.

-- +goose Up
ALTER TABLE alerts
    ADD COLUMN acknowledged_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN acknowledged_at  TIMESTAMPTZ,
    ADD COLUMN silenced_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN silenced_until   TIMESTAMPTZ,
    ADD COLUMN resolved_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN resolved_at      TIMESTAMPTZ,
    ADD COLUMN dismissed_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN dismissed_at     TIMESTAMPTZ;

-- Partial index used by SweepExpiredSilences: find rows whose
-- silenced_until is in the past so the sweeper can re-arm them.
-- Predicate uses only constants — IMMUTABLE-safe.
CREATE INDEX idx_alerts_silenced
    ON alerts (silenced_until)
    WHERE state = 'silenced' AND silenced_until IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_alerts_silenced;
ALTER TABLE alerts
    DROP COLUMN IF EXISTS dismissed_at,
    DROP COLUMN IF EXISTS dismissed_by,
    DROP COLUMN IF EXISTS resolved_at,
    DROP COLUMN IF EXISTS resolved_by,
    DROP COLUMN IF EXISTS silenced_until,
    DROP COLUMN IF EXISTS silenced_by,
    DROP COLUMN IF EXISTS acknowledged_at,
    DROP COLUMN IF EXISTS acknowledged_by;
