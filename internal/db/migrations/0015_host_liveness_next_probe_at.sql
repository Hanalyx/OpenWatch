-- +goose Up
-- Adaptive health checks: per-host "when's the next probe due" cursor.
--
-- Spec: system-liveness-loop v1.2.0 (C-14, C-15).
--
-- next_probe_at is computed in liveness.persist() as
--   now + bandIntervalFor(new_status, new_consecutive, cfg)
-- where the band table comes from services-connectivity-config v1.1.0
-- (Online/Degraded/Critical/Down).
--
-- A NULL value means "due immediately" — the listProbeTargets filter
-- treats NULL as < now() so freshly-migrated rows and brand-new
-- host_liveness inserts both get picked up on the next tick.

ALTER TABLE host_liveness
  ADD COLUMN next_probe_at TIMESTAMPTZ;

-- Tick query path: SELECT ... WHERE next_probe_at IS NULL OR next_probe_at <= $1.
-- Partial index on the "due" rows keeps lookups cheap on large fleets.
CREATE INDEX idx_host_liveness_next_probe_at
  ON host_liveness (next_probe_at)
  WHERE next_probe_at IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_host_liveness_next_probe_at;
ALTER TABLE host_liveness DROP COLUMN IF EXISTS next_probe_at;
