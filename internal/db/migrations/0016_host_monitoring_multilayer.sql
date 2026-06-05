-- +goose Up
-- Slice B.3a: multi-layer adaptive health checks (v1.3.0).
--
-- Extends host_liveness with per-layer counters so the state machine
-- can distinguish DEGRADED (sudo broken), CRITICAL (SSH down), and
-- DOWN (no ping) instead of folding everything into a single failure
-- count. Adds the 5-band monitoring_state surface and the per-host
-- check_priority / maintenance_mode controls. Creates the
-- host_monitoring_history append-only table for diagnostics.

-- Per-layer counters on host_liveness ------------------------------------
ALTER TABLE host_liveness
  ADD COLUMN ping_consecutive_failures      INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN ping_consecutive_successes     INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN ssh_consecutive_failures       INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN ssh_consecutive_successes      INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN privilege_consecutive_failures INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN privilege_consecutive_successes INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN monitoring_state               TEXT NOT NULL DEFAULT 'unknown'
    CHECK (monitoring_state IN
      ('online','degraded','critical','down','maintenance','unknown'));

-- Index lets the operator dashboard summarise band distribution.
CREATE INDEX idx_host_liveness_monitoring_state
  ON host_liveness (monitoring_state);

-- Per-host maintenance + priority ----------------------------------------
ALTER TABLE hosts
  ADD COLUMN maintenance_mode  BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN check_priority    INTEGER NOT NULL DEFAULT 3
    CHECK (check_priority BETWEEN 1 AND 10);

-- The tick query ORDERs by priority DESC, next_probe_at ASC NULLS FIRST.
-- A partial index on the active-and-not-in-maintenance subset keeps the
-- planner's cost low even on fleets with thousands of paused hosts.
CREATE INDEX idx_hosts_active_for_probe
  ON hosts (check_priority DESC, id)
  WHERE deleted_at IS NULL AND maintenance_mode = false;

-- host_monitoring_history append-only diagnostics table ------------------
CREATE TABLE host_monitoring_history (
    id               BIGSERIAL PRIMARY KEY,
    host_id          UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    check_time       TIMESTAMPTZ NOT NULL DEFAULT now(),
    monitoring_state TEXT NOT NULL
      CHECK (monitoring_state IN
        ('online','degraded','critical','down','maintenance','unknown')),
    previous_state   TEXT
      CHECK (previous_state IS NULL OR previous_state IN
        ('online','degraded','critical','down','maintenance','unknown')),
    response_time_ms INTEGER,
    ping_ok          BOOLEAN,
    ssh_ok           BOOLEAN,
    privilege_ok     BOOLEAN,
    failed_layer     TEXT
      CHECK (failed_layer IS NULL OR failed_layer IN ('ping','ssh','privilege')),
    error_message    TEXT,
    error_type       TEXT
);

-- Tail-by-host lookups dominate (UI: "show this host's last N checks").
CREATE INDEX idx_host_monitoring_history_host_time
  ON host_monitoring_history (host_id, check_time DESC);

-- Retention sweeper indexes by check_time so it can DELETE WHERE check_time < cutoff
-- without scanning the whole table.
CREATE INDEX idx_host_monitoring_history_check_time
  ON host_monitoring_history (check_time);

-- +goose Down
DROP INDEX IF EXISTS idx_host_monitoring_history_check_time;
DROP INDEX IF EXISTS idx_host_monitoring_history_host_time;
DROP TABLE IF EXISTS host_monitoring_history;

DROP INDEX IF EXISTS idx_hosts_active_for_probe;
ALTER TABLE hosts
  DROP COLUMN IF EXISTS check_priority,
  DROP COLUMN IF EXISTS maintenance_mode;

DROP INDEX IF EXISTS idx_host_liveness_monitoring_state;
ALTER TABLE host_liveness
  DROP COLUMN IF EXISTS monitoring_state,
  DROP COLUMN IF EXISTS privilege_consecutive_successes,
  DROP COLUMN IF EXISTS privilege_consecutive_failures,
  DROP COLUMN IF EXISTS ssh_consecutive_successes,
  DROP COLUMN IF EXISTS ssh_consecutive_failures,
  DROP COLUMN IF EXISTS ping_consecutive_successes,
  DROP COLUMN IF EXISTS ping_consecutive_failures;
