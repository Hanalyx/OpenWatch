-- +goose Up
-- Slice B.2a: host liveness (TCP-banner reachability probe).
--
-- One row per host. UPSERTed by the liveness probe loop. The
-- scheduler reads reachability_status alongside host_backoff_state.
-- suppress_until to decide whether to dispatch a scan.

CREATE TABLE host_liveness (
    host_id              UUID PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    reachability_status  TEXT NOT NULL DEFAULT 'unknown'
                         CHECK (reachability_status IN ('reachable','unreachable','unknown')),
    last_probe_at        TIMESTAMPTZ,
    last_response_ms     INTEGER,   -- NULL when last probe failed
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    last_state_change_at TIMESTAMPTZ,
    last_error_type      TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Lets the scheduler quickly find unreachable hosts to skip during dispatch.
CREATE INDEX idx_host_liveness_status
  ON host_liveness (reachability_status)
  WHERE reachability_status = 'unreachable';

-- +goose Down
DROP INDEX IF EXISTS idx_host_liveness_status;
DROP TABLE IF EXISTS host_liveness;
