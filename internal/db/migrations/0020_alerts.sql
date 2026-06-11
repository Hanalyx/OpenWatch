-- PR 2 — Alert persistence (system-alert-router v1.1.0).
--
-- Unblocks:
--   - /activity unified feed (UNION over alerts + transactions +
--     intelligence_events + audit_events)
--   - alerts CRUD endpoints (PR 3 — system-alerts + api-alerts)
--   - alert lifecycle (acknowledge / silence / resolve / dismiss)
--
-- State machine v1.1.0 is intentionally minimal: every persisted row
-- starts as 'active'. Transition logic is owned by system-alerts; the
-- router NEVER updates state. C-11.
--
-- UNIQUE (dedup_key, occurred_at): defense-in-depth against router
-- restarts during the dedup TTL window. The in-memory gate forgets on
-- restart; the constraint still catches the duplicate. C-12.

-- +goose Up
CREATE TABLE alerts (
    id           UUID         PRIMARY KEY,
    dedup_key    TEXT         NOT NULL,
    alert_type   TEXT         NOT NULL,
    severity     TEXT         NOT NULL
                 CHECK (severity IN ('critical','high','medium','low','info')),
    host_id      UUID         REFERENCES hosts(id) ON DELETE SET NULL,
    rule_id      TEXT         NOT NULL DEFAULT '',
    title        TEXT         NOT NULL,
    body         TEXT         NOT NULL DEFAULT '',
    tags         JSONB        NOT NULL DEFAULT '{}'::jsonb,
    state        TEXT         NOT NULL DEFAULT 'active'
                 CHECK (state IN ('active','silenced','acknowledged','resolved','dismissed')),
    occurred_at  TIMESTAMPTZ  NOT NULL,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),

    UNIQUE (dedup_key, occurred_at)
);

-- Common reads:
--   /activity feed: WHERE state != 'dismissed' ORDER BY occurred_at DESC LIMIT N
--   per-host detail: WHERE host_id = $1 AND state != 'dismissed' ORDER BY occurred_at DESC
--   lifecycle ops: WHERE id = $1 AND state IN ('active','silenced')
CREATE INDEX idx_alerts_active_recent
    ON alerts (occurred_at DESC)
    WHERE state != 'dismissed';

CREATE INDEX idx_alerts_host_active
    ON alerts (host_id, occurred_at DESC)
    WHERE state != 'dismissed' AND host_id IS NOT NULL;

CREATE INDEX idx_alerts_severity_active
    ON alerts (severity, occurred_at DESC)
    WHERE state = 'active';

-- +goose Down
DROP INDEX IF EXISTS idx_alerts_severity_active;
DROP INDEX IF EXISTS idx_alerts_host_active;
DROP INDEX IF EXISTS idx_alerts_active_recent;
DROP TABLE IF EXISTS alerts;
