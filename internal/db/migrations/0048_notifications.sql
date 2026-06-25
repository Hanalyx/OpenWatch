-- 0048_notifications.sql
--
-- In-app notifications (change-driven bell), Slice 1. A durable, per-user feed
-- of meaningful state changes — fanned out from the alert engine (and, in later
-- slices, the transaction log). Replaces the session-scoped in-memory counter.
--
-- One row per (recipient, change): the alert engine fans an Alert to one row
-- per eligible user. group_key collapses a recurring change for the same user
-- into one row (re-surfaced unread on a new occurrence) instead of flooding.
--
-- Design: docs/engineering/notifications_design.md. Spec: system-notifications.

-- +goose Up
CREATE TABLE notifications (
    id           UUID PRIMARY KEY,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,                 -- alert type / change kind (e.g. host_unreachable, drift_major)
    severity     TEXT NOT NULL,                 -- critical|high|medium|low|info (alertrouter.Severity)
    title        TEXT NOT NULL,
    body         TEXT NOT NULL DEFAULT '',
    host_id      UUID REFERENCES hosts(id) ON DELETE CASCADE,  -- NULL for fleet/system-scoped
    link         TEXT NOT NULL DEFAULT '',      -- deep-link target (/hosts/:id, /transactions/rule/:id, ...)
    group_key    TEXT NOT NULL,                 -- dedup/collapse key (alert DedupKey)
    occurred_at  TIMESTAMPTZ NOT NULL,
    read_at      TIMESTAMPTZ,                   -- NULL = unread
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Collapse a recurring change for the same user into one row.
    UNIQUE (user_id, group_key)
);

-- Unread-badge query: counts/lists a user's unread notifications newest-first.
CREATE INDEX idx_notifications_user_unread
    ON notifications (user_id, occurred_at DESC)
    WHERE read_at IS NULL;

-- General per-user listing (read + unread), newest-first.
CREATE INDEX idx_notifications_user_recent
    ON notifications (user_id, occurred_at DESC);

-- +goose Down
DROP TABLE notifications;
