-- PR 1.2 — host OS Intelligence storage (system-os-intelligence v1.0.0).
--
-- Two tables:
--   1) host_intelligence_state: one snapshot per host (UPSERT, no history).
--      Spec C-03.
--   2) host_intelligence_events: append-only diff log. One row per detected
--      change. UNIQUE (host_id, event_code, occurred_at) for idempotency.
--      Spec C-04 + AC-14.

-- +goose Up

CREATE TABLE host_intelligence_state (
    host_id      UUID PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    snapshot     JSONB NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL,
    collected_by UUID,            -- optional scan_id when piggybacked on a scan, NULL otherwise
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE host_intelligence_events (
    id             UUID         PRIMARY KEY,
    host_id        UUID         NOT NULL REFERENCES hosts(id) ON DELETE RESTRICT,
    event_code     TEXT         NOT NULL,
    severity       TEXT         NOT NULL
                   CHECK (severity IN ('info','low','medium','high','critical')),
    detail         JSONB        NOT NULL,
    occurred_at    TIMESTAMPTZ  NOT NULL,
    detected_at    TIMESTAMPTZ  NOT NULL,
    correlation_id TEXT         NOT NULL,
    UNIQUE (host_id, event_code, occurred_at),
    -- Spec C-05 + AC-15: closed-enum CHECK on event_code. Adding a new code
    -- requires a follow-up migration to extend the enum so review catches it.
    CHECK (event_code IN (
        -- account
        'account.user.locked',
        'account.user.unlocked',
        'account.user.created',
        'account.user.deleted',
        'account.user.privileged_group_added',
        'account.password.expired',
        'account.password.expiring',
        'account.ssh_key.added',
        'account.ssh_key.removed',
        'account.sudo.failure_threshold',
        -- security
        'security.login.new_source_ip',
        'security.login.failed_threshold',
        'security.selinux.denied',
        'security.apparmor.denied',
        'security.firewall.rule_changed',
        'security.port.opened',
        -- system
        'system.package.installed',
        'system.package.updated',
        'system.package.removed',
        'system.kernel.updated',
        'system.reboot.required',
        'system.reboot.completed',
        'system.config.file_changed',
        'system.service.started',
        'system.service.stopped',
        'system.service.failed',
        'system.filesystem.mounted',
        'system.filesystem.unmounted'
    ))
);

-- Common query: latest events for the /activity feed, ordered newest-first.
CREATE INDEX idx_intel_events_recent
    ON host_intelligence_events (detected_at DESC);

-- Common query: events for a single host of a specific code, e.g. all
-- "account.user.locked" events for host X in the last 24h.
CREATE INDEX idx_intel_events_host_code
    ON host_intelligence_events (host_id, event_code, occurred_at DESC);

-- +goose Down
DROP INDEX IF EXISTS idx_intel_events_host_code;
DROP INDEX IF EXISTS idx_intel_events_recent;
DROP TABLE IF EXISTS host_intelligence_events;
DROP TABLE IF EXISTS host_intelligence_state;
