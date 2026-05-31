-- +goose Up
-- system_config: key-value runtime config for operator-tunable knobs.
--
-- Spec: services-connectivity-config (C-02).
--
-- One row per logical key. Value is JSONB so each typed config struct
-- (ConnectivityConfig today; future ComplianceSchedulerConfig, etc.)
-- serializes to one row with no schema migration when fields are
-- added. The systemconfig package owns the namespaces and validates
-- inputs at the language boundary.
--
-- updated_by is a free-text identity (username or "system"); we don't
-- FK to users.id because some writes originate from migrations /
-- bootstrap before any user row exists.

CREATE TABLE system_config (
    key         TEXT PRIMARY KEY,
    value       JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by  TEXT NOT NULL DEFAULT 'system'
);

-- +goose Down
DROP TABLE IF EXISTS system_config;
