-- system-scan-runs v1.0.0 — operational record of compliance-scan
-- attempts (the scan "logbook").
--
-- One row per scan attempt, keyed by the SAME id as the job_queue job
-- (and therefore the same value as transactions.scan_id — the worker
-- already uses job.ID as ScanID for traceability). Powers "last scan",
-- "scan queue" depth, and per-host scan history; complements the audit
-- events (scan.queued / scan.started / scan.completed / scan.failed)
-- which carry the who/when trail.
--
-- trigger_source records who initiated: 'on_demand' (operator, via
-- POST /hosts/{id}/scan, requested_by populated) or 'scheduled' (the
-- adaptive scheduler; requested_by NULL).
--
-- FK style matches transactions / host_rule_state: ON DELETE RESTRICT —
-- scan history is compliance evidence; deleting a host must first
-- archive/clear its records explicitly.

-- +goose Up
CREATE TABLE scan_runs (
    id             UUID         PRIMARY KEY,
    host_id        UUID         NOT NULL REFERENCES hosts(id) ON DELETE RESTRICT,
    trigger_source TEXT         NOT NULL
                   CHECK (trigger_source IN ('on_demand', 'scheduled')),
    requested_by   UUID         NULL REFERENCES users(id) ON DELETE SET NULL,
    status         TEXT         NOT NULL DEFAULT 'queued'
                   CHECK (status IN ('queued', 'running', 'completed', 'failed')),
    queued_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    started_at     TIMESTAMPTZ  NULL,
    finished_at    TIMESTAMPTZ  NULL,
    policy_version TEXT         NULL,
    -- Outcome counts, populated on completion (NULL until then).
    rules_pass     INTEGER      NULL,
    rules_fail     INTEGER      NULL,
    rules_skipped  INTEGER      NULL,
    rules_error    INTEGER      NULL,
    failure_reason TEXT         NULL,
    correlation_id TEXT         NULL
);

-- "Last scan" / history per host, newest first.
CREATE INDEX scan_runs_host_recent ON scan_runs (host_id, queued_at DESC);

-- "Scan queue" depth + in-flight view; partial index keeps it tiny.
CREATE INDEX scan_runs_active ON scan_runs (status)
    WHERE status IN ('queued', 'running');

-- +goose Down
DROP TABLE IF EXISTS scan_runs;
