-- +goose Up
-- Slice B.1a: scheduler.
--
-- host_compliance_schedule — one row per host. The dispatcher claims due
-- rows via SELECT ... FOR UPDATE SKIP LOCKED at every 60s tick and enqueues
-- a scan job. After the scan completes, UpdateAfterScan recomputes
-- compliance_state from the result and writes the next_scheduled_scan.
--
-- host_backoff_state — separate per-host backoff ledger. Lives in its own
-- table (not in host_compliance_schedule) so the executor's failure
-- accounting doesn't write to the scheduler-owned schedule columns;
-- scheduler-domain writes stay scheduler-owned. Dispatcher reads this
-- table via LEFT JOIN to skip hosts whose suppress_until > now().

CREATE TABLE host_compliance_schedule (
    host_id                  UUID PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    compliance_state         TEXT NOT NULL DEFAULT 'unknown'
                             CHECK (compliance_state IN ('compliant','partial','non_compliant','critical','unknown')),
    compliance_score         REAL,
    has_critical_findings    BOOLEAN NOT NULL DEFAULT FALSE,
    current_interval_minutes INTEGER NOT NULL DEFAULT 1440,
    next_scheduled_scan      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_scan_completed_at   TIMESTAMPTZ,
    maintenance_mode         BOOLEAN NOT NULL DEFAULT FALSE,
    maintenance_until        TIMESTAMPTZ,
    policy_version_at_last_scan TEXT,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_host_compliance_schedule_next_scan
  ON host_compliance_schedule (next_scheduled_scan)
  WHERE maintenance_mode = FALSE;

CREATE TABLE host_backoff_state (
    host_id              UUID PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    probe_type           TEXT NOT NULL DEFAULT 'scan'
                         CHECK (probe_type IN ('scan','intel')),
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    suppress_until       TIMESTAMPTZ,
    last_error_code      TEXT,
    last_failure_at      TIMESTAMPTZ,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_host_backoff_state_suppress
  ON host_backoff_state (suppress_until)
  WHERE suppress_until IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_host_backoff_state_suppress;
DROP TABLE IF EXISTS host_backoff_state;
DROP INDEX IF EXISTS idx_host_compliance_schedule_next_scan;
DROP TABLE IF EXISTS host_compliance_schedule;
