-- 0046_report_schedules.sql
--
-- Reports C3: scheduled reports. A report_schedules row recurs a report
-- generation on a daily/weekly/monthly cadence and delivers the rendered
-- PDF by email through an existing email notification channel. The cron
-- dispatcher claims due schedules (next_run_at <= now), generates the
-- report, renders its PDF, emails it, and advances next_run_at.
--
-- Spec: system-report-schedule v1.0.0.

-- +goose Up
CREATE TABLE report_schedules (
    id            UUID PRIMARY KEY,
    name          TEXT NOT NULL,
    kind          TEXT NOT NULL
                  CHECK (kind IN ('executive', 'attestation', 'exception', 'remediation')),
    -- scope mirrors a GenerateRequest: {group_id, framework, period_days}.
    scope         JSONB NOT NULL DEFAULT '{}'::jsonb,
    frequency     TEXT NOT NULL CHECK (frequency IN ('daily', 'weekly', 'monthly')),
    -- hour of day (UTC) to run; weekday (0=Sun..6=Sat) for weekly;
    -- day_of_month (1..28) for monthly.
    hour          INTEGER NOT NULL DEFAULT 6 CHECK (hour >= 0 AND hour <= 23),
    weekday       INTEGER CHECK (weekday >= 0 AND weekday <= 6),
    day_of_month  INTEGER CHECK (day_of_month >= 1 AND day_of_month <= 28),
    -- the email notification channel that provides SMTP transport + recipients.
    channel_id    UUID NOT NULL REFERENCES notification_channels(id) ON DELETE RESTRICT,
    enabled       BOOLEAN NOT NULL DEFAULT true,
    next_run_at   TIMESTAMPTZ NOT NULL,
    last_run_at   TIMESTAMPTZ,
    last_status   TEXT,
    created_by    UUID REFERENCES users(id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The dispatcher scans for due schedules; this index serves it.
CREATE INDEX idx_report_schedules_due ON report_schedules (next_run_at)
    WHERE enabled;

-- +goose Down
DROP TABLE IF EXISTS report_schedules;
