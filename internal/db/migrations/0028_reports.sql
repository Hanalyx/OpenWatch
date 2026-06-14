-- 0028_reports.sql
--
-- Reports library (Reports MVP). A report is a point-in-time, immutable
-- compliance artifact. The MVP generates exactly ONE kind, the Fleet
-- Compliance Executive Summary: generating it computes a posture
-- snapshot from data that already exists (host_rule_state pass/fail
-- counts + critical, host count, top failing rules) and stores it as a
-- JSON document in `content`.
--
-- A report row is WRITE-ONCE: it captures the fleet posture at
-- generation time and is never recomputed. `data_as_of` records the
-- instant the posture was sampled; `content` is the rendered JSON.
--
-- DEFERRED (not in the MVP, hence not in this schema): Ed25519 signing
-- (no signature/key columns), PDF/OSCAL rendering (format stays 'json'),
-- the Scheduled dispatcher, retention sweeps. The `kind` CHECK currently
-- admits only 'executive' but is kept as a column so later report kinds
-- (attestation, remediation, exceptions) extend the CHECK rather than
-- the shape.
--
-- Spec: api-reports v1.0.0.

-- +goose Up
CREATE TABLE reports (
    id           UUID PRIMARY KEY,
    title        TEXT NOT NULL,
    kind         TEXT NOT NULL DEFAULT 'executive'
                 CHECK (kind IN ('executive')),
    scope_label  TEXT NOT NULL DEFAULT 'All hosts',
    data_as_of   TIMESTAMPTZ NOT NULL,
    generated_by TEXT NOT NULL,
    format       TEXT NOT NULL DEFAULT 'json',
    content      JSONB NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Library listing is newest first.
CREATE INDEX reports_created_at ON reports (created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS reports;
