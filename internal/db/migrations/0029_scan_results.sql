-- 0029_scan_results.sql
--
-- Durable, point-in-time per-scan compliance results + evidence.
--
-- The Q1 write-on-change model (host_rule_state = current state,
-- transactions = only rules that CHANGED) deliberately overwrites the
-- per-rule evidence of a superseded scan, so a historical scan's proof
-- is unrecoverable. That is fine for drift/alerts and the live
-- compliance lens, but it cannot answer an audit-window question:
-- "what command output proved rule X passed on the Feb 1 scan?"
--
-- These two tables retain EVERY rule's outcome for EVERY scan so any
-- historical scan is fully browsable and exportable as OSCAL. They are
-- written alongside the transaction log (never instead of it) and have
-- no live readers on the scan/alert path; they back the /api/v1/scans
-- surface (scan:read).
--
--   scan_evidence  - content-addressed evidence blob store. The PK is
--                    the sha256 of the RAW evidence bytes, so an
--                    unchanged passing rule across N scans stores its
--                    proof ONCE (dedup via ON CONFLICT DO NOTHING). This
--                    is what makes full per-scan retention affordable
--                    without the 1.58M-row blob explosion the
--                    write-on-change model was built to avoid.
--   scan_results   - one row per (scan_id, rule_id): the rule's verdict
--                    as of that scan, referencing its evidence by hash
--                    (NULL when the check captured none).
--
-- FK style is ON DELETE RESTRICT to match every other history table
-- (transactions, host_rule_state, scan_runs): compliance history
-- outlives host/scan refs and is never silently dropped. A retention
-- sweep (future) must delete scan_results before orphan evidence blobs.
--
-- Spec: system-scan-results-store v1.0.0, api-scans v1.0.0.

-- +goose Up
CREATE TABLE scan_evidence (
    -- sha256(raw evidence bytes), 32 bytes. Content address => dedup.
    evidence_hash BYTEA       PRIMARY KEY,
    -- the evidenceDoc {detail, error?, checks?} produced by the kensa
    -- executor (internal/kensa/scanfunc.go evidenceJSON).
    evidence      JSONB       NOT NULL,
    -- len() of the raw bytes; the writer caps this at 256 KiB (the same
    -- transactionlog.MaxEvidenceBytes policy constant, enforced in Go).
    byte_size     INTEGER     NOT NULL,
    -- the instant this distinct evidence content was FIRST observed.
    -- ON CONFLICT DO NOTHING preserves it across later identical writes.
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE scan_results (
    scan_id        UUID        NOT NULL REFERENCES scan_runs(id) ON DELETE RESTRICT,
    host_id        UUID        NOT NULL REFERENCES hosts(id)     ON DELETE RESTRICT,
    rule_id        TEXT        NOT NULL,
    status         TEXT        NOT NULL
                   CHECK (status IN ('pass', 'fail', 'skipped', 'error')),
    severity       TEXT,
    -- references the deduped blob; NULL when the check captured no
    -- evidence (a clean "no evidence", never a hash of "{}").
    evidence_hash  BYTEA       REFERENCES scan_evidence(evidence_hash) ON DELETE RESTRICT,
    framework_refs JSONB       NOT NULL DEFAULT '{}'::jsonb,
    skip_reason    TEXT,
    -- the persist instant (audit "when we wrote it"); the authoritative
    -- scan time is scan_runs.finished_at.
    recorded_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- (scan_id, rule_id) gives idempotency for free: re-persisting a
    -- scan is a no-op via ON CONFLICT DO NOTHING. The scan-detail query
    -- (all rules of a scan) is served by this PK's scan_id prefix.
    PRIMARY KEY (scan_id, rule_id)
);

-- "show me every scan of rule R on host H" (point-in-time rule history).
CREATE INDEX idx_scan_results_host_rule ON scan_results (host_id, rule_id);

-- +goose Down
DROP TABLE IF EXISTS scan_results;
DROP TABLE IF EXISTS scan_evidence;
