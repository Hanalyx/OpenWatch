-- 0053_posture_snapshot_framework.sql
--
-- Framework-scoped posture snapshots (compliance-lens Phase 3c).
--
-- Before this, posture_snapshots held ONE row per (host, day) — an
-- all-rules score. The compliance trend card could therefore only ever
-- show all-rules, disagreeing with the host-detail hero tile / list /
-- coverage once a framework lens is the default (a RHEL 9 host reads 88%
-- STIG on the tile but 68% all-rules on the trend).
--
-- This adds a `framework` dimension so the rollup stores a per-FAMILY
-- score (OS-resolved: a RHEL 9 host's "stig" row is its stig_rhel9 score)
-- PLUS the all-rules row (framework=''). The trend then reads the series
-- for whatever lens is in effect, and switching the org default just
-- selects a different pre-computed series — no recompute, no broken
-- history. History is kept "start fresh": existing rows become the
-- all-rules ('') series; per-family series accrue going forward.
--
-- Spec: system-posture-snapshots v1.1.0 / api-compliance-trend v1.1.0.

-- +goose Up
ALTER TABLE posture_snapshots ADD COLUMN framework TEXT NOT NULL DEFAULT '';

-- Widen the identity to (host, day, framework): '' is the all-rules
-- series (the existing rows), a family id (stig, cis, nist_800_53, …) is
-- that lens's OS-resolved score for the host that day.
ALTER TABLE posture_snapshots DROP CONSTRAINT posture_snapshots_pkey;
ALTER TABLE posture_snapshots ADD PRIMARY KEY (host_id, snapshot_date, framework);

-- Fleet trend reads by (framework, date); host trend by (host, framework, date).
CREATE INDEX posture_snapshots_fw_date ON posture_snapshots (framework, snapshot_date);

-- +goose Down
DROP INDEX IF EXISTS posture_snapshots_fw_date;
-- Collapse back to one row per (host, day): drop the per-family rows so
-- the narrower PK does not violate uniqueness.
DELETE FROM posture_snapshots WHERE framework <> '';
ALTER TABLE posture_snapshots DROP CONSTRAINT posture_snapshots_pkey;
ALTER TABLE posture_snapshots ADD PRIMARY KEY (host_id, snapshot_date);
ALTER TABLE posture_snapshots DROP COLUMN framework;
