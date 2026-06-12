-- 0025_posture_snapshots.sql
--
-- Daily per-host compliance posture snapshots (scan plan Phase 6).
-- One row per (host, day): the host_rule_state aggregate as of the
-- last rollup that day. The hourly rollup UPSERTs today's row, so
-- intra-day re-scans refresh it and the row freezes at midnight;
-- history accumulates organically going forward (no retroactive
-- reconstruction from transactions - replaying per-day counts is not
-- worth the complexity for a trend chart).
--
-- score_pct uses the same formula as the compliance lens
-- (passing / total over ALL statuses) so the trend line and the tab
-- headline never disagree.
--
-- Spec: system-posture-snapshots v1.0.0.

-- +goose Up
CREATE TABLE posture_snapshots (
    host_id               UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    snapshot_date         DATE NOT NULL,
    passing               INTEGER NOT NULL DEFAULT 0,
    failing               INTEGER NOT NULL DEFAULT 0,
    skipped               INTEGER NOT NULL DEFAULT 0,
    error                 INTEGER NOT NULL DEFAULT 0,
    total                 INTEGER NOT NULL DEFAULT 0,
    score_pct             REAL NOT NULL DEFAULT 0,
    has_critical_findings BOOLEAN NOT NULL DEFAULT FALSE,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (host_id, snapshot_date)
);

-- Trend reads scan by host + date range; fleet trend by date.
CREATE INDEX posture_snapshots_date ON posture_snapshots (snapshot_date);

-- +goose Down
DROP TABLE IF EXISTS posture_snapshots;
