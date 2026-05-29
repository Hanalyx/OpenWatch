-- +goose Up
-- Slice B.1c: transaction log writer (write-on-change persistence).
--
-- host_rule_state — one row per (host, rule). Holds the CURRENT state of
-- every rule on every host. UPSERTed every scan (last_checked_at moves
-- forward, check_count++, possibly status changes).
--
-- transactions — append-only log of state CHANGES. One row per scan
-- result whose status differs from the prior host_rule_state row (or
-- when there's no prior row — first_seen). NOT one row per scan result.
--
-- Together these tables answer:
--   - "What's the current state of host Y rule R?" → host_rule_state
--   - "When did rule R first fail on host Y?" → transactions, first row
--   - "What was the state at time T?" → transactions, latest at-or-before T
--
-- Both tables FK to hosts(id) ON DELETE RESTRICT — historical findings
-- outlive their host references; an operator must explicitly archive
-- before deleting the host (spec C-06).
--
-- Spec system-transaction-log-writer.

-- host_rule_state: current state per (host, rule)
CREATE TABLE host_rule_state (
    host_id          UUID         NOT NULL REFERENCES hosts(id) ON DELETE RESTRICT,
    rule_id          TEXT         NOT NULL,
    current_status   TEXT         NOT NULL
                     CHECK (current_status IN ('pass','fail','skipped','error')),
    severity         TEXT,
    last_checked_at  TIMESTAMPTZ  NOT NULL,
    check_count      INTEGER      NOT NULL DEFAULT 1,
    last_scan_id     UUID         NOT NULL,  -- FK added below to scans(id) if/when scans table exists
    evidence         JSONB        NOT NULL DEFAULT '{}'::jsonb,
    framework_refs   JSONB        NOT NULL DEFAULT '{}'::jsonb,
    skip_reason      TEXT,
    first_seen_at    TIMESTAMPTZ  NOT NULL,
    last_changed_at  TIMESTAMPTZ  NOT NULL,
    PRIMARY KEY (host_id, rule_id)
);

CREATE INDEX idx_host_rule_state_by_status
    ON host_rule_state (host_id, current_status);

-- transactions: append-only state changes
CREATE TABLE transactions (
    id                UUID         PRIMARY KEY,
    host_id           UUID         NOT NULL REFERENCES hosts(id) ON DELETE RESTRICT,
    rule_id           TEXT         NOT NULL,
    scan_id           UUID         NOT NULL,  -- FK to scans(id) when that table lands
    status            TEXT         NOT NULL
                      CHECK (status IN ('pass','fail','skipped','error')),
    severity          TEXT,
    change_kind       TEXT         NOT NULL
                      CHECK (change_kind IN ('first_seen','state_changed','severity_changed')),
    evidence          JSONB        NOT NULL,
    framework_refs    JSONB        NOT NULL DEFAULT '{}'::jsonb,
    skip_reason       TEXT,
    occurred_at       TIMESTAMPTZ  NOT NULL,
    -- spec C-04: idempotency. A second Apply call with the same scan_id
    -- for the same rule_id is a no-op (the UNIQUE constraint catches it).
    UNIQUE (scan_id, rule_id)
);

CREATE INDEX idx_transactions_host_rule_time
    ON transactions (host_id, rule_id, occurred_at DESC);

CREATE INDEX idx_transactions_scan_id
    ON transactions (scan_id);

-- +goose Down
DROP INDEX IF EXISTS idx_transactions_scan_id;
DROP INDEX IF EXISTS idx_transactions_host_rule_time;
DROP TABLE IF EXISTS transactions;
DROP INDEX IF EXISTS idx_host_rule_state_by_status;
DROP TABLE IF EXISTS host_rule_state;
