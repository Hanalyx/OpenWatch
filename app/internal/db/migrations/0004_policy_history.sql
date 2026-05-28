-- Day-9 policy history. One row per successful policy load. Audit-grade:
-- the row tells "what policy was active at any given time". superseded_at
-- is set when a newer version replaces this one.
--
-- Spec: app/specs/system/policy.spec.yaml AC-09.

-- +goose Up
CREATE TABLE policy_history (
    id              UUID         PRIMARY KEY,
    policy_type     TEXT         NOT NULL,
    version         TEXT         NOT NULL,
    source_hash     TEXT         NOT NULL,
    signed_by       TEXT,
    loaded_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    superseded_at   TIMESTAMPTZ
);

CREATE INDEX idx_policy_history_type_loaded
    ON policy_history (policy_type, loaded_at DESC);

CREATE UNIQUE INDEX idx_policy_history_type_version
    ON policy_history (policy_type, version);

-- +goose Down
DROP TABLE IF EXISTS policy_history;
