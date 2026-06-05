-- Stage 0 baseline schema.
--
-- audit_events: every server action emits a row here. correlation_id
-- threads through HTTP entry → context → audit row per the propagation
-- contract (app/docs/correlation_id_propagation.md). NOT NULL — if it's
-- empty something upstream is broken.
--
-- idempotency_keys: caches a 24h response for replays of mutating
-- requests. Day 6 wires the middleware.
--
-- Day 5 expands audit_events with severity/outcome/actor/redactions/
-- signature columns and the indexes from audit_event_taxonomy.md §6.2.
-- Today's columns are the minimum the audit foundation API requires.

-- +goose Up

CREATE TABLE audit_events (
    id              UUID PRIMARY KEY,
    correlation_id  TEXT NOT NULL,
    actor_type      TEXT NOT NULL,
    actor_id        TEXT,
    action          TEXT NOT NULL,
    resource_type   TEXT,
    resource_id     TEXT,
    detail          JSONB,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_correlation ON audit_events (correlation_id);
CREATE INDEX idx_audit_occurred_at ON audit_events (occurred_at DESC);

CREATE TABLE idempotency_keys (
    key             TEXT PRIMARY KEY,
    request_hash    TEXT NOT NULL,
    response_status INT NOT NULL,
    response_body   JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_idempotency_expires ON idempotency_keys (expires_at);

-- +goose Down

DROP TABLE IF EXISTS idempotency_keys;
DROP TABLE IF EXISTS audit_events;
