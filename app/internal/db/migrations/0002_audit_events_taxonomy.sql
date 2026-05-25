-- Extends the Day-3 audit_events table to the full taxonomy schema from
-- app/docs/audit_event_taxonomy.md §6.2 and app/specs/system/audit-emission.spec.yaml.
--
-- New columns:
--   recorded_at        - when the writer persisted the event (vs occurred_at = when it happened)
--   severity           - info | warning | error | critical (from events.yaml per-code)
--   outcome            - success | failure | denied (operation result)
--   actor_label        - human-readable actor identifier (email, username, "system")
--   actor_ip           - client IP at request time
--   actor_user_agent   - client UA at request time
--   actor_session_id   - session UUID if authenticated
--   parent_event_id    - for child events (e.g., scan.completed parents host audit rows)
--   policy_version     - active policy version when policy.applied was emitted
--   redactions         - TEXT[] of field names that were scrubbed pre-write
--   signature          - EdDSA signature over canonical event bytes (Day 7+, license signing primitive)
--
-- Existing columns from 0001 are retained; this migration is additive only.

-- +goose Up

ALTER TABLE audit_events
    ADD COLUMN recorded_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN severity           TEXT,
    ADD COLUMN outcome            TEXT,
    ADD COLUMN actor_label        TEXT,
    ADD COLUMN actor_ip           TEXT,
    ADD COLUMN actor_user_agent   TEXT,
    ADD COLUMN actor_session_id   UUID,
    ADD COLUMN parent_event_id    UUID,
    ADD COLUMN policy_version     TEXT,
    ADD COLUMN redactions         TEXT[],
    ADD COLUMN signature          BYTEA;

-- Indexes for forensic queries (taxonomy doc §6.2):
--   correlation_id        - already from 0001
--   occurred_at DESC      - already from 0001
--   recorded_at DESC      - for "what was just written" debugging
--   action                - filter by event code
--   severity              - filter by severity level
--   (actor_type, actor_id) - "what did this actor do?"
--   parent_event_id       - traverse event trees
CREATE INDEX idx_audit_recorded_at  ON audit_events (recorded_at DESC);
CREATE INDEX idx_audit_action       ON audit_events (action);
CREATE INDEX idx_audit_severity     ON audit_events (severity);
CREATE INDEX idx_audit_actor        ON audit_events (actor_type, actor_id);
CREATE INDEX idx_audit_parent       ON audit_events (parent_event_id) WHERE parent_event_id IS NOT NULL;

-- +goose Down

DROP INDEX IF EXISTS idx_audit_parent;
DROP INDEX IF EXISTS idx_audit_actor;
DROP INDEX IF EXISTS idx_audit_severity;
DROP INDEX IF EXISTS idx_audit_action;
DROP INDEX IF EXISTS idx_audit_recorded_at;

ALTER TABLE audit_events
    DROP COLUMN IF EXISTS signature,
    DROP COLUMN IF EXISTS redactions,
    DROP COLUMN IF EXISTS policy_version,
    DROP COLUMN IF EXISTS parent_event_id,
    DROP COLUMN IF EXISTS actor_session_id,
    DROP COLUMN IF EXISTS actor_user_agent,
    DROP COLUMN IF EXISTS actor_ip,
    DROP COLUMN IF EXISTS actor_label,
    DROP COLUMN IF EXISTS outcome,
    DROP COLUMN IF EXISTS severity,
    DROP COLUMN IF EXISTS recorded_at;
