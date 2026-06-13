-- 0026_compliance_exceptions.sql
--
-- Operator-approved rule waivers (scan plan Phase 7, exception
-- governance). DB-backed per scan plan decision 2026-06-13: an
-- exception is approval-workflow data with a lifecycle, queries, and
-- an audit trail - relational, not a signed static policy file.
--
-- OVERLAY MODEL: an exception NEVER mutates host_rule_state. A failing
-- rule with an active exception stays 'fail' in the raw scan results
-- (Kensa's verdict is authoritative); the exception is an OpenWatch
-- governance annotation that the lens/UI reads to mark the failure as
-- accepted risk. The raw compliance score stays honest.
--
-- Lifecycle: requested -> approved | rejected ; approved -> revoked |
-- expired. Separation of duties (auth/permissions.yaml): exception:
-- request (ops_lead) is distinct from exception:approve (auditor /
-- security_admin); exception:revoke is dangerous (security_admin).
--
-- "Active" (suppressing) = status 'approved' AND not past expires_at.
-- The expiry sweep flips approved->expired when expires_at passes and
-- emits compliance.exception.expired; count queries also guard on
-- expires_at so they stay correct between sweeps.
--
-- Spec: api-compliance-exceptions v1.0.0.

-- +goose Up
CREATE TABLE compliance_exceptions (
    id            UUID PRIMARY KEY,
    host_id       UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    rule_id       TEXT NOT NULL,
    reason        TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'requested'
                  CHECK (status IN ('requested','approved','rejected','revoked','expired')),
    requested_by  UUID NOT NULL REFERENCES users(id),
    reviewed_by   UUID REFERENCES users(id),
    review_note   TEXT,
    expires_at    TIMESTAMPTZ,
    requested_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- At most ONE open (requested or approved) exception per host+rule, so
-- a duplicate request or a second approval cannot stack. Rejected /
-- revoked / expired rows are historical and do not block a fresh
-- request.
CREATE UNIQUE INDEX compliance_exceptions_one_open
    ON compliance_exceptions (host_id, rule_id)
    WHERE status IN ('requested','approved');

-- Per-host listing (Watchlist row, Compliance tab annotation).
CREATE INDEX compliance_exceptions_host ON compliance_exceptions (host_id);

-- Fleet queue + active-count scans by state.
CREATE INDEX compliance_exceptions_status ON compliance_exceptions (status);

-- +goose Down
DROP TABLE IF EXISTS compliance_exceptions;
