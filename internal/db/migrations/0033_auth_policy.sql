-- 0033_auth_policy.sql
--
-- Workspace-wide authentication policy: a single-row table holding the
-- require-MFA flag and the session idle/absolute timeout windows. These
-- were previously hard-coded constants in the identity package; promoting
-- them to data lets a security admin tune them from Settings -> Security
-- without a redeploy.
--
-- Singleton pattern: a fixed BOOLEAN primary key pinned to TRUE so at most
-- one row can ever exist. Reads and writes always target id = TRUE.
--
-- Defaults match the historical constants (15-minute idle, 12-hour
-- absolute) so promoting to data is behaviour-preserving until an admin
-- changes it.

-- +goose Up
CREATE TABLE auth_policy (
    -- Singleton guard: only id = TRUE is permitted, so the table holds at
    -- most one row.
    id                              BOOLEAN     PRIMARY KEY DEFAULT TRUE
                                                CHECK (id = TRUE),
    -- When TRUE, every user must have MFA enrolled. Soft enforcement: a
    -- password-valid but non-enrolled user still authenticates, but the
    -- login response flags mfa_enrollment_required so the UI forces
    -- enrollment before anything else. Avoids locking out users who have
    -- no other path to reach the (auth-gated) enrollment endpoint.
    require_mfa                     BOOLEAN     NOT NULL DEFAULT FALSE,
    -- Inactivity window: a session expires this many seconds after its
    -- last use. Bounds (5 min .. 24 h) are enforced in the service layer.
    session_idle_timeout_seconds    INTEGER     NOT NULL DEFAULT 900,
    -- Absolute lifetime: a session cannot live longer than this regardless
    -- of activity. Bounds (1 h .. 30 d) enforced in the service layer.
    session_absolute_timeout_seconds INTEGER    NOT NULL DEFAULT 43200,
    updated_at                      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- The admin who last changed the policy (NULL for the seeded default).
    updated_by                      UUID        REFERENCES users(id) ON DELETE SET NULL
);

-- Seed the singleton row with the behaviour-preserving defaults.
INSERT INTO auth_policy (id) VALUES (TRUE);

-- +goose Down
DROP TABLE IF EXISTS auth_policy;
