-- 0032_api_tokens.sql
--
-- API service-account tokens for automation (CI, scripts) that call the
-- REST API without an interactive session.
--
-- A token is a high-entropy random secret shown to the operator exactly
-- once at creation. Only its SHA-256 hash is stored — high entropy means
-- a fast hash is safe (no brute-force surface) and lets the auth path
-- look the token up by an indexed hash. The token acts as a chosen role
-- (role_id): its effective permissions are that role's, re-evaluated by
-- the RBAC middleware on every request, so a later role change applies.

-- +goose Up
CREATE TABLE api_tokens (
    id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT         NOT NULL,
    -- SHA-256 of the raw token. Unique so a (vanishingly unlikely)
    -- collision is rejected rather than silently shared.
    token_hash   BYTEA        NOT NULL UNIQUE,
    -- Non-secret display prefix (e.g. owk_a1b2c3d4) for identifying a
    -- token in the list without revealing the secret.
    prefix       TEXT         NOT NULL,
    -- The role whose permissions the token carries. RESTRICT so a role
    -- can't be deleted out from under live tokens.
    role_id      TEXT         NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    created_by   UUID         REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);

-- Auth-path lookup: by hash, only live (non-revoked) tokens.
CREATE INDEX idx_api_tokens_hash ON api_tokens (token_hash) WHERE revoked_at IS NULL;

-- +goose Down
DROP TABLE IF EXISTS api_tokens;
