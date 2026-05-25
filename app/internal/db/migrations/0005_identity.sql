-- Slice A — auth identity surface.
--
-- users:               account principal (one row per human or service account)
-- sessions:            server-side session record; cookie carries the presentation token
-- refresh_tokens:      JWT refresh-token rotation with reuse detection
-- auth_mfa_secrets:    per-user TOTP secret (encrypted at rest)
--
-- Spec: app/specs/system/auth-identity.spec.yaml.

-- +goose Up
CREATE TABLE users (
    id                       UUID         PRIMARY KEY,
    username                 TEXT         NOT NULL,
    email                    TEXT         NOT NULL,
    password_hash            TEXT         NOT NULL,
    is_admin                 BOOLEAN      NOT NULL DEFAULT false,
    last_password_change_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    created_at               TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deleted_at               TIMESTAMPTZ
);

-- Soft-delete-aware uniqueness: a deleted user's username/email can be
-- reused. Partial unique indexes are the standard PG pattern.
CREATE UNIQUE INDEX idx_users_username_active ON users (username)
    WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX idx_users_email_active ON users (email)
    WHERE deleted_at IS NULL;

CREATE TABLE sessions (
    id                  UUID         PRIMARY KEY,
    user_id             UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- SHA-256 of the presentation token. Storing the hash (not the token)
    -- means a DB read does not expose live sessions.
    token_hash          BYTEA        NOT NULL UNIQUE,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_seen           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    -- Inactivity timeout (15 min by spec C-06). Extended on each verify
    -- but never past absolute_expires_at.
    expires_at          TIMESTAMPTZ  NOT NULL,
    -- Absolute timeout (12 hr by spec C-06). Hard cap regardless of activity.
    absolute_expires_at TIMESTAMPTZ  NOT NULL,
    revoked_at          TIMESTAMPTZ,
    remote_addr         TEXT,
    user_agent          TEXT
);

CREATE INDEX idx_sessions_user_id      ON sessions (user_id);
CREATE INDEX idx_sessions_expires_at   ON sessions (expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE refresh_tokens (
    id                  UUID         PRIMARY KEY,
    user_id             UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash          BYTEA        NOT NULL UNIQUE,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ  NOT NULL,
    -- When this token is consumed (rotated), set rotated_to_id pointing
    -- at the row that replaced it. A second consume attempt against the
    -- same row triggers reuse detection (spec AC-13).
    rotated_to_id       UUID         REFERENCES refresh_tokens(id),
    revoked_at          TIMESTAMPTZ,
    reuse_detected_at   TIMESTAMPTZ
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens (user_id);

CREATE TABLE auth_mfa_secrets (
    user_id           UUID         PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    -- AES-256-GCM ciphertext (key from credential DEK, lands Slice A Week 2).
    encrypted_secret  BYTEA        NOT NULL,
    enrolled_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_verified_at  TIMESTAMPTZ
);

-- Per AC-16: replay protection requires remembering recently-used OTPs
-- within the ±1 step (90s) window. Tiny table; aggressive purge.
CREATE TABLE auth_mfa_otp_uses (
    user_id    UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    otp        TEXT         NOT NULL,
    used_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, otp)
);
CREATE INDEX idx_auth_mfa_otp_uses_used_at ON auth_mfa_otp_uses (used_at);

-- +goose Down
DROP TABLE IF EXISTS auth_mfa_otp_uses;
DROP TABLE IF EXISTS auth_mfa_secrets;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;
