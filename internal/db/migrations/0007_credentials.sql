-- Slice A — SSH credential store with system→host tiering.
--
-- One table for both scopes. system-scope rows are the platform-wide
-- default; host-scope rows override per-host. Resolver in
-- internal/credential picks the highest precedence: host → system.
--
-- Spec: app/specs/system/credential-store.spec.yaml.

-- +goose Up
CREATE TABLE credentials (
    id                                UUID         PRIMARY KEY,
    scope                             TEXT         NOT NULL,
    -- For scope='host', the host UUID. For scope='system', NULL.
    -- No FK to hosts(id) yet — hosts table lands in migration 0008.
    -- A future migration adds the constraint. Application enforces
    -- the relationship today.
    scope_id                          UUID,
    name                              TEXT         NOT NULL,
    description                       TEXT,
    username                          TEXT         NOT NULL,
    auth_method                       TEXT         NOT NULL,

    -- Encrypted with AES-256-GCM (DEK from internal/secretkey).
    encrypted_password                BYTEA,
    encrypted_private_key             BYTEA,
    encrypted_private_key_passphrase  BYTEA,

    -- Public SSH key metadata for display + connection diagnostics.
    -- Stored unencrypted on purpose — fingerprint + key type are not secrets.
    ssh_key_fingerprint               TEXT,
    ssh_key_type                      TEXT,
    ssh_key_bits                      INTEGER,
    ssh_key_comment                   TEXT,

    is_default                        BOOLEAN      NOT NULL DEFAULT false,
    is_active                         BOOLEAN      NOT NULL DEFAULT true,
    created_by                        UUID         NOT NULL REFERENCES users(id),
    created_at                        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at                        TIMESTAMPTZ  NOT NULL DEFAULT now(),

    -- Constraint set per spec C-02, C-03, C-04.
    CONSTRAINT credentials_scope_known
        CHECK (scope IN ('system', 'host')),
    CONSTRAINT credentials_scope_id_match
        CHECK (
            (scope = 'system' AND scope_id IS NULL)
         OR (scope = 'host'   AND scope_id IS NOT NULL)
        ),
    CONSTRAINT credentials_auth_method_known
        CHECK (auth_method IN ('ssh_key', 'password', 'both')),
    CONSTRAINT credentials_auth_method_payload
        CHECK (
            (auth_method = 'ssh_key' AND encrypted_private_key IS NOT NULL)
         OR (auth_method = 'password' AND encrypted_password IS NOT NULL)
         OR (auth_method = 'both' AND encrypted_password IS NOT NULL
                                  AND encrypted_private_key IS NOT NULL)
        )
);

-- Spec C-05: only one (scope='system', is_default=true, is_active=true) at a time.
CREATE UNIQUE INDEX idx_credentials_one_system_default
    ON credentials ((true))
    WHERE scope = 'system' AND is_default = true AND is_active = true;

-- Per-scope name uniqueness. NULL scope_id (system rows) collapses; PG
-- treats NULLs as distinct in unique indexes by default, but we want
-- {scope, name} to be unique among active rows regardless of scope_id.
CREATE UNIQUE INDEX idx_credentials_scope_name_active
    ON credentials (scope, scope_id, name)
    WHERE is_active = true;

-- Resolver lookup index.
CREATE INDEX idx_credentials_scope_lookup
    ON credentials (scope, scope_id, is_active)
    WHERE is_active = true;

-- +goose Down
DROP TABLE IF EXISTS credentials;
