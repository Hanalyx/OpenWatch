-- Slice A — host inventory.
--
-- Identity + connectivity columns only. OS-fingerprinting and
-- monitoring-state columns land with their producers (Slice B's Kensa
-- scanner, post-Slice-B's adaptive scheduler).
--
-- Also adds the deferred FK on credentials.scope_id → hosts(id) per
-- spec system-host-inventory C-04 / AC-02.
--
-- Spec: app/specs/system/host-inventory.spec.yaml.

-- +goose Up
CREATE TABLE hosts (
    id            UUID         PRIMARY KEY,
    hostname      TEXT         NOT NULL,
    ip_address    INET         NOT NULL,
    port          INTEGER      NOT NULL DEFAULT 22,
    display_name  TEXT,
    description   TEXT,
    environment   TEXT         NOT NULL DEFAULT 'production',
    -- TEXT[] (Postgres array) rather than a comma-separated TEXT column —
    -- queryable with `WHERE 'tag' = ANY(tags)` and indexable via GIN.
    tags          TEXT[]       NOT NULL DEFAULT '{}'::TEXT[],
    -- Forward-compatibility for host groups (later slice). Nullable;
    -- no FK yet since host_groups table doesn't exist.
    group_id      UUID,
    -- Per-host SSH username override. NULL = fall back to the system
    -- default credential's username.
    username      TEXT,
    created_by    UUID         NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deleted_at    TIMESTAMPTZ
);

-- Spec C-01: duplicates blocked among active rows; reusable after soft delete.
CREATE UNIQUE INDEX idx_hosts_hostname_environment_active
    ON hosts (hostname, environment)
    WHERE deleted_at IS NULL;

-- Spec C-02: GIN index makes `WHERE 'X' = ANY(tags)` indexed.
CREATE INDEX idx_hosts_tags ON hosts USING GIN (tags);

-- Environment is the most common filter; small btree is plenty.
CREATE INDEX idx_hosts_environment_active ON hosts (environment)
    WHERE deleted_at IS NULL;

-- Spec AC-02 / C-04: add the deferred FK on credentials.scope_id.
-- ON DELETE RESTRICT means a host with host-scope credentials cannot
-- be hard-deleted; soft delete is the only path.
ALTER TABLE credentials
    ADD CONSTRAINT credentials_scope_id_host_fk
        FOREIGN KEY (scope_id) REFERENCES hosts(id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED;
-- DEFERRABLE INITIALLY DEFERRED so a transaction that creates the host
-- and the credential in either order works. The constraint still fires
-- at commit time.

-- +goose Down
ALTER TABLE credentials DROP CONSTRAINT IF EXISTS credentials_scope_id_host_fk;
DROP TABLE IF EXISTS hosts;
