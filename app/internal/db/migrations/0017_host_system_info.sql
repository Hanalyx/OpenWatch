-- Slice 1.1 — host OS fingerprint discovery (system-host-discovery v1.0.0).
--
-- Adds:
--   1) Denormalized os_* + os_discovered_at columns on hosts so list-page
--      filters / group-by stay one-table (spec C-09).
--   2) host_system_info wide row per host. UPSERT-only (spec C-08); never
--      append. UNIQUE constraint on host_id enforces single-row-per-host.

-- +goose Up
ALTER TABLE hosts
    ADD COLUMN os_family            TEXT,
    ADD COLUMN os_version           TEXT,
    ADD COLUMN architecture         TEXT,
    ADD COLUMN platform_identifier  TEXT,
    ADD COLUMN os_discovered_at     TIMESTAMPTZ;

-- Filtering by os_family is the most common list-page query (group hosts
-- by distribution). Partial index since most queries combine with the
-- soft-delete filter.
CREATE INDEX idx_hosts_os_family_active
    ON hosts (os_family)
    WHERE deleted_at IS NULL AND os_family IS NOT NULL;

CREATE TABLE host_system_info (
    host_id             UUID PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,

    -- /etc/os-release
    os_name             TEXT,
    os_version          TEXT,
    os_version_full     TEXT,
    os_id               TEXT,
    os_id_like          TEXT,
    os_pretty_name      TEXT,
    platform_identifier TEXT,
    os_family           TEXT,

    -- uname -srvm
    kernel_name         TEXT,
    kernel_release      TEXT,
    kernel_version      TEXT,
    architecture        TEXT,

    -- /proc/meminfo (MB-rounded integers)
    mem_total_mb        INTEGER,
    mem_available_mb    INTEGER,
    swap_total_mb       INTEGER,

    -- df -BG /
    disk_total_gb       INTEGER,
    disk_used_gb        INTEGER,
    disk_free_gb        INTEGER,

    -- hostname / hostname -f
    hostname            TEXT,
    fqdn                TEXT,

    -- security posture
    selinux_status      TEXT,   -- Enforcing | Permissive | Disabled | (empty if not present)
    apparmor_enabled    BOOLEAN,

    -- firewall introspection. May be empty when probe lacked sudo (C-03).
    firewall_service    TEXT,   -- firewalld | ufw | nftables | iptables | (empty)
    firewall_status     TEXT,   -- active | inactive | (empty)

    collected_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS host_system_info;
DROP INDEX IF EXISTS idx_hosts_os_family_active;
ALTER TABLE hosts
    DROP COLUMN IF EXISTS os_discovered_at,
    DROP COLUMN IF EXISTS platform_identifier,
    DROP COLUMN IF EXISTS architecture,
    DROP COLUMN IF EXISTS os_version,
    DROP COLUMN IF EXISTS os_family;
