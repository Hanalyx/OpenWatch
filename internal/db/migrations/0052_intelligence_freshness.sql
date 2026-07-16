-- 0052_intelligence_freshness.sql
--
-- Per-category collection freshness for discovery + OS intelligence, Phase 1b of
-- the last-known-good model. The no-clobber merge (0051-era code, spec
-- system-host-discovery v1.5.0 / system-os-intelligence v1.2.0) already keeps a
-- failed probe from blanking good data. This adds the metadata a consumer needs
-- to tell FRESH data from CARRIED-FORWARD data: for each fact category, when it
-- was last observed, when it was last attempted, and the last attempt's status.
--
-- Shape (JSONB, one key per fact category):
--   { "<category>": { "observed_at": <ts>, "attempt_at": <ts>, "status": "ok" | "stale" } }
--     * status "ok"    — observed this run; observed_at == attempt_at
--     * status "stale" — not observed this run; observed_at is the last good
--                        time, attempt_at is this run (the failed attempt)
-- A category never observed has no key. NULL column = pre-feature row.
--
-- Discovery categories: os_release, uname, memory, disk, hostname, fqdn,
--   selinux, apparmor, firewall.
-- Intelligence categories: users, groups, listening_ports, network_interfaces,
--   routes, firewall_rule_count, packages, services, kernel_release, uptime,
--   mountpoints, config_hashes.
--
-- Spec: system-host-discovery, system-os-intelligence.

-- +goose Up
ALTER TABLE host_system_info      ADD COLUMN category_freshness JSONB;
ALTER TABLE host_intelligence_state ADD COLUMN category_freshness JSONB;

-- +goose Down
ALTER TABLE host_intelligence_state DROP COLUMN IF EXISTS category_freshness;
ALTER TABLE host_system_info        DROP COLUMN IF EXISTS category_freshness;
