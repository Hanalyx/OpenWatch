-- 0049_host_effective_maintenance.sql
--
-- A single source of truth for "is this host effectively in maintenance?".
--
-- Maintenance can be asserted at two scopes, and until now they were enforced
-- inconsistently:
--
--   * Per-host  — hosts.maintenance_mode, toggled from the host-detail page.
--     Honored by the liveness/connectivity, intelligence, and discovery loops,
--     but NOT by the compliance-scan scheduler (which filtered a separate,
--     never-written host_compliance_schedule.maintenance_mode column — so a host
--     put in maintenance kept getting compliance-scanned).
--   * Per-group — groups.maintenance, toggled from the Groups page. Written and
--     counted, but read by NO runtime loop, so it paused nothing at all.
--
-- This view resolves both scopes (and the two group-membership kinds: manual
-- members in group_members, and auto groups matched live by os_family) into one
-- boolean per host. Every scheduler/probe loop JOINs it and skips a host when
-- in_maintenance is true, so per-host and per-group maintenance now behave
-- identically everywhere. The membership logic mirrors group.Service.Summary's
-- "hosts in maintenance" query, keeping the count and the enforcement in sync.
--
-- Deleted hosts are intentionally NOT filtered here — each consuming query keeps
-- its own deleted_at predicate, so the view stays a pure maintenance resolver.
--
-- Spec: system-scheduler, system-liveness-loop, system-intelligence-scheduler,
--       system-discovery-scheduler, api-groups.

-- +goose Up
CREATE VIEW host_effective_maintenance AS
SELECT
    h.id AS host_id,
    (
        h.maintenance_mode
        OR EXISTS (
            SELECT 1
              FROM group_members gm
              JOIN groups g ON g.id = gm.group_id
             WHERE gm.host_id = h.id
               AND g.maintenance
        )
        OR EXISTS (
            SELECT 1
              FROM groups g
             WHERE g.membership = 'auto'
               AND g.maintenance
               AND g.match_family = h.os_family
        )
    ) AS in_maintenance
FROM hosts h;

-- +goose Down
DROP VIEW IF EXISTS host_effective_maintenance;
