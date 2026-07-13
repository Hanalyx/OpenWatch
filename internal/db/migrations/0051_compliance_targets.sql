-- 0051_compliance_targets.sql
--
-- Per-host and per-group compliance TARGET: durable operator intent about which
-- framework family a host is held to (its default lens, and the basis for
-- cohort scoring). Mirrors host_effective_maintenance (0049): a nullable
-- target-family value at two scopes, resolved into one row per host by
-- precedence.
--
--   * Per-host  — hosts.target_framework, set from the host-detail page. The
--     override; wins over any group.
--   * Per-group — groups.target_framework, set on a SITE group only (D1: an
--     auto os_category group is an OS grouping, not a statement of compliance
--     intent; the service rejects a target on a non-site group). A host in
--     several site groups with different targets resolves to the OLDEST
--     membership (D2: group_members.added_at ASC, then group id).
--
-- The org-wide default (systemconfig ComplianceConfig.DefaultFramework) is the
-- final fallback and is applied by the Go caller (it lives in a JSONB config
-- row a view should not reach into), so this view returns NULL when neither a
-- host nor a site-group target is set. NULL means "inherit the org default".
--
-- A framework family with no matching corpus key for a host scores N/A, never
-- 0% (D3) — enforced at query time by framework.MatchSQL, not here.
--
-- Deleted hosts are intentionally NOT filtered here (mirroring 0049) — each
-- consuming query keeps its own deleted_at predicate, so the view stays a pure
-- target resolver.
--
-- Spec: system-compliance-lens, api-hosts, api-groups.

-- +goose Up
ALTER TABLE hosts ADD COLUMN target_framework TEXT;
ALTER TABLE groups ADD COLUMN target_framework TEXT;

CREATE VIEW host_effective_target AS
SELECT
    h.id AS host_id,
    COALESCE(
        h.target_framework,
        (
            SELECT g.target_framework
              FROM group_members gm
              JOIN groups g ON g.id = gm.group_id
             WHERE gm.host_id = h.id
               AND g.kind = 'site'
               AND g.target_framework IS NOT NULL
             ORDER BY gm.added_at ASC, g.id ASC
             LIMIT 1
        )
    ) AS target_framework
FROM hosts h;

-- +goose Down
DROP VIEW IF EXISTS host_effective_target;
ALTER TABLE groups DROP COLUMN IF EXISTS target_framework;
ALTER TABLE hosts DROP COLUMN IF EXISTS target_framework;
