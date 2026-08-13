-- +goose Up
-- Converge the seeded ops_lead description with auth.BuiltInRoles.
--
-- 0006 seeded the description with an em dash. The registry that generates
-- auth/roles.gen.go from auth/permissions.yaml uses a hyphen, and the two
-- guides use a colon. Every copy outside the database was corrected; the
-- seeded row was not, so a database provisioned by 0006 holds text that
-- disagrees with the SSOT the migration's own comment claims it matches.
--
-- Nobody sees the stale text. GetRoles builds its response from
-- auth.BuiltInRoles (internal/server/handlers.go, buildRoleEntries), so the
-- API has always served the hyphen. The only reads of roles.description are
-- the RETURNING clause when a CUSTOM role is created, which echoes back what
-- the caller just sent. A built-in role's stored description is written and
-- never read.
--
-- That is the reason to fix it rather than to leave it. A stored value that
-- no consumer reads is exactly where a divergence sits undetected, and the
-- next reader to wire the column up inherits it. system-user-management AC-12
-- now asserts the descriptions match the registry, so this cannot drift again
-- without a red test.
--
-- Guarded on the exact prior string, not just the id. No runtime path can
-- change a built-in role's description (users.CreateCustomRole refuses a
-- built-in id), but an operator with database access could have, and this
-- must not overwrite that. Matching zero rows is a correct outcome: it means
-- the row already reads correctly, which is also what makes the migration
-- idempotent and a no-op on a fresh install.
UPDATE roles
   SET description = 'Day-to-day operations - hosts, scans, alerts'
 WHERE id = 'ops_lead'
   AND description = 'Day-to-day operations — hosts, scans, alerts';

-- +goose Down
-- Restores the em dash, which is a defect, because that is what reversing
-- this migration means. Guarded the same way so a description edited after
-- the Up ran is left alone.
UPDATE roles
   SET description = 'Day-to-day operations — hosts, scans, alerts'
 WHERE id = 'ops_lead'
   AND description = 'Day-to-day operations - hosts, scans, alerts';
