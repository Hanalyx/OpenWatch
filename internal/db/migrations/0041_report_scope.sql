-- 0041_report_scope.sql
--
-- Reports A1 (scope the executive report). Adds a structured scope to the
-- reports row so a generated report records WHICH slice of the fleet it
-- summarizes (a group and/or a framework lens), not just the free-text
-- scope_label.
--
-- Stored as a single JSONB blob rather than typed columns: the scope is a
-- small, evolving descriptor ({group_id, group_name, framework}) with no
-- relational queries against it, and later report kinds will carry richer
-- scope shapes (period, explicit host sets). A JSONB column keeps adding a
-- scope dimension a contract-only change. Existing rows backfill to '{}'
-- (the all-hosts, all-frameworks scope), matching the prior fixed
-- scope_label of 'All hosts'.
--
-- Spec: api-reports v1.1.0.

-- +goose Up
ALTER TABLE reports ADD COLUMN scope JSONB NOT NULL DEFAULT '{}'::jsonb;

-- +goose Down
ALTER TABLE reports DROP COLUMN IF EXISTS scope;
