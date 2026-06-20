-- 0040_user_preferences.sql
--
-- Per-user UI preferences, persisted server-side so a user's choices
-- (e.g. the /hosts grid-vs-table default) follow them across devices and
-- browsers instead of living only in localStorage.
--
-- Stored as a single JSONB blob on the users row rather than a wide set of
-- typed columns: preferences are a small, evolving bag of personal UI knobs
-- with no relational queries against them, so a JSONB column keeps adding a
-- new preference a contract-only change (no migration per knob). The set of
-- valid keys is governed at the API layer by the typed UserPreferences
-- schema; PATCH merges via the JSONB || operator.
--
-- Spec: system-user-preferences + api-user-preferences.

-- +goose Up
ALTER TABLE users ADD COLUMN preferences JSONB NOT NULL DEFAULT '{}'::jsonb;

-- +goose Down
ALTER TABLE users DROP COLUMN IF EXISTS preferences;
