-- Drop the users.is_admin column.
--
-- Rationale: the column had unclear semantics. It only ever controlled
-- password-policy strictness (admin users got AdminPolicy — 15-char
-- minimum), but the API exposed it as if it were a permission marker,
-- which led API consumers to expect that `is_admin: true` meant the
-- user had admin RBAC permissions. In practice it did not — RBAC is
-- gated by rows in user_roles, not by this column. Removing the column
-- collapses the two stale-able sources of truth into one (user_roles)
-- and removes a class of drift bug.
--
-- Password policy after this migration is derived from the user's
-- primary role at password-set time: admin role → AdminPolicy, any
-- other role (or none) → DefaultPolicy.
--
-- Reversible via the Down migration below.

-- +goose Up
ALTER TABLE users DROP COLUMN is_admin;

-- +goose Down
ALTER TABLE users ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT false;
