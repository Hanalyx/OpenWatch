-- Slice A — custom-role permission storage.
--
-- Permission catalogue stays in code (auth.Permissions in
-- internal/auth/permissions.gen.go). Roles' grant lists live in the
-- DB as TEXT[] so admins can mint custom roles at runtime.
--
-- Built-in roles get NULL permissions (their grants live in code via
-- internal/auth/roles.gen.go). Custom roles MUST have a non-empty
-- permissions array.
--
-- Spec: app/specs/api/users.spec.yaml C-03, AC-11.

-- +goose Up
ALTER TABLE roles ADD COLUMN permissions TEXT[] NOT NULL DEFAULT '{}'::TEXT[];

-- A custom role's permissions array is small enough that no index is
-- needed for Slice A — admin-side enumeration only. Add GIN later if
-- "show me roles granting X" becomes a workload.

-- +goose Down
ALTER TABLE roles DROP COLUMN IF EXISTS permissions;
