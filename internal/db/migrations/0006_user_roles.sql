-- Slice A — user role assignments.
--
-- roles:        built-in role definitions (seed-only in Slice A; CRUD lands later)
-- user_roles:   many-to-many link between users and roles
--
-- The auth.Permissions registry in internal/auth/permissions.gen.go is
-- the source of truth for which permissions each role grants. This
-- table only enumerates the role IDs; the permissions themselves stay
-- in code so they're version-controlled with the build.
--
-- Spec: app/specs/system/user-management.spec.yaml.

-- +goose Up
CREATE TABLE roles (
    id            TEXT         PRIMARY KEY,
    description   TEXT         NOT NULL,
    is_built_in   BOOLEAN      NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Seed the 5 built-in roles. Matches auth.BuiltInRoles in
-- internal/auth/roles.gen.go. If that file's role list changes, this
-- migration must be updated and a new migration added — built-in roles
-- ship in product releases, never via runtime edits.
INSERT INTO roles (id, description, is_built_in) VALUES
    ('viewer',         'Read-only access across the platform',                              true),
    ('auditor',        'Read-only plus exception authority and audit export',               true),
    ('ops_lead',       'Day-to-day operations — hosts, scans, alerts',                       true),
    ('security_admin', 'Full security operations including dangerous and license-gated actions', true),
    ('admin',          'Full system administration',                                        true);

CREATE TABLE user_roles (
    user_id      UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id      TEXT         NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    granted_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    granted_by   UUID         REFERENCES users(id),
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX idx_user_roles_role_id ON user_roles (role_id);

-- +goose Down
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS roles;
