# User roles and permissions

**Last updated:** 2026-06-25 · **Applies to:** OpenWatch v0.2.0-rc series (Go single-binary)

This guide describes the role-based access control (RBAC) system in the Go-era
OpenWatch. It covers the five built-in roles, the permissions they grant, and how
you create users and assign roles from the single `openwatch` binary.

OpenWatch runs as one Go binary that serves the REST API and the embedded React
UI over HTTPS on port `8443`. All RBAC state lives in PostgreSQL. There is no
separate web tier, container runtime, or Python service.

## How the model is defined

RBAC is registry-driven. The built-in roles and the permissions they grant are
fixed by the platform; you assign roles to users, but you do not redefine what a
built-in role contains.

The live model is observable from the running service:

- The current role list is available from `GET /api/v1/roles`.
- The full permission and role registry is served at runtime by the
  permissions-registry API endpoint.
- Each protected operation declares the permission it requires; a request
  missing that permission is denied.

For the rationale, the custom-role design, and how wildcards expand, see
[User roles](USER_ROLES.md).

## Built-in roles

OpenWatch ships five built-in roles. They form a single privilege ladder from
read-only to full administration; there is no parallel "compliance officer" or
"guest" track. Built-in roles are loaded into the `roles` table by migration with
`is_built_in = true`, so the API rejects attempts to modify them.

| Role ID | Description | Permission count |
|---------|-------------|------------------|
| `viewer` | Read-only access across the platform | 16 |
| `auditor` | Read-only plus exception authority and audit export | 20 |
| `ops_lead` | Day-to-day operations: hosts, scans, alerts | 32 |
| `security_admin` | Full security operations including dangerous and license-gated actions | 56 |
| `admin` | Full system administration | All permissions (bare `*` wildcard) |

A user may hold more than one role. Their effective permission set is the union
of every assigned role's permissions.

### `viewer`

Read-only across every domain. Grants `*:read`-style permissions for hosts,
scans, scan templates, compliance state, baselines, exceptions, alerts,
notifications, license, policy, remediation, integrations, audit, system, and
roles, plus `auth:read` for the user's own profile.

Cannot write, execute, export, approve, or administer anything.

### `auditor`

Everything `viewer` has, plus the exception workflow authority an auditor needs:
`exception:request`, `exception:comment`, and `exception:approve`. Adds
`audit:export` (license-gated by the `audit_export` feature) and `auth:write` so
the auditor can manage their own password, MFA, and sessions.

Cannot create or modify hosts, run scans, or touch system configuration.

### `ops_lead`

The day-to-day operator. Adds write and execute authority over the operational
surface: `host:write`, `host:connectivity_check`, `host:intelligence_refresh`,
`credential:read`, `scan:execute`, `scan:cancel`, `scan_template:write`,
`baseline:write`, alert `acknowledge`/`resolve`, `notification:test`,
`remediation:request`, the free-core `remediation:execute`/`remediation:rollback`
host-mutating verbs, and the exception request/comment verbs.

Cannot delete hosts, manage credentials beyond reading them, approve
remediations (separation of duties: a different `security_admin`/`admin`
approves), install licenses or policies, or manage users.

### `security_admin`

Full security operations. Grants category wildcards (`host:*`, `credential:*`,
`scan:*`, `scan_template:*`, `baseline:*`, `exception:*`, `alert:*`,
`notification:*`, `remediation:*`, `integration:*`, `audit:*`, `token:*`) plus
`user:read`, `user:write`, `license:install`, the
`system:auth_policy_read`/`auth_policy_write` verbs, and the policy
`reload`/`install` verbs. This includes the dangerous host-mutating actions
`remediation:execute` and `remediation:rollback` (free-core, not license-gated)
and the license-gated `audit:export` (via `audit:*`, requires the `audit_export`
feature at runtime).

Cannot perform the high-privilege `admin:*` bundle: managing other users' roles,
SSO providers, retention policy, system settings, or `user:delete`.

### `admin`

Full system administration. Holds the bare `*` wildcard, which is reserved
exclusively for this built-in role and cannot be granted to a custom role. Adds
the `admin:*` bundle (`user_manage`, `role_manage`, `retention_policy`,
`sso_provider`, `system_setting`), `user:delete`, `role:assign`, `role:write`,
`license:revoke`, and `system:config_write`.

## Permission model

Permissions are named `resource:action`, both lowercase
(for example `host:read`, `scan:execute`, `remediation:rollback`). The registry
defines 67 permissions across 20 categories. Two attributes affect enforcement:

- `dangerous: true` marks destructive or high-impact actions (for example
  `host:delete`, `license:install`, `user:delete`). The UI uses this for
  confirmation prompts and the audit middleware records denials at high priority.
- `license_gated: <feature>` makes a permission inert unless the active license
  enables that feature. A role may grant the permission, but the combined
  RBAC-plus-license middleware denies the call with `402` until the license
  enables it. Today this applies to exactly one permission: `audit:export`
  (`audit_export`). Remediation (`remediation:execute` / `remediation:rollback`)
  is free-core and not license-gated; it is marked `dangerous` instead.

Enforcement happens centrally for every protected operation, so each endpoint
checks the caller's permission before running. A request with a missing or
insufficient permission returns `403` with `error.code = "authz.permission_denied"`
and emits an `authz.permission_denied` audit event.

## Permissions matrix

`Y` = granted, `-` = not granted. License-gated permissions are marked `(LG)`;
they are granted by the role but require the matching license feature at runtime.

| Permission | viewer | auditor | ops_lead | security_admin | admin |
|------------|:------:|:-------:|:--------:|:--------------:|:-----:|
| `auth:read` | Y | Y | Y | Y | Y |
| `auth:write` | - | Y | Y | Y | Y |
| `user:read` | - | - | - | Y | Y |
| `user:write` | - | - | - | Y | Y |
| `user:delete` | - | - | - | - | Y |
| `host:read` | Y | Y | Y | Y | Y |
| `host:write` | - | - | Y | Y | Y |
| `host:delete` | - | - | - | Y | Y |
| `host:connectivity_check` | - | - | Y | Y | Y |
| `host:intelligence_refresh` | - | - | Y | Y | Y |
| `credential:read` | - | - | Y | Y | Y |
| `credential:write` | - | - | - | Y | Y |
| `credential:delete` | - | - | - | Y | Y |
| `scan:read` | Y | Y | Y | Y | Y |
| `scan:execute` | - | - | Y | Y | Y |
| `scan:cancel` | - | - | Y | Y | Y |
| `scan_template:read` | Y | Y | Y | Y | Y |
| `scan_template:write` | - | - | Y | Y | Y |
| `scan_template:delete` | - | - | - | Y | Y |
| `compliance:read` | Y | Y | Y | Y | Y |
| `baseline:read` | Y | Y | Y | Y | Y |
| `baseline:write` | - | - | Y | Y | Y |
| `baseline:delete` | - | - | - | Y | Y |
| `exception:read` | Y | Y | Y | Y | Y |
| `exception:request` | - | Y | Y | Y | Y |
| `exception:comment` | - | Y | Y | Y | Y |
| `exception:approve` | - | Y | - | Y | Y |
| `exception:revoke` | - | - | - | Y | Y |
| `alert:read` | Y | Y | Y | Y | Y |
| `alert:acknowledge` | - | - | Y | Y | Y |
| `alert:resolve` | - | - | Y | Y | Y |
| `alert:write` | - | - | - | Y | Y |
| `notification:read` | Y | Y | Y | Y | Y |
| `notification:write` | - | - | - | Y | Y |
| `notification:delete` | - | - | - | Y | Y |
| `notification:test` | - | - | Y | Y | Y |
| `license:read` | Y | Y | Y | Y | Y |
| `license:install` | - | - | - | Y | Y |
| `license:revoke` | - | - | - | - | Y |
| `token:read` | - | - | - | Y | Y |
| `token:write` | - | - | - | Y | Y |
| `token:delete` | - | - | - | Y | Y |
| `policy:read` | Y | Y | Y | Y | Y |
| `policy:reload` | - | - | - | Y | Y |
| `policy:install` | - | - | - | Y | Y |
| `remediation:read` | Y | Y | Y | Y | Y |
| `remediation:request` | - | - | Y | Y | Y |
| `remediation:approve` | - | - | - | Y | Y |
| `remediation:execute` | - | - | Y | Y | Y |
| `remediation:rollback` | - | - | Y | Y | Y |
| `integration:read` | Y | Y | Y | Y | Y |
| `integration:write` | - | - | - | Y | Y |
| `integration:execute` | - | - | - | Y | Y |
| `audit:read` | Y | Y | Y | Y | Y |
| `audit:export` (LG) | - | Y | - | Y | Y |
| `system:read` | Y | Y | Y | Y | Y |
| `system:config_write` | - | - | - | - | Y |
| `system:auth_policy_read` | - | - | - | Y | Y |
| `system:auth_policy_write` | - | - | - | Y | Y |
| `role:read` | Y | - | - | - | Y |
| `role:write` | - | - | - | - | Y |
| `role:assign` | - | - | - | - | Y |
| `admin:user_manage` | - | - | - | - | Y |
| `admin:role_manage` | - | - | - | - | Y |
| `admin:retention_policy` | - | - | - | - | Y |
| `admin:sso_provider` | - | - | - | - | Y |
| `admin:system_setting` | - | - | - | - | Y |

`security_admin` grants `audit:*`, which includes `audit:export`; the `auditor`
row grants `audit:export` explicitly. Both depend on the `audit_export` license
feature at runtime.

## Creating the first admin

The first admin is created from the CLI, not the API. The `create-admin`
subcommand creates the user and assigns the built-in `admin` role in one step. It
requires `--username` and `--email`; the password is read from stdin when
`--password` is omitted, and is held to the 15-character admin policy.

```bash
sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) \
  openwatch --config /etc/openwatch/openwatch.toml \
  create-admin --username admin --email admin@example.com
```

The command connects to PostgreSQL using `OPENWATCH_DATABASE_DSN` from
`/etc/openwatch/secrets.env` and exits non-zero if the user is created but the
role assignment fails, so you can detect a partial state. See
`docs/guides/INSTALLATION.md` for the full install sequence
(`openwatch migrate`, `create-admin`, `systemctl enable --now openwatch`).

## Managing users and roles through the API

Once an admin exists, manage users over HTTPS at `https://<host>:8443` under
`/api/v1`. Authenticate at `POST /api/v1/auth/login` to obtain a bearer token,
then call the user and role endpoints. The required permission for each is below.

| Operation | Method and path | Required permission |
|-----------|-----------------|---------------------|
| List users | `GET /api/v1/users` | `user:read` |
| Fetch a user | `GET /api/v1/users/{id}` | `user:read` |
| Create a user | `POST /api/v1/users` | `user:write` |
| Soft-delete a user | `DELETE /api/v1/users/{id}` | `user:delete` |
| Assign a role | `POST /api/v1/users/{id}/roles:assign` | `role:assign` |
| Remove a role | `POST /api/v1/users/{id}/roles:unassign` | `role:assign` |
| List built-in roles | `GET /api/v1/roles` | `role:read` |
| Create a custom role | `POST /api/v1/roles:create` | `role:write` |
| Effective permissions for the caller | `GET /api/v1/auth/me/permissions` | authenticated |
| Full RBAC registry | `GET` the `permissions:registry` endpoint under `/api/v1/auth` | authenticated |

Creating a user does not assign a role. `POST /api/v1/users` takes only
`username`, `email`, and `password`; role assignment is a separate
`roles:assign` call. Among the built-in roles, only `admin` holds `role:assign`
and `user:delete`.

Assign a role by posting the role id:

```bash
curl -sS -X POST "https://<host>:8443/api/v1/users/<user_id>/roles:assign" \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"role_id": "ops_lead"}'
```

A `roles:assign` call with an unknown role id returns `400`. The
`roles:unassign` call is idempotent and returns `204` whether or not the role
was present.

## Custom roles

The registry supports custom, DB-stored roles created at runtime via
`POST /api/v1/roles:create` (requires `role:write`). A custom role may grant any
registry permission and category wildcards such as `host:*`, but not the bare
`*` wildcard, which is reserved for the built-in `admin` role. Every permission a
custom role lists is validated against the registry; unknown permissions are
rejected with `400`.

For the custom-role design, validation rules, and the relationship between
wildcards and newly added permissions, see [User roles](USER_ROLES.md).

## Related documentation

- [User roles](USER_ROLES.md)—RBAC design and custom roles
- `docs/guides/INSTALLATION.md`—install, `migrate`, `create-admin`, service start
- The running binary serves its API contract under `/api/v1`; the permission and
  role registry is available from the permissions-registry API endpoint
