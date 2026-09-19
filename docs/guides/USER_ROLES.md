# User roles and permissions

**Last updated:** 2026-07-30 · **Applies to:** OpenWatch v0.8.0 (Eyrie)

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

For the live, authoritative role-to-permission mapping, query the roles API,
`GET /api/v1/roles`.

## Built-in roles

OpenWatch ships five built-in roles, ordered by precedence from `viewer` to
`admin`; there is no parallel "compliance officer" or "guest" track. The order
is not a nesting. `auditor` holds `audit:export` and `exception:approve`, which
`ops_lead` does not; `viewer` holds `role:read`, which `auditor`, `ops_lead`
and `security_admin` do not. Only `admin` holds everything. Built-in roles are
loaded into the `roles` table by migration with `is_built_in = true`, so the
API rejects attempts to modify them.

| Role ID | Description | Permission count |
|---------|-------------|------------------|
| `viewer` | Read-only access across the platform | 16 |
| `auditor` | Read-only plus exception authority and audit export | 20 |
| `ops_lead` | Day-to-day operations: hosts, scans, alerts | 32 |
| `security_admin` | Full security operations, including dangerous actions and audit export | 56 |
| `admin` | Full system administration | All permissions (bare `*` wildcard) |

A user may hold more than one role, but a request is bound to one of them.
When a session or token is bound, the service picks the assigned role with the
highest precedence (`admin` > `security_admin` > `ops_lead` > `auditor` >
`viewer`; contract `system-user-management` C-06) and the request carries that
role's permissions alone. The permissions are not combined. A user assigned
both `auditor` and `ops_lead` is bound as `ops_lead`: they gain host and scan
operations and lose `exception:approve` and `audit:export`: they can no
longer approve or reject exceptions or download the audit log, although
they can still read it. To give one person both sets, assign
`security_admin`, which holds everything both roles hold.
`GET /api/v1/auth/me/permissions` returns what the bound role grants.

### `viewer`

Read-only across every domain. Grants `*:read`-style permissions for hosts,
scans, scan templates, compliance state, baselines, exceptions, alerts,
notifications, license, policy, remediation, integrations, audit, system, and
roles, plus `auth:read` for the user's own profile.

Cannot write, execute, export, approve, or administer anything.

### `auditor`

Most of what `viewer` has (one exception: `auditor` does not hold
`role:read`), plus the exception workflow authority an auditor needs:
`exception:request`, `exception:comment`, and `exception:approve`. Adds
`audit:export`, which gates `GET /api/v1/audit/events/export` (reading the
log needs only `audit:read`), and `auth:write` so the auditor can manage
their own password, MFA, and sessions. Per-host audit export is free; the
`audit_export` feature covers fleet-scale signed bundles.

Cannot create or modify hosts, run scans, or touch system configuration.

### `ops_lead`

The day-to-day operator. Adds write and execute authority over the operational
surface: `host:write`, `host:connectivity_check`, `host:intelligence_refresh`,
`credential:read`, `scan:execute`, `scan:cancel`, `scan_template:write`,
`baseline:write`, alert `acknowledge`/`resolve`, `notification:test`,
`remediation:request`, the free `remediation:execute`/`remediation:rollback`
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
`remediation:execute` and `remediation:rollback`, which are free, and
`audit:export` via `audit:*`.

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
defines 67 permissions across 20 categories. One attribute carries extra meaning:

- `dangerous: true` marks destructive or high-impact actions (for example
  `host:delete`, `license:install`, `user:delete`). The UI uses this for
  confirmation prompts and the audit middleware records denials at high priority.

Licensing is not a permission attribute; the registry has no `license_gated`
marker. An operation that needs a paid feature declares `x-required-feature`
in the OpenAPI document, and its handler checks the entitlement after the
permission check, answering `402` when the feature is not licensed. One
permission can therefore cover a free per-host route and a paid fleet-scale
route. Single-host, single-rule remediation with rollback
(`remediation:execute` / `remediation:rollback`) is free; those permissions are
marked `dangerous` instead.

Enforcement happens centrally for every protected operation, so each endpoint
checks the caller's permission before running. A request with a missing or
insufficient permission returns `403` with `error.code = "authz.permission_denied"`
and emits an `authz.permission_denied` audit event.

## Permissions matrix

`Y` = granted, `-` = not granted. A permission marked `(LG)` names a license
feature that covers its fleet-scale use. The role grants the permission either
way.

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
row grants `audit:export` explicitly. For both, per-host export is free and the
`audit_export` feature covers fleet-scale signed bundles.

## Creating the first admin

The first admin is created from the CLI, not the API. The `create-admin`
subcommand creates the user and assigns the built-in `admin` role in one step. It
requires `--username` and `--email`; the password is read from stdin when
`--password` is omitted, and is held to the 15-character admin policy.

```bash
sudo -u openwatch sh -c 'set -a; . /etc/openwatch/secrets.env; set +a; openwatch --config /etc/openwatch/openwatch.toml create-admin --username admin --email admin@example.com'
```

The command connects to PostgreSQL using `OPENWATCH_DATABASE_DSN` from
`/etc/openwatch/secrets.env` and exits non-zero if the user is created but the
role assignment fails, so you can detect a partial state. See the
[installation guide](INSTALLATION.md) for the full install sequence
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
`POST /api/v1/roles:create` (requires `role:write`). A custom role may grant
any concrete `resource:action` permission from the registry (for example
`host:read`, `scan:execute`), but not category wildcards such as `host:*` or
the bare `*` wildcard. Those exist only for the built-in roles. Every
permission a custom role lists is validated against the registry; a wildcard
or any permission not in the registry is rejected with `400`.

A custom role grants exactly its stored list. When a request is bound to a
user whose role is custom, the service reads that list from the `roles`
table and the request carries those permissions; `GET
/api/v1/auth/me/permissions` shows them. An API token minted for a custom
role carries the same list. Precedence still applies: a user who also holds
a built-in role is bound to that built-in role, and the custom role's list
is not added.

For the live permission registry, including category wildcards and newly added
permissions, query the permissions-registry API endpoint.

## Related documentation

- [Installation guide](INSTALLATION.md): install, `migrate`, `create-admin`, service start
- The running binary serves its API contract under `/api/v1`; the permission and
  role registry is available from the permissions-registry API endpoint
