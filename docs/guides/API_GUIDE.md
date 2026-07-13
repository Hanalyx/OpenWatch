# API guide

**Last updated:** 2026-06-25 · **Applies to:** OpenWatch v0.3.0 (Go single-binary)

Most operators use the web UI for daily work—managing hosts, viewing fleet
health, reading compliance state, and triaging alerts. This guide is for
automation: scripting repetitive tasks, integrating with CI/CD, or building
tooling on top of OpenWatch.

OpenWatch is a single Go binary that serves both the REST API and the embedded
React UI over HTTPS on port `8443`. All API paths live under `/api/v1`. The
running binary serves its own OpenAPI document as the contract source of truth,
and `GET /api/v1/version` reports the build it came from.

This guide reflects OpenWatch `v0.3.0`. The compliance
surface (scan execution + results, remediation, exceptions, posture/drift, audit
export, the rule browser) IS exposed over `/api/v1`. See [the compliance API surface
(now live)](#compliance-api-surface-now-live). The genuinely-absent pieces (a
Prometheus `/metrics` endpoint, `/security-info`) are listed under [what is
genuinely not in the API yet](#what-is-genuinely-not-in-the-api-yet).

When the OpenAPI document and this guide disagree, the OpenAPI document wins.

---

## Conventions

- Base URL is `https://<host>:8443`. The server is HTTPS-only. In a default
  install the certificate at `/etc/openwatch/tls/cert.pem` is self-signed, so
  add `--cacert /etc/openwatch/tls/cert.pem` (or, for a throwaway lab box
  only, `-k`) to your `curl` calls. In production, point `--cacert` at your
  own CA bundle instead.
- Resource identifiers are UUIDs.
- Timestamps are ISO 8601 / RFC 3339 (for example `2026-06-10T14:30:00Z`).
- Mutating endpoints that exist to be retried safely take a required
  `Idempotency-Key` header (a unique string per logical operation). Replaying the
  same key with the same body returns the original result; replaying it with a
  different body returns `409`.
- An optional `X-Correlation-Id` header is propagated through logs and audit
  events. If you omit it, the server generates one and returns it in the
  response.

---

## Authentication

The API accepts two credential types. Both resolve to the same identity and
permission set:

- A `Bearer` access token in the `Authorization` header. This is the path for
  scripts and CI.
- The browser session cookie (`openwatch_session`), used by the web UI. Cookie
  rotation and the on-401 refresh flow are UI concerns and are not covered here.

Anonymous endpoints (`GET /api/v1/health`, `GET /api/v1/version`,
`POST /api/v1/auth/login`, `POST /api/v1/auth/refresh`) require no credential.
Everything else requires a valid identity.

### Log in

```bash
TOKEN=$(curl -s --cacert /etc/openwatch/tls/cert.pem \
  -X POST https://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"yourpassword"}' | jq -r '.access_token')
```

The request body is `{username, password}` with an optional `otp` (6 digits)
when the account has TOTP MFA enrolled. The response is:

```json
{
  "access_token": "…",
  "refresh_token": "…",
  "user": {"id": "…", "username": "admin", "email": "…", "role": "admin"}
}
```

All later examples assume `-H "Authorization: Bearer $TOKEN"`.

### Refresh, identity, and log out

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/v1/auth/refresh` | Rotate the refresh token; returns a new access + refresh pair. Body: `{refresh_token}`. |
| `GET` | `/api/v1/auth/me` | Return the calling identity (`id`, `username`, `email`, `role`). |
| `GET` | `/api/v1/auth/me/permissions` | Return the caller's effective permission strings. |
| `POST` | `/api/v1/auth/logout` | Revoke the calling session (`204`). |
| `POST` | `/api/v1/auth/password:change` | Change the caller's password. Body: `{current_password, new_password}`. |
| `POST` | `/api/v1/auth/mfa:enroll` | Begin TOTP enrollment; returns a `provisioning_uri`. |
| `POST` | `/api/v1/auth/mfa:verify` | Confirm an enrolled secret. Body: `{otp}`. |

---

## Authorization

Authorization is permission-based, not role-based, at the endpoint level. Each
protected endpoint declares the permission it requires (visible in the served
OpenAPI document, for example `host:read` or `host:write`). Built-in roles
bundle permission sets:

| Role | Intent |
|------|--------|
| `viewer` | Read-only access |
| `auditor` | Read plus audit/compliance review |
| `ops_lead` | Host + scan + remediation operations |
| `security_admin` | Security configuration |
| `admin` | Full system administration |

A caller missing the required permission receives `403`. The full permission and
role registry is the source of truth at
[User roles](USER_ROLES.md); the running service exposes it through the
permissions-registry endpoint under `/api/v1/auth`.

---

## Hosts

| Method | Path | Permission | Purpose |
|--------|------|------------|---------|
| `GET` | `/api/v1/hosts` | `host:read` | List hosts. Query: `environment`, `tag`. |
| `POST` | `/api/v1/hosts` | `host:write` | Create a host. |
| `GET` | `/api/v1/hosts/{id}` | `host:read` | Host detail with liveness and compliance summary. Query: `framework`. |
| `PATCH` | `/api/v1/hosts/{id}` | `host:write` | Update mutable host fields. |
| `DELETE` | `/api/v1/hosts/{id}` | `host:delete` | Soft-delete a host (`204`; sets `deleted_at`). |
| `GET` | `/api/v1/hosts/{host_id}/monitoring/history` | `host:read` | Monitoring history. |
| `POST` | `/api/v1/hosts/{host_id}/maintenance` | `host:write` | Toggle maintenance mode. |
| `POST` | `/api/v1/hosts/{id}/connectivity:check` | `host:write` | Run a connectivity check (idempotent). |
| `GET` | `/api/v1/hosts/{id}/system-info` | `host:read` | Latest collected system intelligence. |
| `POST` | `/api/v1/hosts/{id}/discovery:run` | `host:write` | Run host discovery (idempotent). |
| `POST` | `/api/v1/hosts/{host_id}/credentials:resolve` | `host:read` | Resolve the effective credential for a host. |

### Create a host

```bash
curl -s --cacert /etc/openwatch/tls/cert.pem \
  -X POST https://localhost:8443/api/v1/hosts \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "rhel9-web01.example.com",
    "ip_address": "10.0.1.50",
    "port": 22,
    "environment": "production",
    "tags": ["web", "rhel9"]
  }'
```

`hostname` and `ip_address` are required; `port`, `display_name`, `description`,
`environment`, `tags`, `group_id`, and `username` are optional. A successful
create returns `201`; a duplicate hostname in the same environment returns `409`.

---

## Credentials

SSH credentials are stored separately from hosts and scoped either to the whole
system (`scope: system`) or to one host (`scope: host`). Secret material is
encrypted at rest and never returned in responses.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/credentials` | List credentials (secrets redacted). |
| `POST` | `/api/v1/credentials` | Create a credential. |
| `GET` | `/api/v1/credentials/{id}` | Get one credential. |
| `PATCH` | `/api/v1/credentials/{id}` | Update a credential. |
| `DELETE` | `/api/v1/credentials/{id}` | Delete a credential. |
| `POST` | `/api/v1/credentials/{id}:clone` | Clone to a new scope (secret inherited; no plaintext on the wire). |

A create body requires `scope`, `name`, `username`, and `auth_method` (one of
`ssh_key`, `password`, `both`). Provide `private_key` (and optional
`private_key_passphrase`) and/or `password` to match the chosen method.

---

## Fleet observability

These endpoints back the dashboard and require read access.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/fleet/score` | Aggregate fleet compliance score. |
| `GET` | `/api/v1/fleet/liveness` | Fleet liveness breakdown. |
| `GET` | `/api/v1/fleet/top-failing-rules` | Rules failing across the most hosts. |
| `GET` | `/api/v1/fleet/top-failing-hosts` | Hosts with the most failing rules. |
| `GET` | `/api/v1/fleet/recent-changes` | Recent compliance state transitions. |
| `GET` | `/api/v1/fleet/connectivity/breakdown` | Connectivity status counts. |

---

## Alerts

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/alerts` | List alerts. |
| `GET` | `/api/v1/alerts/{id}` | Alert detail. |
| `POST` | `/api/v1/alerts/{id}:acknowledge` | Acknowledge an alert. |
| `POST` | `/api/v1/alerts/{id}:silence` | Silence an alert. |
| `POST` | `/api/v1/alerts/{id}:resolve` | Resolve an alert. |
| `POST` | `/api/v1/alerts/{id}:dismiss` | Dismiss an alert. |

---

## Intelligence and activity

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/intelligence/events` | Stream of intelligence-collection events. |
| `GET` | `/api/v1/intelligence/state/{host_id}` | Latest intelligence state for a host. |
| `GET` | `/api/v1/activity` | Unified recent-activity feed. |

---

## System configuration

Connectivity, intelligence-collection, and discovery behavior are configured
through the API. These are admin-level controls.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` / `PUT` | `/api/v1/system/connectivity/config` | Connectivity polling config. |
| `GET` | `/api/v1/system/connectivity/status` | Connectivity worker status. |
| `GET` / `PUT` | `/api/v1/system/intelligence/config` | Intelligence-collection config. |
| `GET` / `PUT` | `/api/v1/system/discovery/config` | Discovery config. |
| `POST` | `/api/v1/system/discovery/sweep` | Trigger a discovery sweep (idempotent). |

---

## Users and roles

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/users` | List users. |
| `POST` | `/api/v1/users` | Create a user. Body: `{username, email, password}`. |
| `GET` | `/api/v1/users/{id}` | Get a user. |
| `PATCH` | `/api/v1/users/{id}` | Update a user. |
| `DELETE` | `/api/v1/users/{id}` | Delete a user. |
| `POST` | `/api/v1/users/{id}/roles:assign` | Assign a role. Body: `{role_id}`. |
| `POST` | `/api/v1/users/{id}/roles:unassign` | Remove a role. |
| `GET` | `/api/v1/roles` | List roles (built-in roles only). |
| `POST` | `/api/v1/roles:create` | Create a custom role. |

For first-admin bootstrap, prefer the CLI (`openwatch create-admin`) over the
API; see [Operations](#operations-the-cli-and-systemd).

---

## License

OpenWatch has a tiered license model (`free`, `openwatch_plus`, `enterprise`).
Premium-gated endpoints return `402` when the active tier lacks the feature.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/license` | Current license tier, status, and features. |
| `POST` | `/api/v1/admin/license:verify` | Dry-run validate a license JWT without installing it. |

---

## Audit events

Every meaningful state change writes an audit event. The log is queryable and
cursor-paginated, newest first.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/audit/events` | List audit events. |

Query parameters: `action`, `correlation_id`, `actor_type`, `resource_type`,
`resource_id`, `since`, `until` (both RFC 3339), `cursor`, and `limit` (1–200,
default 50). Follow the `cursor` field in each page to paginate.

---

## Health and version

These two endpoints are anonymous and are what monitoring should poll.

```bash
curl -s --cacert /etc/openwatch/tls/cert.pem https://localhost:8443/api/v1/health | jq
```

```json
{"status": "healthy", "db_connected": true, "version": "0.3.0"}
```

A healthy response is always `status: "healthy"`, `db_connected: true`. When
the database is unreachable, the endpoint does not return a `degraded` status
body—it returns `503` with the standard `ErrorEnvelope` (code
`server.unavailable`) instead. `GET /api/v1/version` returns build metadata
(`openwatch`, `kensa`, `go`, `commit`, `build_time`).

---

## Error responses

Errors use a single envelope shape, not field-level validation detail:

```json
{
  "error": {
    "code": "hosts.invalid_input",
    "fault": "client",
    "retryable": false,
    "human_message": "ip_address is required",
    "correlation_id": "…"
  }
}
```

`fault` is one of `client`, `server`, `policy`, or `external`. Status codes you
will encounter:

| Code | Meaning |
|------|---------|
| `400` | Bad request—invalid input or a violated business rule |
| `401` | Unauthorized—missing, expired, or invalid credential |
| `402` | Payment required—the license tier lacks this feature |
| `403` | Forbidden—the caller lacks the required permission |
| `404` | Not found |
| `405` | Method not allowed |
| `409` | Conflict—duplicate resource, or a reused `Idempotency-Key` with a different body |
| `429` | Too many requests—`/auth/login` or `/auth/mfa:verify` rate limit exceeded; retry after `Retry-After` seconds |
| `502` | Bad gateway—an external dependency failed |
| `503` | Service unavailable—the service is degraded |

There is no general per-route API rate limiting in this release. `POST
/api/v1/auth/login` and `/api/v1/auth/mfa:verify` are the exceptions: they are
rate-limited per client IP and return `429` with a `Retry-After` header over
the limit. There is no `422` validation status—validation failures return
`400` with the envelope above.

---

## Operations: the CLI and systemd

Automation that manages the deployment itself (rather than calling the API) uses
the `openwatch` binary and `systemd`, not Docker. The subcommands are:

| Command | Purpose |
|---------|---------|
| `openwatch serve` | Run the HTTPS API + UI server (the default subcommand; what `systemd` starts). |
| `openwatch worker` | Run the background job worker (PostgreSQL `SKIP LOCKED` queue). |
| `openwatch migrate` | Apply database migrations. |
| `openwatch create-admin` | Create the first admin user. |
| `openwatch check-config` | Validate `/etc/openwatch/openwatch.toml` and exit. |

Day-to-day lifecycle:

```bash
systemctl status openwatch
systemctl restart openwatch
journalctl -u openwatch -f
```

Configuration lives in `/etc/openwatch/openwatch.toml`, with environment
overrides of the form `OPENWATCH_<SECTION>_<KEY>` and the database DSN in
`/etc/openwatch/secrets.env` (`OPENWATCH_DATABASE_DSN`). For full install and
configuration steps, see
[`docs/guides/INSTALLATION.md`](INSTALLATION.md).

---

## Compliance API surface (now live)

As of `v0.2.0`, the compliance workflow IS exposed over `api/v1` (it is no
longer worker-internal only):

- **Scans**: trigger with `POST /api/v1/hosts/{id}/scans`; browse durable
  per-scan history + per-rule evidence + OSCAL export under `/api/v1/scans` and
  `/api/v1/scans/{id}` (scan:read).
- **Remediation**: request/approve/reject + execute/rollback under
  `/api/v1/remediation/requests` (sub-actions `:approve`, `:dry-run`,
  `:execute`, `:reject`, `:rollback`).
- **Compliance exceptions**: request via `/api/v1/hosts/{id}/exceptions`,
  browse the fleet queue via `/api/v1/compliance/exceptions`, then mutate with
  `/api/v1/exceptions/{xid}:approve`, `:reject`, or `:revoke`.
- **Posture + drift**: per-host `/api/v1/hosts/{id}/compliance` and
  `/api/v1/hosts/{id}/compliance/trend`; fleet `/api/v1/fleet/score`.
- **Audit export**: `GET /api/v1/audit/events` (filterable via query
  parameters, cursor-paginated) and `GET /api/v1/audit/events/export`, a
  synchronous CSV/JSON download of the same filtered set (capped at 10,000
  rows, newest-first).
- **Rule browser**: `/api/v1/rules` (the Kensa rule-library read model).

## What is genuinely not in the API yet

- A Prometheus `/metrics` endpoint and a `/security-info` endpoint—both are
  roadmap items (use `GET /api/v1/health` for liveness today). Do not script
  against them until they appear in the served OpenAPI document.

Kensa is the SSH-based compliance scanning engine OpenWatch invokes to run
scans; see [Scanning and compliance](SCANNING_AND_COMPLIANCE.md) for how it
integrates.

---

## What's next

- [Install guide](INSTALLATION.md)—install, configure, and run the service.
- [User roles](USER_ROLES.md)—permission and role reference.
- [Scanning and compliance](SCANNING_AND_COMPLIANCE.md)—how scanning works.
- The served OpenAPI document—the authoritative, always-current API contract.
