# Quickstart guide

Go from a freshly installed package to your first host under automatic
compliance monitoring. This guide assumes OpenWatch is already installed and
running. If it is not, follow
[docs/engineering/install_guide.md](../engineering/install_guide.md) first, then
return here.

OpenWatch is a single Go binary (`/usr/bin/openwatch`) that serves both the REST
API and the embedded React UI over HTTPS on port `8443`. It is managed by
`systemd` as `openwatch.service` and stores all state in PostgreSQL. There is no
container runtime, no separate web tier, no Redis, and no Celery. Compliance
checks run over SSH via the embedded Kensa engine; OpenSCAP/`oscap` is not used.

## Before you begin

- OpenWatch is installed and `openwatch.service` is active.
- You have the `admin` account created during install
  (`openwatch create-admin`).
- You have a Linux host reachable over SSH (TCP/22) from the OpenWatch server.
- You have SSH credentials for that host (username plus either an SSH private
  key or a password).

| Surface | URL |
|---------|-----|
| Web UI and API | `https://<your-host>:8443/` |
| API base path | `https://<your-host>:8443/api/v1` |

The TLS certificate lives under `/etc/openwatch/tls/`. With a self-signed
certificate, pass `-k` to `curl` and accept the browser warning.

## Step 1: Confirm the service is healthy

Check that the service is running:

```bash
systemctl status openwatch
```

Query the anonymous health endpoint:

```bash
curl -sk https://localhost:8443/api/v1/health | jq .
```

A healthy response looks like this:

```json
{
  "status": "healthy",
  "db_connected": true,
  "version": "0.2.0-rc.10"
}
```

`status` is `healthy` or `degraded`; `db_connected` is `false` when the database
is unreachable. If the request fails or `status` is `degraded`, inspect the logs
before continuing:

```bash
journalctl -u openwatch --no-pager -n 50
```

Common causes are an unreachable database (check
`/etc/openwatch/secrets.env` for `OPENWATCH_DATABASE_DSN`) or pending
migrations. To verify the resolved configuration without starting the server:

```bash
openwatch check-config --config /etc/openwatch/openwatch.toml
```

To confirm the schema is current:

```bash
openwatch migrate --config /etc/openwatch/openwatch.toml
```

`migrate` is idempotent; if everything is applied it prints the current version
and exits.

## Step 2: Sign in

Open `https://<your-host>:8443/` in a browser and sign in with the `admin`
username and the password you set during `openwatch create-admin`. You land on
the dashboard.

OpenWatch does not ship a hard-coded default password. The first admin is
created out-of-band by the CLI, so there is no factory `admin`/`admin`
credential to rotate. If you need an additional admin, run
`openwatch create-admin` again with a different `--username`.

The equivalent API call returns an access token, a refresh token, and the
calling identity:

```bash
TOKEN=$(curl -sk -X POST https://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<your-password>"}' \
  | jq -r '.access_token')
```

Send the token as `Authorization: Bearer $TOKEN` on subsequent requests. The
browser UI uses HttpOnly session cookies instead of the bearer token; the
bearer flow shown here is for scripting.

## Step 3: Add a host

In the UI, go to **Hosts** and add a host. Only `hostname` and `ip_address` are
required; `port` defaults to the SSH port and the rest are optional.

| Field | Required | Notes |
|-------|----------|-------|
| `hostname` | Yes | 1–256 characters |
| `ip_address` | Yes | 1–64 characters |
| `port` | No | 1–65535 |
| `display_name` | No | Up to 256 characters |
| `environment` | No | Up to 64 characters; namespaces the hostname uniqueness check |
| `tags` | No | Array of strings, each up to 64 characters |
| `username` | No | Default SSH username for this host |

The equivalent API call:

```bash
HOST_ID=$(curl -sk -X POST https://localhost:8443/api/v1/hosts \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"hostname":"web-01","ip_address":"192.168.1.10","port":22}' \
  | jq -r '.id')
```

Host IDs are UUIDs. A duplicate `hostname` within the same `environment` returns
`409`.

## Step 4: Add SSH credentials

OpenWatch needs SSH access to reach the host. Add a credential scoped to the
host (or a `system`-scoped default that applies to every host without its own).

| Field | Required | Notes |
|-------|----------|-------|
| `scope` | Yes | `system` or `host` |
| `scope_id` | When `scope=host` | The host UUID |
| `name` | Yes | 1–256 characters |
| `username` | Yes | SSH login user |
| `auth_method` | Yes | `ssh_key`, `password`, or `both` |
| `private_key` | When key-based | PEM private key; stored encrypted |
| `password` | When password-based | Stored encrypted |
| `is_default` | No | Mark a `system` credential as the fleet default |

Secret material (`private_key`, `password`) is encrypted at rest with the
credential data-encryption key loaded at startup
(`[identity].credential_key_file`). It is never returned by the API; read
responses expose only metadata such as the key fingerprint.

The equivalent API call for a host-scoped key credential:

```bash
curl -sk -X POST https://localhost:8443/api/v1/credentials \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"scope\": \"host\",
    \"scope_id\": \"$HOST_ID\",
    \"name\": \"web-01 key\",
    \"username\": \"openwatch\",
    \"auth_method\": \"ssh_key\",
    \"private_key\": \"$(cat ~/.ssh/id_ed25519 | sed ':a;N;$!ba;s/\n/\\n/g')\"
  }"
```

## Step 5: Verify connectivity

Confirm OpenWatch can reach the host over SSH before relying on automatic
checks. In the UI this is the host's connectivity action; via the API:

```bash
curl -sk -X POST "https://localhost:8443/api/v1/hosts/$HOST_ID/connectivity:check" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

A failure here means SSH cannot connect — wrong credentials, an unreachable
address, or a firewall blocking TCP/22. Fix that before expecting compliance
results.

## Step 6: Let automatic compliance checks run

OpenWatch does not have a manual "run scan" button or a scan-trigger API
endpoint. Compliance checking is scheduler-driven: background loops in the
service discover each host's OS, then run Kensa compliance checks over SSH on an
adaptive cadence and write the results into PostgreSQL. The `serve` process runs
these schedulers; the `openwatch worker` subcommand drains the PostgreSQL job
queue (`SKIP LOCKED`) for queued background work.

You do not need to do anything to start the first check beyond adding the host
and working credentials. The first OS-discovery and compliance cycle runs once
the host is due. To watch progress:

```bash
journalctl -u openwatch --no-pager -f
```

## Step 7: View compliance results

Once a check has run, the host's compliance roll-up is available on the host
detail view. In the UI, open the host from **Hosts**. Via the API,
`GET /api/v1/hosts/{id}` returns `compliance_summary` (and a `liveness`
sub-object):

```bash
curl -sk "https://localhost:8443/api/v1/hosts/$HOST_ID" \
  -H "Authorization: Bearer $TOKEN" | jq '.compliance_summary'
```

The summary counts are integers:

```json
{
  "passing": 0,
  "failing": 0,
  "skipped": 0,
  "error": 0,
  "total": 0
}
```

All-zero counts mean no compliance check has completed against the host yet —
give the scheduler time, and confirm Step 5 passed.

For a fleet-wide view, the dashboard aggregates across hosts. The backing
endpoints include:

| Endpoint | Returns |
|----------|---------|
| `GET /api/v1/fleet/score` | Fleet-wide passing/total score |
| `GET /api/v1/fleet/liveness` | Host counts by reachability |
| `GET /api/v1/fleet/top-failing-rules` | Rules failing across the fleet |
| `GET /api/v1/fleet/top-failing-hosts` | Hosts with the most failures |
| `GET /api/v1/fleet/recent-changes` | Recent pass/fail transitions |
| `GET /api/v1/intelligence/state/{host_id}` | Per-host intelligence state |

Most fleet endpoints accept an optional `framework` query parameter to scope the
counts to a single framework key.

## Step 8: Next steps

| Task | Where |
|------|-------|
| Full install and configuration reference | [docs/engineering/install_guide.md](../engineering/install_guide.md) |
| Roles and permissions | [docs/engineering/rbac_registry.md](../engineering/rbac_registry.md) |
| Kensa ↔ OpenWatch boundary | [docs/KENSA_OPENWATCH_BOUNDARY.md](../KENSA_OPENWATCH_BOUNDARY.md) |
| API contract (source of truth) | `api/openapi.yaml` (paths under `/api/v1`) |

## Troubleshooting

The service runs as a single `systemd` unit against PostgreSQL. The recipes
below cover the common first-run failures.

**The UI or API does not respond on 8443.** Check the unit and recent logs:

```bash
systemctl status openwatch
journalctl -u openwatch --no-pager -n 50
```

A boot failure is usually a missing JWT signing key
(`[identity].jwt_private_key`), a missing credential key
(`[identity].credential_key_file`), or an empty
`OPENWATCH_DATABASE_DSN`. Run `openwatch check-config` to see the resolved
configuration with secrets redacted.

**Health reports `db_connected: false`.** The database is unreachable. Verify
PostgreSQL is up and the DSN is correct:

```bash
systemctl status postgresql
psql "$OPENWATCH_DATABASE_DSN" -c "SELECT 1;"
```

If the schema is behind, run `openwatch migrate`.

**Connectivity check fails for a host.** SSH cannot connect. Confirm the address
and port, that the credential username and key/password are correct, and that
TCP/22 is open from the OpenWatch host to the target.

**A host shows all-zero compliance counts.** No compliance cycle has completed
yet. Confirm the connectivity check passes (Step 5), then watch
`journalctl -u openwatch -f` for discovery and compliance activity. The
schedulers run on an adaptive cadence, so the first result is not instantaneous.

**Background work appears stalled.** Confirm the `serve` process is running (it
hosts the schedulers) and, if you run a dedicated worker, that
`openwatch worker` is up. Inspect the PostgreSQL job queue directly:

```bash
psql "$OPENWATCH_DATABASE_DSN" -c \
  "SELECT status, count(*) FROM job_queue GROUP BY status;"
```

## Runbooks

These are first-response steps for the single binary on `systemd` plus
PostgreSQL. Replace `<dsn>` with the value from
`/etc/openwatch/secrets.env`.

### Service down

1. Check the unit and why it stopped:
   `systemctl status openwatch` and
   `journalctl -u openwatch --no-pager -n 100`.
2. If it crash-loops, look for the boot-time fatal log line (missing key, bad
   DSN, validation error). Fix the config, then `systemctl restart openwatch`.
3. Validate config out-of-band before restarting:
   `openwatch check-config --config /etc/openwatch/openwatch.toml`.
4. Confirm the dependency is up: `systemctl status postgresql`.
5. After restart, confirm recovery:
   `curl -sk https://localhost:8443/api/v1/health`.

### Disk full

1. Find what filled up: `df -h` then `du -xhd1 /var | sort -h | tail`.
2. Inspect the journal footprint (logs go to the journal):
   `journalctl --disk-usage`. Vacuum old logs with
   `journalctl --vacuum-time=7d` or `journalctl --vacuum-size=500M`.
3. Check PostgreSQL data growth and look for table bloat:
   `psql "<dsn>" -c "SELECT pg_size_pretty(pg_database_size(current_database()));"`.
4. If audit or history tables dominate, apply your retention policy rather than
   deleting rows ad hoc — these back compliance evidence.
5. After freeing space, confirm the service recovered:
   `systemctl status openwatch` and the health endpoint.

### High CPU

1. Identify the offender: `top` or `pidstat 1`. Confirm whether it is the
   `openwatch` process or `postgres`.
2. If it is `postgres`, look for long-running or stuck queries:
   `psql "<dsn>" -c "SELECT pid, state, now()-query_start AS age, query FROM pg_stat_activity ORDER BY age DESC LIMIT 10;"`.
3. If it is `openwatch`, correlate with scheduler activity in the journal:
   `journalctl -u openwatch --no-pager -n 200`. A burst of discovery or
   compliance cycles across many hosts can drive CPU; the cadence is adaptive
   and self-limits.
4. Check the job queue depth:
   `psql "<dsn>" -c "SELECT status, count(*) FROM job_queue GROUP BY status;"`.
5. If load is sustained and harmful, lower scheduler pressure via the runtime
   config endpoints (`PUT /api/v1/system/intelligence/config`,
   `PUT /api/v1/system/discovery/config`) — for example by enabling the
   maintenance pause — rather than killing the process.

### Security incident

1. Preserve evidence first. Do not wipe logs. Snapshot the journal:
   `journalctl -u openwatch --since "-24h" > /var/tmp/openwatch-incident.log`.
2. Review the audit trail. Audit events are queryable via
   `GET /api/v1/audit/events` and stored in PostgreSQL; export the relevant
   window for analysis.
3. If credentials may be exposed, rotate them: revoke or replace the affected
   SSH credentials (`/api/v1/credentials`) and rotate any user passwords.
   Active sessions can be ended via logout; force re-authentication for
   affected users.
4. If the host itself is compromised, isolate it at the network layer and stop
   the service to halt outbound SSH:
   `systemctl stop openwatch`.
5. Protect the secrets: `/etc/openwatch/secrets.env`,
   `/etc/openwatch/tls/`, and the identity keys referenced by the TOML config.
   If any may have leaked, rotate the JWT signing key and credential key, then
   re-encrypt or re-enter affected secrets.
6. After containment, document the timeline from the preserved journal and audit
   export before restarting.
