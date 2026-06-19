# OpenWatch monitoring and operations guide

**Last updated**: 2026-06-10

This guide describes how you monitor a running OpenWatch deployment and how you
respond to common operational incidents. OpenWatch ships as a single Go binary
(`/usr/bin/openwatch`) that serves the REST API and the embedded React UI over
HTTPS on port `8443`, backed by PostgreSQL and managed by systemd. There is no
container runtime, no separate web tier, and no message broker.

For installation, configuration layering, and first-run setup, see
`docs/engineering/install_guide.md`. This guide does not repeat those steps; it
focuses on observing the service and running it day to day.

## Contents

1. [What you can observe today](#1-what-you-can-observe-today)
2. [Health and version endpoints](#2-health-and-version-endpoints)
3. [Logs via journald](#3-logs-via-journald)
4. [Audit events](#4-audit-events)
5. [Fleet and connectivity signals](#5-fleet-and-connectivity-signals)
6. [Service lifecycle](#6-service-lifecycle)
7. [Operational runbooks](#7-operational-runbooks)
8. [Not yet implemented](#8-not-yet-implemented)

## 1. What you can observe today

OpenWatch exposes operational signals through four channels:

| Channel | Source | Authentication |
|---------|--------|----------------|
| Health probe | `GET /api/v1/health` | None |
| Version metadata | `GET /api/v1/version` | None |
| Structured logs | systemd journal (`journalctl -u openwatch`) | Host access |
| Audit and fleet APIs | `GET /api/v1/audit/events`, `/api/v1/fleet/*`, `/api/v1/system/connectivity/status` | Bearer token |

OpenWatch does not currently expose a Prometheus `/metrics` endpoint and does
not ship a Prometheus, Grafana, Jaeger, or exporter stack. See
[Not yet implemented](#8-not-yet-implemented).

## 2. Health and version endpoints

### Health probe

The health endpoint is anonymous and is the right target for an external uptime
check or a load-balancer probe. It is implemented in
`internal/server/handlers.go` (`GetHealth`) and pings PostgreSQL with a
two-second timeout.

```bash
curl -k https://localhost:8443/api/v1/health
```

A healthy response returns `200 OK`:

```json
{"status": "healthy", "db_connected": true, "version": "0.2.0-rc.11"}
```

When the database ping fails, the endpoint returns `503 Service Unavailable`
with an error envelope. Treat a non-`200` status, or a connection failure, as
service-down.

The response schema (`status`, `db_connected`, `version`) is defined in
`api/openapi.yaml` under `HealthResponse`. The current contract reports only a
binary `healthy`/`degraded` status driven by database reachability.

### Version metadata

The version endpoint is also anonymous and reports build metadata sourced from
ldflags and Go build info (`internal/server/handlers.go`, `GetVersion`):

```bash
curl -k https://localhost:8443/api/v1/version
```

```json
{
  "openwatch": "0.2.0-rc.11",
  "kensa": "<embedded engine version>",
  "go": "<go toolchain>",
  "commit": "<abbrev commit>",
  "build_time": "<ISO-8601 build timestamp>"
}
```

Use this to confirm which build is running after an upgrade. The same metadata
prints from the CLI with `openwatch --version`.

## 3. Logs via journald

The systemd unit (`packaging/common/openwatch.service`) sends both stdout and
stderr to the journal. With `format = "json"` in `[logging]` (the packaged
default in `packaging/common/openwatch.toml`), every line is a structured JSON
record that carries a correlation ID.

```bash
sudo journalctl -u openwatch -f                    # tail live
sudo journalctl -u openwatch --since '15 min ago'  # recent window
sudo journalctl -u openwatch -o cat | jq .         # pretty-print JSON
sudo journalctl -u openwatch -p err --since today  # errors only
```

To trace one request or one boot across log lines, filter on its correlation
ID:

```bash
sudo journalctl -u openwatch -o cat | jq 'select(.correlation_id == "<id>")'
```

Set `level = "debug"` in `[logging]` (or pass `--log-level debug`, or set
`OPENWATCH_LOGGING_LEVEL=debug`) to raise verbosity, then restart the service.
Log level precedence follows the standard config layering documented in
`docs/engineering/install_guide.md`.

## 4. Audit events

Every server action that mutates state, authenticates, or authorizes emits a
row to the `audit_events` PostgreSQL table (migrations `0001_initial.sql` and
`0002_audit_events_taxonomy.sql`). This is the durable record for security
review; the journal is the operational record.

Query audit events through the API (requires a bearer token with the
appropriate permission):

```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  'https://localhost:8443/api/v1/audit/events'
```

The endpoint (`getAuditEvents` in `api/openapi.yaml`) is cursor-paginated. For
direct inspection during an incident you can also read the table with `psql`:

```bash
psql "$OPENWATCH_DATABASE_DSN" -c \
  "SELECT recorded_at, action, severity, actor_type, actor_id, outcome
   FROM audit_events
   ORDER BY recorded_at DESC
   LIMIT 50;"
```

Indexed columns include `recorded_at`, `action`, `severity`, and
`(actor_type, actor_id)`, so filtered queries on those fields stay fast. For the
event taxonomy (action names and severities), see
`docs/engineering/audit_event_taxonomy.md`.

## 5. Fleet and connectivity signals

OpenWatch continuously probes managed hosts (the liveness loop wired in
`cmd/openwatch/main.go`). These endpoints expose the resulting fleet state and
require a bearer token:

| Endpoint | Reports |
|----------|---------|
| `GET /api/v1/fleet/liveness` | Counts: `reachable`, `unreachable`, `unknown`, `never_probed` |
| `GET /api/v1/fleet/connectivity/breakdown` | 4-state breakdown: `online`, `degraded`, `critical`, `down`, `never_probed` |
| `GET /api/v1/system/connectivity/status` | In-process connectivity-monitor metrics and the maintenance flag |

```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  https://localhost:8443/api/v1/fleet/liveness
```

A rising `unreachable`/`down` count is a useful early signal that either the
monitored fleet or the OpenWatch host's network path is degrading. The schemas
(`FleetLiveness`, `ConnectivityBreakdown`) are defined in `api/openapi.yaml`.

## 6. Service lifecycle

OpenWatch runs as the `openwatch.service` systemd unit, which executes
`openwatch serve --config /etc/openwatch/openwatch.toml`.

```bash
sudo systemctl status openwatch     # current state
sudo systemctl restart openwatch    # restart
sudo systemctl stop openwatch       # stop
sudo systemctl enable --now openwatch  # start now and at boot
```

Before restarting after a config change, validate the resolved configuration:

```bash
sudo -u openwatch openwatch check-config --config /etc/openwatch/openwatch.toml
```

Other CLI subcommands (`cmd/openwatch/main.go`): `migrate` applies pending
database migrations, `create-admin` bootstraps the first admin user, and
`worker` runs the background scan-job loop. The packaged systemd unit runs only
`serve`; the in-process schedulers and liveness loop run inside the `serve`
process.

## 7. Operational runbooks

These runbooks assume the single binary on systemd with a PostgreSQL backend.
Run the commands from the OpenWatch host unless noted.

### SERVICE_DOWN

The service is unreachable or `GET /api/v1/health` does not return `200`.

1. Check the unit state and recent errors:

   ```bash
   sudo systemctl status openwatch
   sudo journalctl -u openwatch --since '10 min ago' -p err
   ```

2. Confirm the local probe:

   ```bash
   curl -k https://localhost:8443/api/v1/health
   ```

3. If the journal shows a database ping failure (for example
   `db: ping: ... connection refused`), check PostgreSQL:

   ```bash
   sudo systemctl status postgresql
   psql "$OPENWATCH_DATABASE_DSN" -c 'SELECT 1;'
   ```

4. If the config is suspect, validate it before restarting:

   ```bash
   sudo -u openwatch openwatch check-config --config /etc/openwatch/openwatch.toml
   ```

5. Restart and confirm recovery:

   ```bash
   sudo systemctl restart openwatch
   curl -k https://localhost:8443/api/v1/health
   ```

The unit is configured with `Restart=on-failure` and `RestartSec=5s`, so a
crashing process restarts automatically; persistent restart loops show up in
`systemctl status` as repeated restarts and warrant the steps above.

### DISK_FULL

Disk pressure on the OpenWatch or PostgreSQL data volume.

1. Find what is full:

   ```bash
   df -h
   sudo du -xh /var/log/openwatch /var/lib/openwatch | sort -h | tail
   ```

2. The journal is a common consumer. Inspect and cap it:

   ```bash
   journalctl --disk-usage
   sudo journalctl --vacuum-time=7d      # drop entries older than 7 days
   sudo journalctl --vacuum-size=500M    # or cap total size
   ```

3. Check the PostgreSQL data directory and database size:

   ```bash
   psql "$OPENWATCH_DATABASE_DSN" -c \
     "SELECT pg_size_pretty(pg_database_size(current_database()));"
   ```

   The `audit_events` table grows over time. Confirm its size before pruning,
   and follow your retention policy:

   ```bash
   psql "$OPENWATCH_DATABASE_DSN" -c \
     "SELECT pg_size_pretty(pg_total_relation_size('audit_events'));"
   ```

4. After freeing space, confirm the service is healthy
   (`curl -k https://localhost:8443/api/v1/health`).

OpenWatch does not currently rotate or prune `audit_events` automatically; apply
your own retention if the table dominates database size.

### HIGH_CPU

The OpenWatch process is consuming excessive CPU.

1. Confirm which process and how much:

   ```bash
   top -b -n1 | head -20
   sudo systemctl status openwatch     # shows the main PID
   ```

2. Correlate with request and scan activity in the journal:

   ```bash
   sudo journalctl -u openwatch --since '15 min ago' -o cat | jq -r '.msg' | sort | uniq -c | sort -rn | head
   ```

3. Check whether background work is driving load. The liveness loop and the
   intelligence and discovery schedulers run inside `serve`. If a scheduler is
   misconfigured, pause it via its config endpoint, for example:

   ```bash
   curl -k -H "Authorization: Bearer $TOKEN" \
     https://localhost:8443/api/v1/system/intelligence/config
   ```

4. Check PostgreSQL for long-running or stuck queries:

   ```bash
   psql "$OPENWATCH_DATABASE_DSN" -c \
     "SELECT pid, now()-query_start AS runtime, state, left(query,80)
      FROM pg_stat_activity
      WHERE state <> 'idle'
      ORDER BY runtime DESC NULLS LAST LIMIT 10;"
   ```

5. If the process is wedged rather than merely busy, capture the journal context
   first, then `sudo systemctl restart openwatch`.

### SECURITY_INCIDENT

Suspected unauthorized access, credential misuse, or anomalous authorization
failures.

1. Pull recent authentication and authorization events from the audit log. These
   are the durable security record:

   ```bash
   psql "$OPENWATCH_DATABASE_DSN" -c \
     "SELECT recorded_at, action, severity, actor_type, actor_id, outcome
      FROM audit_events
      WHERE severity IN ('warning','critical')
         OR action LIKE 'auth.%'
      ORDER BY recorded_at DESC
      LIMIT 100;"
   ```

2. Cross-reference with the journal for the same window, filtering by correlation
   ID where you have one:

   ```bash
   sudo journalctl -u openwatch --since '1 hour ago' -o cat | jq 'select(.level=="WARN" or .level=="ERROR")'
   ```

3. If you must contain immediately, stop the service to halt all access while you
   investigate:

   ```bash
   sudo systemctl stop openwatch
   ```

4. Rotate any potentially exposed secrets in `/etc/openwatch/secrets.env` (for
   example `OPENWATCH_DATABASE_DSN`) and the keys under `/etc/openwatch/`, then
   restart. Preserve the journal and a copy of relevant `audit_events` rows
   before you prune anything.

For role and permission definitions referenced by audit `action`/`actor` fields,
see `docs/engineering/rbac_registry.md`.

## 8. Not yet implemented

The following observability capabilities described in earlier (Python-era)
documentation do not exist in the current Go build. They are recorded here so
operators do not look for them:

- **Prometheus `/metrics` endpoint** — not exposed. The only health signal is
  `GET /api/v1/health`.
- **Bundled monitoring stack** (Prometheus, Grafana, Jaeger, Alertmanager,
  node/redis/postgres exporters, cAdvisor) — not shipped. There is no
  `monitoring/` Compose stack and no container runtime in this architecture.
- **Distributed tracing** — not implemented. Correlation IDs in the JSON logs
  are the current mechanism for following a request across log lines.
- **Detailed authenticated health endpoints** (per-service, content, history) —
  not implemented. The current health contract is a single binary
  `healthy`/`degraded` status.

If and when metrics or tracing land, this section and the contract in
`api/openapi.yaml` will be updated together.
