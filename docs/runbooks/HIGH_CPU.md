# Runbook: high CPU usage

**Severity**: P2 - medium
**Last updated**: 2026-06-10
**Owner**: Platform Engineering
**Estimated resolution time**: 10-45 minutes

OpenWatch runs as a single Go binary (`/usr/bin/openwatch`) that serves the REST
API and the embedded React UI over HTTPS on port `8443`. Background scan jobs are
drained by a separate `openwatch worker` process that reads from a PostgreSQL-native
job queue. Both processes share one PostgreSQL database. There is no container
runtime, no Redis, and no Celery. Compliance checks run through Kensa (SSH-based,
native YAML rules); OpenSCAP/`oscap` are not used.

This runbook covers the three processes that can saturate CPU on an OpenWatch host:

| Process | Typical CPU cause |
|---------|-------------------|
| `openwatch serve` | High API/UI request volume, expensive handler queries, in-process schedulers (liveness, intelligence, discovery) |
| `openwatch worker` | Kensa SSH compliance checks running against hosts |
| `postgres` | Expensive queries, missing indexes, autovacuum on large tables |

For install and configuration details, see
[`docs/engineering/install_guide.md`](../engineering/install_guide.md). For the
Kensa boundary, see [`docs/KENSA_OPENWATCH_BOUNDARY.md`](../KENSA_OPENWATCH_BOUNDARY.md).

---

## Symptoms

- Slow API or UI response times reported by users.
- `top`/`htop` shows `openwatch` or `postgres` near a full core (or saturated host).
- Scan completion times noticeably longer than normal.
- The `/api/v1/health` endpoint is slow to respond or times out.

> Note: OpenWatch does not currently expose a Prometheus `/metrics` endpoint.
> The only in-process metrics surfaced over the API are connectivity-monitor
> counters under `/api/v1/system/connectivity` (see `api/openapi.yaml`). CPU
> diagnosis relies on host tools (`top`, `mpstat`) and `journalctl`, not a
> metrics scrape. A metrics/observability endpoint is not yet implemented.

---

## Diagnosis

### Step 1: Identify which process is consuming CPU

```bash
top -bn1 -o %CPU | head -20
```

Look for `openwatch` (serve and/or worker) and `postgres` processes. To narrow to
OpenWatch processes:

```bash
ps -eo pid,ppid,pcpu,pmem,etime,args --sort=-pcpu | grep -E 'openwatch|postgres' | grep -v grep
```

Confirm which OpenWatch units are running:

```bash
systemctl status openwatch
```

The packaged systemd unit (`openwatch.service`) runs `openwatch serve`. If you run
the worker, it is a separate `openwatch worker` invocation; check how it is started
on your host (its own unit, a wrapper, or a manual process).

### Step 2: Check per-core saturation

```bash
mpstat -P ALL 1 3
```

If every core is busy, the host itself is saturated and the cause may be systemic
(co-tenant load, a runaway query, or genuinely high scan demand) rather than a
single OpenWatch process.

### Step 3: Drill into the high-CPU process

#### If `openwatch serve` is high

Check recent request volume and look for error or retry storms:

```bash
journalctl -u openwatch --since "5 min ago" -o cat | wc -l
journalctl -u openwatch --since "5 min ago" -o cat | grep -iE 'error|warn' | tail -50
```

Logs are structured JSON with a correlation ID per request. Look for an endpoint or
correlation ID that appears disproportionately. The `serve` process also runs the
liveness, intelligence, and discovery schedulers in-process; a misconfigured
interval can drive steady CPU (see Resolution path C).

#### If `openwatch worker` is high

The worker runs Kensa SSH checks. Confirm how many scan jobs are queued or running:

```bash
psql "$OPENWATCH_DATABASE_DSN" -c "
SELECT status, count(*)
FROM job_queue
GROUP BY status
ORDER BY status;
"
```

The `job_queue` table holds all background jobs (`status` is one of `pending`,
`processing`, `completed`, `failed`; `job_type` distinguishes scan jobs from other
work). A growing `processing` count with stale `locked_at` timestamps indicates work
that is not draining. The schema is defined in
`internal/db/migrations/0003_job_queue.sql`.

The worker serializes work per host via a PostgreSQL advisory lock
(`pg_advisory_xact_lock`), so two scans against the same host cannot run at once.
CPU pressure from the worker therefore scales with the number of distinct hosts
being scanned concurrently and the cost of each Kensa run.

#### If `postgres` is high

Find expensive active queries:

```bash
psql "$OPENWATCH_DATABASE_DSN" -c "
SELECT pid,
       now() - query_start AS duration,
       state,
       left(query, 120) AS query_preview
FROM pg_stat_activity
WHERE state = 'active'
  AND query NOT ILIKE '%pg_stat_activity%'
ORDER BY duration DESC
LIMIT 10;
"
```

Check whether autovacuum is running:

```bash
psql "$OPENWATCH_DATABASE_DSN" -c "
SELECT pid, left(query, 80) AS query
FROM pg_stat_activity
WHERE query ILIKE '%vacuum%' OR query ILIKE '%analyze%';
"
```

> `OPENWATCH_DATABASE_DSN` is set in `/etc/openwatch/secrets.env`. If `psql` is run
> as the `openwatch` user without that variable exported, source the file first or
> connect with explicit `-h`/`-U`/`-d` flags.

---

## Resolution

### Path A: long-running database queries

Cancel a specific expensive query (use the `pid` from the diagnosis step):

```bash
psql "$OPENWATCH_DATABASE_DSN" -c "SELECT pg_cancel_backend(12345);"
```

Identify tables doing heavy sequential scans, which often indicates a missing index:

```bash
psql "$OPENWATCH_DATABASE_DSN" -c "
SELECT schemaname || '.' || relname AS table,
       seq_scan,
       idx_scan
FROM pg_stat_user_tables
WHERE seq_scan > 100
ORDER BY seq_scan DESC
LIMIT 10;
"
```

A table with a high `seq_scan` count and a large row count is a candidate for an
added index. Do not add indexes ad hoc in production; raise the finding so the
schema change lands as a migration in `internal/db/migrations/`.

### Path B: tune the database connection pool

The `serve` and `worker` processes each open a pool capped by
`[database].max_connections` (default `25`) in `/etc/openwatch/openwatch.toml`. An
oversized pool against an undersized PostgreSQL can amplify CPU contention. Inspect
the resolved value:

```bash
openwatch check-config --config /etc/openwatch/openwatch.toml
```

Adjust `[database].max_connections` (or the `OPENWATCH_DATABASE_MAX_CONNECTIONS`
env override) and restart the process:

```bash
sudo systemctl restart openwatch
```

### Path C: a scheduler is doing too much work

The `serve` process runs the liveness, intelligence, and discovery schedulers
in-process. If one of them is sweeping too aggressively, lower its frequency or
pause it through the operator-tunable system config (changes hot-load; no restart
needed):

```bash
# Pause intelligence collection
curl -sk -X PUT https://localhost:8443/api/v1/system/intelligence/config \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"maintenance_global": true}'

# Pause discovery sweeps
curl -sk -X PUT https://localhost:8443/api/v1/system/discovery/config \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"maintenance_global": true}'
```

> These endpoints require an authenticated token with the appropriate role. Confirm
> the exact request body and required permission against `api/openapi.yaml` and
> [`docs/engineering/rbac_registry.md`](../engineering/rbac_registry.md) before use.
> The schedulers log a warning at startup when paused.

### Path D: slow the worker poll loop

The worker accepts a `--poll-interval` flag (default 1s, 5s max) that controls how
often it polls an empty queue. There is no `MAX_CONCURRENT_SCANS` knob; concurrency
is bounded by the per-host advisory lock and the number of worker processes you run.
If the worker is busy-looping against an empty queue, raise the interval:

```bash
openwatch worker --config /etc/openwatch/openwatch.toml --poll-interval 5s
```

If scan demand is genuinely high and the host has CPU headroom, the queue drains as
the worker processes jobs. If it does not have headroom, reduce how many hosts you
scan concurrently rather than adding load.

### Path E: autovacuum consuming CPU

Autovacuum on a large table is expected and prevents table bloat. Check progress:

```bash
psql "$OPENWATCH_DATABASE_DSN" -c "
SELECT relid::regclass AS table, phase,
       heap_blks_total, heap_blks_scanned, heap_blks_vacuumed
FROM pg_stat_progress_vacuum;
"
```

Do not kill autovacuum unless it is clearly causing an outage. If it consistently
hurts peak hours, tune PostgreSQL's autovacuum cost settings
(`autovacuum_vacuum_cost_delay`) at the database level rather than disabling it.

---

## Recovery verification

### 1. CPU returns to normal

```bash
top -bn1 -o %CPU | head -10
```

The `openwatch` and `postgres` processes should drop well below a full core under
normal load.

### 2. The health endpoint responds quickly

```bash
time curl -sk -o /dev/null https://localhost:8443/api/v1/health
```

Should complete in well under one second.

### 3. No long-running queries remain

```bash
psql "$OPENWATCH_DATABASE_DSN" -c "
SELECT count(*)
FROM pg_stat_activity
WHERE state = 'active'
  AND now() - query_start > interval '60 seconds';
"
```

Expected: `0`.

### 4. The scan queue is stable or draining

```bash
psql "$OPENWATCH_DATABASE_DSN" -c "
SELECT status, count(*) FROM job_queue GROUP BY status ORDER BY status;
"
```

Re-run after a few minutes; the `pending` count should be flat or falling.

---

## Escalation

Escalate if any of the following hold:

- CPU stays saturated after cancelling long-running queries and pausing schedulers.
- The host itself is CPU-saturated across all cores (not a single process).
- The load matches a suspected denial-of-service or anomalous traffic pattern.
- The worker makes no progress while showing high CPU (possible stuck job).

Information to include when escalating:

- Output of `top -bn1 -o %CPU | head -20` and `mpstat -P ALL 1 3`.
- `systemctl status openwatch` and recent `journalctl -u openwatch` excerpts.
- The list of long-running PostgreSQL queries from the diagnosis step.
- Job queue counts (`job_queue` grouped by status).
- A timeline of when the issue started and any recent config or release change.

---

## Prevention

- **Database sizing**: Match `[database].max_connections` to what PostgreSQL is
  provisioned for; an oversized pool amplifies contention under load.
- **Scheduler tuning**: Keep liveness, intelligence, and discovery intervals
  reasonable for your fleet size via the `/api/v1/system/*/config` endpoints.
- **Index review**: When a query is slow, profile it with `EXPLAIN ANALYZE` and land
  any new index as a migration in `internal/db/migrations/` rather than hand-editing
  production.
- **Worker placement**: For sustained high scan demand, run the `openwatch worker`
  process on a host with adequate CPU; the per-host advisory lock prevents duplicate
  work, so the lever is total scan concurrency, not a single tunable.
- **Log retention**: Structured JSON logs go to the journal; ensure journald
  retention is sized so you can review request and scan history during an incident.
