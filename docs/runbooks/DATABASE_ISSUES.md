# Runbook: PostgreSQL database issues

**Severity**: P1 - High
**Last updated**: 2026-06-26
**Owner**: Platform Engineering
**Estimated resolution time**: 5-60 minutes depending on root cause

OpenWatch runs as a single Go binary (`/usr/bin/openwatch`) managed by systemd (`openwatch.service`). It connects to a PostgreSQL server (PostgreSQL is the only datastore; there is no MongoDB, Redis, or Celery). The `psql` commands below assume you have a PostgreSQL client on the database host or a host that can reach it; adjust the connection flags (`-h`, `-p`) for your deployment.

---

## Symptoms

- Application logs show `Could not connect to PostgreSQL` or a connection error.
- API requests return HTTP 500 or 503 errors.
- Health endpoint (`GET /api/v1/health`) returns `503` with an `ErrorEnvelope`
  body (`"code": "server.unavailable"`), not a `"status": "degraded"` body.
- Slow API response times (queries taking seconds instead of milliseconds).
- Connection timeout errors in the `openwatch` service logs (`journalctl -u openwatch`).
- Scans stuck in `pending` or `running` state indefinitely.

---

## Diagnosis

> **Before you start**
> - **You need:** shell access to the OpenWatch host and to the PostgreSQL server it uses.
> - **Run as:** a sudo-capable administrator for service and journal commands; `psql` as the `openwatch` database role using the DSN from `/etc/openwatch/secrets.env`.
> - **What changes:** nothing; every step here reads state.
> - **Verify with:** the symptom you started from, `/api/v1/health` returning `200`, then the full [Recovery verification](#recovery-verification) after any path that restarts OpenWatch.
> - **Recover by:** nothing to recover from a diagnosis; move to [Resolution](#resolution).

### Step 1: Check PostgreSQL service status

```bash
systemctl status postgresql
```

The service should be `active (running)`. If it is `failed` or `inactive`, see Resolution Path A.

### Step 2: Test PostgreSQL connectivity

```bash
pg_isready -U openwatch -d openwatch
```

Expected output ends with `accepting connections` (for example `localhost:5432 - accepting connections`). If it reports `no response` or `rejecting connections`, PostgreSQL is down or overloaded.

### Step 3: Check connection count

```bash
psql -U openwatch -d openwatch -c "
SELECT count(*) AS total_connections,
       count(*) FILTER (WHERE state = 'active') AS active,
       count(*) FILTER (WHERE state = 'idle') AS idle,
       count(*) FILTER (WHERE state = 'idle in transaction') AS idle_in_transaction
FROM pg_stat_activity
WHERE datname = 'openwatch';
"
```

Compare against the maximum connections:

```bash
psql -U openwatch -d openwatch -c "SHOW max_connections;"
```

Default is 100. If `total_connections` is near `max_connections`, connection pool exhaustion is the likely cause.

### Step 4: Check for long-running or blocked queries

```bash
psql -U openwatch -d openwatch -c "
SELECT pid,
       now() - pg_stat_activity.query_start AS duration,
       state,
       left(query, 100) AS query_preview
FROM pg_stat_activity
WHERE datname = 'openwatch'
  AND state != 'idle'
  AND query NOT ILIKE '%pg_stat_activity%'
ORDER BY duration DESC
LIMIT 20;
"
```

Any query running longer than 60 seconds should be investigated.

### Step 5: Check for lock contention

```bash
psql -U openwatch -d openwatch -c "
SELECT blocked.pid AS blocked_pid,
       blocked.query AS blocked_query,
       blocking.pid AS blocking_pid,
       blocking.query AS blocking_query
FROM pg_stat_activity AS blocked
CROSS JOIN LATERAL unnest(pg_blocking_pids(blocked.pid)) AS b(pid)
JOIN pg_stat_activity AS blocking ON blocking.pid = b.pid
LIMIT 10;
"
```

`pg_blocking_pids` covers every lock type, including the per-host advisory lock
a scan holds for its whole run, so a second scan waiting on the same host shows
here.

### Step 6: Check disk space

```bash
# Host disk for the PostgreSQL data directory
# SHOW data_directory needs a superuser or pg_read_all_settings; the openwatch role has neither
df -h "$(sudo -u postgres psql -tAc 'SHOW data_directory;')"

# Database size
psql -U openwatch -d openwatch -c "
SELECT pg_size_pretty(pg_database_size('openwatch')) AS database_size;
"

# Largest tables
psql -U openwatch -d openwatch -c "
SELECT schemaname || '.' || tablename AS table_name,
       pg_size_pretty(pg_total_relation_size(schemaname || '.' || tablename)) AS total_size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname || '.' || tablename) DESC
LIMIT 10;
"
```

### Step 7: Check PostgreSQL logs

```bash
journalctl -u postgresql --no-pager -n 200
```

Look for:
- `FATAL: too many connections` -- connection pool exhaustion.
- `FATAL: could not open file` -- disk full or file corruption.
- `ERROR: deadlock detected` -- lock contention.
- `LOG: checkpoints are occurring too frequently` -- high write load, consider tuning.
- `PANIC` -- severe error requiring immediate attention.

### Step 8: Check table bloat and dead tuples

```bash
psql -U openwatch -d openwatch -c "
SELECT schemaname || '.' || relname AS table_name,
       n_dead_tup AS dead_tuples,
       n_live_tup AS live_tuples,
       CASE WHEN n_live_tup > 0
            THEN round(n_dead_tup::numeric / n_live_tup * 100, 2)
            ELSE 0
       END AS dead_pct,
       last_autovacuum
FROM pg_stat_user_tables
WHERE n_dead_tup > 1000
ORDER BY n_dead_tup DESC
LIMIT 10;
"
```

If `dead_pct` exceeds 20% for any table, a manual vacuum may be needed.

---

## Resolution

> **Before you start**
> - **You need:** the diagnosis result naming which path applies.
> - **Run as:** a sudo-capable administrator; PostgreSQL changes as the PostgreSQL superuser or the `openwatch` role as each command states.
> - **What changes:** PostgreSQL settings, connections or the OpenWatch service state, per path.
> - **Verify with:** [Recovery verification](#recovery-verification).
> - **Recover by:** reverting the setting you changed and restarting the affected service; a database restore only if data was touched, per [Backup and recovery](BACKUP_RECOVERY.md).

### Path A: PostgreSQL is down

```bash
# Check why it stopped
systemctl status postgresql --no-pager

# Check for OOM
dmesg | grep -i "oom\|killed" | tail -10

# Restart PostgreSQL
systemctl restart postgresql

# Wait for it to accept connections
sleep 15
pg_isready -U openwatch -d openwatch
```

After PostgreSQL is back, restart the OpenWatch service so it reopens its
connection pool. Use the first block in
[Prove the restored service works](BACKUP_RECOVERY.md#prove-the-restored-service-works). It restarts the
service itself and proves the rule library loaded.

### Path B: Connection pool exhaustion

If connections are near `max_connections`, look at the idle-in-transaction
connections first. Some of them are OpenWatch doing its job, so do not
terminate them blindly.

OpenWatch holds a transaction open, idle, for the whole of each host scan and
each host intelligence collection. The transaction holds a per-host advisory
lock (`pg_advisory_xact_lock`) so that two workers never work on the same host
at once. A scan has no per-scan timeout today (spec `system-kensa-executor`
C-04 calls for 600 seconds; CP `bugs/OW-109`), so a scan stuck on a host keeps
its transaction open until the scan returns or the service restarts.

Terminating one of these backends is not harmless:

- **Scan.** The scan keeps running over SSH and still writes its results, but
  its host lock is gone. A second scan of the same host can then start
  alongside it.
- **Intelligence collection.** The schedule update is written in that
  transaction, so it is lost and the host is collected again.

List idle-in-transaction connections and whether each holds an advisory lock:

```bash
psql -U openwatch -d openwatch -c "
SELECT a.pid,
       now() - a.xact_start   AS in_transaction_for,
       now() - a.state_change AS idle_for,
       EXISTS (SELECT 1 FROM pg_locks l
               WHERE l.pid = a.pid AND l.locktype = 'advisory' AND l.granted) AS holds_advisory_lock,
       left(a.query, 70) AS last_query
FROM pg_stat_activity a
WHERE a.datname = 'openwatch'
  AND a.state = 'idle in transaction'
ORDER BY a.xact_start;
"
```

`last_query` tells the two apart. A scan shows
`SELECT pg_advisory_xact_lock($1)`; an intelligence collection shows
`SELECT pg_try_advisory_xact_lock(hashtext($1)::int8)`. The lock key is a hash
of the host id, so this view does not name the host. To see which scans are in
flight and for how long:

```bash
psql -U openwatch -d openwatch -c "
SELECT id, host_id, started_at, now() - started_at AS running_for
FROM scan_runs
WHERE status = 'running'
ORDER BY started_at;
"
```

Terminate only the idle transactions that hold no advisory lock. Terminating
one rolls back whatever it had not committed:

```bash
psql -U openwatch -d openwatch -c "
SELECT pg_terminate_backend(a.pid)
FROM pg_stat_activity a
WHERE a.datname = 'openwatch'
  AND a.state = 'idle in transaction'
  AND a.state_change < now() - interval '10 minutes'
  AND NOT EXISTS (SELECT 1 FROM pg_locks l
                  WHERE l.pid = a.pid AND l.locktype = 'advisory');
"
```

Terminate a scan or collection backend only when you accept the effects above,
for example a scan that has hung on an unreachable host.

Then restart the OpenWatch service to reset its connection pool. Use the
first block in [Prove the restored service works](BACKUP_RECOVERY.md#prove-the-restored-service-works). It
restarts the service itself and proves the rule library loaded.

If this recurs frequently, increase `max_connections` in the PostgreSQL configuration or reduce the application connection pool size.

### Path C: Lock contention

Identify the blocking query from Step 5 output and terminate it if safe to do so:

```bash
# Terminate the blocking PID (replace 12345 with actual blocking_pid)
psql -U openwatch -d openwatch -c "
SELECT pg_terminate_backend(12345);
"
```

Verify locks are cleared:

```bash
psql -U openwatch -d openwatch -c "
SELECT count(*) FROM pg_locks WHERE NOT granted;
"
```

### Path D: Long-running queries

Kill queries that have been running too long:

```bash
# Cancel a specific query gracefully (replace PID)
psql -U openwatch -d openwatch -c "
SELECT pg_cancel_backend(12345);
"

# If pg_cancel_backend does not work, force terminate
psql -U openwatch -d openwatch -c "
SELECT pg_terminate_backend(12345);
"
```

### Path E: Disk full

If PostgreSQL data volume is full:

```bash
# Check data directory usage
du -sh "$(sudo -u postgres psql -tAc 'SHOW data_directory;')"

# Run vacuum to reclaim space (does not require exclusive lock)
psql -U openwatch -d openwatch -c "VACUUM VERBOSE;"
```

For more aggressive space reclamation (requires exclusive table lock):

```bash
# VACUUM FULL rewrites the entire table - use with caution during off-hours.
# Replace scan_results with the actual large table from Step 6; confirm it exists first.
psql -U openwatch -d openwatch -c "VACUUM FULL scan_results;"
```

Also see the [disk space runbook](DISK_FULL.md) for broader disk cleanup.

### Path F: Corrupted indexes

If queries return incorrect results or logs show index-related errors:

```bash
# Reindex a specific table
psql -U openwatch -d openwatch -c "REINDEX TABLE scan_results;"

# Reindex the entire database (takes longer, but thorough)
psql -U openwatch -d openwatch -c "REINDEX DATABASE openwatch;"
```

### Path G: Out of memory

If PostgreSQL is being OOM killed:

```bash
# Check current shared_buffers and work_mem
psql -U openwatch -d openwatch -c "
SHOW shared_buffers;
SHOW work_mem;
SHOW effective_cache_size;
"
```

Consider reducing `work_mem` if it is set high, or constraining the PostgreSQL service's memory (for example a systemd `MemoryMax=` on the postgresql unit) to keep it from being targeted by the host OOM killer.

---

## Recovery verification

### 1. PostgreSQL accepts connections

```bash
pg_isready -U openwatch -d openwatch
```

Expected: `accepting connections`.

### 2. Health endpoint reports database healthy

```bash
curl -sk https://localhost:8443/api/v1/health | jq
```

Confirm `"status": "healthy"` and `"db_connected": true`.

### 3. Basic query works

```bash
psql -U openwatch -d openwatch -c "SELECT count(*) FROM hosts;"
```

Should return a count without errors.

### 4. No blocked queries

```bash
psql -U openwatch -d openwatch -c "
SELECT count(*) FROM pg_locks WHERE NOT granted;
"
```

Expected: `0`.

### 5. Connection count is normal

```bash
psql -U openwatch -d openwatch -c "
SELECT count(*) FROM pg_stat_activity WHERE datname = 'openwatch';
"
```

Should be well below `max_connections` (default 100).

---

## Escalation

Escalate if any of the following conditions are met:

- PostgreSQL cannot start after restart (check logs for `PANIC` or data corruption messages).
- Data corruption is suspected (queries return wrong results, `pg_catalog` errors).
- Disk is full and no safe cleanup options are available.
- Connection exhaustion recurs within 30 minutes of fix.
- WAL corruption or replication errors are present in logs.

**Information to include when escalating**:
- PostgreSQL logs (last 200 lines), for example `journalctl -u postgresql -n 200`.
- Output of `pg_isready`.
- Connection count and max_connections values.
- Database size and disk usage.
- Any PANIC or FATAL messages from logs.

---

## Prevention

- **Connection pool monitoring**: Track connection counts (for example with a PostgreSQL metrics exporter or a periodic `pg_stat_activity` query) and set alerts when approaching `max_connections`.
- **Query timeouts**: Configure `statement_timeout` in PostgreSQL to prevent runaway queries:
  ```sql
  ALTER DATABASE openwatch SET statement_timeout = '300s';
  ```
- **Autovacuum tuning**: Ensure autovacuum is running. Check `last_autovacuum` in `pg_stat_user_tables`. If tables are not being vacuumed, tune `autovacuum_vacuum_threshold` and `autovacuum_vacuum_scale_factor`.
- **Disk space monitoring**: Set up alerts when the `postgres_data` volume exceeds 80% capacity.
- **Connection limit per user**: Consider setting `ALTER ROLE openwatch CONNECTION LIMIT 80;` to leave headroom for administrative connections.
- **Regular maintenance**: Schedule weekly `ANALYZE` on large tables to keep query planner statistics current:
  ```sql
  ANALYZE scan_results;
  ANALYZE scan_runs;
  ANALYZE hosts;
  ANALYZE audit_events;
  ```
