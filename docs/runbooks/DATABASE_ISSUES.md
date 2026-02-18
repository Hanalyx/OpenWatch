# Runbook: PostgreSQL Database Issues

**Severity**: P1 - High
**Last Updated**: 2026-02-17
**Owner**: Platform Engineering
**Estimated Resolution Time**: 5-60 minutes depending on root cause

---

## Symptoms

- Application logs show `Could not connect to PostgreSQL` or `OperationalError`.
- API requests return HTTP 500 or 503 errors.
- Health endpoint (`GET /health`) reports `"database": "unhealthy"`.
- Slow API response times (queries taking seconds instead of milliseconds).
- Connection timeout errors in backend or worker logs.
- Scans stuck in `pending` or `running` state indefinitely.

---

## Diagnosis

### Step 1: Check PostgreSQL container status

```bash
docker ps -a --filter "name=openwatch-db"
```

The container should show status `Up` with `(healthy)`. If it shows `Exited` or `unhealthy`, see Resolution Path A.

### Step 2: Test PostgreSQL connectivity

```bash
# From the host
docker exec openwatch-db pg_isready -U openwatch -d openwatch
```

Expected output: `openwatch-db:5432 - accepting connections`. If it reports `no response` or `rejecting connections`, PostgreSQL is down or overloaded.

### Step 3: Check connection count

```bash
docker exec openwatch-db psql -U openwatch -d openwatch -c "
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
docker exec openwatch-db psql -U openwatch -d openwatch -c "SHOW max_connections;"
```

Default is 100. If `total_connections` is near `max_connections`, connection pool exhaustion is the likely cause.

### Step 4: Check for long-running or blocked queries

```bash
docker exec openwatch-db psql -U openwatch -d openwatch -c "
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
docker exec openwatch-db psql -U openwatch -d openwatch -c "
SELECT blocked.pid AS blocked_pid,
       blocked.query AS blocked_query,
       blocking.pid AS blocking_pid,
       blocking.query AS blocking_query
FROM pg_stat_activity AS blocked
JOIN pg_locks AS blocked_locks ON blocked.pid = blocked_locks.pid
JOIN pg_locks AS blocking_locks
    ON blocked_locks.locktype = blocking_locks.locktype
    AND blocked_locks.relation = blocking_locks.relation
    AND blocked_locks.pid != blocking_locks.pid
    AND blocking_locks.granted
JOIN pg_stat_activity AS blocking ON blocking_locks.pid = blocking.pid
WHERE NOT blocked_locks.granted
LIMIT 10;
"
```

### Step 6: Check disk space

```bash
# Host disk
docker exec openwatch-db df -h /var/lib/postgresql/data

# Database size
docker exec openwatch-db psql -U openwatch -d openwatch -c "
SELECT pg_size_pretty(pg_database_size('openwatch')) AS database_size;
"

# Largest tables
docker exec openwatch-db psql -U openwatch -d openwatch -c "
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
docker logs openwatch-db --tail 200
```

Look for:
- `FATAL: too many connections` -- connection pool exhaustion.
- `FATAL: could not open file` -- disk full or file corruption.
- `ERROR: deadlock detected` -- lock contention.
- `LOG: checkpoints are occurring too frequently` -- high write load, consider tuning.
- `PANIC` -- severe error requiring immediate attention.

### Step 8: Check table bloat and dead tuples

```bash
docker exec openwatch-db psql -U openwatch -d openwatch -c "
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

### Path A: PostgreSQL container is down

```bash
# Check why it stopped
docker inspect openwatch-db --format='{{.State.ExitCode}} {{.State.Error}}'

# Check for OOM
dmesg | grep -i "oom\|killed" | tail -10

# Restart PostgreSQL
docker restart openwatch-db

# Wait for health check to pass (up to 50 seconds: 10s start_period + 5s interval * 10 retries)
sleep 15
docker exec openwatch-db pg_isready -U openwatch -d openwatch
```

After PostgreSQL is back, restart dependent services:

```bash
docker restart openwatch-backend
docker restart openwatch-worker
docker restart openwatch-celery-beat
```

### Path B: Connection pool exhaustion

If connections are near `max_connections`:

```bash
# Terminate idle-in-transaction connections (safe to kill)
docker exec openwatch-db psql -U openwatch -d openwatch -c "
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE datname = 'openwatch'
  AND state = 'idle in transaction'
  AND query_start < now() - interval '10 minutes';
"
```

Then restart the backend to reset its connection pool:

```bash
docker restart openwatch-backend
docker restart openwatch-worker
```

If this recurs frequently, increase `max_connections` in the PostgreSQL configuration or reduce the application connection pool size.

### Path C: Lock contention

Identify the blocking query from Step 5 output and terminate it if safe to do so:

```bash
# Terminate the blocking PID (replace 12345 with actual blocking_pid)
docker exec openwatch-db psql -U openwatch -d openwatch -c "
SELECT pg_terminate_backend(12345);
"
```

Verify locks are cleared:

```bash
docker exec openwatch-db psql -U openwatch -d openwatch -c "
SELECT count(*) FROM pg_locks WHERE NOT granted;
"
```

### Path D: Long-running queries

Kill queries that have been running too long:

```bash
# Cancel a specific query gracefully (replace PID)
docker exec openwatch-db psql -U openwatch -d openwatch -c "
SELECT pg_cancel_backend(12345);
"

# If pg_cancel_backend does not work, force terminate
docker exec openwatch-db psql -U openwatch -d openwatch -c "
SELECT pg_terminate_backend(12345);
"
```

### Path E: Disk full

If PostgreSQL data volume is full:

```bash
# Check volume usage
docker exec openwatch-db du -sh /var/lib/postgresql/data

# Run vacuum to reclaim space (does not require exclusive lock)
docker exec openwatch-db psql -U openwatch -d openwatch -c "VACUUM VERBOSE;"
```

For more aggressive space reclamation (requires exclusive table lock):

```bash
# VACUUM FULL rewrites the entire table - use with caution during off-hours
docker exec openwatch-db psql -U openwatch -d openwatch -c "VACUUM FULL scan_findings;"
```

Also see the [DISK_FULL.md](DISK_FULL.md) runbook for broader disk cleanup.

### Path F: Corrupted indexes

If queries return incorrect results or logs show index-related errors:

```bash
# Reindex a specific table
docker exec openwatch-db psql -U openwatch -d openwatch -c "REINDEX TABLE scan_findings;"

# Reindex the entire database (takes longer, but thorough)
docker exec openwatch-db psql -U openwatch -d openwatch -c "REINDEX DATABASE openwatch;"
```

### Path G: Out of memory

If PostgreSQL is being OOM killed:

```bash
# Check current shared_buffers and work_mem
docker exec openwatch-db psql -U openwatch -d openwatch -c "
SHOW shared_buffers;
SHOW work_mem;
SHOW effective_cache_size;
"
```

Consider reducing `work_mem` if it is set high, or adding a memory limit to the container to prevent it from being targeted by the host OOM killer.

---

## Recovery Verification

### 1. PostgreSQL accepts connections

```bash
docker exec openwatch-db pg_isready -U openwatch -d openwatch
```

Expected: `accepting connections`.

### 2. Health endpoint reports database healthy

```bash
curl -s http://localhost:8000/health | python3 -m json.tool
```

Confirm `"database": "healthy"`.

### 3. Basic query works

```bash
docker exec openwatch-db psql -U openwatch -d openwatch -c "SELECT count(*) FROM hosts;"
```

Should return a count without errors.

### 4. No blocked queries

```bash
docker exec openwatch-db psql -U openwatch -d openwatch -c "
SELECT count(*) FROM pg_locks WHERE NOT granted;
"
```

Expected: `0`.

### 5. Connection count is normal

```bash
docker exec openwatch-db psql -U openwatch -d openwatch -c "
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
- PostgreSQL container logs (last 200 lines).
- Output of `pg_isready`.
- Connection count and max_connections values.
- Database size and disk usage.
- Any PANIC or FATAL messages from logs.

---

## Prevention

- **Connection pool monitoring**: Track connection counts via the Postgres Exporter (port 9187) and set alerts when approaching `max_connections`.
- **Query timeouts**: Configure `statement_timeout` in PostgreSQL to prevent runaway queries:
  ```sql
  ALTER DATABASE openwatch SET statement_timeout = '300s';
  ```
- **Autovacuum tuning**: Ensure autovacuum is running. Check `last_autovacuum` in `pg_stat_user_tables`. If tables are not being vacuumed, tune `autovacuum_vacuum_threshold` and `autovacuum_vacuum_scale_factor`.
- **Disk space monitoring**: Set up alerts when the `postgres_data` volume exceeds 80% capacity.
- **Connection limit per user**: Consider setting `ALTER ROLE openwatch CONNECTION LIMIT 80;` to leave headroom for administrative connections.
- **Regular maintenance**: Schedule weekly `ANALYZE` on large tables to keep query planner statistics current:
  ```sql
  ANALYZE scan_findings;
  ANALYZE scans;
  ANALYZE hosts;
  ANALYZE audit_logs;
  ```
