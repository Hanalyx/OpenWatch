# Runbook: High CPU Usage

**Severity**: P2 - Medium
**Last Updated**: 2026-02-17
**Owner**: Platform Engineering
**Estimated Resolution Time**: 10-45 minutes

---

## Symptoms

- Slow API response times reported by users or monitoring.
- Container CPU usage at or near limits (visible in `docker stats` or cAdvisor).
- Prometheus alerts for high CPU utilization.
- Scan execution times significantly longer than normal.
- Backend health check timeouts (the 10-second timeout in `docker-compose.yml` is exceeded).
- `secureops_http_request_duration_seconds` histogram shows elevated p95/p99 latency.

---

## Diagnosis

### Step 1: Identify which container is consuming CPU

```bash
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.PIDs}}"
```

Note which container has the highest CPU percentage. The most common offenders are:

| Container | Common CPU Cause |
|-----------|-----------------|
| openwatch-worker | Concurrent compliance scans (Aegis SSH checks) |
| openwatch-backend | High API request volume, expensive queries |
| openwatch-db | Complex queries, missing indexes, VACUUM operations |
| openwatch-redis | Large key scans, persistence operations |

### Step 2: Drill into the high-CPU container

#### If openwatch-backend is high:

Check for high request volume:

```bash
docker logs openwatch-backend --since 5m 2>&1 | grep -c "HTTP"
```

Check the Prometheus metrics for request rate:

```bash
curl -s http://localhost:8000/metrics | grep "secureops_http_requests_total"
```

Look for endpoints receiving disproportionate traffic.

#### If openwatch-worker is high:

Check active Celery tasks:

```bash
docker exec openwatch-backend python3 -m celery -A app.celery_app inspect active
```

Check how many scans are running concurrently:

```bash
docker exec openwatch-backend python3 -m celery -A app.celery_app inspect active 2>/dev/null | grep -c "execute_scan\|aegis"
```

Check the scan queue depth:

```bash
docker exec openwatch-redis redis-cli -a "${REDIS_PASSWORD}" llen default
docker exec openwatch-redis redis-cli -a "${REDIS_PASSWORD}" llen scans
docker exec openwatch-redis redis-cli -a "${REDIS_PASSWORD}" llen results
docker exec openwatch-redis redis-cli -a "${REDIS_PASSWORD}" llen maintenance
docker exec openwatch-redis redis-cli -a "${REDIS_PASSWORD}" llen monitoring
docker exec openwatch-redis redis-cli -a "${REDIS_PASSWORD}" llen host_monitoring
docker exec openwatch-redis redis-cli -a "${REDIS_PASSWORD}" llen health_monitoring
docker exec openwatch-redis redis-cli -a "${REDIS_PASSWORD}" llen compliance_scanning
```

#### If openwatch-db is high:

Check for expensive active queries:

```bash
docker exec openwatch-db psql -U openwatch -d openwatch -c "
SELECT pid,
       now() - query_start AS duration,
       state,
       left(query, 120) AS query_preview
FROM pg_stat_activity
WHERE datname = 'openwatch'
  AND state = 'active'
  AND query NOT ILIKE '%pg_stat_activity%'
ORDER BY duration DESC
LIMIT 10;
"
```

Check if VACUUM or ANALYZE is running:

```bash
docker exec openwatch-db psql -U openwatch -d openwatch -c "
SELECT pid, query
FROM pg_stat_activity
WHERE query ILIKE '%vacuum%' OR query ILIKE '%analyze%';
"
```

### Step 3: Check host-level CPU

```bash
# Overall host CPU
top -bn1 | head -5

# Per-core utilization
mpstat -P ALL 1 3
```

If host CPU is saturated across all cores, the issue may be systemic rather than limited to a single container.

---

## Resolution

### Path A: Too many concurrent scans (worker)

The `OPENWATCH_MAX_CONCURRENT_SCANS` setting (default: 5) controls how many scans can run in parallel. Reduce it to lower CPU pressure:

```bash
# Check current value
docker exec openwatch-backend printenv | grep MAX_CONCURRENT
```

To apply a new value, update the environment in `docker-compose.yml` or `.env` and restart:

```bash
# Temporary: restart worker with reduced concurrency
docker stop openwatch-worker
docker run -d --name openwatch-worker \
  --network openwatch_openwatch-network \
  -e OPENWATCH_MAX_CONCURRENT_SCANS=2 \
  ... # (use same env as docker-compose.yml)
```

Or update `docker-compose.yml` and recreate:

```bash
# In docker-compose.yml, add to worker environment:
# OPENWATCH_MAX_CONCURRENT_SCANS: "2"

docker compose up -d openwatch-worker
```

### Path B: Long-running database queries

Identify and cancel expensive queries:

```bash
# Cancel a specific query (replace PID)
docker exec openwatch-db psql -U openwatch -d openwatch -c "
SELECT pg_cancel_backend(12345);
"
```

Check for missing indexes on frequently queried columns:

```bash
docker exec openwatch-db psql -U openwatch -d openwatch -c "
SELECT schemaname || '.' || relname AS table,
       seq_scan,
       idx_scan,
       CASE WHEN seq_scan + idx_scan > 0
            THEN round(seq_scan::numeric / (seq_scan + idx_scan) * 100, 1)
            ELSE 0
       END AS seq_scan_pct
FROM pg_stat_user_tables
WHERE seq_scan > 100
ORDER BY seq_scan DESC
LIMIT 10;
"
```

Tables with a high `seq_scan_pct` (above 50%) on large tables may benefit from additional indexes.

### Path C: Scale Celery workers

If scan demand is legitimately high and the host has available CPU capacity, scale the number of worker processes:

```bash
# Check current worker concurrency
docker exec openwatch-worker python3 -m celery -A app.celery_app inspect stats 2>/dev/null | grep "concurrency"
```

To increase concurrency, update the worker command in `docker-compose.yml`:

```yaml
command: ["python3", "-m", "celery", "-A", "app.celery_app", "worker", "--loglevel=info", "--concurrency=4", "-Q", "default,scans,results,maintenance,monitoring,host_monitoring,health_monitoring,compliance_scanning"]
```

Then recreate the worker:

```bash
docker compose up -d openwatch-worker
```

### Path D: Add container resource limits

If a container is consuming unbounded CPU, add resource limits in `docker-compose.yml`:

```yaml
services:
  backend:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M
```

Apply:

```bash
docker compose up -d
```

### Path E: VACUUM consuming CPU

If PostgreSQL is running autovacuum on a large table, this is generally expected behavior. You can check progress:

```bash
docker exec openwatch-db psql -U openwatch -d openwatch -c "
SELECT relname, phase, heap_blks_total, heap_blks_scanned, heap_blks_vacuumed
FROM pg_stat_progress_vacuum;
"
```

If vacuum is causing problems during peak hours, consider tuning autovacuum to run during off-hours by adjusting `autovacuum_vacuum_cost_delay`.

Do not kill autovacuum unless absolutely necessary -- it prevents table bloat.

---

## Recovery Verification

### 1. CPU usage returns to normal

```bash
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}"
```

All containers should be below 80% CPU under normal load.

### 2. API response times are acceptable

```bash
# Quick latency check
time curl -s -o /dev/null http://localhost:8000/health
```

Should complete in under 1 second.

### 3. Scan queue is not growing

```bash
docker exec openwatch-redis redis-cli -a "${REDIS_PASSWORD}" llen scans
```

The queue length should be stable or decreasing.

### 4. No long-running queries

```bash
docker exec openwatch-db psql -U openwatch -d openwatch -c "
SELECT count(*)
FROM pg_stat_activity
WHERE datname = 'openwatch'
  AND state = 'active'
  AND now() - query_start > interval '60 seconds';
"
```

Expected: `0`.

---

## Escalation

Escalate if any of the following conditions are met:

- CPU remains saturated after reducing concurrent scans and killing long-running queries.
- The host itself is CPU-saturated (not just containers).
- The issue is caused by a suspected denial-of-service or unusual traffic pattern.
- Worker processes are deadlocked (tasks show as active but make no progress).

**Information to include when escalating**:
- Output of `docker stats --no-stream`.
- Number of active Celery tasks and queue depths.
- List of long-running PostgreSQL queries.
- Host-level CPU utilization (`top` or `mpstat` output).
- Timeline of when the issue started.

---

## Prevention

- **Concurrency limits**: Set `OPENWATCH_MAX_CONCURRENT_SCANS` appropriately for the host's CPU capacity. A reasonable starting point is 1 scan per 2 CPU cores.
- **Query performance monitoring**: Use the Postgres Exporter to track query durations. Set alerts for queries exceeding 30 seconds.
- **Index maintenance**: Regularly review slow queries and add indexes as needed. Run `EXPLAIN ANALYZE` on frequently executed queries.
- **Resource limits**: Define CPU and memory limits for all containers in `docker-compose.yml` to prevent runaway processes from affecting other services.
- **Celery queue monitoring**: Monitor queue lengths via Redis Exporter. Set alerts when the `scans` queue exceeds 20 items (configurable via alert thresholds).
- **Horizontal scaling**: For sustained high load, consider running multiple worker containers or deploying workers on separate hosts.
- **Background metrics**: The `BackgroundMetricsUpdater` in the backend runs every 30 seconds. If it causes CPU spikes, review the queries it executes in `backend/app/middleware/metrics.py`.
