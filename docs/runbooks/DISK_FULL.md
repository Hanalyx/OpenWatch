# Runbook: Disk Space Issues

**Severity**: P1 - High
**Last Updated**: 2026-02-17
**Owner**: Platform Engineering
**Estimated Resolution Time**: 10-30 minutes

---

## Symptoms

- Container logs show `OSError: [Errno 28] No space left on device`.
- PostgreSQL stops accepting writes or crashes.
- Redis persistence fails (RDB/AOF write errors).
- Docker cannot create new containers or volumes.
- Application write operations fail (scan results, audit logs, exports).
- Celery tasks fail with I/O errors.

---

## Diagnosis

### Step 1: Check host disk usage

```bash
df -h
```

Identify which filesystem is full. Key mount points to check:
- `/var/lib/docker` -- Docker data root (images, containers, volumes).
- `/` -- Root filesystem (if Docker data is not on a separate partition).

### Step 2: Check Docker disk usage

```bash
docker system df
```

This shows a breakdown of disk usage by:
- **Images** -- Container images (base images, build layers).
- **Containers** -- Container writable layers and logs.
- **Volumes** -- Named volumes (persistent data).
- **Build Cache** -- Cached build layers.

For more detail:

```bash
docker system df -v
```

### Step 3: Check individual volume sizes

OpenWatch uses five named Docker volumes:

```bash
# List volumes with sizes
for vol in postgres_data redis_data app_data app_logs ssh_known_hosts; do
  size=$(docker run --rm -v "openwatch_${vol}:/data" alpine du -sh /data 2>/dev/null | cut -f1)
  echo "${vol}: ${size}"
done
```

| Volume | Contents | Expected Size |
|--------|----------|---------------|
| postgres_data | PostgreSQL data files | Varies (100MB - 10GB+) |
| redis_data | Redis RDB/AOF persistence | Small (< 100MB typically) |
| app_data | SCAP content, scan results | Varies (100MB - 5GB+) |
| app_logs | Application and audit logs | Varies (grows over time) |
| ssh_known_hosts | SSH known hosts database | Small (< 1MB) |

### Step 4: Check PostgreSQL data size

```bash
docker exec openwatch-db psql -U openwatch -d openwatch -c "
SELECT pg_size_pretty(pg_database_size('openwatch')) AS database_size;
"

# Table-level breakdown
docker exec openwatch-db psql -U openwatch -d openwatch -c "
SELECT schemaname || '.' || tablename AS table_name,
       pg_size_pretty(pg_total_relation_size(schemaname || '.' || tablename)) AS total_size,
       pg_size_pretty(pg_relation_size(schemaname || '.' || tablename)) AS data_size,
       pg_size_pretty(pg_indexes_size(quote_ident(schemaname) || '.' || quote_ident(tablename))) AS index_size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname || '.' || tablename) DESC
LIMIT 15;
"
```

### Step 5: Check container log sizes

```bash
# Find log file locations for each container
for container in openwatch-backend openwatch-worker openwatch-celery-beat openwatch-frontend openwatch-db openwatch-redis; do
  log_file=$(docker inspect "$container" --format='{{.LogPath}}')
  log_size=$(du -sh "$log_file" 2>/dev/null | cut -f1)
  echo "${container}: ${log_size} (${log_file})"
done
```

### Step 6: Check Docker build cache

```bash
docker builder prune --dry-run
```

---

## Resolution

### Path A: Clean Docker system (dangling resources)

Remove unused Docker resources that are safe to clean:

```bash
# Remove dangling images (untagged, unused)
docker image prune -f

# Remove stopped containers
docker container prune -f

# Remove unused networks
docker network prune -f

# Remove build cache
docker builder prune -f
```

For a more aggressive cleanup (removes ALL unused images, not just dangling):

```bash
docker system prune -f
```

**Warning**: `docker system prune` will remove all stopped containers and unused images. Do not run `docker system prune -a` unless you are prepared to re-pull all images.

### Path B: Clean application logs

If the `app_logs` volume is large:

```bash
# Check what is in the logs volume
docker run --rm -v openwatch_app_logs:/logs alpine ls -lah /logs/

# Check audit log size
docker run --rm -v openwatch_app_logs:/logs alpine du -sh /logs/audit.log
```

Truncate large log files (preserves the file but clears contents):

```bash
# Truncate the audit log (data is also in the audit_logs PostgreSQL table)
docker exec openwatch-backend truncate -s 0 /openwatch/logs/audit.log
```

For container logs managed by Docker's logging driver:

```bash
# Truncate a specific container's log file
truncate -s 0 $(docker inspect openwatch-backend --format='{{.LogPath}}')
truncate -s 0 $(docker inspect openwatch-worker --format='{{.LogPath}}')
```

### Path C: Clean old scan results

If the `app_data` volume is large due to accumulated scan results:

```bash
# Check scan results directory
docker run --rm -v openwatch_app_data:/data alpine du -sh /data/results/
docker run --rm -v openwatch_app_data:/data alpine ls -lt /data/results/ | head -20
```

Remove old scan result files (keep last 30 days):

```bash
docker run --rm -v openwatch_app_data:/data alpine find /data/results/ -type f -mtime +30 -delete
```

### Path D: Clean audit exports

Completed audit exports are stored on disk and have expiration dates. Clean expired exports:

```bash
# Check exports directory
docker run --rm -v openwatch_app_data:/data alpine du -sh /data/exports/ 2>/dev/null

# Remove export files older than 7 days
docker run --rm -v openwatch_app_data:/data alpine find /data/exports/ -type f -mtime +7 -delete
```

### Path E: PostgreSQL VACUUM

Reclaim space from deleted rows in PostgreSQL:

```bash
# Standard VACUUM (reclaims space for reuse within the database)
docker exec openwatch-db psql -U openwatch -d openwatch -c "VACUUM VERBOSE;"

# VACUUM FULL on the largest tables (returns space to OS, requires exclusive lock)
# Only run during maintenance windows
docker exec openwatch-db psql -U openwatch -d openwatch -c "VACUUM FULL scan_findings;"
docker exec openwatch-db psql -U openwatch -d openwatch -c "VACUUM FULL audit_logs;"
docker exec openwatch-db psql -U openwatch -d openwatch -c "VACUUM FULL posture_snapshots;"
```

Clean up old data if retention policies allow:

```bash
# Delete scan findings older than 90 days (adjust retention as needed)
docker exec openwatch-db psql -U openwatch -d openwatch -c "
DELETE FROM scan_findings
WHERE created_at < now() - interval '90 days';
VACUUM scan_findings;
"

# Delete old posture snapshots beyond retention period
docker exec openwatch-db psql -U openwatch -d openwatch -c "
DELETE FROM posture_snapshots
WHERE snapshot_date < now() - interval '90 days';
VACUUM posture_snapshots;
"
```

### Path F: Redis memory management

Check Redis memory usage:

```bash
docker exec openwatch-redis redis-cli -a "${REDIS_PASSWORD}" INFO memory | grep -E "used_memory_human|maxmemory"
```

If Redis memory is high, flush non-essential caches:

```bash
# Check key count by pattern
docker exec openwatch-redis redis-cli -a "${REDIS_PASSWORD}" DBSIZE

# Flush all cached data (Celery results, application caches)
# WARNING: This will clear all Celery task results and cached data
docker exec openwatch-redis redis-cli -a "${REDIS_PASSWORD}" FLUSHDB
```

### Path G: Remove old Docker images

```bash
# List images sorted by size
docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" | sort -k3 -h

# Remove images older than 7 days
docker image prune -a --filter "until=168h" -f
```

---

## Recovery Verification

### 1. Disk has adequate free space

```bash
df -h | grep -E "/$|docker"
```

Target: at least 20% free space on all relevant filesystems.

### 2. Docker can operate normally

```bash
docker system df
```

### 3. PostgreSQL can write

```bash
docker exec openwatch-db psql -U openwatch -d openwatch -c "
CREATE TEMP TABLE disk_test (val TEXT);
INSERT INTO disk_test VALUES ('write_test');
DROP TABLE disk_test;
SELECT 'write_ok' AS status;
"
```

### 4. Application can write logs

```bash
docker exec openwatch-backend python3 -c "
import logging
logger = logging.getLogger('openwatch.test')
logger.info('Disk recovery write test')
print('Write test passed')
"
```

### 5. Health endpoint is healthy

```bash
curl -s http://localhost:8000/health | python3 -m json.tool
```

---

## Escalation

Escalate if any of the following conditions are met:

- Disk is full and no safe cleanup options are available.
- PostgreSQL data corruption occurred due to disk-full conditions.
- The volume is on a filesystem that cannot be expanded.
- Data loss occurred (files were truncated or deleted unintentionally).

**Information to include when escalating**:
- Output of `df -h`.
- Output of `docker system df -v`.
- Volume sizes for all OpenWatch volumes.
- PostgreSQL database size and largest tables.
- Container log file sizes.

---

## Prevention

### Log rotation

Configure the Docker logging driver with size limits. Add to each service in `docker-compose.yml`:

```yaml
services:
  backend:
    logging:
      driver: json-file
      options:
        max-size: "50m"
        max-file: "5"
```

This limits each container's log to 50 MB with 5 rotated files (250 MB total per container).

### Monitoring alerts

Set up disk space alerts in Prometheus. Example alert rule for `monitoring/config/alerts/`:

```yaml
groups:
  - name: disk-alerts
    rules:
      - alert: DiskSpaceLow
        expr: (node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}) < 0.15
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Disk space below 15% on root filesystem"

      - alert: DiskSpaceCritical
        expr: (node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}) < 0.05
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Disk space below 5% on root filesystem"
```

### Data retention policies

Implement automated cleanup:

- **Scan findings**: Retain 90 days (configurable). Older findings are summarized in posture snapshots.
- **Audit logs**: Retain per compliance requirements (typically 1 year minimum for FedRAMP).
- **Posture snapshots**: Retain 90 days for free tier, configurable for OpenWatch+.
- **Audit exports**: Expire after 7 days (handled by `cleanup_expired_audit_exports` Celery task).
- **Scan result files**: Delete files older than 30 days from `app_data/results/`.

### Volume sizing

Plan volume sizes based on expected data growth:

| Volume | Recommended Minimum | Growth Factor |
|--------|---------------------|---------------|
| postgres_data | 10 GB | ~1 GB per 100 hosts per month |
| app_logs | 5 GB | Depends on log level and scan frequency |
| app_data | 10 GB | ~500 MB per 100 scans |
| redis_data | 1 GB | Relatively stable |
