# Runbook: Service Unavailable

**Severity**: P1 - High
**Last Updated**: 2026-02-17
**Owner**: Platform Engineering
**Estimated Resolution Time**: 5-30 minutes (typical)

---

## Symptoms

- Docker health check reports container as `unhealthy` or `exited`.
- Users report HTTP 502/503 errors or connection timeouts.
- Monitoring alerts fire (`ServiceDown` or `secureops_service_up == 0`).
- Prometheus target page (http://localhost:9090/targets) shows `openwatch-backend` as DOWN.
- The `/health` endpoint returns `503 Service Unavailable` or does not respond.

---

## Diagnosis

### Step 1: Check container status

```bash
docker ps -a --filter "name=openwatch-"
```

Look for containers with status `Exited`, `Restarting`, or health status `unhealthy`. All six containers should be running:

| Container | Expected Status |
|-----------|----------------|
| openwatch-backend | Up (healthy) |
| openwatch-worker | Up (healthy) |
| openwatch-celery-beat | Up |
| openwatch-frontend | Up (healthy) |
| openwatch-db | Up (healthy) |
| openwatch-redis | Up (healthy) |

### Step 2: Check health endpoint

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/health
```

Expected: `200`. If the endpoint responds with `503`, the response body indicates which dependency is degraded:

```bash
curl -s http://localhost:8000/health | python3 -m json.tool
```

Example degraded response:

```json
{
  "status": "degraded",
  "database": "unhealthy",
  "redis": "healthy"
}
```

### Step 3: Check container logs

```bash
# Backend application logs
docker logs openwatch-backend --tail 200

# Celery worker logs
docker logs openwatch-worker --tail 200

# Frontend logs
docker logs openwatch-frontend --tail 100
```

Look for:
- `ConnectionRefusedError` -- dependency service is down.
- `OperationalError` -- database connection problem.
- `OSError: [Errno 28] No space left on device` -- disk full.
- `MemoryError` or `Killed` -- OOM kill.

### Step 4: Check resource usage

```bash
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}"
```

Note any container using more than 90% of its memory limit.

### Step 5: Check for OOM kills

```bash
dmesg | grep -i "oom\|killed process" | tail -20
```

Also check Docker's internal OOM tracking:

```bash
docker inspect openwatch-backend --format='{{.State.OOMKilled}}'
docker inspect openwatch-worker --format='{{.State.OOMKilled}}'
```

---

## Resolution

### Path A: Container crashed or exited

If a container has exited:

```bash
# Check exit code
docker inspect openwatch-backend --format='{{.State.ExitCode}}'
```

| Exit Code | Meaning | Action |
|-----------|---------|--------|
| 0 | Clean shutdown | Restart the container |
| 1 | Application error | Check logs, fix, restart |
| 137 | SIGKILL (OOM) | Increase memory limit, then restart |
| 139 | SIGSEGV | Check logs for crash details, rebuild |

Restart the failed container:

```bash
docker restart openwatch-backend
```

If OOM killed, check memory and consider increasing limits before restarting:

```bash
# View current memory limit
docker inspect openwatch-backend --format='{{.HostConfig.Memory}}'
```

### Path B: Database connection failure

If the health endpoint reports `database: unhealthy`:

```bash
# Check PostgreSQL container
docker ps -a --filter "name=openwatch-db"

# Test PostgreSQL connectivity
docker exec openwatch-db pg_isready -U openwatch -d openwatch

# Check PostgreSQL logs
docker logs openwatch-db --tail 100
```

If PostgreSQL is down, restart it:

```bash
docker restart openwatch-db
```

Wait 10 seconds for it to become healthy, then restart the backend:

```bash
sleep 10
docker restart openwatch-backend
docker restart openwatch-worker
```

### Path C: Redis connection failure

If the health endpoint reports `redis: unhealthy`:

```bash
# Check Redis container
docker ps -a --filter "name=openwatch-redis"

# Test Redis connectivity (password required)
docker exec openwatch-redis redis-cli -a "${REDIS_PASSWORD}" ping
```

Expected response: `PONG`. If Redis is unresponsive:

```bash
docker restart openwatch-redis
sleep 5
docker restart openwatch-backend
docker restart openwatch-worker
docker restart openwatch-celery-beat
```

### Path D: Disk full

If logs show `No space left on device`:

```bash
df -h
docker system df
```

See the [DISK_FULL.md](DISK_FULL.md) runbook for detailed cleanup steps.

### Path E: Dependency service (upstream) down

If the backend cannot reach an external service it depends on (such as a target host for scanning), check network connectivity:

```bash
# Check Docker network
docker network inspect openwatch-network

# Verify all expected containers are on the network
docker network inspect openwatch-network --format='{{range .Containers}}{{.Name}} {{end}}'
```

If a container dropped off the network, reconnect it:

```bash
docker network connect openwatch_openwatch-network openwatch-backend
```

---

## Recovery Verification

After applying a fix, verify recovery with these steps:

### 1. Health endpoint returns 200

```bash
curl -s http://localhost:8000/health | python3 -m json.tool
```

Confirm `"status": "healthy"`, `"database": "healthy"`, and `"redis": "healthy"`.

### 2. All containers are healthy

```bash
docker ps --filter "name=openwatch-" --format "table {{.Names}}\t{{.Status}}"
```

All containers should show `Up` with `(healthy)` where applicable.

### 3. No error logs in the last 5 minutes

```bash
docker logs openwatch-backend --since 5m 2>&1 | grep -i "error\|exception\|traceback"
```

This should return no results or only non-critical warnings.

### 4. Frontend is accessible

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/
```

Expected: `200`.

### 5. Celery worker is processing tasks

```bash
docker exec openwatch-backend python3 -m celery -A app.celery_app inspect ping
```

Expected: a response from the worker showing `{"ok": "pong"}`.

---

## Escalation

Escalate if any of the following conditions are met:

- The service remains unavailable after 15 minutes of troubleshooting.
- The root cause is unclear after checking logs and container status.
- Data corruption is suspected (e.g., PostgreSQL reports WAL corruption).
- Multiple containers are crash-looping simultaneously.
- The issue recurs within 1 hour of initial recovery.

**Escalation contacts**: Platform Engineering lead, then Infrastructure team.

**Information to include when escalating**:
- Which containers are affected and their exit codes.
- Output of `docker ps -a --filter "name=openwatch-"`.
- Last 200 lines of logs from affected containers.
- Output of `docker stats --no-stream`.
- Output of `dmesg | grep -i oom | tail -20`.
- Time the issue was first observed.

---

## Prevention

- **Monitoring**: Ensure Prometheus is scraping the `/health` endpoint and `ServiceDown` alert rules are configured in `monitoring/config/alerts/`.
- **Resource limits**: Set memory limits on all containers in `docker-compose.yml` to prevent a single container from consuming all host memory.
- **Log rotation**: Configure the Docker json-file logging driver with `max-size` and `max-file` to prevent log files from filling the disk.
- **Health check tuning**: Review health check intervals and retries in `docker-compose.yml`. The backend health check (`curl -f http://localhost:8000/health`) runs every 30 seconds with 3 retries.
- **Restart policies**: All containers use `restart: unless-stopped`. Verify this is configured correctly.
- **Dependency ordering**: The backend depends on `database` and `redis` with `condition: service_healthy`. Verify these dependency conditions remain in place.
