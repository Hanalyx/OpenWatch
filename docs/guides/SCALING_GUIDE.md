# Scaling Guide

This guide covers scaling OpenWatch for larger environments with more hosts, concurrent scans, and higher availability requirements.

## Scaling Dimensions

| Component | Scaling Method | Bottleneck Indicator |
|-----------|---------------|----------------------|
| Backend API | Horizontal (multiple containers) | High response latency, 5xx errors |
| Celery Workers | Horizontal (add workers) | Scan queue backlog, tasks stuck in "queued" |
| PostgreSQL | Vertical first, then read replicas | Slow queries, connection pool exhaustion |
| Redis | Vertical, then clustering | High memory usage, connection timeouts |
| Frontend/Nginx | Horizontal behind load balancer | Slow page loads |

## Celery Worker Scaling

Workers are the most common scaling target since compliance scans are CPU and I/O intensive.

### Adding Workers

Scale the worker service in docker-compose:

```bash
docker compose up -d --scale worker=4
```

Or define separate workers for different queue priorities:

```yaml
# docker-compose.override.yml
services:
  worker-scans:
    extends:
      service: worker
    container_name: openwatch-worker-scans
    command: >
      python3 -m celery -A app.celery_app worker
      --loglevel=info
      -Q scans,compliance_scanning
      --concurrency=4

  worker-maintenance:
    extends:
      service: worker
    container_name: openwatch-worker-maintenance
    command: >
      python3 -m celery -A app.celery_app worker
      --loglevel=info
      -Q default,maintenance,monitoring,health_monitoring
      --concurrency=2
```

### Queue Architecture

OpenWatch uses dedicated queues for workload isolation:

| Queue | Purpose | Priority |
|-------|---------|----------|
| `scans` | Active compliance scans | High |
| `compliance_scanning` | Scheduled compliance scans | High |
| `results` | Scan result processing | Medium |
| `host_monitoring` | Host status checks | Medium |
| `health_monitoring` | Health data collection | Low |
| `monitoring` | General monitoring tasks | Low |
| `maintenance` | Cleanup, expiration tasks | Low |
| `default` | Unclassified tasks | Normal |

### Worker Concurrency

Each worker defaults to one process per CPU core. Tune with `--concurrency`:

```bash
# For CPU-bound scan processing
--concurrency=2

# For I/O-bound SSH operations (more concurrent connections)
--concurrency=8
```

## Backend API Scaling

### Multiple API Instances

Run multiple backend containers behind a load balancer:

```yaml
# docker-compose.override.yml
services:
  backend:
    deploy:
      replicas: 3
    ports: []  # Remove direct port mapping

  nginx-lb:
    image: nginx:alpine
    ports:
      - "8000:8000"
    volumes:
      - ./config/nginx-lb.conf:/etc/nginx/conf.d/default.conf:ro
    depends_on:
      - backend
```

### Session Considerations

OpenWatch uses stateless JWT authentication, so API instances do not share session state. Any instance can handle any request as long as it can verify the JWT signature.

Ensure all instances share:
- The same `OPENWATCH_SECRET_KEY` for JWT verification
- The same `OPENWATCH_MASTER_KEY` for credential decryption
- Access to the same PostgreSQL and Redis instances

## PostgreSQL Scaling

### Vertical Scaling

Tune PostgreSQL for the workload:

```ini
# postgresql.conf recommendations for production
max_connections = 200
shared_buffers = 2GB           # 25% of available RAM
effective_cache_size = 6GB     # 75% of available RAM
work_mem = 16MB
maintenance_work_mem = 512MB
wal_buffers = 64MB
max_wal_size = 2GB
```

### Connection Pooling

For high connection counts, add PgBouncer:

```yaml
# docker-compose.override.yml
services:
  pgbouncer:
    image: edoburu/pgbouncer:latest
    environment:
      DATABASE_URL: postgresql://openwatch:${POSTGRES_PASSWORD}@database:5432/openwatch
      POOL_MODE: transaction
      MAX_CLIENT_CONN: 500
      DEFAULT_POOL_SIZE: 50
    ports:
      - "6432:6432"
    depends_on:
      - database
```

Then point `OPENWATCH_DATABASE_URL` to PgBouncer on port 6432.

### Read Replicas

For read-heavy workloads (dashboard queries, reporting), configure PostgreSQL streaming replication and route read queries to replicas.

## Redis Scaling

### Memory Sizing

Estimate Redis memory needs:

| Data | Approximate Size |
|------|-----------------|
| Celery task queue (100 tasks) | ~5MB |
| Task results cache | ~10MB |
| Rate limiting counters | ~1MB |
| Session data | ~2MB per 100 users |

For most deployments, a single Redis instance with 1-2GB is sufficient.

### Persistence

Redis is configured with default persistence. For production, ensure `redis_data` volume is on reliable storage and backed up regularly.

## Network Architecture

### Load Balancer Configuration

For multi-instance deployments, place a load balancer in front of both the API and frontend:

```
                    +--> openwatch-frontend-1
Client --> LB:443 --+--> openwatch-frontend-2
                    |
                    +--> openwatch-backend-1 (via /api)
                    +--> openwatch-backend-2 (via /api)
```

Use health check endpoints for load balancer probes:
- Frontend: `GET /` (returns 200)
- Backend: `GET /health` (returns JSON with status)

## Monitoring at Scale

As you scale, monitoring becomes more important:

- Deploy the monitoring stack: `./monitoring/start-monitoring.sh`
- Watch Celery queue depth in Prometheus/Grafana
- Monitor PostgreSQL connection count and query latency
- Set alerts for scan queue backlog exceeding 20 tasks (default threshold)
- Monitor Redis memory usage

See [Monitoring Setup](MONITORING_SETUP.md) for detailed configuration.

## Capacity Planning

Rough guidelines for host count vs. infrastructure:

| Managed Hosts | Workers | API Instances | PostgreSQL RAM | Redis RAM |
|---------------|---------|---------------|----------------|-----------|
| 1-50 | 1 | 1 | 4GB | 512MB |
| 50-200 | 2-4 | 2 | 8GB | 1GB |
| 200-1000 | 4-8 | 3-4 | 16GB | 2GB |
| 1000+ | 8+ | 4+ | 32GB+ | 4GB+ |

These are starting points. Actual requirements depend on scan frequency, rule count, and reporting patterns. The adaptive compliance scheduler (max 48-hour scan interval) determines scanning load.
