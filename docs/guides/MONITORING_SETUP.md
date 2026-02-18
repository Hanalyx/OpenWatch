# OpenWatch Monitoring Setup Guide

**Last Updated**: 2026-02-17

---

## Table of Contents

1. [Overview](#1-overview)
2. [Health Check Endpoints](#2-health-check-endpoints)
3. [Monitoring Stack Setup](#3-monitoring-stack-setup)
4. [Starting the Monitoring Stack](#4-starting-the-monitoring-stack)
5. [Prometheus Configuration](#5-prometheus-configuration)
6. [Grafana Dashboards](#6-grafana-dashboards)
7. [Alert Configuration](#7-alert-configuration)
8. [Log Monitoring](#8-log-monitoring)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Overview

OpenWatch uses a dedicated monitoring stack that runs in a **separate** Docker Compose deployment from the main application. The monitoring infrastructure provides four pillars of observability:

- **Prometheus** -- Metrics collection and storage with a 30-day retention window.
- **Grafana** -- Dashboard visualization with pre-provisioned dashboards.
- **Jaeger** -- Distributed tracing for request flow analysis.
- **Alertmanager** -- Alert routing and notification delivery.

In addition, the stack deploys several exporters that gather metrics from the underlying infrastructure:

- **Node Exporter** -- Host-level CPU, memory, disk, and network metrics.
- **Redis Exporter** -- Redis connection pool, command latency, and memory usage.
- **Postgres Exporter** -- PostgreSQL query performance, connection counts, and replication status.
- **cAdvisor** -- Container-level resource usage (CPU, memory, network per container).

### Architecture Diagram

```
                          Monitoring Network (172.22.0.0/16)
                    +-----------------------------------------+
                    |                                         |
                    |   +-----------+     +---------------+   |
                    |   | Prometheus|---->| Alertmanager  |   |
                    |   | :9090     |     | :9093         |   |
                    |   +-----+-----+     +---------------+   |
                    |         |                               |
                    |         v                               |
                    |   +-----------+     +---------------+   |
                    |   | Grafana   |     | Jaeger        |   |
                    |   | :3001     |     | :16686        |   |
                    |   +-----------+     +---------------+   |
                    |                                         |
                    |   +-----------+  +-----------+          |
                    |   | Node Exp. |  | cAdvisor  |          |
                    |   | :9100     |  | :8080     |          |
                    |   +-----------+  +-----------+          |
                    |                                         |
                    +------+-------------+--------------------+
                           |             |
               +-----------+---+   +-----+----------+
               | openwatch-    |   | aegis-         |
               | network       |   | network        |
               | (external)    |   | (external)     |
               +---+-----------+   +--------+-------+
                   |                         |
           +-------+--------+        +------+-------+
           | OpenWatch App  |        | Aegis Engine |
           | Backend :8000  |        |              |
           | Redis   :6379  |        +--------------+
           | Postgres :5432 |
           +----------------+
```

The monitoring network (172.22.0.0/16) connects to the OpenWatch application network (`openwatch_openwatch-network`) and the Aegis engine network (`aegis_aegis-network`) as external Docker networks. This allows Prometheus and Jaeger to scrape metrics and collect traces from the running application containers without being co-located in the same Compose file.

### Application Metrics Endpoint

The OpenWatch backend exposes a Prometheus-compatible metrics endpoint at `GET /metrics`. This endpoint is served by the `PrometheusMiddleware` registered in `backend/app/main.py` and returns metrics in the Prometheus text exposition format (content type `text/plain; version=0.0.4`).

Metrics are collected automatically by the middleware for every HTTP request and include:

| Metric Name | Type | Description |
|-------------|------|-------------|
| `secureops_http_requests_total` | Counter | Total HTTP requests by method, endpoint, status, service |
| `secureops_http_request_duration_seconds` | Histogram | Request latency by method, endpoint, service |
| `secureops_service_up` | Gauge | Service availability flag per service name |
| `secureops_scans_total` | Counter | Total scans by status, profile, framework |
| `secureops_scans_active` | Gauge | Currently running scans |
| `secureops_scan_duration_seconds` | Histogram | Scan duration by profile and framework |
| `secureops_scan_rules_processed_total` | Counter | Rules processed by status and severity |
| `secureops_compliance_score` | Gauge | Compliance score per host and framework |
| `secureops_compliance_rules_failed` | Gauge | Failed compliance rules per host |

The middleware also tracks security events (authentication failures, forbidden access, rate limit exceeded, server errors) and integration call metrics.

A `BackgroundMetricsUpdater` class in `backend/app/middleware/metrics.py` periodically (every 30 seconds) collects system-level metrics using `psutil` and queries the database for host status counts and active scan counts.

---

## 2. Health Check Endpoints

OpenWatch exposes multiple health check endpoints at different levels of detail and authentication requirements.

### Basic Health Check (Unauthenticated)

| Endpoint | Method | Authentication | Purpose |
|----------|--------|---------------|---------|
| `GET /health` | GET | None | Container orchestration health check |

This endpoint is defined directly in `backend/app/main.py` and is used by Docker health checks. It verifies:

- PostgreSQL connectivity (executes `SELECT 1`)
- Redis connectivity (executes `PING`)
- MongoDB is reported as `deprecated`

Response codes:
- `200 OK` -- All services healthy
- `503 Service Unavailable` -- One or more services degraded or unreachable

Example response:

```json
{
  "status": "healthy",
  "timestamp": 1739830000.123,
  "version": "1.2.0",
  "fips_mode": true,
  "database": "healthy",
  "redis": "healthy",
  "mongodb": "deprecated"
}
```

### Prometheus Metrics (Unauthenticated)

| Endpoint | Method | Authentication | Purpose |
|----------|--------|---------------|---------|
| `GET /metrics` | GET | None | Prometheus scrape target |

Returns all collected metrics in Prometheus text exposition format. Rate limiting is explicitly bypassed for this endpoint.

### Detailed Health Endpoints (Authenticated)

These endpoints are registered under the `/api/health-monitoring` prefix via the system router and require a valid JWT bearer token.

| Endpoint | Method | Authentication | Purpose |
|----------|--------|---------------|---------|
| `GET /api/health-monitoring/health/service` | GET | Required | Detailed service health metrics |
| `GET /api/health-monitoring/health/content` | GET | Required | Content and rule health metrics |
| `GET /api/health-monitoring/health/summary` | GET | Required | Combined health overview |
| `POST /api/health-monitoring/health/refresh` | POST | Required | Force refresh all health data |
| `GET /api/health-monitoring/health/history/service` | GET | Required | Service health history |
| `GET /api/health-monitoring/health/history/content` | GET | Required | Content health history |

**Service Health** (`/health/service`) returns:
- Core service statuses
- Database connection health
- Resource usage (CPU, memory, storage)
- Recent operation statistics
- Active alerts

Data is cached for 5 minutes. Requests within the cache window return the cached result; requests after 5 minutes trigger a fresh collection.

**Content Health** (`/health/content`) returns:
- Framework coverage statistics
- Benchmark implementation status
- Rule distribution and statistics
- Content integrity validation
- Performance metrics
- Content-related alerts

Data is cached for 1 hour.

**Health Summary** (`/health/summary`) returns:
- Overall system status
- Key metrics
- Active issue count
- Critical alerts

This endpoint always generates a fresh summary on each request.

**Force Refresh** (`POST /health/refresh`) triggers immediate collection of all health data (service, content, and summary) regardless of cache age.

**History Endpoints** accept an `hours` query parameter (default 24, minimum 1, maximum 168) and return historical data points for trending and analysis:

```
GET /api/health-monitoring/health/history/service?hours=48
GET /api/health-monitoring/health/history/content?hours=24
```

### Compliance Engine Health (Authenticated)

| Endpoint | Method | Authentication | Purpose |
|----------|--------|---------------|---------|
| `GET /api/scans/aegis/health` | GET | Required | Aegis compliance engine health |
| `GET /api/integrations/orsa/health` | GET | Required | ORSA plugin registry health |

**Aegis Health** returns the Aegis engine version, rules path, number of available YAML rules, and the list of supported frameworks. If the Aegis package is not installed, the status will be `unavailable`.

Example response:

```json
{
  "status": "healthy",
  "aegis_version": "0.1.0",
  "rules_path": "/app/backend/aegis/rules",
  "rules_available": 338,
  "frameworks_supported": [
    "cis-rhel9-v2.0.0",
    "stig-rhel9-v2r7",
    "nist-800-53"
  ]
}
```

**ORSA Health** checks the plugin registry and all registered plugins. Returns per-plugin health status, the total plugin count, and whether all plugins are healthy.

---

## 3. Monitoring Stack Setup

The monitoring stack is defined in `monitoring/docker-compose.monitoring.yml`. All images are pulled from public registries and pinned to specific versions.

### Services

| Service | Image | Port | Purpose | Runs As |
|---------|-------|------|---------|---------|
| Prometheus | `prom/prometheus:v2.56.0` | 9090 | Metrics collection and storage | UID 1000 |
| Alertmanager | `prom/alertmanager:v0.28.0` | 9093 | Alert routing and notifications | UID 1000 |
| Grafana | `grafana/grafana:11.4.0` | 3001 (maps to internal 3000) | Dashboard visualization | UID 472 |
| Jaeger | `jaegertracing/all-in-one:1.65.0` | 16686 (UI), 14268 (HTTP), 14250 (gRPC), 6831/udp, 6832/udp | Distributed tracing | UID 10001 |
| Node Exporter | `prom/node-exporter:v1.8.2` | 9100 | Host system metrics | UID 65534 |
| Redis Exporter | `oliver006/redis_exporter:v1.69.0` | 9121 | Redis metrics | UID 59000 |
| Postgres Exporter | `prometheuscommunity/postgres-exporter:v0.18.0` | 9187 | PostgreSQL metrics | UID 70000 |
| cAdvisor | `gcr.io/cadvisor/cadvisor:v0.51.0` | 8080 | Container metrics | Privileged |

### Security Configuration

All containers except cAdvisor run with the `no-new-privileges:true` security option, which prevents processes from gaining additional privileges via setuid/setgid binaries. cAdvisor requires `privileged: true` and has `no-new-privileges:false` because it needs direct access to `/proc`, `/sys`, and Docker internals to collect container metrics.

Node Exporter and Redis Exporter additionally run with `read_only: true` filesystem access.

### Storage

Three named Docker volumes provide persistent storage:

| Volume | Mount Point | Purpose |
|--------|-------------|---------|
| `prometheus_data` | `/prometheus` | Metrics time-series data |
| `grafana_data` | `/var/lib/grafana` | Grafana configuration, dashboards, users |
| `alertmanager_data` | `/alertmanager` | Alert state and silences |

Prometheus is configured with a 30-day retention period and a 50 GB storage cap via command-line flags:

```
--storage.tsdb.retention.time=30d
--storage.tsdb.retention.size=50GB
```

### Networking

The monitoring stack creates its own bridge network and connects to two external networks:

| Network | Type | Subnet | Purpose |
|---------|------|--------|---------|
| `monitoring-network` | Bridge | 172.22.0.0/16 | Internal monitoring communication |
| `openwatch_openwatch-network` | External | -- | Access to OpenWatch backend, Redis, PostgreSQL |
| `aegis_aegis-network` | External | -- | Access to Aegis engine containers |

Prometheus and Jaeger are attached to all three networks so they can scrape metrics from and collect traces from the application containers. The exporters (Redis, Postgres) are attached to `monitoring-network` and `openwatch-network` to reach the databases they monitor.

### Health Checks

Each monitoring service has a Docker health check configured:

| Service | Health Check | Interval | Timeout | Retries | Start Period |
|---------|-------------|----------|---------|---------|--------------|
| Prometheus | `wget http://localhost:9090/-/healthy` | 30s | 10s | 3 | 30s |
| Alertmanager | `wget http://localhost:9093/-/healthy` | 30s | 10s | 3 | -- |
| Grafana | `curl -f http://localhost:3000/api/health` | 30s | 10s | 3 | -- |
| Jaeger | `wget http://localhost:14269/` | 30s | 10s | 3 | -- |

### Environment Variables

The stack reads from a `.env` file in the `monitoring/` directory. Required variables:

| Variable | Purpose | Default |
|----------|---------|---------|
| `GRAFANA_ADMIN_PASSWORD` | Grafana admin login password | Auto-generated on first run |
| `POSTGRES_PASSWORD` | PostgreSQL password for the Postgres Exporter | Auto-generated on first run |
| `REDIS_PASSWORD` | Redis password for the Redis Exporter | Auto-generated on first run |
| `SMTP_PASSWORD` | SMTP password for email alerts (Alertmanager) | Empty |
| `SLACK_WEBHOOK_URL` | Slack webhook for alert notifications | Empty |

The `.env` file is automatically created by `start-monitoring.sh` on first run with randomly generated passwords.

---

## 4. Starting the Monitoring Stack

### Prerequisites

1. **Docker or Podman** must be installed with compose support (`docker-compose` or `podman-compose`).
2. **External networks must exist** before starting the monitoring stack. These are created by the main OpenWatch and Aegis Compose files:
   - `openwatch_openwatch-network`
   - `aegis_aegis-network`

   Start the main application first:
   ```bash
   ./start-openwatch.sh --runtime docker --build
   ```

3. **Configuration files** must be present (see [Section 5](#5-prometheus-configuration)):
   - `monitoring/config/prometheus.yml`
   - `monitoring/config/alertmanager.yml`

### Starting

The `start-monitoring.sh` script handles all setup:

```bash
cd monitoring/
./start-monitoring.sh start
```

The script performs these steps in order:

1. Detects the container runtime (Podman or Docker).
2. Creates the `.env` file with generated secrets if it does not exist.
3. Creates required data and configuration directories.
4. Validates configuration files (uses `promtool` if available).
5. Pulls the latest container images.
6. Starts all services with `docker-compose up -d`.
7. Waits 30 seconds for services to initialize.
8. Runs health checks against Prometheus (9090), Grafana (3001), Jaeger (16686), and Alertmanager (9093).
9. Prints service URLs and Grafana credentials.

### Other Commands

```bash
# Stop the monitoring stack
./start-monitoring.sh stop

# Restart (stop + 5s delay + start)
./start-monitoring.sh restart

# Show container status
./start-monitoring.sh status

# Follow logs for all services
./start-monitoring.sh logs

# Follow logs for a specific service
./start-monitoring.sh logs prometheus

# Back up Prometheus data, Grafana data, and configuration
./start-monitoring.sh backup

# Print service URLs and Grafana credentials
./start-monitoring.sh urls
```

### Service URLs

After starting, the following URLs are available:

| Service | URL |
|---------|-----|
| Grafana Dashboard | http://localhost:3001 |
| Prometheus | http://localhost:9090 |
| Jaeger Tracing UI | http://localhost:16686 |
| Alertmanager | http://localhost:9093 |

---

## 5. Prometheus Configuration

### Configuration File Location

Prometheus reads its main configuration from:

```
monitoring/config/prometheus.yml
```

This file is mounted read-only into the Prometheus container at `/etc/prometheus/prometheus.yml`.

### Alert Rules Location

Alert rule files are stored in:

```
monitoring/config/alerts/
```

This directory is mounted read-only at `/etc/prometheus/alerts/` inside the container. Prometheus loads all `*.yml` rule files from this directory.

### Scrape Targets

Configure scrape targets in `prometheus.yml`. A typical configuration for OpenWatch includes these jobs:

```yaml
scrape_configs:
  # OpenWatch backend application metrics
  - job_name: 'openwatch-backend'
    scrape_interval: 15s
    static_configs:
      - targets: ['openwatch-backend:8000']
    metrics_path: /metrics

  # Node Exporter - host metrics
  - job_name: 'node-exporter'
    scrape_interval: 15s
    static_configs:
      - targets: ['secureops-node-exporter:9100']

  # Redis Exporter
  - job_name: 'redis-exporter'
    scrape_interval: 15s
    static_configs:
      - targets: ['secureops-redis-exporter:9121']

  # Postgres Exporter
  - job_name: 'postgres-exporter'
    scrape_interval: 15s
    static_configs:
      - targets: ['secureops-postgres-exporter:9187']

  # cAdvisor - container metrics
  - job_name: 'cadvisor'
    scrape_interval: 15s
    static_configs:
      - targets: ['secureops-cadvisor:8080']
```

Note: Scrape targets use Docker service names because Prometheus is attached to the same Docker networks as the target services.

### Lifecycle API

The Prometheus container is started with `--web.enable-lifecycle`, which enables runtime configuration reloading:

```bash
# Reload Prometheus configuration without restart
curl -X POST http://localhost:9090/-/reload
```

The admin API is also enabled (`--web.enable-admin-api`) for operations such as snapshot creation and TSDB cleanup.

### Validating Configuration

If you have `promtool` installed locally, validate the configuration before applying:

```bash
promtool check config monitoring/config/prometheus.yml
```

The `start-monitoring.sh` script runs this validation automatically if `promtool` is available.

---

## 6. Grafana Dashboards

### Accessing Grafana

Grafana is available at **http://localhost:3001** (mapped from the internal port 3000).

Default credentials:
- **Username**: `admin`
- **Password**: Value of `GRAFANA_ADMIN_PASSWORD` from `monitoring/.env`

To retrieve the password:

```bash
grep GRAFANA_ADMIN_PASSWORD monitoring/.env
```

Sign-up is disabled (`GF_USERS_ALLOW_SIGN_UP=false`), and anonymous access is disabled (`GF_AUTH_ANONYMOUS_ENABLED=false`).

### Provisioned Dashboards

Grafana is configured to auto-provision dashboards from local JSON files. The provisioning configuration and dashboard files are mounted from:

```
monitoring/config/grafana/provisioning/   -> /etc/grafana/provisioning/
monitoring/config/grafana/dashboards/     -> /var/lib/grafana/dashboards/
```

The `start-monitoring.sh` script creates three dashboard subdirectories:

| Directory | Purpose |
|-----------|---------|
| `dashboards/secureops/` | OpenWatch application dashboards (scans, compliance, hosts) |
| `dashboards/infrastructure/` | Infrastructure dashboards (containers, databases, Redis) |
| `dashboards/business/` | Business metrics dashboards (compliance trends, SLA) |

Place Grafana dashboard JSON files in these directories. They will be automatically loaded when Grafana starts.

### Installed Plugins

The Grafana container installs two additional plugins on startup:

- `grafana-piechart-panel` -- Pie chart visualizations for compliance distribution
- `grafana-worldmap-panel` -- Geographic map visualization for distributed hosts

### Alerting

Grafana unified alerting is enabled:

- `GF_ALERTING_ENABLED=true`
- `GF_UNIFIED_ALERTING_ENABLED=true`
- `GF_FEATURE_TOGGLES_ENABLE=ngalert`

This allows creating Grafana-native alert rules directly within dashboards.

### Embedding

Grafana embedding is enabled (`GF_SECURITY_ALLOW_EMBEDDING=true`), which allows embedding Grafana panels in the OpenWatch frontend using iframes.

---

## 7. Alert Configuration

### Alertmanager

Alertmanager handles alert routing and notification delivery. Its configuration file is located at:

```
monitoring/config/alertmanager.yml
```

This file is mounted read-only into the container at `/etc/alertmanager/alertmanager.yml`.

### Notification Channels

Configure notification channels in `alertmanager.yml`. The `.env` file provides placeholder variables for two common channels:

- **Email** -- Set `SMTP_PASSWORD` in `monitoring/.env` and configure SMTP settings in `alertmanager.yml`.
- **Slack** -- Set `SLACK_WEBHOOK_URL` in `monitoring/.env` and configure the Slack receiver in `alertmanager.yml`.

Example `alertmanager.yml` structure:

```yaml
global:
  resolve_timeout: 5m

route:
  group_by: ['alertname', 'severity']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'default'

  routes:
    - match:
        severity: critical
      receiver: 'critical-alerts'

receivers:
  - name: 'default'
    # Configure default notification channel

  - name: 'critical-alerts'
    # Configure high-priority notification channel
```

### Prometheus Alert Rules

Alert rules are defined in YAML files under `monitoring/config/alerts/`. These rules are evaluated by Prometheus and firing alerts are forwarded to Alertmanager.

Example alert rule:

```yaml
groups:
  - name: openwatch-alerts
    rules:
      - alert: HighErrorRate
        expr: rate(secureops_http_requests_total{status=~"5.."}[5m]) > 0.1
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High HTTP error rate detected"
          description: "Error rate exceeds 10% over the last 5 minutes."

      - alert: ServiceDown
        expr: secureops_service_up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "OpenWatch service is down"
```

### Alertmanager Web UI

The Alertmanager web interface is available at **http://localhost:9093**. Use it to:

- View active and silenced alerts
- Create silences to temporarily suppress alerts
- Inspect alert grouping and routing

---

## 8. Log Monitoring

### Structured Logging

OpenWatch uses Python's built-in `logging` module with structured log output. Key loggers:

| Logger | Purpose |
|--------|---------|
| `openwatch.audit` | Security audit events (authentication, authorization, data access) |
| `app.*` | Application-level logs (services, routes, tasks) |
| `celery.*` | Background task execution logs |

### Audit Log

The audit logger (`openwatch.audit`) records security-critical events including:

- Authentication attempts (success and failure)
- Authorization failures and forbidden access
- Privilege escalation events
- Sensitive data access
- Configuration changes

Audit events are also persisted to the `audit_logs` PostgreSQL table for durable storage and querying.

### Viewing Logs

Application and worker logs are accessible through Docker:

```bash
# Backend application logs
docker logs openwatch-backend --tail 100 --follow

# Celery worker logs (scan execution, background tasks)
docker logs openwatch-worker --tail 100 --follow

# Monitoring service logs
cd monitoring/
./start-monitoring.sh logs

# Specific monitoring service logs
./start-monitoring.sh logs prometheus
./start-monitoring.sh logs grafana
```

### Log-Based Alerting

While the current monitoring stack does not include a dedicated log aggregation system (such as Loki or the ELK stack), you can monitor for issues by:

1. Checking container logs for error patterns.
2. Using Prometheus metrics that track error rates (`secureops_http_requests_total` with status 5xx).
3. Reviewing the `audit_logs` table in PostgreSQL for security events.
4. Monitoring the security event counter (`secureops_security_events_total`) exposed via the `/metrics` endpoint.

---

## 9. Troubleshooting

### External Network Not Found

**Symptom**: Docker Compose fails with an error about missing external networks.

```
ERROR: Network openwatch_openwatch-network declared as external, but could not be found.
```

**Cause**: The main OpenWatch application (or Aegis) has not been started, so the external Docker networks do not exist yet.

**Solution**: Start the main application first, then start the monitoring stack.

```bash
# Start the main application (creates the networks)
./start-openwatch.sh --runtime docker --build

# Verify the networks exist
docker network ls | grep -E "openwatch-network|aegis-network"

# Then start monitoring
cd monitoring/
./start-monitoring.sh start
```

If you need to create the networks manually for testing:

```bash
docker network create openwatch_openwatch-network
docker network create aegis_aegis-network
```

### Exporter Connection Failures

**Symptom**: Redis Exporter or Postgres Exporter shows connection errors in logs.

**Cause**: The exporter cannot reach the database service, or the password is incorrect.

**Solution**:

1. Verify the database containers are running:

   ```bash
   docker ps | grep -E "openwatch-redis|openwatch-db"
   ```

2. Check that the passwords in `monitoring/.env` match the passwords used by the main application:

   ```bash
   # Compare Redis password
   grep REDIS_PASSWORD monitoring/.env
   grep REDIS_PASSWORD .env  # or the main app env file

   # Compare Postgres password
   grep POSTGRES_PASSWORD monitoring/.env
   grep POSTGRES_PASSWORD .env
   ```

3. Test connectivity from the monitoring network:

   ```bash
   # Test Redis connectivity
   docker exec secureops-redis-exporter wget -q -O- http://localhost:9121/metrics | head -5

   # Test Postgres connectivity
   docker exec secureops-postgres-exporter wget -q -O- http://localhost:9187/metrics | head -5
   ```

### Prometheus Not Scraping Targets

**Symptom**: Prometheus targets page (`http://localhost:9090/targets`) shows targets as DOWN.

**Cause**: Network connectivity issue or incorrect target address.

**Solution**:

1. Check the Prometheus targets page at http://localhost:9090/targets for specific error messages.

2. Verify that Prometheus can reach the target container:

   ```bash
   docker exec secureops-prometheus wget -q -O- http://openwatch-backend:8000/metrics | head -5
   ```

3. Verify the container name matches the target in `prometheus.yml`. Docker Compose service names and container names may differ.

4. Ensure Prometheus is attached to the correct networks:

   ```bash
   docker inspect secureops-prometheus --format='{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}'
   ```

### Grafana Cannot Connect to Prometheus

**Symptom**: Grafana dashboards show "No data" or the Prometheus data source test fails.

**Cause**: Grafana is using an incorrect Prometheus URL.

**Solution**: In Grafana data source configuration, the Prometheus URL should use the Docker service name, not `localhost`:

```
http://secureops-prometheus:9090
```

Both containers must be on the `monitoring-network` for this to work.

### cAdvisor Permission Errors

**Symptom**: cAdvisor container fails to start or shows permission denied errors.

**Cause**: cAdvisor requires privileged access to read container metrics from `/proc`, `/sys`, and `/var/lib/docker`.

**Solution**: Verify that the container is running in privileged mode. This is configured in `docker-compose.monitoring.yml`:

```yaml
cadvisor:
  privileged: true
  devices:
    - /dev/kmsg
```

On SELinux-enabled systems, you may also need to set appropriate context labels on the mounted volumes.

### Prometheus Storage Full

**Symptom**: Prometheus stops ingesting metrics or shows storage errors.

**Cause**: The 50 GB storage limit has been reached.

**Solution**:

1. Check current storage usage:

   ```bash
   docker exec secureops-prometheus du -sh /prometheus
   ```

2. If near the limit, Prometheus will automatically prune the oldest data to stay within bounds (the `--storage.tsdb.retention.size=50GB` flag). However, you can also manually trigger compaction:

   ```bash
   curl -X POST http://localhost:9090/api/v1/admin/tsdb/clean_tombstones
   ```

3. To increase storage, modify the `--storage.tsdb.retention.size` flag in `docker-compose.monitoring.yml` and restart:

   ```bash
   cd monitoring/
   ./start-monitoring.sh restart
   ```

### Monitoring Data Backup

To back up monitoring data (Prometheus TSDB, Grafana databases, and configuration):

```bash
cd monitoring/
./start-monitoring.sh backup
```

This creates a timestamped backup directory at `monitoring/backups/YYYYMMDD_HHMMSS/` containing compressed archives of Prometheus data, Grafana data, and configuration files.
