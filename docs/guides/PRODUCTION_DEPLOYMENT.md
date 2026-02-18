# Production Deployment Guide

This guide covers deploying OpenWatch in a production environment using Docker or Podman.

## Prerequisites

- Docker 24+ or Podman 4+ with compose support
- 4 CPU cores, 8GB RAM minimum (16GB recommended)
- 50GB disk space for application data, logs, and database
- TLS certificates (self-signed for internal, CA-signed for public)
- DNS or hostname configured for the deployment target

## Architecture Overview

OpenWatch runs as 5 core containers plus optional monitoring:

| Service | Container | Port | Purpose |
|---------|-----------|------|---------|
| PostgreSQL 15 | openwatch-db | 5432 (localhost only) | Primary database |
| Redis 7.4 | openwatch-redis | 6379 (internal) | Task queue broker and cache |
| FastAPI Backend | openwatch-backend | 8000 | REST API server |
| Celery Worker | openwatch-worker | - | Background task execution |
| Celery Beat | openwatch-celery-beat | - | Scheduled task scheduling |
| Nginx Frontend | openwatch-frontend | 3000 | Static assets and reverse proxy |

All containers communicate over a private bridge network (`openwatch-network`, subnet `172.20.0.0/16`).

## Step 1: Clone and Configure

```bash
git clone <repository-url> openwatch
cd openwatch
```

Copy the environment template:

```bash
cp .env.example .env
```

## Step 2: Configure Environment Variables

Edit `.env` with production values. At minimum, set these required variables:

```bash
# Database
POSTGRES_PASSWORD=<strong-random-password>

# Redis
REDIS_PASSWORD=<strong-random-password>

# Application secrets (minimum 32 characters each)
OPENWATCH_SECRET_KEY=<random-string-32+-chars>
MASTER_KEY=<random-string-32+-chars>
OPENWATCH_ENCRYPTION_KEY=<random-string-32+-chars>

# Production settings
OPENWATCH_DEBUG=false
OPENWATCH_FIPS_MODE=true
OPENWATCH_REQUIRE_HTTPS=true
```

Generate strong random values:

```bash
openssl rand -base64 48  # Use for each secret
```

See [Environment Reference](ENVIRONMENT_REFERENCE.md) for the complete variable list.

## Step 3: TLS Certificate Setup

OpenWatch expects TLS certificates at specific paths:

```bash
mkdir -p security/certs security/keys

# For self-signed certificates (development/internal):
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout security/keys/frontend.key \
  -out security/certs/frontend.crt \
  -subj "/CN=openwatch.local"

# Set appropriate permissions
chmod 600 security/keys/frontend.key
chmod 644 security/certs/frontend.crt
```

For production, use CA-signed certificates and place them at the same paths. The frontend Nginx container mounts these as read-only volumes.

## Step 4: Deploy Services

Using the startup script:

```bash
./start-openwatch.sh --runtime docker --build
```

Or manually with docker compose:

```bash
docker compose up -d --build
```

The startup script supports these options:

| Flag | Description |
|------|-------------|
| `--runtime docker` | Use Docker (default: auto-detect) |
| `--runtime podman` | Use Podman |
| `--build` | Build images before starting |
| `--dev` | Use development compose file |

## Step 5: Verify Deployment

Check container health:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
```

All containers should show `healthy` status. Verify individual services:

```bash
# Database
docker exec openwatch-db pg_isready -U openwatch -d openwatch

# Redis
docker exec openwatch-redis redis-cli -a "$REDIS_PASSWORD" ping

# Backend API
curl -f http://localhost:8000/health

# Frontend
curl -f http://localhost:3000/
```

The `/health` endpoint returns:

```json
{
  "status": "healthy",
  "timestamp": 1708000000.0,
  "version": "1.2.0",
  "fips_mode": true
}
```

## Step 6: Run Database Migrations

Migrations run automatically on first startup. To verify:

```bash
docker exec openwatch-backend alembic current
```

This should show the latest migration revision. See [Database Migrations](DATABASE_MIGRATIONS.md) for migration management.

## Step 7: Create Initial Admin User

Access the API documentation at `http://localhost:8000/api/docs` to create the first admin user, or use the CLI:

```bash
docker exec openwatch-backend python -m app.cli.create_admin \
  --username admin \
  --email admin@example.com
```

## Nginx Reverse Proxy

The frontend container runs Nginx with security-hardened configuration:

- TLS 1.2 and 1.3 only (no older protocols)
- FIPS-compatible cipher suites (ECDHE-RSA-AES256-GCM-SHA384, etc.)
- Security headers: HSTS, X-Frame-Options, CSP, X-Content-Type-Options
- Gzip compression for static assets
- Hidden server version (`server_tokens off`)

To customize, modify `docker/frontend/nginx.conf` and rebuild the frontend container.

### Exposing on Standard Ports

The default compose file maps port 3000. To expose on port 443:

```yaml
# In docker-compose.override.yml
services:
  frontend:
    ports:
      - "443:443"
      - "80:80"
```

## Volume Management

OpenWatch uses 5 named volumes:

| Volume | Mount Point | Purpose |
|--------|-------------|---------|
| `postgres_data` | `/var/lib/postgresql/data` | Database files |
| `redis_data` | `/data` | Redis persistence |
| `app_data` | `/openwatch/data` | SCAP content, scan results |
| `app_logs` | `/openwatch/logs` | Application and audit logs |
| `ssh_known_hosts` | `/openwatch/security/known_hosts` | SSH host key database |

Back up `postgres_data` and `app_data` regularly.

## Health Checks

Docker health checks are configured for automated restart:

| Service | Check | Interval | Retries |
|---------|-------|----------|---------|
| PostgreSQL | `pg_isready` | 5s | 10 |
| Redis | `redis-cli incr ping` | 10s | 5 |
| Backend | `curl /health` | 30s | 3 |
| Worker | `celery inspect ping` | 30s | 3 |
| Frontend | `curl /` | 30s | 3 |

## Celery Workers

The worker container processes these queues:

```
default, scans, results, maintenance, monitoring,
host_monitoring, health_monitoring, compliance_scanning
```

Celery Beat runs scheduled tasks (daily posture snapshots, exception expiration, export cleanup). Both services share the same backend image and connect to the same Redis broker.

## Stopping Services

```bash
# Graceful stop (preserves all data)
./stop-openwatch.sh

# Full cleanup (deletes all data and volumes)
./stop-openwatch.sh --deep-clean
```

## Troubleshooting

### Backend Not Starting

Check logs:

```bash
docker logs openwatch-backend --tail 100
```

Common causes:
- Missing required environment variables (`OPENWATCH_SECRET_KEY`, `MASTER_KEY`)
- Database not ready (check `depends_on` and health checks)
- Secret key too short (minimum 32 characters)

### Database Connection Failures

```bash
# Verify database is running
docker ps | grep openwatch-db

# Test connection
docker exec openwatch-db psql -U openwatch -d openwatch -c "SELECT 1;"
```

### Celery Tasks Not Running

```bash
# Check worker status
docker logs openwatch-worker --tail 50

# Verify Redis connectivity
docker exec openwatch-redis redis-cli -a "$REDIS_PASSWORD" ping

# Inspect active tasks
docker exec openwatch-backend python -m celery -A app.celery_app inspect active
```

### Container Health Check Failures

```bash
# Inspect health check details
docker inspect --format='{{json .State.Health}}' openwatch-backend | python -m json.tool
```
