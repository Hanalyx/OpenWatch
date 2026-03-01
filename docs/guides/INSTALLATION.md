# Installation Guide

This guide covers installing and running OpenWatch on a single host.
Choose the deployment method that matches your environment: Docker (recommended),
Podman, RPM packages, or from source.

---

## Prerequisites

**Hardware**

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM | 4 GB | 8 GB |
| CPU | 2 cores | 4 cores |
| Disk | 20 GB | 50 GB |

**Software**

- Linux host: RHEL 8/9, Rocky Linux, AlmaLinux, Ubuntu 22.04+, or any Docker-capable system
- Docker 24+ or Podman 4+ (for container deployment)
- Network access to target hosts on port 22 (SSH) for compliance scanning
- `curl` and `openssl` available on the host

**Network Ports**

| Port | Service | Direction |
|------|---------|-----------|
| 3000 | Frontend (dev/Docker) | Inbound |
| 8000 | Backend API | Inbound |
| 22 | SSH to scan targets | Outbound |
| 443/80 | Frontend (production) | Inbound |

---

## Option A: Docker (Recommended)

Docker Compose is the fastest path to a running OpenWatch instance. The compose
file defines six services: PostgreSQL 15, Redis 7, the FastAPI backend, a Celery
worker, a Celery beat scheduler, and an Nginx-based React frontend.

### 1. Clone the Repository

```bash
git clone https://github.com/Hanalyx/openwatch.git
cd openwatch
```

### 2. Configure Environment

Copy the example environment file and set secure values:

```bash
cp .env.example .env
```

Open `.env` and set the following required variables. Use strong, unique values
for each secret:

```bash
# Required -- set these before first start
POSTGRES_PASSWORD=<strong-database-password>
REDIS_PASSWORD=<strong-redis-password>
OPENWATCH_SECRET_KEY=<random-64-char-hex>
MASTER_KEY=<random-64-char-hex>
OPENWATCH_ENCRYPTION_KEY=<random-64-char-hex>
```

Generate random keys with:

```bash
openssl rand -hex 32
```

The startup script will generate defaults if `.env` is missing, but those
defaults are not suitable for production.

### 3. Start Services

```bash
./start-openwatch.sh --runtime docker --build
```

On first run, this builds the backend and frontend container images, starts all
six services, and runs a health check. The build takes several minutes depending
on network speed and host performance.

Subsequent starts (without code changes) can skip the build:

```bash
./start-openwatch.sh --runtime docker
```

### 4. Verify

Wait approximately 30 seconds for all services to initialize, then confirm the
backend is healthy:

```bash
curl -s http://localhost:8000/health | python3 -m json.tool
```

Expected response:

```json
{
    "status": "healthy"
}
```

Open the frontend in a browser:

```
http://localhost:3000
```

### 5. Log In and Change the Default Password

Log in with the default credentials:

| Field | Value |
|-------|-------|
| Username | `admin` |
| Password | `admin` |

**Change the default password immediately** after first login. Navigate to
Settings > Account to update it.

### 6. Stop Services

```bash
# Stop containers, preserve data volumes
./stop-openwatch.sh

# Stop containers and delete all data (databases, logs, volumes)
./stop-openwatch.sh --deep-clean
```

---

## Option B: Podman

OpenWatch supports Podman as an alternative container runtime. The startup script
handles the differences automatically.

### 1. Install Podman and Podman Compose

On RHEL/Rocky/Alma:

```bash
sudo dnf install -y podman podman-compose
```

On Ubuntu/Debian:

```bash
sudo apt install -y podman podman-compose
```

### 2. Clone and Configure

Follow the same clone and `.env` setup steps from Option A.

### 3. Start Services

```bash
./start-openwatch.sh --runtime podman --build
```

### Podman-Specific Notes

**Rootless mode**: Podman runs rootless by default. If containers cannot bind to
privileged ports (80, 443), either run with `sudo` or configure
`net.ipv4.ip_unprivileged_port_start=80` in `/etc/sysctl.conf`.

**SELinux volume mounts**: On SELinux-enforcing hosts, you may need the `:Z` flag
on volume mounts. If containers fail to read mounted files, update the compose
file volume entries to append `:Z`:

```yaml
volumes:
  - ./security/certs:/openwatch/security/certs:ro,Z
```

**Podman socket**: Some compose tooling requires the Podman socket. Enable it
with:

```bash
systemctl --user enable --now podman.socket
```

---

## Option C: RPM Packages (Bare Metal)

RPM packages are available for RHEL 9 and compatible distributions. This method
installs OpenWatch directly on the host without containers.

### 1. Install External Dependencies

```bash
# PostgreSQL 15
sudo dnf module enable postgresql:15
sudo dnf install -y postgresql-server postgresql-contrib
sudo postgresql-setup --initdb
sudo systemctl enable --now postgresql

# Redis 7
sudo dnf install -y redis
sudo systemctl enable --now redis
```

### 2. Install Python 3.12

```bash
sudo dnf install -y python3.12 python3.12-pip python3.12-devel
```

### 3. Install OpenWatch RPM Packages

Build or obtain the RPM packages from `packaging/rpm/`:

```bash
sudo rpm -ivh openwatch-<version>.rpm
```

### 4. Install Kensa (Compliance Engine)

Kensa is installed via pip, not bundled with OpenWatch:

```bash
sudo python3.12 -m pip install kensa
```

Set the rules path in your environment or systemd unit file:

```bash
export KENSA_RULES_PATH=/opt/openwatch/kensa-rules
```

### 5. Configure the Database

```bash
sudo -u postgres createuser openwatch
sudo -u postgres createdb -O openwatch openwatch
```

Set `POSTGRES_PASSWORD` and configure `pg_hba.conf` to allow password
authentication for the `openwatch` user.

### 6. Run Database Migrations

```bash
cd /opt/openwatch/backend
python3.12 -m alembic upgrade head
```

### 7. Configure Systemd Services

Create unit files for the backend API, Celery worker, and Celery beat scheduler.
Start and enable them:

```bash
sudo systemctl enable --now openwatch-api
sudo systemctl enable --now openwatch-worker
sudo systemctl enable --now openwatch-beat
```

For the complete RPM installation walkthrough, see
[Native RPM Installation](../architecture/NATIVE_RPM_INSTALLATION.md).

---

## Option D: Debian/Ubuntu Packages

Debian/Ubuntu package support is planned but not yet available. For Debian-based
systems, use Docker (Option A) or install from source (Option E).

---

## Option E: From Source (Development)

This method is intended for developers contributing to OpenWatch.

### 1. Install Prerequisites

- Python 3.12+
- Node.js 20+
- PostgreSQL 15
- Redis 7

### 2. Clone the Repository

```bash
git clone https://github.com/Hanalyx/openwatch.git
cd openwatch
```

### 3. Backend Setup

```bash
cd backend
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file with database and Redis connection strings, then run
migrations:

```bash
alembic upgrade head
```

Start the backend:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 4. Celery Worker

In a separate terminal (with the virtualenv activated):

```bash
cd backend
celery -A app.celery_app worker --loglevel=info \
  -Q default,scans,results,maintenance,monitoring,host_monitoring,health_monitoring,compliance_scanning
```

### 5. Frontend Setup

```bash
cd frontend
npm ci
npm run dev
```

The frontend dev server starts on `http://localhost:3001` with hot reload.

### 6. Kensa (Compliance Engine)

Install Kensa into the backend virtualenv:

```bash
pip install kensa
```

Set the rules path environment variable if running outside Docker:

```bash
export KENSA_RULES_PATH=/path/to/kensa-rules
```

---

## Production Deployment

For production, use the Docker Compose overlay that enables HTTPS, FIPS mode,
resource limits, and JSON logging:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

Key differences from the development configuration:

| Setting | Development | Production |
|---------|-------------|------------|
| `OPENWATCH_DEBUG` | `true` | `false` |
| `OPENWATCH_FIPS_MODE` | `false` | `true` |
| `OPENWATCH_REQUIRE_HTTPS` | `false` | `true` |
| `OPENWATCH_SSH_STRICT_MODE` | `false` | `true` |
| Frontend ports | 3000:80 | 443:443, 80:80 |
| Resource limits | None | Per-service CPU/memory limits |
| Log driver | Default | JSON file with rotation |
| Restart policy | `unless-stopped` | `always` |

Before deploying to production:

1. Place TLS certificates in `security/certs/` and keys in `security/keys/`.
2. Set all environment variables to strong, unique values.
3. Review [Security Hardening](SECURITY_HARDENING.md) for full guidance.
4. Review [Production Deployment](PRODUCTION_DEPLOYMENT.md) for operational details.

---

## Post-Install Checklist

Complete these steps after any installation method:

- [ ] Backend health check passes: `curl http://localhost:8000/health`
- [ ] Frontend loads in browser
- [ ] Default admin password changed
- [ ] SSH credentials configured for target hosts (Settings > SSH Keys)
- [ ] TLS certificates in place (production only)
- [ ] Backup schedule configured (see [Backup and Recovery](BACKUP_RECOVERY.md))
- [ ] Log rotation configured for `/openwatch/logs/`
- [ ] Firewall rules restrict access to ports 8000 and 3000/443

---

## Environment Variables

The following variables are required for all deployment methods:

| Variable | Description | Example |
|----------|-------------|---------|
| `POSTGRES_PASSWORD` | PostgreSQL password for the `openwatch` user | Random 32+ character string |
| `REDIS_PASSWORD` | Redis authentication password | Random 32+ character string |
| `OPENWATCH_SECRET_KEY` | Application secret for session signing | `openssl rand -hex 32` |
| `MASTER_KEY` | Master encryption key | `openssl rand -hex 32` |
| `OPENWATCH_ENCRYPTION_KEY` | Data-at-rest encryption key | `openssl rand -hex 32` |

For the complete list of configuration options, see
[Environment Variable Reference](ENVIRONMENT_REFERENCE.md).

---

## Monitoring (Optional)

OpenWatch ships with a monitoring stack (Prometheus, Grafana, Alertmanager)
defined in a separate compose file:

```bash
docker compose -f monitoring/docker-compose.monitoring.yml up -d
```

See [Monitoring Setup](MONITORING_SETUP.md) for dashboards and alert
configuration.

---

## Troubleshooting

### Backend container fails to start

Check logs for database connection issues:

```bash
docker logs openwatch-backend --tail 50
```

Verify PostgreSQL is healthy:

```bash
docker exec openwatch-db pg_isready -U openwatch -d openwatch
```

### Frontend returns 502 Bad Gateway

The backend may still be initializing. Wait 30 seconds and retry. If the problem
persists, check that the backend container is running:

```bash
docker ps | grep openwatch-backend
```

### Celery worker not processing tasks

Verify the worker is running and connected to Redis:

```bash
docker logs openwatch-worker --tail 50
```

Check that Redis is reachable:

```bash
docker exec openwatch-redis redis-cli -a "${REDIS_PASSWORD}" ping
```

### Permission denied on volume mounts (Podman/SELinux)

Add the `:Z` suffix to volume mounts in the compose file, or disable SELinux
enforcement temporarily for troubleshooting:

```bash
sudo setenforce 0  # Temporary -- reverts on reboot
```

---

## What's Next

- [Quickstart Guide](QUICKSTART.md) -- run your first compliance scan
- [Security Hardening](SECURITY_HARDENING.md) -- production security configuration
- [Backup and Recovery](BACKUP_RECOVERY.md) -- data protection and disaster recovery
- [Upgrade Procedure](UPGRADE_PROCEDURE.md) -- upgrading to new releases
