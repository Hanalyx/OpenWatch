# OpenWatch Native RPM Installation Plan

> **Purpose**: Design a native RPM installation path for OpenWatch that runs directly on RHEL/CentOS/Rocky Linux without requiring Docker or Podman containers.

**Version**: 1.3.0
**Date**: 2026-02-12
**Status**: Implementation Complete (Pending RHEL Testing)

---

## Implementation Status

| Step | Description | Status |
|------|-------------|--------|
| 1 | Fix deprecated `ioutil` usage in `validate.go` | ✅ Complete |
| 2 | Add `//go:build container` tags to container-specific files | ✅ Complete |
| 3 | Create `prerequisites_native.go` with systemd checks | ✅ Complete |
| 4 | Create `openwatch.spec` for native deployment | ✅ Complete |
| 5 | Create `openwatch-po.spec` for Podman deployment | ✅ Complete |
| 6 | Move owadm code to `internal/owadm/` (matches imports) | ✅ Complete |
| 7 | Create `scripts/build-owadm.sh` build script | ✅ Complete |
| 8 | Build and test Go code with build tags | ✅ Complete |
| 9 | Create admin commands (backup, restore, health, etc.) | ✅ Complete |
| 10 | Create migration scripts (container → native) | ✅ Complete |
| 11 | Test on RHEL 8, 9, 10 environments | ⏳ Pending (requires RHEL) |
| 12 | Build actual RPM packages | ⏳ Pending (requires RHEL) |

**Files Created/Modified**:
- `packaging/rpm/openwatch.spec` - Native deployment (v2.0.0)
- `packaging/rpm/openwatch-po.spec` - Podman deployment (v2.0.0)
- `internal/owadm/utils/prerequisites_native.go` - Native prerequisite checks
- `internal/owadm/cmd/validate.go` - Fixed deprecated `ioutil` usage
- `internal/owadm/cmd/root_native.go` - Native-specific root command config
- `internal/owadm/cmd/backup.go` - Database and config backup
- `internal/owadm/cmd/restore.go` - Restore from backup
- `internal/owadm/cmd/db_migrate.go` - Alembic database migrations
- `internal/owadm/cmd/create_admin.go` - Create admin user
- `internal/owadm/cmd/generate_secrets.go` - Generate secrets and JWT keys
- `internal/owadm/cmd/health.go` - Health check all components
- `scripts/build-owadm.sh` - Build script for native/container variants
- `scripts/migrate-container-to-native.sh` - Migration script
- Added `//go:build container` to 12 container-specific files
- Moved `utils/owadm/` to `internal/owadm/` (matches main.go imports)

**Next Steps (Requires RHEL Environment)**:

1. **Build RPM packages** on RHEL 9:
   ```bash
   rpmbuild -bb packaging/rpm/openwatch.spec      # Native
   rpmbuild -bb packaging/rpm/openwatch-po.spec   # Podman
   ```

2. **Test installation** on clean RHEL 8, 9, 10 VMs:
   ```bash
   dnf install ./openwatch-2.0.0-1.el9.x86_64.rpm
   systemctl start openwatch.target
   owadm health
   ```

3. **Test migration** from container to native:
   ```bash
   ./scripts/migrate-container-to-native.sh --dry-run
   ./scripts/migrate-container-to-native.sh
   ```

---

## RPM Package Naming Convention

OpenWatch uses a deployment-suffix naming convention for different installation modes:

| Package Name | Deployment Mode | Description |
|--------------|-----------------|-------------|
| `openwatch-2.0.0-1.el9.x86_64.rpm` | **Native** | Direct systemd services, no containers (this plan) |
| `openwatch-do-2.0.0-1.el9.x86_64.rpm` | Docker | Docker container orchestration (future) |
| `openwatch-po-2.0.0-1.el9.x86_64.rpm` | Podman | Podman container orchestration (current v1.2.1) |
| `openwatch-ko-2.0.0-1.el9.x86_64.rpm` | Kubernetes | Kubernetes/OpenShift deployment (future) |

**Current Version**: 2.0.0 (major version bump for native architecture)

**Note**: The existing `openwatch-1.2.1-*.rpm` package will be renamed to `openwatch-po-1.2.1-*.rpm` to clarify it uses Podman container orchestration.

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Current State Analysis](#current-state-analysis)
3. [Target Architecture](#target-architecture)
4. [RPM Package Structure](#rpm-package-structure)
5. [Implementation Phases](#implementation-phases)
6. [Detailed Component Specifications](#detailed-component-specifications)
7. [Installation Flow](#installation-flow)
8. [Configuration Management](#configuration-management)
9. [Security Considerations](#security-considerations)
10. [Testing Strategy](#testing-strategy)
    - [Supported Operating Systems](#supported-operating-systems)
    - [Test Matrix](#test-matrix)
11. [Migration Path](#migration-path)
12. [Go Utility Code Review](#go-utility-code-review)
13. [Appendix: File Inventory](#appendix-file-inventory)

---

## Executive Summary

### Problem Statement

The current OpenWatch RPM package (`openwatch-1.2.1-*.rpm`) installs a container orchestration layer that still requires Podman or Docker to run the actual services. This creates barriers for:

1. **Air-gapped environments** - Container registries inaccessible
2. **Government/DoD systems** - Policies prohibiting containers
3. **Traditional operations teams** - Prefer systemd-managed processes
4. **Resource-constrained systems** - Container overhead unacceptable
5. **Compliance requirements** - Some frameworks require native process visibility

### Proposed Solution

Create a **native installation path** using `openwatch-2.0.0-*.rpm` packages that:

- Install Python application directly to `/opt/openwatch/`
- Use system PostgreSQL 15+ and Redis 7+
- Run FastAPI backend via uvicorn as a systemd service
- Run Celery workers as systemd services
- Serve frontend via system nginx
- Manage all configuration via `/etc/openwatch/`

### Key Benefits

| Benefit | Description |
|---------|-------------|
| No container runtime | Zero dependency on Docker/Podman |
| System visibility | All processes visible via `ps`, `top`, `systemctl` |
| Standard tooling | Use familiar RHEL admin tools |
| SELinux integration | Native file contexts, no container escapes |
| Simpler debugging | Direct access to logs, processes, files |
| Lower overhead | No container layer, direct kernel access |

### Aegis-Based Architecture (No SCAP Content Required)

OpenWatch has migrated from OpenSCAP/XCCDF to **Aegis v0.1.0** as the compliance engine:

| Legacy (OpenSCAP) | Current (Aegis) |
|-------------------|-----------------|
| Upload SCAP content bundles | Rules bundled with application |
| XCCDF/OVAL XML parsing | Native YAML rule format |
| File-based scan results | PostgreSQL database storage |
| Content library management | Rule Reference UI (read-only) |

**Storage Simplification**:
- **No `/var/lib/openwatch/scap/`** - Aegis rules at `/opt/openwatch/backend/aegis/rules/`
- **No `/var/lib/openwatch/results/`** - Results in PostgreSQL `scan_findings` table
- **No `/var/lib/openwatch/uploads/`** - SCAP upload deprecated
- **Minimal runtime data** - Only Celery state, exports, SSH cache

---

## Current State Analysis

### Existing RPM Package Structure

The current `openwatch.spec` (v1.2.1-8) provides:

```
/usr/bin/owadm                    # Go CLI for container orchestration
/etc/openwatch/ow.yml             # Configuration file
/etc/openwatch/secrets.env        # Secrets file
/usr/share/openwatch/compose/     # Docker/Podman compose files
/lib/systemd/system/*.service     # Systemd services (container wrappers)
```

**Key Limitation**: All systemd services invoke `owadm` which starts containers.

### Current Container Services

| Container | Base Image | Purpose |
|-----------|------------|---------|
| openwatch-backend | UBI9 + Python 3.12 | FastAPI application |
| openwatch-worker | UBI9 + Python 3.12 | Celery task workers |
| openwatch-celery-beat | UBI9 + Python 3.12 | Celery scheduler |
| openwatch-db | PostgreSQL 15.14 | Database |
| openwatch-redis | Redis 7.4.6 | Message broker |
| openwatch-frontend | Nginx 1.29.4 | React UI |

### What Already Exists (Reusable)

| Component | Location | Reusability |
|-----------|----------|-------------|
| Systemd service templates | `packaging/systemd/` | Modify for native |
| Configuration schema | `packaging/config/config-schema.json` | Use as-is |
| Configuration template | `packaging/config/ow.yml.template` | Extend for native |
| SELinux policy | `packaging/selinux/` | Extend for native paths |
| Secret generation | `packaging/rpm/scripts/generate-secrets.sh` | Use as-is |
| Python requirements | `backend/requirements.txt` | Use as-is |
| Aegis rules | `backend/aegis/` | Copy to package |

---

## Target Architecture

### Native Component Deployment

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         RHEL/Rocky Linux Host                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │  systemd Service Management                                         │ │
│  ├────────────────────────────────────────────────────────────────────┤ │
│  │                                                                      │ │
│  │  openwatch.target                                                    │ │
│  │  ├── postgresql.service (system)        ←── Database                │ │
│  │  ├── redis.service (system)             ←── Message broker          │ │
│  │  ├── openwatch-api.service              ←── FastAPI + Uvicorn       │ │
│  │  ├── openwatch-worker@.service          ←── Celery workers (N)      │ │
│  │  ├── openwatch-beat.service             ←── Celery scheduler        │ │
│  │  └── nginx.service (system)             ←── Frontend + API proxy    │ │
│  │                                                                      │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │  File System Layout                                                  │ │
│  ├────────────────────────────────────────────────────────────────────┤ │
│  │                                                                      │ │
│  │  /opt/openwatch/                                                     │ │
│  │  ├── venv/               ←── Python 3.12 virtualenv                 │ │
│  │  ├── backend/            ←── FastAPI application code               │ │
│  │  │   ├── app/                                                        │ │
│  │  │   └── aegis/          ←── Aegis compliance engine + rules        │ │
│  │  └── frontend/           ←── Built React static files               │ │
│  │                                                                      │ │
│  │  /etc/openwatch/                                                     │ │
│  │  ├── ow.yml              ←── Main configuration                     │ │
│  │  ├── secrets.env         ←── Database/Redis passwords               │ │
│  │  ├── jwt_private.pem     ←── JWT signing key                        │ │
│  │  ├── jwt_public.pem      ←── JWT verification key                   │ │
│  │  └── ssl/                ←── TLS certificates                       │ │
│  │                                                                      │ │
│  │  /var/lib/openwatch/                                                 │ │
│  │  ├── celery/             ←── Celery scheduler state                 │ │
│  │  ├── exports/            ←── Audit query exports (temporary)        │ │
│  │  └── ssh/                ←── SSH known hosts cache                  │ │
│  │  # NOTE: No SCAP/uploads dirs - Aegis rules bundled, results in DB  │ │
│  │                                                                      │ │
│  │  /var/log/openwatch/                                                 │ │
│  │  ├── api.log             ←── Backend application logs               │ │
│  │  ├── worker.log          ←── Celery worker logs                     │ │
│  │  ├── beat.log            ←── Celery scheduler logs                  │ │
│  │  └── audit.log           ←── Security audit trail                   │ │
│  │                                                                      │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Service Dependencies

```
                    ┌─────────────────┐
                    │ openwatch.target│
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
         ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  postgresql     │ │     redis       │ │     nginx       │
│  (external)     │ │   (external)    │ │   (external)    │
└────────┬────────┘ └────────┬────────┘ └────────┬────────┘
         │                   │                   │
         └───────────┬───────┘                   │
                     │                           │
                     ▼                           │
         ┌─────────────────────┐                 │
         │  openwatch-api      │◄────────────────┘
         │  (uvicorn)          │      (reverse proxy)
         └──────────┬──────────┘
                    │
         ┌──────────┴──────────┐
         │                     │
         ▼                     ▼
┌─────────────────┐   ┌─────────────────┐
│ openwatch-worker│   │ openwatch-beat  │
│ (celery worker) │   │ (celery beat)   │
└─────────────────┘   └─────────────────┘
```

---

## RPM Package Structure

### Package Split Strategy

Create multiple RPM packages for modularity:

| Package | Contents | Dependencies |
|---------|----------|--------------|
| `openwatch-common` | User/group, directories, base config | - |
| `openwatch-backend` | Python app, virtualenv, Aegis | common, python3.12 |
| `openwatch-frontend` | Built React app, nginx config | common, nginx |
| `openwatch-aegis` | Aegis rules only (for updates) | common |
| `openwatch` | Metapackage | backend, frontend |

### Alternative: Single Package

For simplicity, a single `openwatch` package containing everything:

```
openwatch-2.0.0-1.el9.x86_64.rpm
├── /opt/openwatch/                    # Application
├── /etc/openwatch/                    # Configuration
├── /lib/systemd/system/               # Service files
├── /etc/nginx/conf.d/openwatch.conf   # Nginx config
├── /var/lib/openwatch/                # Data directories
└── /var/log/openwatch/                # Log directories
```

**Recommendation**: Start with single package for initial release, split later if needed.

---

## Implementation Phases

### Phase 1: Foundation (Week 1)

**Goal**: Create basic native RPM that installs and runs backend

| Task | Description | Deliverable |
|------|-------------|-------------|
| 1.1 | Create `openwatch.spec` | RPM spec file |
| 1.2 | Build Python virtualenv in RPM | `/opt/openwatch/venv/` |
| 1.3 | Create native systemd services | `openwatch-api.service` |
| 1.4 | Package backend code | `/opt/openwatch/backend/` |
| 1.5 | Create installation scripts | `%post`, `%preun` scripts |

**Acceptance Criteria**:
- [ ] RPM installs on clean RHEL 9
- [ ] Backend starts via `systemctl start openwatch-api`
- [ ] Health endpoint responds at `localhost:8000/health`

### Phase 2: Database & Worker (Week 2)

**Goal**: Integrate with system PostgreSQL/Redis, add Celery workers

| Task | Description | Deliverable |
|------|-------------|-------------|
| 2.1 | PostgreSQL integration | DB setup script, SELinux contexts |
| 2.2 | Redis integration | Connection configuration |
| 2.3 | Celery worker service | `openwatch-worker@.service` |
| 2.4 | Celery beat service | `openwatch-beat.service` |
| 2.5 | Database migrations | Alembic upgrade in `%post` |

**Acceptance Criteria**:
- [ ] Database created and migrated on install
- [ ] Workers process tasks from Redis queues
- [ ] Beat schedules periodic tasks

### Phase 3: Frontend & Proxy (Week 3)

**Goal**: Serve frontend via nginx, configure reverse proxy

| Task | Description | Deliverable |
|------|-------------|-------------|
| 3.1 | Build React frontend | Pre-built in package |
| 3.2 | Nginx configuration | `/etc/nginx/conf.d/openwatch.conf` |
| 3.3 | TLS configuration | Certificate handling |
| 3.4 | SELinux policy updates | Allow nginx → backend |
| 3.5 | Installation docs | Admin guide |

**Acceptance Criteria**:
- [ ] UI accessible at `https://hostname/`
- [ ] API proxied to backend
- [ ] TLS working (self-signed or provided)

### Phase 4: Hardening & Testing (Week 4)

**Goal**: Security hardening, comprehensive testing

| Task | Description | Deliverable |
|------|-------------|-------------|
| 4.1 | SELinux policy module | `openwatch.pp` |
| 4.2 | FIPS mode support | Crypto configuration |
| 4.3 | Firewalld integration | Zone configuration |
| 4.4 | Installation testing | Test on RHEL 9, Rocky 9 |
| 4.5 | Upgrade testing | Container → Native migration |

**Acceptance Criteria**:
- [ ] Works with SELinux enforcing
- [ ] FIPS mode operational
- [ ] Clean install/upgrade/remove cycle

---

## Detailed Component Specifications

### 1. Python Virtual Environment

**Build Process**:
```bash
# During RPM build
python3.12 -m venv /opt/openwatch/venv
source /opt/openwatch/venv/bin/activate
pip install --upgrade pip wheel
pip install -r requirements.txt
```

**Package Size Estimate**: ~500MB (includes all dependencies)

**Key Dependencies**:
- FastAPI 0.128.0
- Uvicorn 0.40.0
- SQLAlchemy 2.0.45
- Celery 5.6.2
- Cryptography 46.0.3
- Paramiko 3.5.0
- 40+ additional packages

### 2. Systemd Service: openwatch-api.service

```ini
[Unit]
Description=OpenWatch API Server
Documentation=https://github.com/hanalyx/openwatch
After=network-online.target postgresql.service redis.service
Requires=postgresql.service redis.service
Wants=network-online.target

[Service]
Type=notify
User=openwatch
Group=openwatch
WorkingDirectory=/opt/openwatch/backend

# Environment
EnvironmentFile=/etc/openwatch/secrets.env
Environment=PYTHONPATH=/opt/openwatch/backend
Environment=OPENWATCH_CONFIG_FILE=/etc/openwatch/ow.yml

# Start command
ExecStart=/opt/openwatch/venv/bin/uvicorn \
    app.main:app \
    --host 127.0.0.1 \
    --port 8000 \
    --workers 4 \
    --log-config /etc/openwatch/logging.yml

# Lifecycle
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10
TimeoutStartSec=120
TimeoutStopSec=30

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/openwatch /var/log/openwatch
ReadOnlyPaths=/opt/openwatch /etc/openwatch

# Resource limits
LimitNOFILE=65536
TasksMax=4096

[Install]
WantedBy=multi-user.target
```

### 3. Systemd Service: openwatch-worker@.service

Template service for multiple worker instances:

```ini
[Unit]
Description=OpenWatch Celery Worker %i
Documentation=https://github.com/hanalyx/openwatch
After=network-online.target postgresql.service redis.service openwatch-api.service
Requires=postgresql.service redis.service
PartOf=openwatch-api.service

[Service]
Type=notify
User=openwatch
Group=openwatch
WorkingDirectory=/opt/openwatch/backend

# Environment
EnvironmentFile=/etc/openwatch/secrets.env
Environment=PYTHONPATH=/opt/openwatch/backend
Environment=OPENWATCH_CONFIG_FILE=/etc/openwatch/ow.yml
Environment=C_FORCE_ROOT=false

# Celery worker command
ExecStart=/opt/openwatch/venv/bin/celery \
    -A app.celery_app worker \
    --loglevel=info \
    --hostname=worker-%i@%%h \
    --queues=default,scans,results,maintenance,monitoring,host_monitoring,health_monitoring,compliance_scanning \
    --concurrency=4 \
    --logfile=/var/log/openwatch/worker-%i.log

# Lifecycle
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10

# Security (less restrictive for SSH scanning)
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=false
ReadWritePaths=/var/lib/openwatch /var/log/openwatch /tmp
ReadOnlyPaths=/opt/openwatch /etc/openwatch /etc/ssl

# Resource limits
LimitNOFILE=16384
TasksMax=2048

[Install]
WantedBy=multi-user.target
```

### 4. Systemd Service: openwatch-beat.service

```ini
[Unit]
Description=OpenWatch Celery Beat Scheduler
Documentation=https://github.com/hanalyx/openwatch
After=network-online.target postgresql.service redis.service
Requires=postgresql.service redis.service

[Service]
Type=simple
User=openwatch
Group=openwatch
WorkingDirectory=/opt/openwatch/backend

# Environment
EnvironmentFile=/etc/openwatch/secrets.env
Environment=PYTHONPATH=/opt/openwatch/backend

# Celery beat command
ExecStart=/opt/openwatch/venv/bin/celery \
    -A app.celery_app beat \
    --loglevel=info \
    --logfile=/var/log/openwatch/beat.log \
    --schedule=/var/lib/openwatch/celery/celerybeat-schedule

Restart=on-failure
RestartSec=10

# Security
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=true
ReadWritePaths=/var/lib/openwatch /var/log/openwatch
ReadOnlyPaths=/opt/openwatch /etc/openwatch

[Install]
WantedBy=multi-user.target
```

### 5. Nginx Configuration

```nginx
# /etc/nginx/conf.d/openwatch.conf

upstream openwatch_backend {
    server 127.0.0.1:8000;
    keepalive 32;
}

server {
    listen 80;
    server_name _;

    # Redirect HTTP to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name _;

    # TLS Configuration
    ssl_certificate /etc/openwatch/ssl/openwatch.crt;
    ssl_certificate_key /etc/openwatch/ssl/openwatch.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000" always;

    # Frontend (React SPA)
    root /opt/openwatch/frontend;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    # API Proxy
    location /api/ {
        proxy_pass http://openwatch_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
    }

    # Health check (no auth)
    location /health {
        proxy_pass http://openwatch_backend/health;
        proxy_http_version 1.1;
    }

    # Metrics (internal only)
    location /metrics {
        allow 127.0.0.1;
        deny all;
        proxy_pass http://openwatch_backend/metrics;
    }
}
```

---

## Configuration Management

### Configuration File: /etc/openwatch/ow.yml

```yaml
# OpenWatch Native Installation Configuration
# Version: 2.0.0

# Runtime mode (container or native)
runtime:
  mode: native                    # CHANGED: native instead of container

# Database configuration
database:
  host: localhost                 # Local PostgreSQL
  port: 5432
  name: openwatch
  user: openwatch
  # Password from secrets.env: OPENWATCH_DATABASE_PASSWORD
  ssl_mode: prefer                # require for remote DB
  pool_size: 25
  max_overflow: 10

# Redis configuration
redis:
  host: localhost
  port: 6379
  db: 0
  # Password from secrets.env: OPENWATCH_REDIS_PASSWORD

# Web/API configuration
api:
  host: 127.0.0.1                # Bind to localhost (nginx proxies)
  port: 8000
  workers: 4                      # Uvicorn workers

# Celery configuration
celery:
  worker_concurrency: 4
  worker_instances: 2             # Number of worker@N services
  queues:
    - default
    - scans
    - results
    - maintenance
    - monitoring
    - compliance_scanning

# Scanning configuration (Aegis-based, no SCAP files needed)
scanning:
  ssh_key_path: /etc/openwatch/ssh/openwatch_rsa
  concurrent_scans: 5
  timeout_seconds: 600
  # NOTE: No scap_content_dir or results_dir needed
  # - Aegis rules are bundled with the application
  # - Scan results are stored in PostgreSQL (scan_findings table)

# Aegis compliance engine (bundled with application)
aegis:
  rules_path: /opt/openwatch/backend/aegis/rules    # 338 YAML rules (bundled)
  config_path: /opt/openwatch/backend/aegis/config  # Variable definitions

# Logging configuration
logging:
  level: INFO
  format: json                    # json or text
  api_log: /var/log/openwatch/api.log
  worker_log: /var/log/openwatch/worker.log
  audit_log: /var/log/openwatch/audit.log
  max_size_mb: 100
  max_age_days: 30

# Security configuration
security:
  fips_mode: false                # Enable on FIPS systems
  require_https: true
  session_timeout_minutes: 60
  jwt_algorithm: RS256
  jwt_private_key: /etc/openwatch/jwt_private.pem
  jwt_public_key: /etc/openwatch/jwt_public.pem
```

### Secrets File: /etc/openwatch/secrets.env

```bash
# OpenWatch Secrets (chmod 600, owned by openwatch:openwatch)

# Database credentials
OPENWATCH_DATABASE_PASSWORD=<generated>

# Redis credentials
OPENWATCH_REDIS_PASSWORD=<generated>

# Application secrets
OPENWATCH_SECRET_KEY=<64-char-random>
OPENWATCH_MASTER_KEY=<32-char-random>
OPENWATCH_ENCRYPTION_KEY=<32-char-random>

# Derived URLs (constructed from above)
OPENWATCH_DATABASE_URL=postgresql://openwatch:${OPENWATCH_DATABASE_PASSWORD}@localhost:5432/openwatch
OPENWATCH_REDIS_URL=redis://:${OPENWATCH_REDIS_PASSWORD}@localhost:6379/0
```

---

## Installation Flow

### Pre-Installation Requirements

```bash
# 1. Enable required repositories
dnf install -y epel-release

# 2. Install system dependencies
dnf install -y \
    python3.12 \
    python3.12-pip \
    python3.12-devel \
    postgresql15-server \
    redis \
    nginx \
    openssl \
    openssh-clients \
    openscap-scanner \
    gcc

# 3. Initialize PostgreSQL
postgresql-setup --initdb
systemctl enable --now postgresql

# 4. Start Redis
systemctl enable --now redis
```

### RPM Installation

```bash
# Install OpenWatch native package
dnf install openwatch-2.0.0-1.el9.x86_64.rpm

# This will:
# 1. Create openwatch user/group
# 2. Install application to /opt/openwatch/
# 3. Install configuration to /etc/openwatch/
# 4. Install systemd services
# 5. Create data directories
# 6. Generate secrets (if not exist)
# 7. Create database and run migrations
# 8. Enable services (not start)
```

### Post-Installation

```bash
# 1. Review configuration
vim /etc/openwatch/ow.yml

# 2. Configure TLS certificates
cp your-cert.crt /etc/openwatch/ssl/openwatch.crt
cp your-key.key /etc/openwatch/ssl/openwatch.key
chown openwatch:openwatch /etc/openwatch/ssl/*
chmod 600 /etc/openwatch/ssl/openwatch.key

# 3. Start services
systemctl start openwatch.target

# 4. Verify status
systemctl status openwatch-api openwatch-worker@1 openwatch-beat nginx

# 5. Access UI
firefox https://localhost/
```

---

## Security Considerations

### SELinux Policy

Native installation requires custom SELinux policy:

```
# openwatch.te (native mode policy)

policy_module(openwatch, 1.0.0)

require {
    type httpd_t;
    type postgresql_t;
    type redis_t;
}

# Define OpenWatch types
type openwatch_t;
type openwatch_exec_t;
type openwatch_var_lib_t;
type openwatch_log_t;
type openwatch_etc_t;

# Domain transitions
domain_auto_trans(init_t, openwatch_exec_t, openwatch_t)

# Allow OpenWatch to connect to PostgreSQL
allow openwatch_t postgresql_t:tcp_socket { name_connect };

# Allow OpenWatch to connect to Redis
allow openwatch_t redis_t:tcp_socket { name_connect };

# Allow nginx to proxy to OpenWatch
allow httpd_t openwatch_t:tcp_socket { name_connect };

# File contexts
/opt/openwatch(/.*)?                 gen_context(system_u:object_r:openwatch_exec_t,s0)
/var/lib/openwatch(/.*)?             gen_context(system_u:object_r:openwatch_var_lib_t,s0)
/var/log/openwatch(/.*)?             gen_context(system_u:object_r:openwatch_log_t,s0)
/etc/openwatch(/.*)?                 gen_context(system_u:object_r:openwatch_etc_t,s0)
```

### Firewall Configuration

```bash
# Required ports
firewall-cmd --permanent --add-service=https
firewall-cmd --permanent --add-service=http  # Redirect to HTTPS
firewall-cmd --reload
```

### File Permissions

| Path | Owner | Mode | Purpose |
|------|-------|------|---------|
| `/opt/openwatch/` | root:openwatch | 755 | Application + Aegis rules (read-only) |
| `/opt/openwatch/backend/aegis/` | root:openwatch | 755 | Aegis engine + 338 YAML rules |
| `/etc/openwatch/` | root:openwatch | 750 | Configuration |
| `/etc/openwatch/secrets.env` | openwatch:openwatch | 600 | Secrets |
| `/etc/openwatch/ssl/` | openwatch:openwatch | 700 | TLS keys |
| `/var/lib/openwatch/` | openwatch:openwatch | 750 | Runtime data (minimal) |
| `/var/log/openwatch/` | openwatch:openwatch | 750 | Logs |

**Note**: No SCAP content or scan result directories needed - Aegis rules are bundled with the application and scan results are stored in PostgreSQL.

---

## Testing Strategy

### Supported Operating Systems

OpenWatch native RPM supports RHEL-based systems version 8, 9, and 10:

| Distribution | Version 8 | Version 9 | Version 10 |
|--------------|-----------|-----------|------------|
| **Red Hat Enterprise Linux (RHEL)** | 8.x | 9.x | 10.x |
| **Rocky Linux** | 8.x | 9.x | 10.x |
| **Oracle Linux** | 8.x | 9.x | 10.x |
| **AlmaLinux** | 8.x | 9.x | 10.x |
| **CentOS Stream** | 8 | 9 | 10 |
| **Fedora** | 38+ | 39+ | 40+ |

**Package Naming by OS Version:**
- EL8: `openwatch-2.0.0-1.el8.x86_64.rpm`
- EL9: `openwatch-2.0.0-1.el9.x86_64.rpm`
- EL10: `openwatch-2.0.0-1.el10.x86_64.rpm`
- Fedora: `openwatch-2.0.0-1.fc40.x86_64.rpm`

**Version-Specific Considerations:**

| Feature | RHEL 8 | RHEL 9 | RHEL 10 |
|---------|--------|--------|---------|
| Python | 3.8 (default), 3.11 (module) | 3.9 (default), 3.11/3.12 (module) | 3.12 (default) |
| PostgreSQL | 10/12/13/15 (module) | 13/15/16 (module) | 16/17 (module) |
| Redis | 6.x | 6.x/7.x | 7.x |
| SELinux | Enforcing | Enforcing | Enforcing |
| FIPS 140-2 | Supported | Supported | FIPS 140-3 |

**Note:** OpenWatch requires Python 3.12+. On RHEL 8/9, install via `dnf module enable python312` before installation.

### Test Matrix

| Test Type | RHEL 8 | RHEL 9 | RHEL 10 | Rocky 8 | Rocky 9 | Rocky 10 | Oracle 8 | Oracle 9 | AlmaLinux 8 | AlmaLinux 9 | Fedora 40 | CentOS Stream 9 |
|-----------|--------|--------|---------|---------|---------|----------|----------|----------|-------------|-------------|-----------|-----------------|
| Clean Install | Required | Required | Required | Required | Required | Optional | Optional | Optional | Optional | Optional | Optional | Optional |
| Upgrade from Container | Required | Required | Required | Required | Required | Optional | Optional | Optional | Optional | Optional | Optional | Optional |
| SELinux Enforcing | Required | Required | Required | Required | Required | Optional | Optional | Optional | Optional | Optional | Optional | Optional |
| FIPS Mode | Required | Required | Required | Optional | Optional | Optional | Optional | Optional | Optional | Optional | N/A | Optional |
| Uninstall/Reinstall | Required | Required | Required | Required | Required | Optional | Optional | Optional | Optional | Optional | Optional | Optional |

### Automated Test Cases

1. **Installation Tests**
   - Package installs without errors
   - All files installed to correct locations
   - User/group created correctly
   - Services enabled (not started)

2. **Service Tests**
   - All services start successfully
   - Health endpoint responds
   - Workers process tasks
   - Beat schedules tasks

3. **Functional Tests**
   - User can log in via UI
   - Scan can be executed
   - Results stored correctly
   - Alerts generated

4. **Security Tests**
   - SELinux contexts correct
   - No AVC denials during operation
   - Secrets file permissions correct
   - TLS working correctly

---

## Migration Path

### Container to Native Migration

```bash
# 1. Backup container data
owadm backup --output /backup/openwatch-$(date +%Y%m%d).tar.gz

# 2. Stop container services
systemctl stop openwatch

# 3. Export database
pg_dump -h localhost -p 5432 -U openwatch openwatch > /backup/database.sql

# 4. Install native package
dnf install openwatch-2.0.0-1.el9.x86_64.rpm

# 5. Restore database (if using new PostgreSQL)
psql -h localhost -U openwatch openwatch < /backup/database.sql

# 6. Migrate configuration
# (automated script compares old/new config)
openwatch-migrate-config /etc/openwatch/ow.yml.container

# 7. Start native services
systemctl start openwatch.target

# 8. Verify migration
systemctl status openwatch-api openwatch-worker@1 openwatch-beat
owadm health

# 9. Remove container package (optional)
dnf remove openwatch-po
```

---

## Go Utility Code Review

The `owadm` CLI utility is a **pure administrative tool** for OpenWatch management tasks. For native installations, service lifecycle management uses standard RHEL tools (`systemctl`, `journalctl`), following established system administration patterns.

### Native Installation: Tool Responsibilities

```
┌─────────────────────────────────────────────────────────────────┐
│                    Native Installation                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Service Lifecycle (Standard RHEL Tools)                        │
│  ─────────────────────────────────────────                      │
│  systemctl start openwatch.target    # Start all services       │
│  systemctl stop openwatch.target     # Stop all services        │
│  systemctl restart openwatch-api     # Restart specific service │
│  systemctl status openwatch-*        # Check service status     │
│  journalctl -u openwatch-api -f      # View logs (follow)       │
│                                                                  │
│  Administrative Tasks (owadm)                                    │
│  ────────────────────────────                                   │
│  owadm validate-config               # Validate configuration   │
│  owadm backup                        # Backup DB + config       │
│  owadm restore <file>                # Restore from backup      │
│  owadm db-migrate                    # Run Alembic migrations   │
│  owadm create-admin                  # Create admin user        │
│  owadm generate-secrets              # Generate secrets/JWT     │
│  owadm health                        # Health check components  │
│  owadm version                       # Show version info        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Container Installation: Tool Responsibilities

```
┌─────────────────────────────────────────────────────────────────┐
│              Container Installation (Podman/Docker)              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Service Lifecycle (owadm wraps compose)                        │
│  ─────────────────────────────────────────                      │
│  owadm start                         # podman-compose up -d     │
│  owadm stop                          # podman-compose down      │
│  owadm status                        # podman-compose ps        │
│  owadm logs backend                  # podman-compose logs      │
│                                                                  │
│  Administrative Tasks (owadm - same as native)                  │
│  ────────────────────────────────────────────                   │
│  owadm validate-config               # Validate configuration   │
│  owadm backup                        # Backup DB + config       │
│  owadm restore <file>                # Restore from backup      │
│  owadm db-migrate                    # Run Alembic migrations   │
│  owadm create-admin                  # Create admin user        │
│  owadm generate-secrets              # Generate secrets/JWT     │
│  owadm health                        # Health check components  │
│  owadm version                       # Show version info        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Benefits of Pure Administrative Tool (Native)

| Aspect | Description |
|--------|-------------|
| **Follows RHEL conventions** | Sysadmins already know `systemctl` and `journalctl` |
| **No code duplication** | Leverages battle-tested systemd service management |
| **Ansible/automation friendly** | Standard `systemd` module works out of the box |
| **Consistent with ecosystem** | Same pattern as PostgreSQL, Redis, nginx, httpd |
| **Simpler codebase** | `owadm` focuses only on OpenWatch-specific tasks |
| **Better debugging** | Standard tools, standard log locations, standard troubleshooting |

### Build Tags Implementation

Use Go build tags to include/exclude commands based on deployment mode:

```go
// file: cmd/start.go
//go:build container

package cmd

// start command only included in container builds
var startCmd = &cobra.Command{
    Use:   "start",
    Short: "Start OpenWatch containers",
    RunE:  runStart,
}

func init() {
    rootCmd.AddCommand(startCmd)
}
```

```go
// file: cmd/backup.go
// No build tag - included in ALL builds

package cmd

// backup command included in all builds (native + container)
var backupCmd = &cobra.Command{
    Use:   "backup",
    Short: "Backup OpenWatch database and configuration",
    RunE:  runBackup,
}
```

**Build Commands**:
```bash
# Native build (for openwatch-*.rpm)
# Excludes: start, stop, status, logs (use systemctl instead)
# Includes: validate-config, backup, restore, db-migrate, create-admin, generate-secrets, health, version
go build -tags native -o owadm ./cmd/owadm

# Podman build (for openwatch-po-*.rpm)
# Includes all commands (start, stop, status, logs + admin commands)
go build -tags container,podman -o owadm ./cmd/owadm

# Docker build (for openwatch-do-*.rpm)
go build -tags container,docker -o owadm ./cmd/owadm

# Kubernetes build (for openwatch-ko-*.rpm)
go build -tags container,kubernetes -o owadm ./cmd/owadm
```

### Deprecated Usages (RESOLVED)

| File | Line | Issue | Status |
|------|------|-------|--------|
| `internal/owadm/cmd/validate.go` | 5 | Uses deprecated `io/ioutil` package | ✅ Fixed - now uses `os` package |
| `internal/owadm/cmd/validate.go` | 67 | `ioutil.ReadFile()` deprecated in Go 1.16 | ✅ Fixed - now uses `os.ReadFile()` |
| `internal/owadm/cmd/validate.go` | 180 | `ioutil.ReadFile()` deprecated in Go 1.16 | ✅ Fixed - now uses `os.ReadFile()` |

**Go Version**: `go 1.21` in `go.mod`. Verified builds with Go 1.22.2 on Ubuntu.

### Code Refactoring (COMPLETED)

**Note**: Code moved from `utils/owadm/` to `internal/owadm/` to match `main.go` imports.

| File | Change | Status |
|------|--------|--------|
| `internal/owadm/utils/prerequisites.go` | Added `//go:build container` tag | ✅ Complete |
| `internal/owadm/utils/prerequisites_native.go` | Created with `//go:build !container` tag | ✅ Complete |
| `internal/owadm/runtime/runtime.go` | Added `//go:build container` tag | ✅ Complete |
| `internal/owadm/runtime/podman.go` | Added `//go:build container` tag | ✅ Complete |
| `internal/owadm/runtime/docker.go` | Added `//go:build container` tag | ✅ Complete |
| `internal/owadm/runtime/docker_test.go` | Added `//go:build container` tag | ✅ Complete |
| `internal/owadm/cmd/start.go` | Added `//go:build container` tag | ✅ Complete |
| `internal/owadm/cmd/stop.go` | Added `//go:build container` tag | ✅ Complete |
| `internal/owadm/cmd/status.go` | Added `//go:build container` tag | ✅ Complete |
| `internal/owadm/cmd/logs.go` | Added `//go:build container` tag | ✅ Complete |
| `internal/owadm/cmd/exec.go` | Added `//go:build container` tag | ✅ Complete |
| `internal/owadm/cmd/scan.go` | Added `//go:build container` tag | ✅ Complete |
| `internal/owadm/cmd/daemon.go` | Added `//go:build container` tag | ✅ Complete |

### Build Verification Results (2026-02-12)

Builds verified on Ubuntu 22.04 with Go 1.22.2:

**Native Build** (`go build -o bin/owadm-native ./cmd/owadm`):
```
OpenWatch Admin (owadm) - Administrative CLI for OpenWatch native installations.

Manages OpenWatch SCAP compliance scanning platform installed directly on the host.
For service lifecycle, use standard systemd commands (systemctl, journalctl).

Available Commands:
  backup           Backup OpenWatch database and configuration
  completion       Generate the autocompletion script for the specified shell
  create-admin     Create an admin user
  db-migrate       Run database migrations
  generate-secrets Generate security secrets and JWT keys
  health           Check health of OpenWatch components
  help             Help about any command
  restore          Restore OpenWatch from a backup
  validate-config  Validate OpenWatch configuration
```

**Container Build** (`go build -tags container -o bin/owadm-container ./cmd/owadm`):
```
OpenWatch Admin (owadm) - A fast, intuitive CLI for managing OpenWatch containers.

Available Commands:
  backup, completion, create-admin, db-migrate, exec, generate-secrets,
  health, help, logs, restore, scan, start, status, stop, validate-config
```

### Command Availability by Build (VERIFIED)

| Command | Native | Container | Description |
|---------|--------|-----------|-------------|
| `validate-config` | ✅ | ✅ | Validate /etc/openwatch/ow.yml |
| `backup` | ✅ | ✅ | Backup database + configuration |
| `restore` | ✅ | ✅ | Restore from backup |
| `db-migrate` | ✅ | ✅ | Run Alembic database migrations |
| `create-admin` | ✅ | ✅ | Create admin user |
| `generate-secrets` | ✅ | ✅ | Generate secrets and JWT keys |
| `health` | ✅ | ✅ | Health check all components |
| `completion` | ✅ | ✅ | Shell completion scripts |
| `start` | ❌ | ✅ | Start containers (use `systemctl` for native) |
| `stop` | ❌ | ✅ | Stop containers (use `systemctl` for native) |
| `status` | ❌ | ✅ | Container status (use `systemctl` for native) |
| `logs` | ❌ | ✅ | Container logs (use `journalctl` for native) |
| `exec` | ❌ | ✅ | Execute command in container |
| `scan` | ❌ | ✅ | Execute SCAP compliance scans |

### Native Build: owadm Commands

```go
// cmd/backup.go (included in all builds - no build tag)
package cmd

var backupCmd = &cobra.Command{
    Use:   "backup",
    Short: "Backup OpenWatch database and configuration",
    Long: `Create a backup of the OpenWatch PostgreSQL database and configuration files.

Example:
  owadm backup                          # Backup to default location
  owadm backup --output /backup/ow.tar  # Backup to specific file`,
    RunE: runBackup,
}

func runBackup(cmd *cobra.Command, args []string) error {
    // 1. pg_dump database
    // 2. Copy /etc/openwatch/ config files
    // 3. Create tarball
    return nil
}
```

```go
// cmd/db_migrate.go (included in all builds)
package cmd

var dbMigrateCmd = &cobra.Command{
    Use:   "db-migrate",
    Short: "Run database migrations",
    Long:  `Run Alembic database migrations to update the schema.`,
    RunE:  runDBMigrate,
}

func runDBMigrate(cmd *cobra.Command, args []string) error {
    // Execute: /opt/openwatch/venv/bin/alembic upgrade head
    return exec.Command(
        "/opt/openwatch/venv/bin/alembic",
        "-c", "/opt/openwatch/backend/alembic.ini",
        "upgrade", "head",
    ).Run()
}
```

```go
// cmd/health.go (included in all builds)
package cmd

var healthCmd = &cobra.Command{
    Use:   "health",
    Short: "Check health of OpenWatch components",
    RunE:  runHealth,
}

func runHealth(cmd *cobra.Command, args []string) error {
    // Check: PostgreSQL, Redis, API endpoint, worker processes
    // For native: also check systemd service states
    return nil
}
```

### Shared Code (All Builds)

These files remain unchanged and are included in all builds:

| File | Purpose |
|------|---------|
| `cmd/root.go` | Root command, flags, version info |
| `cmd/validate.go` | Config validation (fix deprecated ioutil) |
| `utils/helpers.go` | Random string generation, common utilities |

### Code Compatibility Matrix

| Go Feature | RHEL 8 | RHEL 9 | RHEL 10 |
|------------|--------|--------|---------|
| Go 1.21+ | Via EPEL/Module | Default | Default |
| crypto/rand | Supported | Supported | Supported |
| os.ReadFile | Go 1.16+ | Go 1.16+ | Go 1.16+ |
| context package | Supported | Supported | Supported |
| Build tags | Supported | Supported | Supported |

---

## Appendix: File Inventory

### Files Installed by RPM

```
/usr/bin/
└── owadm                             # Admin CLI (native build - manages systemd services)

/opt/openwatch/
├── venv/                             # Python virtual environment
│   ├── bin/
│   │   ├── python3.12
│   │   ├── uvicorn
│   │   ├── celery
│   │   └── alembic
│   └── lib/python3.12/site-packages/
├── backend/
│   ├── app/                          # FastAPI application
│   │   ├── main.py
│   │   ├── routes/
│   │   ├── services/
│   │   ├── models/
│   │   ├── tasks/
│   │   └── ...
│   ├── aegis/                        # Aegis engine + rules
│   │   ├── runner/
│   │   ├── rules/
│   │   └── config/
│   ├── alembic/                      # Database migrations
│   └── requirements.txt
└── frontend/                         # Built React application
    ├── index.html
    ├── static/
    └── assets/

/etc/openwatch/
├── ow.yml                            # Main configuration
├── secrets.env                       # Secrets (600 perms)
├── logging.yml                       # Logging configuration
├── jwt_private.pem                   # JWT signing key
├── jwt_public.pem                    # JWT verification key
└── ssl/
    ├── openwatch.crt                 # TLS certificate
    └── openwatch.key                 # TLS private key

/etc/nginx/conf.d/
└── openwatch.conf                    # Nginx configuration

/lib/systemd/system/
├── openwatch-api.service             # Backend API
├── openwatch-worker@.service         # Celery workers (template)
├── openwatch-beat.service            # Celery scheduler
└── openwatch.target                  # Target for all services

/var/lib/openwatch/
├── celery/                           # Celery scheduler state
├── exports/                          # Audit query exports (temporary)
└── ssh/                              # SSH known hosts cache
# NOTE: No SCAP content or results directories needed
# - Aegis rules bundled at /opt/openwatch/backend/aegis/rules/
# - Scan results stored in PostgreSQL scan_findings table
# - No user uploads required (SCAP import deprecated)

/var/log/openwatch/
├── api.log                           # API logs
├── worker-1.log                      # Worker logs
├── beat.log                          # Scheduler logs
└── audit.log                         # Audit trail

/usr/share/selinux/packages/
└── openwatch.pp               # SELinux policy module
```

---

## Summary

This plan provides a comprehensive approach to native RPM installation of OpenWatch:

1. **Primary native path** - `openwatch-*.rpm` for direct systemd deployment
2. **Container options** - `openwatch-do-*.rpm` (Docker), `openwatch-po-*.rpm` (Podman), `openwatch-ko-*.rpm` (Kubernetes)
3. **Standard RHEL patterns** - Service lifecycle via `systemctl`/`journalctl`, admin tasks via `owadm`
4. **Pure admin CLI** - `owadm` focuses on OpenWatch-specific tasks (backup, migrate, health), not service management
5. **Security-first** - SELinux, FIPS 140-2/140-3, proper permissions
6. **Broad OS support** - RHEL/Rocky/Oracle/AlmaLinux 8, 9, 10 + CentOS Stream + Fedora
7. **Migration support** - Path from container to native

**Estimated effort**: 4 weeks for initial release, 2 additional weeks for hardening

**Next steps**:
1. Refactor `owadm` with Go build tags (native vs container builds)
2. Fix deprecated `ioutil` usage in `validate.go`
3. Create native `openwatch.spec` (for `openwatch-*.rpm`)
4. Rename existing `openwatch.spec` to `openwatch-po.spec` (for `openwatch-po-*.rpm`)
5. Build and test on RHEL 8, 9, 10
6. Create migration scripts (container → native)
7. Document installation procedures

---

**Document Version**: 1.2.0
**Created**: 2026-02-12
**Author**: OpenWatch Team
