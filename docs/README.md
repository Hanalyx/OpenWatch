# OpenWatch Documentation

Production documentation for deploying, operating, and maintaining OpenWatch.

Start here: [Introduction](INTRODUCTION.md) | [Quickstart](guides/QUICKSTART.md)

> **⚠️ Migration note (2026-06-05).** OpenWatch is being rebuilt on Go (the Go tree
> now lives at the repo root); the Python implementation was archived to
> `~/hanalyx/OWAR/openwatch-python/`. Many operator guides and the design docs below
> were written for the Python/FastAPI container stack and reference `docker-compose`,
> `start-openwatch.sh`, Alembic, and Redis — these describe the **archived** stack and
> are pending a Go-era rewrite. The authoritative engineering docs for the active tree
> are under **`docs/engineering/`** and the specs under **`specs/`**.

---

## Getting Started

| Document | Description |
|----------|-------------|
| [Introduction](INTRODUCTION.md) | Platform philosophy, architecture overview, supported frameworks |
| [Quickstart](guides/QUICKSTART.md) | First 15 minutes: log in, add a host, run a scan, read results |
| [Installation](guides/INSTALLATION.md) | Deploy from a native RPM/DEB package or from source |

## Operator Guides

| Document | Description |
|----------|-------------|
| [Scanning and Compliance](guides/SCANNING_AND_COMPLIANCE.md) | Run scans, read posture scores, detect drift, manage alerts |
| [Hosts and Remediation](guides/HOSTS_AND_REMEDIATION.md) | Add hosts, configure credentials, remediate findings, rollback |
| [User Roles](guides/USER_ROLES.md) | 6 roles, 33 permissions, workflows per role |
| [API Guide](guides/API_GUIDE.md) | REST API reference for automation and CI/CD integration |

## Operations

| Document | Description |
|----------|-------------|
| [Production Deployment](guides/PRODUCTION_DEPLOYMENT.md) | Production deployment procedures for the single `openwatch` binary |
| [Environment Reference](guides/ENVIRONMENT_REFERENCE.md) | All environment variables and configuration |
| [Database Migrations](guides/DATABASE_MIGRATIONS.md) | Migration procedures via `openwatch migrate` (migrations in `internal/db/migrations/`) |
| [Monitoring Setup](guides/MONITORING_SETUP.md) | Prometheus, Grafana, and health checks |
| [Security Hardening](guides/SECURITY_HARDENING.md) | TLS, FIPS, rate limiting, audit logging |
| [Scaling Guide](guides/SCALING_GUIDE.md) | Horizontal scaling and performance tuning |
| [Backup & Recovery](guides/BACKUP_RECOVERY.md) | PostgreSQL backup, restore, and disaster recovery |
| [Secret Rotation](guides/SECRET_ROTATION.md) | Rotating database, session, and encryption keys |
| [Upgrade Procedure](guides/UPGRADE_PROCEDURE.md) | Upgrading OpenWatch with rollback procedures |
| [Releasing](runbooks/RELEASING.md) | Gated pre-release process: docs freeze → RC → verification gate → GA, plus signing-key setup |
| [Compliance Controls](guides/COMPLIANCE_CONTROLS.md) | NIST, CIS, CMMC, FedRAMP control mapping |

## Incident Response Runbooks

| Runbook | Trigger |
|---------|---------|
| [Service Down](runbooks/SERVICE_DOWN.md) | Health check failure, service unavailable |
| [Database Issues](runbooks/DATABASE_ISSUES.md) | Connection errors, slow queries, replication lag |
| [High CPU](runbooks/HIGH_CPU.md) | CPU utilization above threshold |
| [Disk Full](runbooks/DISK_FULL.md) | Disk space critically low |
| [Security Incident](runbooks/SECURITY_INCIDENT.md) | Unauthorized access, data breach |

## Architecture

| Document | Description |
|----------|-------------|
| [Kensa Integration](architecture/KENSA_INTEGRATION.md) | Kensa compliance engine integration manual |

For installing OpenWatch from the native RPM/DEB, see
[guides/INSTALLATION.md](guides/INSTALLATION.md). (The earlier owadm-based
"Native RPM Installation Plan" was superseded by the single-`openwatch`-binary
model and archived.)

> **Design documents** — the Python-era `openwatchos/` planning sketches and other
> dated planning/review docs were archived to `~/hanalyx/OWAR/openwatch-python/docs-archive/`.
> Current design direction lives in `docs/engineering/openwatch_roadmap.md` and the Go-era
> vision/plan docs (`OPENWATCH_VISION*.md`, `OPENWATCH_Q*_PLAN.md`) in this directory.

---

## Quick Links

- **Health Check**: `GET /health`
- **Run the Go backend (dev)**: `go build -o dist/openwatch ./cmd/openwatch && ./dist/openwatch serve` (port 8443)
- **Run the frontend (dev)**: `cd frontend && npm install && npm run dev` (port 5173)
- **API contract**: `api/openapi.yaml` (source of truth)

> The `start-openwatch.sh` / `docker-compose` container flow was Python-era and is
> archived; a Go-native container/packaging flow is being re-established under `packaging/`.
