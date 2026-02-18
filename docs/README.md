# OpenWatch Documentation

Production documentation for deploying, operating, and maintaining OpenWatch.

## Guides

| Document | Description |
|----------|-------------|
| [Production Deployment](guides/PRODUCTION_DEPLOYMENT.md) | Deploy OpenWatch with Docker/Podman |
| [Environment Reference](guides/ENVIRONMENT_REFERENCE.md) | All environment variables and configuration |
| [Database Migrations](guides/DATABASE_MIGRATIONS.md) | Alembic migration procedures and rollback |
| [Monitoring Setup](guides/MONITORING_SETUP.md) | Prometheus, Grafana, and health checks |
| [Security Hardening](guides/SECURITY_HARDENING.md) | TLS, FIPS, rate limiting, audit logging |
| [Scaling Guide](guides/SCALING_GUIDE.md) | Horizontal scaling and performance tuning |
| [Backup & Recovery](guides/BACKUP_RECOVERY.md) | PostgreSQL backup, restore, and disaster recovery |
| [Secret Rotation](guides/SECRET_ROTATION.md) | Rotating database, Redis, JWT, and encryption keys |
| [Upgrade Procedure](guides/UPGRADE_PROCEDURE.md) | Upgrading OpenWatch with rollback procedures |
| [Compliance Controls](guides/COMPLIANCE_CONTROLS.md) | NIST, CIS, CMMC, FedRAMP control mapping |

## Incident Response Runbooks

| Runbook | Trigger |
|---------|---------|
| [Service Down](runbooks/SERVICE_DOWN.md) | Health check failure, service unavailable |
| [Database Issues](runbooks/DATABASE_ISSUES.md) | Connection errors, slow queries, replication lag |
| [High CPU](runbooks/HIGH_CPU.md) | CPU utilization above threshold |
| [Disk Full](runbooks/DISK_FULL.md) | Disk space critically low |
| [Security Incident](runbooks/SECURITY_INCIDENT.md) | Unauthorized access, data breach |

## OpenWatch OS Transformation

Design documentation for the Compliance Operating System initiative.

| Document | Description |
|----------|-------------|
| [Assessment Summary](openwatchos/01-ASSESSMENT-SUMMARY.md) | Vision, components, and status overview |
| [Adaptive Compliance Scheduler](openwatchos/02-ADAPTIVE-COMPLIANCE-SCHEDULER.md) | Auto-scan with state-based intervals |
| [Alert Thresholds](openwatchos/03-ALERT-THRESHOLDS.md) | Compliance, operational, and drift alerts |
| [Server Intelligence](openwatchos/04-SERVER-INTELLIGENCE.md) | Package, service, user, network collection |
| [MongoDB Deprecation Plan](openwatchos/05-DEPRECATION-PLAN.md) | 5-phase legacy code removal |
| [Host Detail Page Redesign](openwatchos/06-HOST-DETAIL-PAGE-REDESIGN.md) | Auto-scan centric UI redesign |

## Architecture

| Document | Description |
|----------|-------------|
| [Aegis Integration](architecture/AEGIS_INTEGRATION.md) | Aegis compliance engine integration manual |
| [Native RPM Installation](architecture/NATIVE_RPM_INSTALLATION.md) | RPM-based deployment design |

## Architecture Decision Records

| ADR | Title | Status |
|-----|-------|--------|
| [ADR-001](decisions/ADR-001-postgresql-primary-database.md) | PostgreSQL as primary database | Accepted |
| [ADR-002](decisions/ADR-002-aegis-compliance-engine.md) | Aegis replaces OpenSCAP | Accepted |
| [ADR-003](decisions/ADR-003-modular-service-architecture.md) | Modular service package pattern | Accepted |

## Quick Links

- **API Documentation**: `http://localhost:8000/api/docs` (Swagger UI, running instance required)
- **Health Check**: `GET /health`
- **Start Services**: `./start-openwatch.sh --runtime docker --build`
- **Stop Services**: `./stop-openwatch.sh`
- **Load Tests**: See [k6/README.md](../k6/README.md)
