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
