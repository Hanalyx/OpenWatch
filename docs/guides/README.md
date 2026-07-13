# OpenWatch operator guides

Operator and administrator documentation for OpenWatch. The current
general-availability release is `v0.3.0`; confirm the version you are running with
`GET /api/v1/health` or `openwatch --version`.

## Getting started

- [Quickstart](QUICKSTART.md) — install and reach a working server fast.
- [Install guide](INSTALLATION.md) — native RPM and DEB packages, step by step.
- [Linux distribution support](LINUX_DISTRIBUTION_SUPPORT.md) — tested targets.

## Deploy and operate

- [Production deployment](PRODUCTION_DEPLOYMENT.md) — hardened production setup.
- [Configuration and environment reference](ENVIRONMENT_REFERENCE.md) — every setting.
- [Monitoring and operations](MONITORING_SETUP.md) — health, metrics, day-2 ops.
- [Backup and recovery](BACKUP_RECOVERY.md) — back up and restore data.
- [Upgrade procedure](UPGRADE_PROCEDURE.md) — move between releases safely.
- [Database migrations](DATABASE_MIGRATIONS.md) — how schema changes are applied.
- [Scaling guide](SCALING_GUIDE.md) — grow with fleet size.

## Security

- [Security hardening](SECURITY_HARDENING.md) — lock down a deployment.
- [Secret rotation](SECRET_ROTATION.md) — rotate keys and credentials.
- [User roles and permissions](USER_ROLES.md) — the RBAC model.

## Compliance and scanning

- [Scanning and compliance](SCANNING_AND_COMPLIANCE.md) — run scans, read results.
- [Compliance control mapping](COMPLIANCE_CONTROLS.md) — frameworks and controls.
- [Host management and remediation](HOSTS_AND_REMEDIATION.md) — manage hosts, apply fixes.

## API

- [API guide](API_GUIDE.md) — the REST API surface and usage.

## Runbooks

Incident response procedures live in [runbooks/](runbooks/): service down, database
issues, disk full, high CPU, and security incident response.
