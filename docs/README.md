# OpenWatch documentation

An index of the operator documentation tracked in this repository. Every
document linked below is in the repository, so it is available from a clean
clone.

Start here: [Introduction](../README.md) | [Quickstart](guides/QUICKSTART.md)

This index links documents rather than restating what they say. Version
numbers, supported platforms, rule counts, permission counts and configuration
values live in the guides themselves, so there is one place to correct each of
them.

---

## Getting started

| Document | Description |
|----------|-------------|
| [Introduction](../README.md) | What OpenWatch does, how it compares, architecture and security overview |
| [Quickstart](guides/QUICKSTART.md) | First 15 minutes: log in, add a host, run a scan, read results |
| [Installation](guides/INSTALLATION.md) | Deploy from a native RPM or DEB package, or from source |

## Operator guides

| Document | Description |
|----------|-------------|
| [Scanning and compliance](guides/SCANNING_AND_COMPLIANCE.md) | Run scans, read posture scores, detect drift, manage alerts |
| [Hosts and remediation](guides/HOSTS_AND_REMEDIATION.md) | Add hosts, configure credentials, remediate findings, roll back |
| [User roles](guides/USER_ROLES.md) | Built-in roles, the permission registry, and the workflow for each role |
| [API guide](guides/API_GUIDE.md) | REST API reference for automation and CI/CD integration |
| [Verifying a report](guides/REPORT_VERIFICATION.md) | Check a report's content hash and Ed25519 signature, and what that does not prove |
| [Compliance controls](guides/COMPLIANCE_CONTROLS.md) | NIST, CIS, CMMC and FedRAMP control mapping |
| [Supported Linux distributions](guides/LINUX_DISTRIBUTION_SUPPORT.md) | Target distributions for the RPM and DEB packages |

## Operations

| Document | Description |
|----------|-------------|
| [Production deployment](guides/PRODUCTION_DEPLOYMENT.md) | Deployment procedures for the single `openwatch` binary |
| [Environment reference](guides/ENVIRONMENT_REFERENCE.md) | Environment variables and configuration settings |
| [Database migrations](guides/DATABASE_MIGRATIONS.md) | Migration procedures using `openwatch migrate` |
| [Monitoring setup](guides/MONITORING_SETUP.md) | Prometheus, Grafana and health checks |
| [Security hardening](guides/SECURITY_HARDENING.md) | TLS, FIPS, rate limiting and audit logging |
| [Scaling guide](guides/SCALING_GUIDE.md) | Horizontal scaling and performance tuning |
| [Backup and recovery](guides/BACKUP_RECOVERY.md) | PostgreSQL backup, restore and disaster recovery |
| [Secret rotation](guides/SECRET_ROTATION.md) | Rotating database, session and encryption keys |
| [Upgrade procedure](guides/UPGRADE_PROCEDURE.md) | Upgrading OpenWatch, with the rollback path |
| [Releasing](runbooks/RELEASING.md) | The gated pre-release process and signing-key setup |

## Incident response runbooks

| Runbook | Trigger |
|---------|---------|
| [Service down](guides/runbooks/SERVICE_DOWN.md) | Health check failure, service unavailable |
| [Database issues](guides/runbooks/DATABASE_ISSUES.md) | Connection errors, slow queries, replication lag |
| [High CPU](guides/runbooks/HIGH_CPU.md) | CPU use above threshold |
| [Disk full](guides/runbooks/DISK_FULL.md) | Disk space critically low |
| [Security incident](guides/runbooks/SECURITY_INCIDENT.md) | Unauthorized access, suspected breach |

## Other tracked references

| Document | Description |
|----------|-------------|
| [Guides index](guides/README.md) | A second index covering the `guides/` directory alone |
| [Changelog](../CHANGELOG.md) | Release history, including breaking changes and required operator actions |
| [Contributing](../CONTRIBUTING.md) | Contributor workflow, hooks and pull request rules |
| [Security policy](../SECURITY.md) | How to report a vulnerability |
| `api/openapi.yaml` | The API contract, and the source of truth for request and response shapes |
