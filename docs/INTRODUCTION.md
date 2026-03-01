# Introduction to OpenWatch

## What is OpenWatch

OpenWatch is a continuous compliance platform for Linux infrastructure. It connects to servers over SSH, runs compliance checks via the Kensa engine, and provides visibility into compliance posture over time. OpenWatch answers not just what is passing now, but what was passing last week, what drifted since the last scan, and what needs immediate attention. All findings include machine-generated evidence, framework mappings, and timestamps suitable for audit review.

---

## The Problem

Compliance in most environments is manual, fragmented, and reactive.

- **Point-in-time scans decay immediately.** A passing result from last Tuesday says nothing about today. Without continuous scanning, compliance status is unknown between assessments.
- **Historical questions are unanswerable.** When an auditor asks "were you compliant on January 15th?", the answer requires re-scanning infrastructure that may have changed. If the environment was rebuilt, the answer is lost entirely.
- **Exceptions live in spreadsheets.** Waiver approvals, risk acceptances, and compensating controls are tracked outside the scanning tool. There is no link between the exception and the finding it covers.
- **Drift is invisible until the next audit.** A configuration change at 2 AM on a Saturday will not surface until someone manually re-scans the host or an auditor flags it weeks later.
- **Evidence is assembled after the fact.** Instead of generating evidence during checks, teams spend days before audits collecting screenshots, command outputs, and configuration files to prove compliance.

These gaps create risk. They also create unnecessary work for teams that are already stretched thin. The typical result is that compliance becomes an audit preparation exercise -- a burst of activity before an assessment, followed by months of unknown state.

OpenWatch eliminates this cycle.

---

## The Solution: See, Scan, Secure

OpenWatch addresses each of these problems through three capabilities.

### See

The dashboard provides real-time compliance posture across all managed hosts. Historical trend data shows how posture has changed over days, weeks, and months. Drift alerts notify operators when a previously-passing check begins failing. Point-in-time queries answer "what was the state on this date?" without re-scanning.

### Scan

The Kensa compliance engine runs 338 YAML-based rules over SSH connections. Each rule maps to one or more compliance frameworks simultaneously. A single scan produces results for CIS, STIG, NIST 800-53, PCI-DSS, and FedRAMP without running separate tools for each framework. Rules detect OS capabilities at runtime rather than requiring per-distribution configuration.

### Secure

When findings are identified, OpenWatch provides remediation workflows. Automated fixes include rollback capability in case a remediation introduces unintended side effects. Exception governance tracks waivers through an approval workflow with expiration dates. All scan results, remediations, and exceptions produce audit-ready evidence packages.

---

## Core Values

1. **Security-First** -- Every feature is designed with security as the primary requirement. Authentication uses Argon2id password hashing. API tokens use RS256 JWT. All SSH credentials are encrypted at rest with AES-256-GCM. Audit logging covers every authentication and authorization event.

2. **Transparency** -- Compliance status is visible at all times. There is no hidden state. Dashboard views, API endpoints, and audit exports all reflect the same underlying data. When a check fails, the evidence explains why.

3. **Automation** -- Manual effort is reduced through intelligent scanning schedules and automated remediation. Operators configure policies once. The platform enforces them continuously.

4. **Rule-Based Compliance** -- One rule set covers many frameworks. Kensa rules declare what to check and how to evaluate the result. Framework mappings are maintained separately, so adding a new framework does not require writing new rules. Capabilities are detected at runtime, not hardcoded per operating system.

---

## Operating Principle

Compliance should be a seamless part of operations, not a periodic burden.

Kensa scans run on adaptive schedules based on host compliance state:

| Host State | Scan Interval | Rationale |
|------------|---------------|-----------|
| Healthy | Every 24 hours | Baseline monitoring, low overhead |
| Degraded | Every 6 hours | Track remediation progress |
| Critical | Every 1 hour | Rapid feedback on urgent fixes |

These intervals are configurable per policy. No manual scanning is required for day-to-day operations.

When scan results change, the platform generates alerts based on configurable thresholds. Operators respond to alerts rather than polling dashboards. This shifts compliance from a reactive audit preparation exercise to a continuous operational practice.

---

## Architecture at a Glance

OpenWatch runs as six Docker containers.

```
+---------------------------------------------------+
|  openwatch-frontend  (React 19, Nginx)      :3000 |
+---------------------------------------------------+
|  openwatch-backend   (FastAPI, Python 3.12) :8000 |
+------------------------+--------------------------+
|  openwatch-worker      |  openwatch-celery-beat   |
|  (Celery task workers) |  (Periodic scheduler)    |
+------------------------+--------------------------+
|  openwatch-db          |  openwatch-redis         |
|  (PostgreSQL 15)       |  (Redis 7.4)             |
+------------------------+--------------------------+
```

**Frontend** serves the React application through Nginx. All API requests are proxied to the backend.

**Backend** exposes the REST API via FastAPI. It handles authentication, authorization, scan management, compliance queries, and framework mappings.

**Worker** processes asynchronous tasks including scan execution, result parsing, alert evaluation, and remediation jobs. Workers connect to target hosts over SSH using credentials encrypted in the database.

**Celery Beat** triggers scheduled scans based on adaptive compliance policies. It enqueues scan tasks for the worker pool.

**PostgreSQL** stores all persistent data: hosts, scans, findings, users, exceptions, alerts, framework mappings, and audit logs. All primary keys are UUIDs.

**Redis** serves as the Celery message broker and result backend. It also provides caching for frequently accessed compliance data.

**Kensa** is the compliance engine installed on the backend container. It is maintained as a separate project and installed via pip. Kensa connects to target hosts over SSH, executes rule checks, and returns structured results with evidence. It does not store results, manage exceptions, or provide a UI -- those responsibilities belong to OpenWatch.

All inter-service communication stays within the Docker network. The only externally exposed ports are 3000 (frontend) and 8000 (API). Target hosts are reached over SSH from the worker containers.

---

## Who OpenWatch Is For

**System Administrators** managing compliance across a Linux fleet. OpenWatch connects to hosts they already manage via SSH, runs checks on their schedule, and surfaces findings that need attention.

**Security Engineers** building and enforcing security baselines. The rule reference interface shows every check Kensa performs, which frameworks it satisfies, and what evidence it collects.

**Security Analysts** investigating compliance drift and remediation effectiveness. Point-in-time queries and trend data support root cause analysis when compliance degrades.

**Compliance Officers** preparing for audits and generating evidence packages. Temporal compliance queries produce the exact posture at any historical date. Exception governance provides auditable waiver records.

**Auditors** reviewing compliance posture and exceptions. Audit export endpoints produce structured data covering findings, evidence, exceptions, and remediation history.

These roles are not mutually exclusive. OpenWatch provides role-based access control so each user sees the views and actions relevant to their responsibilities.

---

## Supported Frameworks

Kensa rules map to the following compliance frameworks.

| Framework | Mapping ID | Rules |
|-----------|------------|-------|
| CIS RHEL 9 v2.0.0 | cis-rhel9-v2.0.0 | 271 |
| STIG RHEL 9 V2R7 | stig-rhel9-v2r7 | 338 |
| NIST 800-53 R5 | nist-800-53-r5 | 87 |
| PCI-DSS v4.0 | pci-dss-v4.0 | 45 |
| FedRAMP Moderate | fedramp-moderate | 87 |

A single scan evaluates all applicable rules. Framework filtering is applied at query time, not scan time. Adding support for a new framework requires only a mapping file -- no new rules or scanner changes.

Rule counts reflect current Kensa mapping files. As Kensa releases new rule versions, these counts will change. The Rule Reference interface in the OpenWatch UI shows the current rule inventory, organized by framework, severity, and category.

---

## What's Next

- [Quickstart Guide](guides/QUICKSTART.md) -- First 15 minutes with OpenWatch
- [Installation Guide](guides/INSTALLATION.md) -- Deployment options and configuration
- [User Roles](guides/USER_ROLES.md) -- Permissions and workflows
- [Scanning and Compliance](guides/SCANNING_AND_COMPLIANCE.md) -- Scan lifecycle, frameworks, and posture queries
- [Hosts and Remediation](guides/HOSTS_AND_REMEDIATION.md) -- Host management, remediation, and exception workflows
- [API Guide](guides/API_GUIDE.md) -- Automation and integration reference
