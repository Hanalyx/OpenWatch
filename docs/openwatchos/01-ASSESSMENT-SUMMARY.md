# OpenWatch OS - Assessment Summary

OpenWatch is transforming from a manual SCAP scanner into a **Compliance Operating System** -- a platform that continuously monitors, measures, and reports on infrastructure compliance posture.

## Vision

Traditional compliance scanning is reactive: an operator runs a scan, reviews results, remediates, and scans again. OpenWatch OS makes compliance **continuous and automatic**. The system scans on adaptive schedules, collects server intelligence, generates alerts on drift, and presents a unified view of compliance posture over time.

## Core Principles

1. **Auto-scan centric** -- Kensa compliance checks run automatically on adaptive schedules (max 48-hour interval). Manual scan buttons are removed from the primary workflow.
2. **Server Intelligence** -- Collect packages, services, users, network configuration, firewall rules, and audit events via SSH during every scan.
3. **Clean UI** -- Purposeful icons only, minimal color, readability first. No decorative elements.
4. **Temporal compliance** -- Point-in-time posture queries, drift analysis, and historical trend tracking.

## Components and Status

| Component | Purpose | Status | Key PR |
|-----------|---------|--------|--------|
| ORSA v2.0 Plugin Interface | Standardized plugin API for compliance engines | Complete | -- |
| Temporal Compliance | Point-in-time posture, history, drift analysis | Complete | #275 |
| Governance Primitives | Compliance exceptions with approval workflow | Complete | -- |
| Audit Queries | Saved queries, export (CSV/JSON/PDF) | Complete | -- |
| Rule Reference UI | Browse 338 Kensa YAML rules with filtering | Complete | #276 |
| Alert Thresholds | Compliance/operational/drift alerts | Complete | #281 |
| Server Intelligence | Packages, services, users, network collection | Complete | #274 |
| Adaptive Compliance Scheduler | State-based scan intervals, auto-dispatch | Complete | #274 |
| Host Detail Page Redesign | Auto-scan centric UI, server intelligence tabs | In Progress | -- |
| Remediation + Subscription | Kensa Phase 4 -- automated remediation | Not Started | -- |
| OTA Updates | Kensa Phase 5 -- over-the-air rule updates | Not Started | -- |

## Architecture

```
                          +-------------------+
                          |   Celery Beat     |
                          | (every 2 minutes) |
                          +--------+----------+
                                   |
                          dispatch_compliance_scans
                                   |
                          +--------v----------+
                          |  Compliance       |
                          |  Scheduler Svc    |
                          +--------+----------+
                                   |
                    +--------------+--------------+
                    |              |              |
            +-------v--+  +-------v--+  +-------v--+
            | Kensa    |  | Kensa    |  | Kensa    |
            | Scan     |  | Scan     |  | Scan     |
            | (Host A) |  | (Host B) |  | (Host C) |
            +----+-----+  +----+-----+  +----+-----+
                 |              |              |
            +----v--------------v--------------v----+
            |          Results Pipeline             |
            |  - Store scan findings                |
            |  - Collect server intelligence        |
            |  - Update compliance score            |
            |  - Generate alerts                    |
            |  - Calculate next scan interval       |
            +---------------------------------------+
                              |
                    +---------v---------+
                    |    PostgreSQL      |
                    | scans, findings,   |
                    | host_schedule,     |
                    | host_packages, ... |
                    +-------------------+
```

## Kensa Integration Phases

| Phase | Feature | Status |
|-------|---------|--------|
| Phase 1 | ORSA v2.0 Plugin Interface | Complete |
| Phase 2 | Temporal Compliance | Complete |
| Phase 3 | Governance Primitives (Exceptions) | Complete |
| Phase 4 | Remediation + Subscription | Not Started |
| Phase 5 | OTA Updates | Not Started |
| Phase 6 | Audit Queries | Complete |

## UI Design Principles

- **Icons**: Only when they contribute to understanding. Status dots and severity indicators are acceptable; decorative icons are not.
- **Color**: Dark background, white/gray text, blue accent used sparingly. No color blocks for cards.
- **Typography**: Clear hierarchy with adequate whitespace. Data presented as plain text, not styled blocks.
- **Layout**: Summary cards in a grid (2 rows of 3), tabbed detail views beneath.

## Licensing Model

| Feature | Free | OpenWatch+ |
|---------|------|------------|
| Compliance scanning | Yes | Yes |
| Framework reporting | Yes | Yes |
| Basic dashboard | Yes | Yes |
| Temporal queries | -- | Yes |
| Structured exceptions | -- | Yes |
| Remediation | -- | Yes |
| Date range audit queries | -- | Yes |

## Related Documentation

- [Adaptive Compliance Scheduler](02-ADAPTIVE-COMPLIANCE-SCHEDULER.md) -- Auto-scan architecture
- [Alert Thresholds](03-ALERT-THRESHOLDS.md) -- Alert system design
- [Server Intelligence](04-SERVER-INTELLIGENCE.md) -- Data collection details
- [MongoDB Deprecation Plan](05-DEPRECATION-PLAN.md) -- Removal of legacy database
- [Host Detail Page Redesign](06-HOST-DETAIL-PAGE-REDESIGN.md) -- Frontend redesign
