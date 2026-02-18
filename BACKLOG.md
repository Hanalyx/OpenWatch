# BACKLOG.md - OpenWatch Prioritized Work Queue

> **Purpose**: Single source of truth for all pending work items, prioritized and actionable.
> Updated at the end of each AI session. Items flow in from PRD epics, bug reports, and session discoveries.

**Last Updated**: 2026-02-18

---

## Priority Legend

| Priority | Meaning |
|----------|---------|
| P0 | Blocker - must be done before production |
| P1 | High - needed for production readiness |
| P2 | Medium - improves quality, can defer |
| P3 | Low - nice to have |

---

## Active Epics

### E3: Documentation Reorganization (P1, Complete)

| ID | Story | Priority | Status | Notes |
|----|-------|----------|--------|-------|
| E3-S1 | Create Documentation Index | P0 | Complete | `docs/README.md` with navigation |
| E3-S2 | Create Archive Structure | P1 | Complete | Scope reduced - 2 docs relocated to `architecture/` |
| E3-S3 | Production Deployment Guide | P0 | Complete | `docs/guides/PRODUCTION_DEPLOYMENT.md` |
| E3-S4 | Environment Variable Reference | P0 | Complete | `docs/guides/ENVIRONMENT_REFERENCE.md` |
| E3-S5 | Monitoring Setup Guide | P1 | Complete | `docs/guides/MONITORING_SETUP.md` |
| E3-S6 | Database Migration Guide | P1 | Complete | `docs/guides/DATABASE_MIGRATIONS.md` |
| E3-S7 | Security Hardening Guide | P1 | Complete | `docs/guides/SECURITY_HARDENING.md` |
| E3-S8 | Scaling Guide | P2 | Complete | `docs/guides/SCALING_GUIDE.md` |
| E3-S9 | Architecture Decision Records | P2 | Complete | 3 ADRs: PostgreSQL, Aegis, modular services |
| E3-S10 | Update Context Files | P1 | Complete | `context/QUICK_REFERENCE.md`, `DEBUGGING_GUIDE.md` |
| E3-S11 | Categorize and Move Active Docs | P1 | Complete | 2 docs relocated to `docs/architecture/` |

---

### E6: Production Hardening (P1, Complete)

**Depends On**: E1 (Complete), E2 (Complete), E3 (Complete), E5 (Complete)

| ID | Story | Priority | Status | Notes |
|----|-------|----------|--------|-------|
| E6-S1 | Production Docker Compose | P0 | Complete | `docker-compose.prod.yml` |
| E6-S2 | Security Hardening Checklist | P0 | Complete | Covered by E3 `SECURITY_HARDENING.md` section 13 |
| E6-S3 | Monitoring Dashboard Setup | P1 | Complete | `monitoring/config/` (prometheus, alertmanager, 3 Grafana dashboards) |
| E6-S4 | Backup and Recovery Procedures | P0 | Complete | `docs/guides/BACKUP_RECOVERY.md` |
| E6-S5 | Incident Response Runbooks | P1 | Complete | `docs/runbooks/` (5 runbooks) |
| E6-S6 | Log Aggregation Setup | P2 | Complete | JSON logging in `docker-compose.prod.yml` |
| E6-S7 | Secret Rotation Procedures | P1 | Complete | `docs/guides/SECRET_ROTATION.md` |
| E6-S8 | Performance Baseline | P2 | Complete | `k6/baseline.js`, `k6/stress.js` |
| E6-S9 | Upgrade Procedures | P1 | Complete | `docs/guides/UPGRADE_PROCEDURE.md` |
| E6-S10 | Compliance Documentation | P2 | Complete | `docs/guides/COMPLIANCE_CONTROLS.md` (NIST/CIS/CMMC/FedRAMP) |

---

## Stretch Goals (from completed epics)

These items were deferred when their parent epics were marked "Complete" with baselines in place.

| ID | Item | Priority | Source | Notes |
|----|------|----------|--------|-------|
| E5-G1 | Raise backend coverage to 80% | P2 | E5 | Currently 32%, CI threshold 31% |
| E5-G2 | Raise frontend coverage to 60% | P2 | E5 | Currently 1.5%, 88 tests |
| E5-G3 | JWT token tests | P1 | E5-S2 | `test_jwt.py` not yet written |
| E5-G4 | Credential encryption tests | P1 | E5-S3 | `test_credential_encryption.py` not yet written |
| E5-G5 | Scan integration tests | P1 | E5-S4 | `test_scan_api.py`, `test_scan_workflow.py` pending |
| E5-G6 | Auth integration tests | P1 | E5-S2 | `test_auth_api.py` pending |
| E5-G7 | Regression test README | P2 | E5-S9 | Process documentation for `tests/regression/` |

---

## OpenWatch OS Remaining Work

Items from the OpenWatch OS transformation initiative that are not yet complete.

| Item | Priority | Status | Notes |
|------|----------|--------|-------|
| Adaptive Compliance Scheduler | P1 | Planned | Auto-scan with state-based intervals (max 48h) |
| Host Detail Page Redesign | P1 | In Progress | Phase 0 done (backend data fix), Phases 1-6 pending |
| MongoDB Legacy Code Removal | P2 | Planned | 5-phase plan in [`docs/openwatchos/05-DEPRECATION-PLAN.md`](docs/openwatchos/05-DEPRECATION-PLAN.md) (26 files, ~5-7h) |
| Remediation + Subscription (Phase 4) | P3 | Not Started | Aegis integration Phase 4 |
| OTA Updates (Phase 5) | P3 | Not Started | Aegis integration Phase 5 |

---

## Technical Debt

| Item | Priority | Notes |
|------|----------|-------|
| MongoDB packages in requirements.txt | P3 | Kept for import compatibility only; remove after full deprecation |
| 3 oversized frontend components noted in PRD | P2 | E4 marked Complete but verify ScanDetail/Hosts/AddHost sizes |
| Frontend state management inconsistency | P2 | Redux Toolkit + React Query + Direct Services (3 patterns) |
| Snake_case to camelCase scattered transformation | P2 | No centralized adapters (Rule Reference has one, others don't) |

---

## How to Use This File

1. **Starting a session**: Read this file to understand current priorities
2. **Picking work**: Start from the top of the highest-priority active epic
3. **Completing work**: Update status here and in the relevant PRD epic file
4. **Discovering new work**: Add items to the appropriate section
5. **Ending a session**: Update statuses and add any new items discovered
