# BACKLOG.md - OpenWatch Prioritized Work Queue

> **Purpose**: Single source of truth for all pending work items, prioritized and actionable.
> Updated at the end of each AI session. Items flow in from PRD epics, bug reports, and session discoveries.

**Last Updated**: 2026-02-23

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
| E3-S9 | Architecture Decision Records | P2 | Complete | 3 ADRs: PostgreSQL, Kensa, modular services |
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

## Recently Completed (2026-02-23)

| Item | PR | Notes |
|------|----|-------|
| Framework mapping file sync | #304 | PCI DSS now shows ~120 rules (was 2), FedRAMP added as new framework |
| README rewrite | #306 | Value-first messaging, dashboard screenshot, "Deploy in 10 Minutes" |
| GitHub Discussions enabled | [#305](https://github.com/Hanalyx/OpenWatch/discussions/305) | Welcome post created, default categories active |
| CLAUDE.md size reduction | — | 50.7k → 39.8k chars (gitignored, local only) |
| Aegis to Kensa migration | commit 59cba9ee | Full rename across codebase |

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
| MongoDB Legacy Code Removal | P2 | **Complete** | PR #295: 80 files changed, 19,488 deletions |
| Remediation + Subscription (Phase 4) | P3 | Not Started | Kensa integration Phase 4. See K-2, K-3, K-4 for detailed gaps. |
| OTA Updates (Phase 5) | P3 | Not Started | Kensa integration Phase 5 |

---

## Kensa Integration Gaps

Gaps identified by comparing `docs/KENSA_DEVELOPER_GUIDE_V0.md` against current OpenWatch implementation (2026-02-23).

### Not Implemented

| ID | Item | Priority | Notes |
|----|------|----------|-------|
| K-1 | **Full Evidence storage** | P1 | `scan_findings` only stores `detail` string. Kensa returns `method`, `command`, `stdout`, `stderr`, `exit_code`, `expected`, `actual`, `timestamp` — need `evidence JSONB` column. Blocks audit artifact export and field-level drift. |
| K-2 | **Remediation workflow** | P1 | `orsa_plugin.py` can call `remediate_rule()` but no user-facing workflow exists: no API endpoints to trigger remediation, no Celery task, no dry-run approval UI, no before/after comparison, no remediation tracking dashboard, no fix-rate metrics. |
| K-3 | **Rollback** | P2 | `orsa_plugin.py:531-559` is a stub (`# TODO`). No pre-state snapshot storage, no rollback handler calls, no `kensa rollback` integration. Depends on K-2. |
| K-4 | **Risk-aware remediation policies** | P2 | Kensa classifies remediation steps as high/medium/low risk. Not used for approval gates (e.g., auto-approve low-risk, require human approval for high-risk GRUB/PAM/fstab changes). |
| K-5 | **Snapshot retention/pruning** | P3 | Kensa has 7-day active / 90-day archive lifecycle for pre-state snapshots. No integration. Depends on K-3. |
| K-6 | **`get_applicable_mappings()`** | P3 | Kensa can filter mappings by platform (RHEL 8 vs 9). OpenWatch loads all mappings without platform filtering. |
| K-7 | **`build_rule_to_section_map()`** | P3 | Kensa utility for `rule_id → section_id`. Not used — DB queries used instead. |
| K-8 | **Inventory file support** | P3 | Kensa accepts INI/YAML/text inventory files. OpenWatch creates individual SSH sessions from host DB. Low value — OpenWatch's approach is correct for its architecture. |

### Partially Implemented

| ID | Item | Priority | Current State | Missing |
|----|------|----------|---------------|---------|
| K-9 | **Field-level drift detection** | P1 | `TemporalComplianceService.detect_drift()` compares pass/fail status | No `actual` value comparison across scans (e.g., config changed from `no` to `yes`). Depends on K-1. |
| K-10 | **Platform filtering** | P2 | `detect_platform()` called, info captured | `rule_applies_to_platform()` not used to filter rules before evaluation |
| K-11 | **Host context in evidence** | P2 | `SystemInfoCollector` gathers packages, services, users, network | Not stored alongside scan findings; host groups and effective variables not in evidence exports |
| K-12 | **Parallel workers** | P3 | `max_concurrent_checks` config exists (default 10) | Unclear if Kensa's worker parallelism is actually used during scans |

### Highest-Impact Items

1. **K-1 (Evidence storage)** — Unlocks audit artifact export, field-level drift (K-9), and evidence-based reporting
2. **K-2 (Remediation workflow)** — Plugin-level call exists but no user-facing workflow, API, or UI
3. **K-9 (Field-level drift)** — Depends on K-1; enables "PermitRootLogin changed from no to yes" alerts
4. **K-3 (Rollback)** — Remediation has no undo path; depends on K-2

---

## Technical Debt

| Item | Priority | Notes |
|------|----------|-------|
| MongoDB packages in requirements.txt | P3 | **Complete** - removed in PR #295 |
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
