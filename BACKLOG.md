# BACKLOG.md - OpenWatch Prioritized Work Queue

> **Purpose**: Single source of truth for all pending work items, prioritized and actionable.
> Updated at the end of each AI session. Items flow in from PRD epics, bug reports, and session discoveries.

**Last Updated**: 2026-03-06

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

## Recently Completed (2026-03-06)

| Item | PR | Notes |
|------|----|-------|
| SDD Phase 6: CI enforcement, advisory drift check, 100% AC coverage | #335 | `spec-checks` CI job (mandatory schema + coverage), `check-spec-changes.py` (advisory), 306/306 ACs; SPEC_GOVERNANCE.md maintenance process |
| SDD Phase 5: 10 API contract specs promoted to active | #333 | error-model + 9 API route contracts; 150 unit tests; 32 active specs total |
| SDD Phase 4: auth/RBAC specs promoted to active | #332 | authentication, authorization, encryption, mfa, security-controls; 145 tests; fixed Permission count 31→33 |
| SDD Phase 3: 4 compliance specs promoted to active | #331 | temporal-compliance, exception-governance, alert-thresholds, drift-analysis; 117 tests |
| SDD Phase 2: 5 specs promoted to active | #328, #329, #330 | remediation-lifecycle, remediation-execution, risk-classification, ssh-security, ssh-connection |
| SDD Phase 1: scan pipeline specs | prior PRs | kensa-scan, scan-orchestration, drift-detection, orsa-v2 |
| K-9 Field-level drift detection | #308 | Full implementation: snapshot population fix, value drift, group drift, CSV export, backfill task |
| K-1 Full Evidence storage | #307 | `evidence JSONB` column on `scan_findings`, populated during Kensa scans |
| Framework mapping file sync | #304 | PCI DSS now shows ~120 rules (was 2), FedRAMP added as new framework |
| README rewrite | #306 | Value-first messaging, dashboard screenshot, "Deploy in 10 Minutes" |
| Aegis to Kensa migration | commit 59cba9ee | Full rename across codebase |

---

## Stretch Goals (from completed epics)

These items were deferred when their parent epics were marked "Complete" with baselines in place.

| ID | Item | Priority | Source | Notes |
|----|------|----------|--------|-------|
| E5-G1 | Raise backend coverage to 80% | P2 | E5 | Currently 32%, CI threshold 31% |
| E5-G2 | Raise frontend coverage to 60% | P2 | E5 | Currently 1.5%, 88 tests |
| E5-G3 | JWT token tests | P1 | E5-S2 | **Satisfied by SDD**: `test_auth_api.py` covers JWT (AC-5..AC-9 in auth/login spec) |
| E5-G4 | Credential encryption tests | P1 | E5-S3 | **Satisfied by SDD**: `test_auth_api.py` + auth/encryption specs cover key behaviors |
| E5-G5 | Scan integration tests | P1 | E5-S4 | **Satisfied by SDD**: `test_scan_api.py` (36 source-inspection tests, 10/10 ACs) |
| E5-G6 | Auth integration tests | P1 | E5-S2 | **Satisfied by SDD**: `test_auth_api.py` (24 source-inspection tests, 10/10 ACs) |
| E5-G7 | Regression test README | P2 | E5-S9 | Process documentation for `tests/regression/` |

---

## OpenWatch OS Remaining Work

Items from the OpenWatch OS transformation initiative that are not yet complete.

| Item | Priority | Status | Notes |
|------|----------|--------|-------|
| **Host monitoring spec + bug fix** | P1 | Spec required | Write `specs/services/monitoring/host-monitoring.spec.yaml` (Tier 1: state machine, scan eligibility, compliance implications), then fix `MonitoringState` enum. Unblocks Adaptive Scheduler. |
| Adaptive Compliance Scheduler | P1 | Planned | Depends on monitoring spec. Auto-scan with state-based intervals (max 48h). |
| Host Detail Page Redesign | P1 | In Progress | Phase 0 done (backend data fix), Phases 1-6 pending |
| MongoDB Legacy Code Removal | P2 | **Complete** | PR #295: 80 files changed, 19,488 deletions |
| Remediation + Subscription (Phase 4) | P3 | Mostly Complete | K-2 and K-3 complete. Remaining: K-4 (risk-aware policies), K-5 (snapshot retention). |
| OTA Updates (Phase 5) | P3 | Not Started | Kensa integration Phase 5 |

---

## Kensa Integration Gaps

Gaps identified by comparing `docs/KENSA_DEVELOPER_GUIDE_V0.md` against current OpenWatch implementation (2026-02-23).

### Not Implemented

| ID | Item | Priority | Notes |
|----|------|----------|-------|
| K-1 | **Full Evidence storage** | P1 | **Complete** (PR #307). `evidence JSONB` column added to `scan_findings`, populated during Kensa scans. |
| K-2 | **Remediation workflow** | P1 | **Complete**. Full workflow existed (RemediationService, 9 API endpoints, Celery tasks, frontend RemediationPanel). Fixed 3 bugs: missing `manual` enum value, rollback task routing, duplicate alerts_router. |
| K-3 | **Rollback** | P2 | **Complete** (implemented as part of K-2). Rollback API endpoint, Celery task, and frontend UI all functional. |
| K-4 | **Risk-aware remediation policies** | P2 | Kensa classifies remediation steps as high/medium/low risk. Not used for approval gates (e.g., auto-approve low-risk, require human approval for high-risk GRUB/PAM/fstab changes). |
| K-5 | **Snapshot retention/pruning** | P3 | Kensa has 7-day active / 90-day archive lifecycle for pre-state snapshots. No integration. Depends on K-3. |
| K-6 | **`get_applicable_mappings()`** | P3 | Kensa can filter mappings by platform (RHEL 8 vs 9). OpenWatch loads all mappings without platform filtering. |
| K-7 | **`build_rule_to_section_map()`** | P3 | Kensa utility for `rule_id → section_id`. Not used — DB queries used instead. |
| K-8 | **Inventory file support** | P3 | Kensa accepts INI/YAML/text inventory files. OpenWatch creates individual SSH sessions from host DB. Low value — OpenWatch's approach is correct for its architecture. |

### Partially Implemented

| ID | Item | Priority | Current State | Missing |
|----|------|----------|---------------|---------|
| K-9 | **Field-level drift detection** | P1 | **Complete** (PR #308) | Extended `detect_drift()` with `include_value_drift`, group drift, CSV export, "What Changed?" column in UI. Backfill task populated 70 existing snapshots. |
| K-10 | **Platform filtering** | P2 | `detect_platform()` called, info captured | `rule_applies_to_platform()` not used to filter rules before evaluation |
| K-11 | **Host context in evidence** | P2 | `SystemInfoCollector` gathers packages, services, users, network | Not stored alongside scan findings; host groups and effective variables not in evidence exports |
| K-12 | **Bulk scan via Kensa ThreadPoolExecutor** | P3 | OpenWatch dispatches one Celery task per host | Kensa has built-in `--workers N` (ThreadPoolExecutor, max 50) that parallelizes across hosts with one SSH connection per thread. Instead of N Celery tasks for a host group, OpenWatch could dispatch a single Kensa invocation with `-w 30` and an inventory file. Requires: inventory file generation from host DB, result fan-out to per-host DB records, progress tracking for multi-host jobs. |

### Highest-Impact Items

1. ~~**K-1 (Evidence storage)**~~ — **Complete** (PR #307)
2. ~~**K-2 (Remediation workflow)**~~ — **Complete** (3 bug fixes applied)
3. ~~**K-9 (Field-level drift)**~~ — **Complete** (PR #308)
4. ~~**K-3 (Rollback)**~~ — **Complete** (implemented as part of K-2)

---

## Bugs

| Item | Priority | Status | Notes |
|------|----------|--------|-------|
| Host monitoring state transition: `'offline' is not a valid MonitoringState` | P1 | **Spec required first** | After adding host 192.168.1.212, connectivity check succeeds (ping=True, ssh=True, status=online) but state transition from `offline` fails. Host ends up in `unknown` state instead of `online`. `MonitoringState` enum missing `offline` value. Classified Tier 1 (monitoring is scan-eligibility and compliance-critical — an offline/down host is non-compliant; unknown state is a blind spot). **Next step**: write `specs/services/monitoring/host-monitoring.spec.yaml`, then tests, then fix. See `services/monitoring/state.py`. |
| SSH Host Key Policy GET returns hardcoded value | P1 | **Fixed** | `routes/ssh/settings.py:63` was returning `"default_policy"` instead of calling `service.get_ssh_policy()`. Frontend Select had no matching MenuItem so it displayed blank. Fix: call `SSHConfigManager.get_ssh_policy()`. Also added `renderValue` prop to frontend Select for readable labels. **Needs spec + test.** |
| Session Timeout PUT fails with 500 (SQL syntax error) | P1 | **Fixed** | `routes/system/settings.py:1125-1138` had Python `# noqa: E501` comments inside raw SQL string. `#` is not valid SQL, causing PostgreSQL syntax error. Fix: removed inline comments and reformatted SQL. Also note: this upsert uses raw `text()` instead of `InsertBuilder` — should be migrated to mutation builders for consistency. **Needs spec + test.** |
| Known SSH Hosts: `get_known_hosts` missing from SSHConfigManager | P2 | Open | `routes/ssh/settings.py:172` calls `service.get_known_hosts(hostname)` but `SSHConfigManager` has no such method. SSH Configuration tab shows "Failed to load known hosts". Missing feature, not a regression. |
| Host creation missing NOT NULL monitoring columns | P1 | Fixed | `InsertBuilder` in `routes/hosts/crud.py` was missing `check_priority` and 6 consecutive failure/success counter columns. Python-level `default=` not applied by raw SQL. Fixed by adding columns with defaults to INSERT. |
| Alert generator: `passed` column does not exist in `scan_findings` | P1 | Fixed | `alert_generator.py` `_check_configuration_drift()` queried `passed` column and `host_id` directly on `scan_findings`. Actual schema uses `status` ('pass'/'fail') and requires JOIN through `scans` for `host_id`. |

---

## Spec/Test Notes: Settings Page Fixes (2026-03-07)

### Needed: API spec for SSH Settings routes

No spec exists for `routes/ssh/settings.py`. The ssh-connection spec covers `SSHConfigManager` internals (AC-7: default policy, AC-8: valid policies) but NOT the API route behavior.

**Proposed spec**: `specs/api/ssh/ssh-settings.spec.yaml`

Acceptance criteria to cover:
1. `GET /api/ssh/settings/policy` reads policy from DB via `SSHConfigManager.get_ssh_policy()`, not hardcoded
2. `GET /api/ssh/settings/policy` returns `SSHPolicyResponse` with `policy`, `trusted_networks`, `description`
3. `POST /api/ssh/settings/policy` updates policy and returns updated config
4. `GET /api/ssh/settings/known-hosts` returns list of known hosts (blocked: `get_known_hosts` not implemented)
5. `POST /api/ssh/settings/known-hosts` adds a known host
6. `DELETE /api/ssh/settings/known-hosts/{hostname}` removes a known host
7. `GET /api/ssh/settings/test-connectivity/{host_id}` tests SSH connectivity
8. All endpoints require `Permission.SYSTEM_CONFIG` (except test-connectivity: `SCAN_EXECUTE`)

**Test file**: `tests/backend/unit/api/test_ssh_settings_api.py`

Regression tests needed:
- SSH policy GET must call `service.get_ssh_policy()` (source inspection: verify no hardcoded `"default_policy"` string)
- SSH policy GET returns valid policy values from `SSHConfigManager.VALID_POLICIES`

### Needed: API spec for System Settings routes (session timeout)

No spec exists for `routes/system/settings.py`. Session timeout is one of many endpoints in this large file (~1172 lines).

**Proposed spec**: `specs/api/system/session-timeout.spec.yaml`

Acceptance criteria to cover:
1. `GET /api/system/settings/session-timeout` returns current timeout from `system_settings` table
2. `GET /api/system/settings/session-timeout` returns default (15 min) when no DB row exists
3. `PUT /api/system/settings/session-timeout` validates range (1-480 minutes)
4. `PUT /api/system/settings/session-timeout` upserts to `system_settings` table
5. `PUT /api/system/settings/session-timeout` SQL contains no Python comments (regression: `# noqa` inside SQL string)
6. Both endpoints require `Permission.SYSTEM_MAINTENANCE`

**Test file**: `tests/backend/unit/api/test_system_settings_api.py`

Regression tests needed:
- Session timeout PUT SQL string must not contain `#` character (source inspection)
- Session timeout PUT SQL should ideally use `InsertBuilder.on_conflict_do_update()` instead of raw `text()`

### Frontend: SSH Policy Select `renderValue`

The SSH Host Key Policy `<Select>` in `Settings.tsx` now has a `renderValue` prop that maps internal values (`strict`, `auto_add`, etc.) to readable labels. Also added `auto_add_warning` to the label map since `SSHConfigManager.VALID_POLICIES` includes it but the original frontend only had 3 MenuItems (missing `auto_add_warning`).

**Observation**: Frontend only shows 3 policy options in the dropdown but backend supports 4 (`strict`, `auto_add`, `auto_add_warning`, `bypass_trusted`). The `auto_add_warning` option is the default but has no MenuItem — users can never select it via UI if they change away from it.

### Other Settings Page Issues (not yet fixed)

- **Logging Policy Management**: Non-functional placeholder — `loadLoggingPolicies` sets empty array, "Create Policy" button does nothing
- **Compliance Framework Support**: Shows wrong frameworks (SOC2/HIPAA/PCI-DSS/GDPR) — should be CIS/STIG/NIST/PCI-DSS/FedRAMP
- **About tab**: Says "OpenSCAP-based compliance scanning" — should reference Kensa
- **Known SSH Hosts**: `SSHConfigManager.get_known_hosts()` method not implemented

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
