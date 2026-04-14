# BACKLOG.md - OpenWatch Prioritized Work Queue

> **Purpose**: Single source of truth for all pending work items, prioritized and actionable.
> Updated at the end of each AI session. Items flow in from PRD epics, bug reports, and session discoveries.

**Last Updated**: 2026-03-27

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

## Recently Completed (2026-03-27)

| Item | PR | Notes |
|------|----|-------|
| Alpha 0.1.0-alpha.1 release prep | - | 80 specs active, 682 ACs, 44% coverage, RBAC enforced |
| Dead SCAP-era code deletion | - | ~31K lines removed (content/, xccdf/, owscan, kubernetes scanner, legacy services) |
| RBAC enforcement audit | - | 188 endpoints across 26 route files |
| datetime.utcnow() migration | - | 381 occurrences across 98 files replaced with timezone-aware calls |
| CSP hardening | - | Removed unsafe-inline from script-src |
| Absolute session timeout | - | 12-hour cap enforced in token verification and refresh |
| mypy error cleanup | - | 584 to 0 locally |
| Integration tests | - | 21 test files exercising 284 API endpoints |
| Documentation stale reference cleanup | - | CLAUDE.md, backend/CLAUDE.md, context/ files updated |
| Project manifest (.openwatch.yml) | - | Machine-readable single source of truth |
| requirements-dev.txt | - | CI tool versions pinned |
| Makefile Python targets | - | py-lint, py-format, py-test, py-coverage, py-specs, py-check |
| Role-based dashboards | #349 | Widget registry, 6 role presets, 15 ACs, 64 tests |
| Redux full removal (Phase 8B) | #340 | Packages uninstalled, store/index.ts deleted, hooks/redux.ts deleted, Provider removed |
| Host monitoring state bug fix | #337 | Spec v1.1 AC-11: graceful handling of stale 'offline' DB values; MonitoringState uses 6-value enum by design |
| Settings page SSH + session timeout fixes | #348 | SSH policy dropdown, session timeout 500 error |
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
| MongoDB full removal | #295 | 80 files changed, 19,488 deletions |

---

## Stretch Goals (from completed epics)

These items were deferred when their parent epics were marked "Complete" with baselines in place.

| ID | Item | Priority | Source | Notes |
|----|------|----------|--------|-------|
| E5-G1 | Raise backend coverage to 80% | P2 | E5 | Currently 44%, CI threshold 42% |
| E5-G2 | Raise frontend coverage to 60% | P2 | E5 | Currently 310+ tests |
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
| **RBAC enforcement audit** | P1 | **Complete** | 188 endpoints across 26 route files now have @require_role() decorators. Verified against authorization spec. |
| Adaptive Compliance Scheduler | P1 | Planned | Auto-scan with state-based intervals (max 48h). Monitoring spec/fix complete — no longer blocked. |
| Host Detail Page Redesign | P1 | In Progress | Phase 0 done (backend data fix), Phases 1-6 pending |
| **Email alert notifications** | P1 | Planned | Allow OpenWatch to send email alerts (SMTP/SES). Users configure which alert types they receive (compliance drift, scan failures, exceptions expiring, host state changes). RBAC-gated: users only receive alerts for resources their role can access. Needs: email service, user notification preferences table, alert-to-email dispatcher, unsubscribe support. |
| **In-app notifications** | P1 | Planned | Real-time in-app notification system. Bell icon with unread count, notification drawer, mark-as-read. Sources: alerts, scan completions, exception approvals, system events. RBAC-gated: notifications filtered by user role permissions. Needs: notification model (DB), WebSocket or polling delivery, frontend notification center component. |
| Dashboard layout customization (drag/drop) | P2 | Planned | Spec AC-12 defines 3 tiers: full (drag/drop for admins), limited (show/hide for analysts/compliance), none (fixed for auditor/guest). Preset data structure ready (`customization` field), needs DnD library (e.g. `@dnd-kit/core`), show/hide toggles, and layout persistence (localStorage or API). |
| Remediation + Subscription (Phase 4) | P3 | Mostly Complete | K-2 and K-3 complete. Remaining: K-4 (risk-aware policies), K-5 (snapshot retention). |
| OTA Updates (Phase 5) | P3 | Not Started | Kensa integration Phase 5 |

---

## OpenWatch+ Subscription

Full product/business planning for the OpenWatch+ paid tier.

| Item | Priority | Status | Notes |
|------|----------|--------|-------|
| **Subscription matrix** | P1 | Planned | Define free vs. OpenWatch+ feature matrix. Candidates for gating: host count limits, advanced reporting/export, email alerts, priority support, OTA rule updates, multi-tenant, custom frameworks. |
| **License key system** | P1 | Planned | Design how license keys are generated, distributed, and validated. Options: offline key file (air-gapped), online activation (phone-home), or hybrid. `LicenseService` already exists in `services/licensing/` — extend it. Key format, expiry, renewal, grace period. |
| **Payment and activation flow** | P1 | Planned | How customers purchase (website, sales team, PO), receive keys (email, portal), and activate (CLI `owadm activate`, UI Settings page, API endpoint). Consider air-gapped environments (manual key upload). |
| **License enforcement** | P1 | Planned | Backend enforcement: feature-gate decorators, host count checks, graceful degradation on expiry. Frontend: upgrade prompts, feature lock UI, subscription status in Settings. Existing `LicenseService` has `check_feature()` — wire into routes and UI. |
| **Sales and distribution** | P2 | Planned | Pricing model (per-host, per-seat, flat tier), trial period, volume discounts, renewal automation. Distribution: self-serve portal vs. sales-assisted. |

---

## Kensa Integration Gaps

Gaps identified by comparing `docs/KENSA_DEVELOPER_GUIDE_V0.md` against current OpenWatch implementation (2026-02-23).

### Not Implemented

| ID | Item | Priority | Notes |
|----|------|----------|-------|
| K-4 | **Risk-aware remediation policies** | P2 | Kensa classifies remediation steps as high/medium/low risk. Not used for approval gates (e.g., auto-approve low-risk, require human approval for high-risk GRUB/PAM/fstab changes). |
| K-5 | **Snapshot retention/pruning** | P3 | Kensa has 7-day active / 90-day archive lifecycle for pre-state snapshots. No integration. Depends on K-3. |
| K-6 | **`get_applicable_mappings()`** | P3 | Kensa can filter mappings by platform (RHEL 8 vs 9). OpenWatch loads all mappings without platform filtering. |
| K-7 | **`build_rule_to_section_map()`** | P3 | Kensa utility for `rule_id → section_id`. Not used — DB queries used instead. |
| K-8 | **Inventory file support** | P3 | Kensa accepts INI/YAML/text inventory files. OpenWatch creates individual SSH sessions from host DB. Low value — OpenWatch's approach is correct for its architecture. |

### Partially Implemented

| ID | Item | Priority | Current State | Missing |
|----|------|----------|---------------|---------|
| K-10 | **Platform filtering** | P2 | `detect_platform()` called, info captured | `rule_applies_to_platform()` not used to filter rules before evaluation |
| K-11 | **Host context in evidence** | P2 | `SystemInfoCollector` gathers packages, services, users, network | Not stored alongside scan findings; host groups and effective variables not in evidence exports |
| K-12 | **Bulk scan via Kensa ThreadPoolExecutor** | P3 | OpenWatch dispatches one Celery task per host | Kensa has built-in `--workers N` (ThreadPoolExecutor, max 50) that parallelizes across hosts with one SSH connection per thread. Instead of N Celery tasks for a host group, OpenWatch could dispatch a single Kensa invocation with `-w 30` and an inventory file. Requires: inventory file generation from host DB, result fan-out to per-host DB records, progress tracking for multi-host jobs. |

---

## Security Assessment Remediation (2026-03-08)

Items from `docs/OW_SECURITY_ASSESSMENT.md` that require careful sequencing due to breakage risk.

| Item | Priority | Status | Notes |
|------|----------|--------|-------|
| **M-2: MFA enforcement in login flow** | P1 | Complete | Login now queries `mfa_enabled`/`mfa_secret` from users table. If MFA enabled: returns `mfa_required: true` when no code provided, validates TOTP/backup code when provided. Migration 002 already added columns. Hardcoded `False` removed. |
| **H-2: Refresh token rotation** | P1 | Complete | Backend `/api/auth/refresh` now returns rotated `refresh_token` alongside `access_token`. Frontend `tokenService.ts` passes new token to `refreshTokenSuccess()`. `useAuthStore.ts` stores rotated refresh token in both state and localStorage. |

---

## Bugs

| Item | Priority | Status | Notes |
|------|----------|--------|-------|
| Fix 9 pre-existing test failures | P1 | Open | Spec-code drift: MFA admin endpoints, X-Forwarded-For handling |
| "OpenSCAP" text in 4 frontend files | P2 | Open | `PreFlightValidationDialog.tsx:170`, `ScanMetricsCards.tsx:53`, `ReviewStartStep.tsx:126`, `scanUtils.ts:237,240` — should reference Kensa |
| Settings: placeholder compliance frameworks list | P2 | Open | `Settings.tsx:~1014-1028` — hardcoded framework table, not fetched from backend |
| Settings: logging policy placeholder | P2 | Open | `Settings.tsx:~998-1028` — audit logging section has placeholder content |
| Settings: Known Hosts tab not wired to backend | P2 | Open | `get_known_hosts()` exists in `KnownHostsManager` (`ssh/known_hosts.py:118`) but frontend doesn't call it |

---

## Technical Debt

| Item | Priority | Notes |
|------|----------|-------|
| Remove XCCDF/lxml dependency from OWCA | P2 | `owca/extraction/xccdf_parser.py` imports lxml at module level via `owca/__init__.py`. Legacy OpenSCAP path — Kensa doesn't use XCCDF. Refactor to make import conditional or remove XCCDF parser from OWCA init. Blocks removing lxml from requirements.txt. |
| Snake_case to camelCase scattered transformation | P2 | No centralized adapters (Rule Reference has one, others don't) |
| Liveness ping port detection | P2 | `liveness_tasks.py` defaults to port 22. Hosts on non-standard SSH ports show as unreachable. Read port from host credential config. |
| Compliance-as-Code API | P3 | External tool integration for compliance checks |

## Q1 Completed (2026-04-11 to 2026-04-13)

| Item | Notes |
|------|-------|
| Transaction log (write-on-change model) | `transactions` + `host_rule_state` tables, 99.7% write reduction |
| Host liveness monitoring | TCP ping every 5 min, HOST_UNREACHABLE/RECOVERED alerts |
| Notification channels | Slack, email, webhook dispatch + admin CRUD |
| SSO federation | OIDC (authlib) + SAML (pysaml2), login/callback routes |
| PostgreSQL job queue | Replaces Celery + Redis (SKIP LOCKED, 40 tasks, scheduler) |
| Dependency cleanup | 13 packages removed, Chart.js removed from frontend |
| Redis + Celery removed | Zero Redis/Celery in codebase, 4 containers (down from 6) |
| Rules-first transactions UI | `/transactions` → `/transactions/rule/:id` → `/transactions/:id` |

---

## How to Use This File

1. **Starting a session**: Read this file to understand current priorities
2. **Picking work**: Start from the top of the highest-priority active epic
3. **Completing work**: Update status here and in the relevant PRD epic file
4. **Discovering new work**: Add items to the appropriate section
5. **Ending a session**: Update statuses and add any new items discovered
