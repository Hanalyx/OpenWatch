# OpenWatch Q1 Implementation Plan

**Date:** 2026-04-11
**Window:** Weeks 1–12 (~3 months)
**Parent:** [OPENWATCH_Q1_Q3_PLAN.md](OPENWATCH_Q1_Q3_PLAN.md)
**Vision:** [OPENWATCH_VISION.md](OPENWATCH_VISION.md) § Quarter 1

---

## Q1 Goals (from vision)

| Identity | Milestone |
|---|---|
| **Eye** | Refactor schema into `transactions` table (four-phase model). Ship transaction log as primary top-level UI. Per-transaction detail view. |
| **Heartbeat** | Scheduled scans enabled by default on every host. Host liveness monitoring. Fleet-level health view. |
| **Control Plane** | Slack + Jira integration (outbound alerts). SAML/OIDC SSO. |

**Scope cut for Q1**: Jira moves to Q2 (bidirectional sync is non-trivial). Q1 control plane = SSO + Slack/email outbound only.

**Not in Q1**: OSCAL export (deferred to Kensa), Ed25519 signing (Q2), per-host audit timeline API (Q2), proactive remediation workflow (Q3), multi-approval (Q3), fleet-group policies (Q3).

---

## Phasing

Three parallel workstreams, 12 weeks total. Phase 1 (transaction log) is the critical path — everything else is important but not blocking.

```
Workstream A: Transaction Log         [weeks 1-12, critical path]
Workstream B: Heartbeat Completion    [weeks 6-12, parallel]
Workstream C: Control Plane           [weeks 6-12, parallel]
```

---

## Workstream A — Transaction Log (weeks 1–12, critical path)

### Week 1: Schema design + spec freeze

**Deliverables:**
- [ ] `specs/system/transaction-log.spec.yaml` (new, draft → review)
- [ ] PRD epic opened: `PRD/epics/E7-TRANSACTION-LOG.md`
- [ ] Design review with founding team (spec walkthrough, exit criteria agreement)
- [ ] Schema decision: `transactions` table columns, index plan, FK rules, `tenant_id` nullable for Q6 groundwork
- [ ] Customer survey: "what fields do you depend on in `/api/compliance/audit/exports` CSVs?"  — locks the export contract regression test

**Artifacts:**
- New spec: `system/transaction-log.spec.yaml` (15 ACs covering schema, write path, read path, backfill, migration rollback)
- New test stub: `tests/backend/unit/system/test_transaction_log_spec.py` (skip-marked until code lands)

### Week 2: Alembic migration + dual-write scaffold

**Deliverables:**
- [ ] Alembic migration `040_add_transactions_table.py` — create `transactions` table, indexes, FKs. Does NOT drop old tables.
- [ ] `backend/app/models/transaction_models.py` — SQLAlchemy model for `Transaction`
- [ ] `backend/app/repositories/transaction_repository.py` — new repository with `insert`, `get_by_id`, `list_by_host`, `query` methods
- [ ] Modify `backend/app/tasks/kensa_scan_tasks.py` (write path lines 250–343) to dual-write: keep existing INSERTs into `scans`/`scan_results`/`scan_findings`, add parallel INSERT into `transactions` in the same DB transaction
- [ ] Feature flag `OPENWATCH_DUAL_WRITE_TRANSACTIONS` (default `true` in dev, `false` in prod for rollback safety)

**Spec coverage (transaction-log.spec.yaml):** AC-1 (table exists), AC-2 (dual-write on scan completion)

### Week 3: Pre-state capture for read-only checks

**Deliverables:**
- [ ] Extend `backend/app/plugins/kensa/evidence.py:19-45` — `_evidence_to_dict` returns envelope shape with `phases.capture`, `phases.validate`, `phases.commit` populated (for read-only checks, capture == commit.post_state)
- [ ] `evidence_envelope` JSONB column written for every transaction row
- [ ] Schema versioning: `evidence_envelope.schema_version = "1.0"`, `kensa_version` captured

**Spec coverage:** AC-3 (envelope schema v1.0), AC-4 (validate-phase fields), AC-5 (schema_version always set)

### Week 4: Backfill task

**Deliverables:**
- [ ] `backend/app/tasks/transaction_backfill_tasks.py` — `backfill_transactions_from_scans` Celery task
- [ ] Chunked at 10k rows, progress tracking in `backfill_progress` table
- [ ] Resumable: if task dies mid-run, next invocation picks up from last checkpoint
- [ ] Admin route: `POST /api/admin/transactions/backfill` (SUPER_ADMIN only)
- [ ] Historical transactions have `phase=validate` only; pre/post-state is `null` for pre-refactor rows

**Spec coverage:** AC-6 (backfill is idempotent), AC-7 (historical rows marked with schema_version=0.9)

### Week 5: Service migration — read-only services first

Migrate in dependency order from lowest-risk to highest:

**Deliverables:**
- [ ] `audit_query.py` reads from `transactions` via `TransactionRepository`
- [ ] `temporal.py` `get_posture()` and `get_posture_history()` read from `transactions`
- [ ] Benchmark: `get_posture(host_id, as_of)` p95 `<500ms` on 1M-row fixture database
- [ ] Tests updated to source-inspect the new read path

**Spec coverage:** AC-8 (audit query reads transactions), AC-9 (temporal queries meet 500ms SLA)

### Week 6: Service migration — drift + alerts

**Deliverables:**
- [ ] `alert_generator.py` reads from `transactions`
- [ ] `drift.py` routes source from `transactions`
- [ ] `DriftDetectionService.detect_drift()` compares transaction aggregates (grouped by `host_id, started_at::date`) against baselines

**Spec coverage:** AC-10 (drift uses transaction aggregates), AC-11 (alerts query transactions)

### Week 7: Service migration — audit export (highest risk)

**Deliverables:**
- [ ] `audit_export.py` reads from `transactions`
- [ ] **Critical regression test**: `tests/backend/integration/test_audit_export_parity.py` — runs export on a fixture scan against old schema, runs export against new schema, asserts byte-identical CSV/JSON output
- [ ] Customer contract locked from week 1 survey
- [ ] Fallback plan: feature flag `AUDIT_EXPORT_SOURCE=legacy|transactions` for instant rollback

**Spec coverage:** AC-12 (export parity), AC-13 (fallback flag works)

### Week 8: Service migration — routes + scan execution

**Deliverables:**
- [ ] `routes/scans/kensa.py`, `routes/scans/reports.py` — source from `transactions`
- [ ] `routes/compliance/posture.py` — source from `transactions`
- [ ] All integration tests in `tests/backend/integration/` passing against new read path
- [ ] Old tables still dual-written (rollback path preserved)

### Week 9: New `/api/transactions/*` endpoints

**Deliverables:**
- [ ] `backend/app/routes/transactions/crud.py` — new router
  - `GET /api/transactions` — paginated list with filters (`host_id`, `status`, `framework`, `phase`, `rule_id`, `started_at` range, `initiator_type`)
  - `GET /api/transactions/{id}` — single transaction, full envelope
  - `GET /api/hosts/{host_id}/transactions` — per-host timeline (stub: paginated by `started_at DESC`, full filter surface in Q2)
- [ ] `specs/api/transactions/transaction-crud.spec.yaml` (new, draft)
- [ ] OpenAPI spec regenerated, Swagger docs updated

### Week 10: Frontend — Transactions list + detail

**Deliverables:**
- [ ] `frontend/src/services/adapters/transactionAdapter.ts` — API client for `/api/transactions/*`
- [ ] `frontend/src/pages/transactions/Transactions.tsx` — list page with filter bar (status, framework, date range, host)
- [ ] `frontend/src/pages/transactions/TransactionDetail.tsx` — detail page with four tabs:
  - **Execution**: phase timeline (capture → validate → commit) with durations
  - **Evidence**: raw evidence envelope (pretty-printed JSON)
  - **Controls**: framework mappings with control descriptions
  - **Related**: other transactions for same host/rule
- [ ] `scanAdapter.ts` becomes a thin re-export shim pointing at `transactionAdapter`
- [ ] `specs/frontend/transactions-list.spec.yaml` (new, draft)
- [ ] `specs/frontend/transaction-detail.spec.yaml` (new, draft)

### Week 11: Navigation rename + Findings filter view

**Deliverables:**
- [ ] Top-nav **Scans → Transactions** (one-line change in `frontend/src/components/layout/Sidebar.tsx` or equivalent)
- [ ] **Findings** becomes a preset filter on Transactions page: `status=fail`, no separate page
- [ ] Old `/api/scans/*` endpoints gain `Deprecation` response header pointing at `/api/transactions/*`
- [ ] `frontend/src/pages/scans/Scans.tsx` redirects to `/transactions` with a one-time notice
- [ ] Update frontend specs: `scan-workflow.spec.yaml` → add AC for redirect behavior

### Week 12: Exit criteria validation + spec promotion

**Deliverables:**
- [ ] All existing tests passing (no regressions)
- [ ] Temporal query benchmark: p95 `<500ms` on production-sized fixture DB
- [ ] Audit export parity test passing
- [ ] `kensa_scan_tasks` duration regression: new dual-write adds `<10%` overhead vs baseline
- [ ] `specs/system/transaction-log.spec.yaml` promoted **draft → active** (CI now enforces 100% AC coverage)
- [ ] `specs/api/transactions/transaction-crud.spec.yaml` promoted **draft → active**
- [ ] `specs/frontend/transactions-list.spec.yaml` promoted **draft → active**
- [ ] `specs/frontend/transaction-detail.spec.yaml` promoted **draft → active**
- [ ] Old tables still dual-written — **do not drop until Q2** (operational safety net)
- [ ] Existing active specs updated with changelog entries (see "Spec Updates" below)

---

## Workstream B — Heartbeat Completion (weeks 6–12)

Starts in week 6 when Workstream A has freed enough engineer attention.

### Week 6: Auto-baseline on first scan

**Current state:** `PostureSnapshot` model + daily snapshots shipped. `BaselineService` exists. No trigger on first scan.

**Deliverables:**
- [ ] Modify `kensa_scan_tasks.py` (end-of-scan hook): after successful scan, call `BaselineService.establish_baseline_if_missing(host_id, source_scan_id)`
- [ ] Idempotent: no-ops if host already has `is_active=true` baseline
- [ ] `specs/services/compliance/compliance-scheduler.spec.yaml` — add AC: "First successful scan MUST auto-establish baseline"

### Weeks 7–8: Separate liveness ping

**Current state:** Liveness inferred from `last_scan_completed`. At 6–24h scan cadence, signal is too slow for vision's 15-min detection target.

**Deliverables:**
- [ ] New Alembic migration `041_add_host_liveness.py` — `host_liveness` table: `host_id (PK)`, `last_ping_at`, `last_response_ms`, `reachability_status` (`reachable`/`unreachable`/`unknown`), `consecutive_failures`
- [ ] `backend/app/models/host_liveness.py` — SQLAlchemy model
- [ ] `backend/app/services/monitoring/liveness.py` — `LivenessService.ping_host(host_id)` opens a TCP connection to SSH port, records response time, updates row
- [ ] `backend/app/tasks/liveness_tasks.py` — Celery Beat task `ping_all_managed_hosts`, schedule every 5 minutes
- [ ] Alert dispatch: transition from `reachable → unreachable` triggers `HOST_UNREACHABLE` alert via `AlertService.create_alert()`
- [ ] **New spec**: `specs/services/monitoring/host-liveness.spec.yaml` (draft)
- [ ] Test stub: `tests/backend/unit/services/monitoring/test_host_liveness_spec.py`

### Week 9: Maintenance mode UI

**Current state:** Backend fully shipped at `compliance_scheduler.py:508-549`. Frontend absent.

**Deliverables:**
- [ ] Add "Maintenance Mode" toggle to `HostDetail.tsx` header — wired to `POST /api/hosts/{id}/schedule/maintenance`
- [ ] Add column to `Hosts.tsx` list view showing maintenance state
- [ ] Confirmation dialog: "Hosts in maintenance mode are not scanned and do not generate alerts. Continue?"
- [ ] Update `specs/frontend/host-detail-behavior.spec.yaml` — add AC for maintenance mode toggle

### Weeks 10–11: Fleet health "at a glance"

**Current state:** `FleetHealthWidget.tsx` (336 LOC) shows status pie chart. Missing: drift count, failed scans count, liveness distinct from scan recency.

**Deliverables:**
- [ ] Extend `FleetHealthWidget.tsx` with three metric tiles:
  - "**X / Y hosts reachable**" — from `host_liveness` (not scan_results)
  - "**Z drift events** in last 24h"
  - "**N failed scans** in last 24h"
- [ ] New backend endpoint: `GET /api/fleet/health-summary` — single call returning all three metrics
- [ ] Query goes against `transactions` table (Workstream A dependency — this is why B starts week 6, not week 1)
- [ ] Update `specs/frontend/role-dashboards.spec.yaml` — add AC for fleet health summary

### Week 12: Heartbeat exit validation

**Deliverables:**
- [ ] First-scan baseline established for new host in <1s
- [ ] Liveness ping task running in production, p95 latency tracked
- [ ] Fleet health widget loads in `<500ms`
- [ ] `specs/services/monitoring/host-liveness.spec.yaml` promoted to active

---

## Workstream C — Control Plane Tier 1 (weeks 6–12)

### Weeks 6–7: Notification dispatch foundation

**Current state:** `AlertService` creates alert DB rows. `routes/integrations/webhooks.py` exists for generic webhooks but is not wired to alerts. No Slack, no email.

**Deliverables:**
- [ ] `backend/app/services/notifications/__init__.py` — new package
- [ ] `backend/app/services/notifications/base.py` — `NotificationChannel` ABC: `async send(alert: Alert) -> DeliveryResult`
- [ ] `backend/app/services/notifications/slack.py` — `SlackChannel` using `slack-sdk`, Block Kit message format
- [ ] `backend/app/services/notifications/email.py` — `EmailChannel` using `aiosmtplib`, HTML template for alerts
- [ ] `backend/app/services/notifications/webhook.py` — thin wrapper around existing webhook service
- [ ] New table `notification_channels`: `id, tenant_id, channel_type, name, config_encrypted (JSONB), enabled`
- [ ] `requirements.txt`: add `slack-sdk>=3.27.0`, `aiosmtplib>=3.0.0`
- [ ] **New spec**: `specs/services/infrastructure/notification-channels.spec.yaml` (draft)
- [ ] Test stub: `tests/backend/unit/services/infrastructure/test_notification_channels_spec.py`

### Week 8: Alert → notification wiring

**Deliverables:**
- [ ] Modify `AlertService.create_alert()` — after DB insert, dispatch to all enabled channels via `NotificationDispatchService`
- [ ] Dedupe via existing 60-min window (`alerts.py:137`)
- [ ] Async dispatch: Celery task per channel per alert, failures logged but don't block alert creation
- [ ] New endpoints in `routes/admin/notifications.py`:
  - `GET /api/admin/notifications/channels` — list
  - `POST /api/admin/notifications/channels` — create (SUPER_ADMIN)
  - `POST /api/admin/notifications/channels/{id}/test` — send test notification
- [ ] Frontend: `frontend/src/pages/admin/NotificationSettings.tsx` — admin-only page
- [ ] Update `specs/services/compliance/alert-thresholds.spec.yaml` — add AC: "Alerts MUST dispatch to all enabled notification channels"

### Weeks 9–11: SAML/OIDC SSO

**Current state:** Zero groundwork. Local JWT auth, FIPS Argon2id/RS256 (both good). No federation library, no provider abstraction.

**Deliverables week 9:**
- [ ] Dependency evaluation: `authlib` (OIDC) + `python3-saml` vs `pysaml2` (SAML). **Decision by end of week 9**. Recommended: `authlib` for OIDC, `pysaml2` for SAML (pure Python, simpler RPM/DEB packaging)
- [ ] `requirements.txt` updated with chosen libraries
- [ ] Alembic migration `042_add_sso_providers.py`:
  - `sso_providers` table: `id, provider_type (saml|oidc), name, config_encrypted (JSONB), enabled, created_at`
  - `users` table: add `sso_provider_id (FK)`, `external_id (VARCHAR 255)`, `last_sso_login_at (TIMESTAMPTZ)`
- [ ] **New spec**: `specs/services/auth/sso-federation.spec.yaml` (draft)
- [ ] Test stub: `tests/backend/unit/services/auth/test_sso_federation_spec.py`

**Deliverables week 10:**
- [ ] `backend/app/services/auth/sso/__init__.py`
- [ ] `backend/app/services/auth/sso/provider.py` — abstract `SSOProvider` with:
  - `get_login_url(state: str, redirect_uri: str) -> str`
  - `handle_callback(request_data: dict) -> SSOUserClaims`
  - `map_claims_to_user(claims: SSOUserClaims) -> User` (creates or updates local user record)
- [ ] `backend/app/services/auth/sso/oidc.py` — `OIDCProvider(SSOProvider)` using authlib
- [ ] `backend/app/services/auth/sso/saml.py` — `SAMLProvider(SSOProvider)` using pysaml2
- [ ] Claim-to-role mapping configurable per provider (stored in `sso_providers.config_encrypted`)
- [ ] First-login creates local user linked via `external_id`; subsequent logins refresh claims

**Deliverables week 11:**
- [ ] Routes in `backend/app/routes/auth/sso.py`:
  - `GET /api/auth/sso/providers` — list enabled providers for login screen (public)
  - `GET /api/auth/sso/login?provider_id={id}` — redirect to IdP
  - `GET /api/auth/sso/callback/oidc/{provider_id}` — OIDC callback
  - `POST /api/auth/sso/callback/saml/{provider_id}` — SAML ACS endpoint
- [ ] Admin CRUD in `backend/app/routes/admin/sso.py`:
  - `POST /api/admin/sso/providers` — create
  - `PUT /api/admin/sso/providers/{id}` — update
  - `POST /api/admin/sso/providers/{id}/test` — test login flow
- [ ] Frontend: login page `LoginPage.tsx` displays "Sign in with {Provider}" buttons for each enabled provider
- [ ] Frontend admin page: `frontend/src/pages/admin/SSOSettings.tsx`
- [ ] Integration tests:
  - OIDC flow against a mock IdP (authlib supports local test IdPs)
  - SAML flow against a mock IdP (pysaml2 ships with test fixtures)
- [ ] **New spec**: `specs/api/auth/sso-routes.spec.yaml` (draft)
- [ ] **Security review gate** — external review of SSO implementation before promotion to active

### Week 12: Control Plane exit validation

**Deliverables:**
- [ ] Slack notification delivered end-to-end on a synthetic alert
- [ ] Email notification delivered to configured SMTP
- [ ] OIDC login flow works against Okta dev tenant (or Keycloak test instance)
- [ ] SAML login flow works against AD FS test instance (or SimpleSAMLphp)
- [ ] Security review sign-off
- [ ] Specs promoted draft → active:
  - `services/auth/sso-federation.spec.yaml`
  - `services/infrastructure/notification-channels.spec.yaml`
  - `api/auth/sso-routes.spec.yaml`

---

## Spec Updates

### New specs (created as **draft**, promoted to **active** at week 12)

| Spec | Location | Workstream | Week Active |
|---|---|---|---|
| transaction-log | `specs/system/transaction-log.spec.yaml` | A | 12 |
| transaction-crud (API) | `specs/api/transactions/transaction-crud.spec.yaml` | A | 12 |
| transactions-list (FE) | `specs/frontend/transactions-list.spec.yaml` | A | 12 |
| transaction-detail (FE) | `specs/frontend/transaction-detail.spec.yaml` | A | 12 |
| host-liveness | `specs/services/monitoring/host-liveness.spec.yaml` | B | 12 |
| notification-channels | `specs/services/infrastructure/notification-channels.spec.yaml` | C | 12 |
| sso-federation | `specs/services/auth/sso-federation.spec.yaml` | C | 12 |
| sso-routes (API) | `specs/api/auth/sso-routes.spec.yaml` | C | 12 |

### Existing specs that will change in Q1

These specs keep their current ACs but gain new ones as Q1 features land. Each change is a version bump with a changelog entry in the YAML.

| Spec | Change | Version Bump |
|---|---|---|
| `pipelines/scan-execution.spec.yaml` | Add AC: transactions row written alongside scan_findings | 1.2 → 1.3 |
| `pipelines/drift-detection.spec.yaml` | Add AC: drift reads from transactions aggregates | 1.x → 1.y |
| `services/compliance/temporal-compliance.spec.yaml` | Add AC: get_posture sources from transactions | bump |
| `services/compliance/audit-query.spec.yaml` | Add AC: audit queries target transactions | bump |
| `services/compliance/alert-thresholds.spec.yaml` | Add AC: alerts dispatch via notification channels | bump |
| `services/compliance/compliance-scheduler.spec.yaml` | Add AC: first-scan auto-baseline | bump |
| `api/scans/scan-results.spec.yaml` | Add AC: endpoint includes Deprecation header | bump |
| `api/scans/scan-crud.spec.yaml` | Add AC: endpoint includes Deprecation header | bump |
| `frontend/scan-workflow.spec.yaml` | Add AC: /scans redirects to /transactions | bump |
| `frontend/scans-list.spec.yaml` | Add AC: Scans list redirects to Transactions | bump |
| `frontend/host-detail-behavior.spec.yaml` | Add AC: maintenance mode toggle | bump |
| `frontend/role-dashboards.spec.yaml` | Add AC: fleet health summary tiles | bump |

### SPEC_REGISTRY update

- Add 8 new specs to the registry in draft status during weeks 1–11
- Bump totals: System 10→11, API 28→30, Frontend 13→15, Services 22→25, **Total 80→88**
- After week 12 promotions: 88 Active, 0 Draft (matching current "only active" convention)

---

## Test Updates

### New test files (stubs during weeks 1–11, fleshed out as code lands)

Each new draft spec gets a matching test file with AC classes pre-scaffolded. Tests are skip-marked until the corresponding code lands. At week 12 promotion, all skip marks are removed and tests must pass.

| Test File | Spec | Scaffold Week | Complete Week |
|---|---|---|---|
| `tests/backend/unit/system/test_transaction_log_spec.py` | transaction-log | 1 | 12 |
| `tests/backend/unit/api/test_transaction_crud_spec.py` | transaction-crud | 9 | 12 |
| `tests/frontend/transactions/transactions-list.spec.test.ts` | transactions-list | 10 | 12 |
| `tests/frontend/transactions/transaction-detail.spec.test.ts` | transaction-detail | 10 | 12 |
| `tests/backend/unit/services/monitoring/test_host_liveness_spec.py` | host-liveness | 7 | 12 |
| `tests/backend/unit/services/infrastructure/test_notification_channels_spec.py` | notification-channels | 6 | 12 |
| `tests/backend/unit/services/auth/test_sso_federation_spec.py` | sso-federation | 9 | 12 |
| `tests/backend/unit/api/test_sso_routes_spec.py` | sso-routes | 11 | 12 |

### Regression tests (critical — must ship before dependent feature)

| Test | Purpose | Week |
|---|---|---|
| `tests/backend/integration/test_audit_export_parity.py` | Byte-identical CSV/JSON export across schema refactor | 7 |
| `tests/backend/integration/test_temporal_query_perf.py` | p95 `<500ms` on 1M-row fixture | 5 |
| `tests/backend/integration/test_scan_execution_dual_write.py` | Dual-write produces consistent rows in old + new tables | 2 |
| `tests/backend/integration/test_transaction_backfill.py` | Backfill is idempotent and resumable | 4 |
| `tests/backend/integration/test_sso_oidc_flow.py` | End-to-end OIDC against mock IdP | 11 |
| `tests/backend/integration/test_sso_saml_flow.py` | End-to-end SAML against mock IdP | 11 |

### Test marker conventions

- `@pytest.mark.unit` — source-inspection tests (current project convention)
- `@pytest.mark.integration` — database + full stack
- `@pytest.mark.regression` — marks tests that pin existing behavior (audit export parity)
- `@pytest.mark.slow` — performance benchmarks
- `@pytest.mark.skip(reason="Q1: transaction log not yet implemented")` — skip-marked stubs during weeks 1–11

---

## Dependencies & risks

### Dependency graph

```
week 1:  spec freeze (transaction-log)
         ↓
week 2:  Alembic migration + dual-write
         ↓
week 3:  pre-state capture (may require Kensa team coordination)
         ↓
week 4:  backfill task (independent)
         ↓
weeks 5-8: service migration (in risk order)
         ↓
week 9:  /api/transactions/* endpoints
         ↓
weeks 10-11: frontend
         ↓
week 12: exit validation + spec promotion

Workstream B (weeks 6-12): depends on A's transactions table (for fleet health summary)
Workstream C (weeks 6-12): independent of A, can start any time engineers free up
```

### Risks (ranked by severity)

1. **Kensa team coordination on pre-state capture** (week 3). If Kensa needs changes to emit pre-state, it's an upstream PR on a different repo. **Mitigation:** open the conversation week 1; Phase 4 (Q2) is the real deadline for full envelope, so week 3 only needs read-only-check envelope shape.

2. **Audit export contract drift** (week 7). Customer CSVs may depend on undocumented column order. **Mitigation:** week 1 customer survey, regression test from fixture file, feature flag rollback.

3. **Temporal query performance on new schema** (week 5). 500ms SLA could fail if composite index `(host_id, started_at)` is mis-tuned. **Mitigation:** benchmark early, add covering indexes if needed, cold/warm cache test.

4. **SAML library packaging** (weeks 9–10). `python3-saml` has C deps that complicate RPM/DEB. **Mitigation:** decide on `pysaml2` (pure Python) by end of week 9.

5. **SSO security review delay** (week 12). External security review blocks promotion to active. **Mitigation:** schedule reviewer in week 9, deliver for review by week 11.

6. **Large-deployment backfill** (week 4). Customers with millions of `scan_findings` rows will have multi-hour backfills. **Mitigation:** resumable chunked task, progress UI, Phase 2 UI can run on forward-only dual-written data without full backfill.

---

## Exit criteria (end of week 12)

### Transaction Log (Workstream A)
- [ ] `transactions` table in production, dual-written from every scan path
- [ ] `/api/transactions/*` endpoints documented and live
- [ ] Transaction list + detail pages shipped
- [ ] Findings as filtered transaction view
- [ ] Top-nav says **Transactions**; old `/api/scans/*` has `Deprecation` headers
- [ ] Temporal query benchmark: p95 `<500ms`
- [ ] Audit export parity regression passes
- [ ] `kensa_scan_tasks` regression: dual-write adds `<10%` overhead
- [ ] 4 new specs promoted to active; 10 existing specs updated with changelog

### Heartbeat (Workstream B)
- [ ] First-scan auto-baseline in production
- [ ] `host_liveness` table + 5-min ping task running
- [ ] Maintenance mode UI in Host Detail + Hosts list
- [ ] Fleet health widget shows reachable/drift/failed tiles
- [ ] 1 new spec promoted to active; 3 existing specs updated

### Control Plane (Workstream C)
- [ ] Slack notifications firing on synthetic alerts
- [ ] Email notifications firing on synthetic alerts
- [ ] OIDC login flow validated against real IdP (Okta/Keycloak)
- [ ] SAML login flow validated against real IdP (AD FS/SimpleSAMLphp)
- [ ] External security review sign-off on SSO
- [ ] 3 new specs promoted to active; 1 existing spec updated

### Cross-cutting
- [ ] CI green: `validate-specs.py`, `check-spec-coverage.py --enforce-active`, `check-spec-changes.py`
- [ ] Test coverage floor maintained (42%)
- [ ] No regression in existing CI suite
- [ ] PRD epic E7 closed; session handoff log updated
- [ ] Old scan tables still written (rollback possible) — drop deferred to Q2

---

## PR decomposition (suggested)

Small PRs, incremental commits. Each PR should pass CI independently.

| PR | Contents | Reviewers | Week |
|---|---|---|---|
| 1 | `specs/system/transaction-log.spec.yaml` (draft) + test stub | founding engineer | 1 |
| 2 | Alembic `040_add_transactions_table.py` + model + repository | backend | 2 |
| 3 | Dual-write in `kensa_scan_tasks.py` + feature flag | backend | 2 |
| 4 | Envelope shape in `kensa/evidence.py` | backend | 3 |
| 5 | Backfill task + admin endpoint | backend | 4 |
| 6 | `audit_query.py` migration | backend | 5 |
| 7 | `temporal.py` migration + perf test | backend | 5 |
| 8 | `alert_generator.py` + `drift.py` migration | backend | 6 |
| 9 | `audit_export.py` migration + parity regression test | backend + security | 7 |
| 10 | Routes migration | backend | 8 |
| 11 | `/api/transactions/*` endpoints + spec + tests | backend | 9 |
| 12 | `transactionAdapter.ts` + Transactions list page + spec | frontend | 10 |
| 13 | Transaction detail page with four tabs + spec | frontend | 10 |
| 14 | Nav rename + Findings filter + deprecation headers | frontend + backend | 11 |
| 15 | Auto-baseline wiring | backend | 6 |
| 16 | `host_liveness` table + ping task + spec | backend | 7–8 |
| 17 | Maintenance mode UI | frontend | 9 |
| 18 | Fleet health summary endpoint + widget extension | backend + frontend | 10–11 |
| 19 | `notifications/` package + Slack + email + spec | backend | 6–7 |
| 20 | Alert dispatch wiring + admin notification settings UI | backend + frontend | 8 |
| 21 | SSO Alembic + models + abstract provider + spec | backend | 9 |
| 22 | OIDC provider + routes + integration test | backend | 10 |
| 23 | SAML provider + routes + integration test | backend | 10–11 |
| 24 | SSO admin + login pages | frontend | 11 |
| 25 | Spec promotions (draft → active) + SPEC_REGISTRY update | founding engineer | 12 |

**~25 PRs over 12 weeks = ~2 PRs/week.** Realistic with 2 backend + 1 frontend engineer.

---

## Workstream D — Redis/Celery Migration (weeks 8–12)

### Motivation

OpenWatch uses <10% of Celery's features (no canvas, no rate limits, no chaining) and
Redis only as a Celery broker + 3 small application caches (token blacklist, rule cache,
SSO state). Eliminating both dependencies:
- Removes 2 infrastructure services (Redis container, Celery Beat container)
- Simplifies air-gapped RPM/DEB packaging (no Redis to bundle)
- All state in one durable store (PostgreSQL WAL vs Redis in-memory)
- Reduces Docker containers from 6 to 3 (backend, worker, db)

### Scalability analysis

PostgreSQL `SKIP LOCKED` handles ~5,000 dequeues/second. OpenWatch peak load:
- 7 hosts: ~0.07 tasks/sec (trivial)
- 700 hosts: ~2.6 tasks/sec (0.05% of capacity)
- 7,000 hosts: ~25 tasks/sec (0.5% of capacity)
- 70,000 hosts: ~250 tasks/sec (5% of capacity)

The scaling wall is SSH scan execution (~60s per host), not task dispatch.

### Phase D1: Job queue infrastructure (week 8)

**Deliverables:**
- [ ] Alembic migration: `job_queue` table (id, task_name, args JSONB, status, priority,
      queue, scheduled_at, started_at, completed_at, result JSONB, error, retry_count,
      max_retries, timeout_seconds, created_at)
- [ ] Index: `(status, scheduled_at, queue, priority DESC)` for `SKIP LOCKED` polling
- [ ] `backend/app/services/job_queue/service.py` — `JobQueueService` with:
  - `enqueue(task_name, args, queue, priority, delay, max_retries, timeout)` → INSERT
  - `dequeue(queue)` → SELECT FOR UPDATE SKIP LOCKED + UPDATE status=running
  - `complete(job_id, result)` → UPDATE status=completed
  - `fail(job_id, error, retry)` → UPDATE status=failed or re-enqueue with backoff
  - `schedule_recurring(name, cron_expr, task_name, args, queue)` → recurring job config
- [ ] `backend/app/services/job_queue/worker.py` — `Worker` class:
  - Poll loop: `dequeue()` → dispatch to task registry → `complete()`/`fail()`
  - Timeout enforcement via `signal.alarm()` (Unix) or threading timer
  - Graceful shutdown on SIGTERM
  - Configurable concurrency (thread pool or process pool)
- [ ] `backend/app/services/job_queue/scheduler.py` — `Scheduler` class:
  - Reads `recurring_jobs` table, INSERTs due jobs into `job_queue`
  - Runs every 10 seconds in a loop
  - Replaces Celery Beat entirely
- [ ] New spec: `specs/system/job-queue.spec.yaml` (draft)
- [ ] Test stubs

### Phase D2: Task registry + adapter layer (week 9)

**Deliverables:**
- [ ] `backend/app/services/job_queue/registry.py` — maps task names to callables:
  ```python
  TASK_REGISTRY = {
      "app.tasks.ping_all_managed_hosts": ping_all_managed_hosts,
      "app.tasks.dispatch_compliance_scans": dispatch_compliance_scans,
      ...
  }
  ```
- [ ] Adapter: `enqueue()` wrapper that matches Celery's `.delay()` API for gradual migration:
  ```python
  # Drop-in replacement:
  # Old: execute_kensa_scan_task.delay(scan_id=x, host_id=y)
  # New: job_queue.enqueue("app.tasks.execute_kensa_scan", {"scan_id": x, "host_id": y})
  ```
- [ ] Migrate 2 simple tasks as proof of concept:
  - `detect_stale_scans` (periodic, no retry, no dependencies)
  - `cleanup_old_posture_snapshots` (periodic, no retry)
- [ ] Both Celery and job_queue running side-by-side (feature flag `OPENWATCH_USE_PG_QUEUE`)

### Phase D3: Replace Redis direct usage (week 10)

**Deliverables:**
- [ ] Token blacklist → PostgreSQL table `token_blacklist` (jti PK, expires_at):
  - `is_blacklisted(jti)` → SELECT EXISTS
  - `blacklist(jti, expires_at)` → INSERT
  - Hourly cleanup: DELETE WHERE expires_at < NOW()
  - No latency impact: blacklist check is on token refresh (not every request)
- [ ] Rule cache → in-process `cachetools.TTLCache`:
  - Kensa rules are static YAML loaded from disk
  - No cross-process sharing needed (each worker loads its own copy)
  - TTL 30 min matches current Redis TTL
  - Eliminates Redis DB 2 entirely
- [ ] SSO state → PostgreSQL table `sso_state` (state_token PK, provider_id, expires_at):
  - 5-minute TTL, cleaned up by scheduler
  - Low volume (<10 logins/hour)
- [ ] Remove `redis` from `requirements.txt` imports in these modules

### Phase D4: Migrate all tasks (week 11)

**Deliverables:**
- [ ] Migrate remaining 26 tasks from Celery to job_queue, in batches:
  - Batch 1: Maintenance tasks (stale detection, cleanup, snapshots) — 5 tasks
  - Batch 2: Monitoring tasks (host checks, liveness, OS discovery) — 5 tasks
  - Batch 3: Compliance tasks (scheduler dispatch, scans, alerts) — 8 tasks
  - Batch 4: On-demand tasks (remediation, exports, webhooks, backfill) — 8 tasks
- [ ] Each batch: migrate, test, verify in running infrastructure before next batch
- [ ] `recurring_jobs` table populated with all 8 Beat schedule entries
- [ ] Feature flag `OPENWATCH_USE_PG_QUEUE=true` becomes default

### Phase D5: Remove Celery + Redis (week 12)

**Deliverables:**
- [ ] Remove from `requirements.txt`: `celery`, `redis`, `kombu`, `flower`
- [ ] Delete: `backend/app/celery_app.py`
- [ ] Delete: `backend/app/services/auth/token_blacklist.py` (replaced)
- [ ] Delete: `backend/app/services/rules/cache.py` (replaced)
- [ ] Update `docker-compose.yml`:
  - Remove `openwatch-redis` container
  - Remove `openwatch-celery-beat` container
  - Change `openwatch-worker` to run `python -m app.services.job_queue.worker`
  - Result: 3 containers (backend, worker, db) instead of 6
- [ ] Update `packaging/rpm/build-rpm.sh` and `packaging/deb/build-deb.sh`:
  - Remove Redis dependency from package requirements
  - Worker systemd service runs job_queue worker instead of Celery
- [ ] Update health check endpoint to remove Redis health
- [ ] Spec promotion: `job-queue.spec.yaml` draft → active
- [ ] Integration test: full scan cycle with no Redis/Celery running

### Phase D exit criteria

- [ ] Zero Redis connections in the running system
- [ ] Zero Celery imports in the codebase
- [ ] All 28 tasks executing via job_queue
- [ ] All 8 periodic schedules running via scheduler
- [ ] Scan → transaction → alert → notification pipeline works end-to-end
- [ ] Docker containers: backend, worker, db (3 total, down from 6)
- [ ] RPM/DEB packages build without Redis dependency
- [ ] `pg_queue.spec.yaml` active with 100% AC coverage

### PR decomposition

| PR | Contents | Week |
|---|---|---|
| 26 | job_queue table + service + worker + scheduler + spec | 8 |
| 27 | Task registry + adapter + 2 proof-of-concept migrations | 9 |
| 28 | Token blacklist → PG + rule cache → in-process + SSO state → PG | 10 |
| 29 | Migrate tasks batch 1+2 (maintenance + monitoring) | 11 |
| 30 | Migrate tasks batch 3+4 (compliance + on-demand) | 11 |
| 31 | Remove Celery + Redis + docker-compose + packaging updates | 12 |

**~6 PRs over 5 weeks.** Can overlap with Workstream A/B/C wrap-up.

### Risks

1. **Task timeout enforcement**: Celery uses OS signals (SIGTERM/SIGKILL) to enforce
   time limits. The custom worker needs the same — `signal.alarm()` works on Unix but
   not Windows. OpenWatch targets Linux only, so this is fine.

2. **Concurrent worker scaling**: Celery's prefork pool is battle-tested. The custom
   worker can use `concurrent.futures.ProcessPoolExecutor` for the same effect, but
   needs testing under load.

3. **Graceful shutdown**: Celery handles SIGTERM → warm shutdown → finish current task.
   The custom worker needs the same signal handling.

4. **Migration window**: During D2–D4, both Celery and job_queue run side-by-side.
   This means Redis is still required until D5. Plan for a clean cutover.

---

**~31 PRs over 12 weeks = ~2.5 PRs/week.** Realistic with 2 backend + 1 frontend engineer.

---

## Workstream E — Dependency Minimization (3 tiers)

OpenWatch targets air-gapped federal environments where every dependency is an attack
surface, a licensing risk, and a packaging burden. This workstream systematically
reduces the dependency tree across three tiers of increasing ambition.

### Tier 1: Python dependency cleanup (Q1, weeks 10–12, alongside Workstream D)

**Goal:** Consolidate redundant packages, remove dead dependencies. ~45 → ~30 packages.

**Phase E1.1: Consolidate HTTP clients (week 10)**

Three HTTP client libraries exist: `requests`, `httpx`, `aiohttp`. Only `httpx` is needed.

- [ ] Audit all `import requests` callsites — migrate to `httpx`
- [ ] Audit all `import aiohttp` callsites — migrate to `httpx` (supports async natively)
- [ ] Remove from `requirements.txt`: `requests`, `aiohttp`
- [ ] Keep: `httpx` (already used for webhooks and SSO)
- [ ] Verify: Kensa does not import requests/aiohttp internally

**Phase E1.2: Remove redundant schedulers (week 10)**

Two scheduling libraries exist alongside Celery Beat: `APScheduler`, `schedule`.
After Workstream D, all scheduling goes through the job_queue scheduler.

- [ ] Audit all `import apscheduler` and `import schedule` callsites
- [ ] Remove from `requirements.txt`: `APScheduler`, `schedule`
- [ ] Verify no runtime usage remains

**Phase E1.3: Remove dead SCAP/XML dependencies (week 11)**

Kensa replaced OpenSCAP. The XML processing chain may be dead code.

- [ ] Audit all `import lxml` and `import xmltodict` callsites
- [ ] If only used in legacy SCAP result parsing (OpenSCAP pathway): remove
- [ ] If used in active code (audit export PDF?): keep
- [ ] Remove `Pillow` and `python-magic` if unused outside SCAP content import
- [ ] Remove from `requirements.txt` any confirmed-dead packages

**Phase E1.4: Frontend chart library consolidation (week 11)**

Two charting libraries: `chart.js` + `react-chartjs-2` AND `recharts`.

- [ ] Audit which components use which library
- [ ] Consolidate to one (recommend `recharts` — more React-native, smaller bundle)
- [ ] Remove the unused library from `package.json`

**Phase E1.5: Remove Celery ecosystem (week 12, part of D5)**

Handled by Workstream D. Removes: `celery`, `redis`, `kombu`, `amqp`, `flower`.

**Tier 1 exit criteria:**
- [ ] `requirements.txt` has ≤30 direct dependencies (down from ~45)
- [ ] Zero redundant HTTP client libraries (httpx only)
- [ ] Zero redundant scheduler libraries
- [ ] Zero dead SCAP/XML dependencies (unless audit finds active usage)
- [ ] Frontend `package.json` has one charting library

**Tier 1 package inventory (target ~30):**

| Category | Packages | Count |
|---|---|---|
| Core runtime | fastapi, uvicorn, starlette, python-multipart | 4 |
| Database | SQLAlchemy, alembic, psycopg2-binary, asyncpg | 4 |
| Validation | pydantic, pydantic-settings, email-validator | 3 |
| Auth + crypto | PyJWT, passlib, argon2-cffi, cryptography, pyotp, qrcode | 6 |
| SSH | paramiko | 1 |
| HTTP client | httpx | 1 |
| Notifications | aiosmtplib, slack-sdk | 2 |
| SSO | authlib, pysaml2 | 2 |
| Config | python-dotenv, PyYAML | 2 |
| Monitoring | psutil | 1 |
| Kensa | kensa (git) | 1 |
| Observability | opentelemetry-api, opentelemetry-sdk, prometheus-client | 3 |
| **Total** | | **~30** |

**Removed (~15 packages):** celery, redis, kombu, amqp, requests, aiohttp, APScheduler,
schedule, lxml, xmltodict, Pillow, python-magic, Jinja2 (if unused outside templates),
aiofiles (if unused), chardet (if unused)

---

### Tier 2: FreeBSD 15.0 minimal containers (Q1, weeks 10–12) — ABANDONED 2026-04-14

> **STATUS UPDATE:** Tier 2 is abandoned. Linux Docker hosts (developer machines
> and GitHub Actions Linux runners) cannot execute FreeBSD OCI containers; that
> requires OCI v1.3 with a FreeBSD-aware runtime, which only exists on FreeBSD
> hosts. GitHub Actions does not provide FreeBSD runners. The maintenance cost
> of self-hosted FreeBSD infrastructure was not justified by the image-size
> reduction goal.
>
> All FreeBSD artifacts (Dockerfile.*.freebsd, docker-compose.freebsd.yml,
> packaging/freebsd/) were removed on 2026-04-14. Containers remain on the
> current Linux mix: UBI 9 (backend, worker), Alpine (db, frontend).
>
> The original Tier 2 plan is preserved below as historical record.

**Goal:** Migrate all containers from the current 3-distro mix (Red Hat UBI 9, Debian,
Alpine) to FreeBSD 15.0-RELEASE minimal. Eliminate package managers, shells, and
unnecessary system libraries from production images. Reduce total image size from
~600MB to ~200MB.

**Platform:** FreeBSD 15.0-RELEASE (2025-12-02, supported until 2026-09-30, OCI spec v1.3 recognized).

**Phase E2.1: FreeBSD base image (week 10)**

Build a custom minimal FreeBSD 15.0 base image for OpenWatch:

- [ ] Create `docker/Dockerfile.freebsd-base` — FreeBSD 15.0 minimal with:
  - Python 3.12 (from FreeBSD ports/pkg)
  - PostgreSQL 15 client libraries (libpq)
  - OpenSSL 3.x with FIPS provider module
  - openssh-portable (client only, for Kensa SSH)
  - No X11, no docs, no games, no unnecessary ports
- [ ] Target: base image ≤80MB
- [ ] Verify all Python C extensions compile on FreeBSD:
  - psycopg2 (libpq) — FreeBSD Tier 1 platform for PostgreSQL
  - cryptography (OpenSSL) — FreeBSD uses OpenSSL from base or ports
  - argon2-cffi (libargon2) — available in FreeBSD ports
  - paramiko (no C deps, pure Python)
- [ ] FIPS: Configure OpenSSL 3.x FIPS provider (`fips=yes` in openssl.cnf)

**Phase E2.2: Backend on FreeBSD (week 10)**

Replace `registry.access.redhat.com/ubi9/ubi:9.7` with FreeBSD 15.0:

- [ ] `docker/Dockerfile.backend` — multi-stage:
  - Stage 1: full FreeBSD 15.0 — install build deps, create venv, pip install
  - Stage 2: FreeBSD 15.0 minimal — copy venv + app code, no build tools
- [ ] `docker/Dockerfile.backend.dev` — full FreeBSD 15.0 with dev tools
- [ ] Verify: all backend tests pass on FreeBSD
- [ ] Verify: signal.alarm() works on FreeBSD (needed for job_queue worker timeouts)
- [ ] Target: backend image ≤120MB (down from ~400MB)

**Phase E2.3: Frontend serving on FreeBSD (week 11)**

Replace `nginx:1.29.5-alpine` with FreeBSD Nginx or embedded serving:

- [ ] Option A (recommended): Embed SPA in backend via FastAPI `StaticFiles` mount
  - Eliminates frontend container entirely
  - Backend serves both API (`:8000/api/*`) and SPA (`:8000/*`)
  - Nginx remains as reverse proxy only (optional, can be on host)
  - Container count: 3 → 2 (backend+SPA, worker, db)
- [ ] Option B: Nginx on FreeBSD 15.0 minimal
  - `docker/Dockerfile.frontend` — FreeBSD + nginx, no node/npm at runtime
  - Multi-stage: node:20 builds SPA, FreeBSD serves it
- [ ] Decision: Option A unless there's a specific reason for separate Nginx container

**Phase E2.4: PostgreSQL on FreeBSD (week 11)**

Replace `postgres:15.14-alpine` with FreeBSD PostgreSQL:

- [ ] `docker/Dockerfile.db` — FreeBSD 15.0 + PostgreSQL 15 from ports
- [ ] Minimal configuration: only en_US.UTF-8 locale, no unnecessary extensions
- [ ] Data directory on volume mount (same as current)
- [ ] Target: PostgreSQL image ≤80MB
- [ ] Alternative: keep Alpine PostgreSQL if FreeBSD PostgreSQL image is significantly larger
  (PostgreSQL is the same binary regardless of OS — the base matters less for DB)

**Phase E2.5: Worker on FreeBSD (week 12)**

- [ ] Worker Dockerfile inherits from the backend base (same Python + deps)
- [ ] `ExecStart` changes from `celery worker` to `python -m app.services.job_queue.worker`
  (handled by Workstream D)
- [ ] Verify: concurrent.futures.ProcessPoolExecutor works on FreeBSD (it does — POSIX fork)

**Phase E2.6: Native FreeBSD package (week 12)**

- [ ] Create `packaging/freebsd/` directory
- [ ] `packaging/freebsd/build-pkg.sh` — builds FreeBSD pkg package
- [ ] Package installs to `/usr/local/openwatch/` (FreeBSD convention)
- [ ] Systemd equivalent: FreeBSD rc.d scripts for openwatch-api and openwatch-worker
- [ ] `packaging/freebsd/rc.d/openwatch_api` — rc.d service script
- [ ] `packaging/freebsd/rc.d/openwatch_worker` — rc.d service script
- [ ] PostgreSQL and Nginx managed by FreeBSD pkg (system packages)

**Tier 2 exit criteria:**
- [ ] All containers run on FreeBSD 15.0-RELEASE minimal
- [ ] Zero Alpine, Debian, or Red Hat images in docker-compose.yml
- [ ] Total image size ≤200MB (down from ~600MB)
- [ ] FIPS: OpenSSL 3.x FIPS provider active on FreeBSD
- [ ] All backend tests pass on FreeBSD
- [ ] FreeBSD pkg package builds and installs correctly
- [ ] 2-3 containers total (backend+SPA, worker, db)

**Tier 2 container inventory (target):**

| Container | Base | Size |
|---|---|---|
| backend (API + SPA) | FreeBSD 15.0 minimal + Python 3.12 | ~120MB |
| worker | FreeBSD 15.0 minimal + Python 3.12 | ~120MB (shared base) |
| db | FreeBSD 15.0 minimal + PostgreSQL 15 | ~80MB |
| **Total** | | **~200MB** (with shared layers: ~150MB) |

If Option A (embedded SPA): backend+worker share the same image, db is separate = **2 images**.

**Native deployment (no containers):**

| Platform | Package | Services |
|---|---|---|
| FreeBSD 15.0 | `openwatch-0.1.0.pkg` | rc.d: openwatch_api, openwatch_worker |
| RHEL 9 / CentOS 9 | `openwatch-0.1.0.rpm` | systemd: openwatch-api, openwatch-worker |
| Ubuntu 24.04 | `openwatch-0.1.0.deb` | systemd: openwatch-api, openwatch-worker |

---

### Tier 3: Compiled core (Q3+, if business requires)

**Goal:** Rewrite performance-critical and dependency-heavy components in a compiled
language (Go or Rust) to produce static binaries with zero runtime dependencies.
This is a major architectural decision, not a cleanup task.

**Rationale:** Python contributes ~150MB of runtime overhead (interpreter + stdlib +
compiled extensions). A Go binary statically links against libpq and libssh2,
producing a ~30MB executable with no runtime dependencies. For air-gapped federal
deployments, "no runtime dependencies" is the ultimate packaging simplification.

**Phase E3.1: Assess viability (Q3 week 1)**

- [ ] Inventory which Python packages have Go/Rust equivalents:
  - FastAPI → Go `net/http` + `chi`/`echo` (mature)
  - SQLAlchemy → Go `sqlx` or `pgx` (mature)
  - Paramiko → Go `golang.org/x/crypto/ssh` (mature)
  - Pydantic → Go struct tags + validation (built-in)
  - Celery → already replaced by PostgreSQL job queue
- [ ] Assess Kensa compatibility: Kensa is Python. Options:
  - Keep Kensa as Python subprocess invoked by Go binary
  - Rewrite Kensa in Go (separate project decision)
  - Use Go-Python bridge (cgo + embedded Python — adds complexity)
- [ ] Decision gate: proceed only if Kensa team agrees on integration path
- [ ] Kensa integration: **Keep Kensa as Python subprocess**
  - Go binary invokes `python3 -m runner.engine` via subprocess, parses JSON output
  - Zero changes to Kensa required
  - Python becomes a single system dependency (alongside PostgreSQL)
  - Whether Kensa eventually gets a Go port is a Kensa team decision driven by
    Kensa's own community needs, NOT by OpenWatch's packaging preferences.
    OpenWatch is a consumer of Kensa; proposing Kensa rewrite itself to suit
    OpenWatch's binary size goals would invert the relationship.

**Phase E3.2: Go API server prototype (Q3 weeks 2–6)**

- [ ] Rewrite REST API layer in Go with identical endpoint contracts
- [ ] Use `pgx` for PostgreSQL (no ORM — matches current SQL Builders pattern)
- [ ] Use `golang.org/x/crypto/ssh` for SSH connections
- [ ] Use Go's `crypto/tls` with BoringCrypto for FIPS (certificate #4407)
- [ ] Embed frontend SPA as `embed.FS` — single binary serves API + SPA
- [ ] Target: single `openwatch` binary, ~30MB, zero runtime dependencies

**Phase E3.3: Worker in Go (Q3 weeks 4–8)**

- [ ] Rewrite job_queue worker in Go
- [ ] `SKIP LOCKED` polling with `pgx`
- [ ] Task dispatch via function registry
- [ ] Signal handling (SIGTERM graceful shutdown) built into Go runtime
- [ ] SSH scan execution via `golang.org/x/crypto/ssh`

**Tier 3 implications:**

| Aspect | Python (current) | Go (Tier 3) |
|---|---|---|
| Binary size | ~150MB (runtime + venv) | ~30MB (static binary) |
| Runtime deps | python3.12, libpq, libssl, ... | none (statically linked) |
| Startup time | ~2-5 seconds | ~50ms |
| Memory usage | ~100-200MB per process | ~20-50MB per process |
| Deployment | install Python, create venv, pip install | copy one binary |
| Kensa integration | native import | subprocess or rewrite |
| Development speed | faster (Python) | slower (Go) |
| Team skill requirement | Python | Go (new skill) |

**Tier 3 exit criteria (if pursued):**
- [ ] `openwatch` single binary serves API + SPA
- [ ] `openwatch-worker` single binary runs job queue
- [ ] RPM/DEB packages contain 2 binaries + config files (no Python, no venv)
- [ ] Total installed size ≤100MB including Kensa rules
- [ ] FIPS compliance via BoringCrypto (Go) or OpenSSL FIPS provider

**Tier 3 is a Q3+ decision.** It depends on team capacity, Kensa integration path,
and whether the packaging simplification justifies a full rewrite. Tiers 1 and 2
deliver 80% of the dependency reduction at 20% of the effort.

---

### Dependency reduction roadmap

```
Current state (Q1 start):
  Backend:    ~45 Python packages
  Frontend:   ~30 npm packages
  System:     6 deps (python, pg, redis, nginx, openssl, ssh)
  Containers: 6 (3 distros: UBI9, Debian, Alpine)
  Images:     ~600MB total
  Platforms:  RPM (RHEL 9), DEB (Ubuntu 24.04)

After Tier 1 + D (Q1 week 12):
  Backend:    ~30 Python packages  (-33%)
  Frontend:   ~28 npm packages     (-7%)
  System:     4 deps               (-33%, no Redis)
  Containers: 3-4 (still mixed distros)
  Images:     ~500MB total

After Tier 2 (Q1 week 12):
  Backend:    ~30 Python packages  (same)
  Frontend:   embedded in backend  (-100%, FastAPI StaticFiles)
  System:     2 deps (python, pg)  (-67%, no Redis, no Nginx container)
  Containers: 2-3 (all FreeBSD 15.0)
  Images:     ~200MB total         (-67%)
  Platforms:  FreeBSD pkg, RPM (RHEL 9), DEB (Ubuntu 24.04)

After Tier 3 (Q3+ if pursued):
  Backend:    0 Python packages    (Go binary)
  Frontend:   embedded in binary   (embed.FS)
  System:     1 dep (pg)           (-83%)
  Containers: 2 (FreeBSD 15.0)
  Images:     ~100MB total         (-83%)
  Platforms:  FreeBSD pkg, RPM, DEB (single static binary for all)
```

---

**~37 PRs total across all workstreams.** Tier 1 is part of Q1. Tier 2 is Q2.
Tier 3 is a separate decision.

---

## Next steps

1. **Walk this plan with founding team** — confirm Workstream A timing and parallelism assumption
2. **Open PRD epic E7** in `PRD/epics/E7-TRANSACTION-LOG.md`
3. **Customer survey** for audit export contract (week 1, blocking week 7)
4. **Kensa team sync** on pre-state capture (week 1, blocking Q2)
5. **Schedule security reviewer** for week 11 SSO review (week 9)
6. **Draft specs committed** this week so the CI framework picks them up early
7. **Redis/Celery migration** — Workstream D starts week 8 after transaction log stabilizes
8. **Dependency cleanup** — Workstream E Tier 1 runs alongside D (weeks 10-12)
9. **FIPS assessment** — determine if customers need CMVP certificate or just FIPS algorithms
10. **BSD minimal** — all containers and native deployments will target BSD minimal base (decision made 2026-04-13)
