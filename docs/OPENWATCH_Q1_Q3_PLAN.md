# OpenWatch Q1–Q3 Implementation Plan

**Date:** 2026-04-11
**Last updated:** 2026-04-14 (Kensa Convergence Addendum)
**Source:** Synthesis of codebase assessments against [OPENWATCH_VISION.md](OPENWATCH_VISION.md) Q1–Q3 milestones
**Companion:** [OPENWATCH_VISION_STATUS.md](OPENWATCH_VISION_STATUS.md)

**Scope note on OSCAL:** Per decision on 2026-04-11, OSCAL export is deferred — the feature belongs in Kensa first, then OpenWatch calls into it. This plan includes evidence envelope structure and Ed25519 signing (which are OpenWatch concerns) but omits OSCAL serialization.

---

## Kensa Convergence Addendum (2026-04-14)

This addendum captures the coordination outcome between the OpenWatch team and the Kensa team on 2026-04-14. It supersedes sections of this plan that assumed OpenWatch would implement functionality the Kensa Go Day-1 plan (`kensa/docs/KENSA_GO_DAY1_PLAN.md`) now commits to providing through its `api/` surface.

### The posture

Per the `OPENWATCH_VISION.md` framing (git : GitHub :: Kensa : OpenWatch), **OpenWatch is a collaboration, aggregation, and orchestration layer over Kensa**. OpenWatch does not re-implement what Kensa already does for a single host.

### What this changes in this plan

| Plan section | Original assumption | Revised assumption |
|---|---|---|
| **§6.1 Transaction log query API** | OpenWatch builds and owns the read path against PostgreSQL `transactions` | Endpoint URL + schema owned by OpenWatch; implementation delegates to `kensa.api.Kensa.TransactionLog().Query()` at **Kensa Week 22**. Interim implementation annotated in `specs/api/transactions/transaction-query.spec.yaml` v1.1. |
| **§6.2 Proactive remediation workflow** | OpenWatch generates the plan (capture/apply/validate/rollback) | OpenWatch wraps `Kensa.Plan` / `Kensa.Execute` with an approval-workflow UI. See revised §6.2 below. **Do not implement until Kensa Week 24.** |
| **Phase 3.4 Fleet health** | Queries `transactions` table + `host_liveness` | Same queries; PostgreSQL `transactions` is now framed as a **derived multi-host aggregation cache over Kensa's SQLite store** per Kensa Day-1 plan §13A. Survives through Kensa v1.0.0. |
| **Phase 3 Heartbeat (broadly)** | OpenWatch-internal event generation | OpenWatch subscribes to `Kensa.Subscribe(EventFilter{...})` at **Kensa Week 25** for transaction lifecycle events; OpenWatch still owns its own TCP liveness ping (§3.2 — distinct from Kensa's `HeartbeatPulse` and complementary). |
| **Per-transaction Ed25519 signing** | OpenWatch signs transaction envelopes via `POST /api/transactions/{id}/sign` | **Removed from OpenWatch.** Kensa signs envelopes at capture/execute time. OpenWatch's `SigningService` narrows to aggregate artifacts it originates (audit exports, quarterly posture reports, State-of-Production release). See `specs/services/signing/evidence-signing.spec.yaml` v2.0. |

### What this keeps unchanged

These remain purely OpenWatch-layer concerns and ship on their original schedule:

- SSO federation (Phase 3.6) — OIDC + SAML, purely user-auth concern
- Notification dispatch (Phase 3.5) — Slack/email/webhook/Jira fan-out from `AlertService`
- Adaptive scan scheduling — OpenWatch decides *when* to call `Kensa.Scan`
- Multi-approval chains and approval policies (Phase 6.3)
- Fleet grouping + per-group policies (Phase 6.4)
- State-of-Production Rollback report (Phase 6.5) — cross-tenant aggregation
- RBAC, audit logging of OpenWatch user actions, multi-tenant isolation
- Audit-export generation and its Ed25519 signing (OpenWatch-originated artifact)

### Kensa milestones OpenWatch converges onto

| Kensa week | OpenWatch action |
|---|---|
| **Week 1** — `api/` surface frozen with stubs | OpenWatch codes against signatures immediately; stubs return `ErrNotYetImplemented` |
| **Week 22** — `LogQuery` real | OpenWatch swaps `/api/transactions/query` from PostgreSQL to `Kensa.TransactionLog()` |
| **Week 24** — `Plan`/`Execute` real | OpenWatch starts §6.2 implementation |
| **Week 25** — `Subscribe` real | OpenWatch cuts Heartbeat (the event stream parts) from polling to subscription |
| **Week 26 (M5)** — all OpenWatch-facing APIs real | Full integration test: Plan → Subscribe → Execute → Query |
| **Week 40 (M7)** — Kensa Go v1.0.0 | OpenWatch is pure consumer; Python Kensa archived |

### Convergence-annotation convention

Every OpenWatch spec or interim implementation that delegates to a Kensa `api/` method post-convergence carries a frontmatter block:

```yaml
interim_implementation:
  delegates_to: kensa.api.Kensa.TransactionLog().Query
  convergence_week: 22
  kensa_plan_ref: kensa/docs/KENSA_GO_DAY1_PLAN.md §3.5.1 LogQuery
  notes: |
    ...
```

This makes drift visible at review time. The pattern is established in `specs/api/transactions/transaction-query.spec.yaml` v1.1 (PR #399).

### Related documents

- `docs/KENSA_OPENWATCH_COORDINATION_2026-04-14.md` — the outbound memo from OpenWatch to Kensa
- `/home/rracine/hanalyx/kensa/docs/KENSA_OPENWATCH_RESPONSE_2026-04-14.md` — Kensa team's response with accepted resolutions + interface decisions
- `/home/rracine/hanalyx/kensa/docs/KENSA_GO_DAY1_PLAN.md` — Kensa's Day-1 build plan (updated 2026-04-14 §3.5 with interface refinements from OpenWatch's asks)

---

## Executive Summary

The assessment confirms the vision doc's diagnosis: **OpenWatch's engine layer is strong, but the product-identity layer — the transaction log, Control Plane integrations, and signed evidence — is absent.** The single highest-leverage change is the Q1 transaction log refactor, because every subsequent milestone (per-host audit timeline, Agent API, historical posture, query API, signed bundles) assumes it exists.

**Critical finding**: Kensa already captures the `validate` phase of the four-phase model in `scan_findings.evidence` JSONB. **Pre-state and post-state are not systematically captured.** The refactor is primarily (a) schema unification, (b) adding pre/post-state capture to `kensa_scan_tasks.py`, and (c) UI reorganization — NOT greenfield data modeling. The data mostly exists; it's in the wrong shape.

**Second critical finding**: The compliance scheduler is more mature than the vision status suggested. Adaptive intervals (1h–48h based on compliance state) are shipped, Celery Beat dispatches every 2 minutes, per-host schedules live in `host_compliance_schedule`. The Heartbeat is **~60% there**; the gaps are auto-baseline-on-first-scan, a separate liveness ping (independent of scan cadence), and notification dispatch (Slack/email/webhook — the service layer exists, the channels don't).

**Third critical finding**: The Control Plane has the biggest absolute gap. **Zero** SAML/OIDC groundwork. **No** multi-approval infrastructure (single-approver exceptions only). **No** Slack/Jira integrations (webhooks exist, but generic and outbound-only). Exception workflow has a complete backend API but **no frontend UI**. Scheduled-scan management has the same shape: backend ready, UI missing.

---

## Phasing

The plan is organized into **6 phases over ~9 months**, mapping to Q1/Q2/Q3 milestones. Each phase is ~4–6 weeks. Phases 1–3 are Q1, phases 4–5 are Q2, phase 6 is Q3. Critical path is Phase 1 (transaction log schema) — everything else compounds on it.

```
Phase 1  (wks 1-6)   : Transaction log schema + write-path refactor   [Q1 — Eye]
Phase 2  (wks 4-8)   : Transaction log UI + navigation rename         [Q1 — Eye]
Phase 3  (wks 6-12)  : Heartbeat completion + Control Plane integrations Tier 1
                       (SSO, Slack/email, auto-baseline, liveness ping) [Q1 — Heartbeat + CP]
Phase 4  (wks 12-18) : Evidence envelope four-phase capture + Ed25519 signing
                       + per-host timeline API + exception UI + scheduler UI [Q2]
Phase 5  (wks 14-20) : Baseline auto-management + alert routing + Jira sync
                       + retention policies                          [Q2]
Phase 6  (wks 20-36) : Transaction log query API + proactive remediation workflow
                       + multi-approval infrastructure + fleet-group policies
                       + first "State of Production Rollback" report [Q3]
```

Phases overlap deliberately: while Phase 1's backend refactor is in flight, Phase 2's frontend work can start against the (versioned) new API; Phase 3 Control Plane work doesn't depend on transactions and starts in parallel.

---

## Phase 1: Transaction Log Schema & Write Path (weeks 1–6) — Q1

**Why first:** Every Q2/Q3 deliverable (per-host timeline, query API, signed bundles, proactive remediation, Agent API) reads from the transaction log. Without the unified schema, later work either builds on shifting foundations or duplicates effort.

**Current state (from assessment):**
- 5 separate tables: `scans`, `scan_results`, `scan_findings`, `scan_baselines`, `scan_drift_events`
- `scan_findings.evidence` (JSONB) already captures Kensa's validate-phase evidence (method, command, stdout, stderr, expected, actual, exit_code, timestamp)
- `scan_findings.framework_refs` (JSONB) already stores rule-to-control mappings with GIN indexes
- **Missing**: pre-state, post-state, four-phase-shaped envelope, initiator metadata, approval/rollback linkage
- Write surface: `backend/app/tasks/kensa_scan_tasks.py:312-341` (single INSERT point for findings)

### 1.1 New `transactions` table (week 1)

Create a new Alembic migration adding a `transactions` table **alongside** the existing scan tables (do not drop old tables yet). Columns:

| Column | Type | Notes |
|---|---|---|
| `id` | UUID (PK) | |
| `host_id` | UUID (FK hosts.id) | |
| `rule_id` | VARCHAR(255) | Kensa rule id; NULL for orchestration transactions |
| `scan_id` | UUID (FK scans.id) | Legacy linkage during migration window |
| `phase` | VARCHAR(16) | `capture` / `apply` / `validate` / `commit` / `rollback` |
| `status` | VARCHAR(16) | `pass` / `fail` / `skipped` / `error` / `rolled_back` |
| `severity` | VARCHAR(16) | |
| `initiator_type` | VARCHAR(16) | `user` / `scheduler` / `drift_trigger` / `agent` |
| `initiator_id` | VARCHAR(255) | user_id or service name |
| `pre_state` | JSONB | System state before apply (nullable for read-only checks) |
| `apply_plan` | JSONB | Handler + params that Kensa executed |
| `validate_result` | JSONB | stdout, stderr, exit_code, expected, actual |
| `post_state` | JSONB | System state after commit / restored state after rollback |
| `evidence_envelope` | JSONB | Full structured envelope (see Phase 4) |
| `framework_refs` | JSONB | `{cis-rhel9-v2.0.0: "5.1.12", stig-rhel9-v2r7: "V-257778"}` |
| `baseline_id` | UUID (FK scan_baselines.id) | For drift comparison |
| `remediation_job_id` | UUID | Links remediation transactions back to finding transaction |
| `started_at` | TIMESTAMPTZ | |
| `completed_at` | TIMESTAMPTZ | |
| `duration_ms` | INTEGER | |
| `tenant_id` | UUID | Nullable now; foundation for Q6 multi-tenancy |

**Indexes:**
- `(host_id, started_at DESC)` — primary per-host timeline query
- `(scan_id)` — legacy join during migration
- `(status, started_at)` — "all failures in last N hours" (alerts)
- GIN on `framework_refs` — "all transactions satisfying NIST AC-2"
- GIN on `evidence_envelope` — audit search
- `(remediation_job_id)` — link remediation chains

**Spec:** Create a new `specs/system/transaction-log.spec.yaml` (Active, owner: backend) as the authoritative contract for the four-phase model. This becomes a hard CI gate via existing `check-spec-coverage.py`.

### 1.2 Dual-write from `kensa_scan_tasks.py` (week 2)

Modify `backend/app/tasks/kensa_scan_tasks.py` (lines 250–343, the existing write path) to emit both old-schema rows AND new transaction rows on the same DB transaction. This gives us a reversible migration.

**Capturing pre/post-state (the real new work):**
- Kensa's current `Evidence.actual` field records post-validation state
- `pre_state` is **not** captured today. Two options:
  1. **Minimal**: for read-only compliance checks (the common case), pre_state == post_state (nothing changed), record once
  2. **Full**: before Kensa applies a check, run a lightweight `capture_state` call via the same SSH session. Reuses Kensa's `detect_capabilities` mechanism but narrowed to the rule's target
- **Recommendation**: ship Option 1 for read-only checks in Phase 1; extend to Option 2 for remediation transactions in Phase 4 (where pre/post genuinely differ)

For **remediation** transactions (which already have richer data per migration `20260224_0100_039_add_remediation_evidence.py`), write a second transaction row with `phase=apply`/`commit`/`rollback` and link it to the original finding transaction via `remediation_job_id`.

### 1.3 Shim read layer (weeks 2–3)

Add a `TransactionRepository` in `backend/app/repositories/transaction_repository.py` that services will use going forward. For Phase 1, it reads from the new `transactions` table. Existing services (`DriftDetectionService`, `AlertGeneratorService`, `AuditQueryService`, `TemporalComplianceService`) stay on the old tables until Phase 2 migrates them one at a time.

**Critical dependency map (from assessment) — these 14+ services read the old tables and must migrate:**

- `services/compliance/temporal.py` — `get_posture()`, `detect_drift()`, `create_snapshot()` (historical queries)
- `services/compliance/alert_generator.py` — severity threshold reads
- `services/compliance/audit_query.py` — evidence search
- `services/compliance/audit_export.py` — CSV/PDF/JSON exports (**highest risk** — customer-facing contract)
- `services/compliance/exceptions.py` — finding suppression
- `services/compliance/remediation.py` — job creation
- `services/monitoring/drift.py` — drift monitoring
- `services/baseline_service.py` — baseline management
- `routes/scans/reports.py` — report generation
- `routes/scans/kensa.py` — scan execution
- `routes/compliance/drift.py` — drift API
- `routes/compliance/posture.py` — posture API
- `routes/compliance/audit.py` — audit API
- `tasks/backfill_snapshot_rule_states.py` — snapshot backfill

### 1.4 Backfill task (week 4)

Celery task `backfill_transactions_from_scans` that reads all historical `scan_findings` rows and synthesizes transaction rows. Run in chunks of 10k rows with progress tracking. Transactions generated from historical data have `phase=validate` only (we can't reconstruct pre/post-state for rows that predate the refactor — this is fine; historical rows become immutable validate-only entries).

### 1.5 Service migration (weeks 4–6)

Migrate services off old tables to `TransactionRepository` one at a time, in order of risk:

1. `audit_query.py` (read-only; low risk)
2. `temporal.py` — `get_posture()` and `detect_drift()` — **most important because temporal compliance is a key differentiator**. Ensure `(host_id, started_at)` index query plans are <500ms
3. `alert_generator.py`
4. `audit_export.py` — **high risk**. Keep exports emitting the same CSV/JSON column contract; only the read source changes. Add a regression test that compares old vs new export bytes for a known fixture scan.
5. `drift.py`, `posture.py` route layers
6. `kensa.py` route layer

**At end of Phase 1:** all services read from `transactions`, old tables still exist as write-through shadow tables (safe rollback), Phase 2 frontend work can begin.

### 1.6 Risk mitigation

From the assessment:
- **Foreign key cascades**: `scan_findings.scan_id → scans.id ON DELETE CASCADE` could orphan transactions during the dual-write window. Add an explicit `ON DELETE` policy on `transactions.scan_id` (SET NULL, not CASCADE — we want transactions to survive scan deletion; they're the audit trail)
- **Framework mapping consistency**: `RuleReferenceService` already syncs inline `references:` + mapping files into `framework_mappings`. Extend it to also sync into `transactions.framework_refs` on write (not retroactively — only on new transactions)
- **Export schema stability**: regression test on fixture scan, as above

### 1.7 Exit criteria

- [ ] `transactions` table in production, dual-writing
- [ ] All services migrated to `TransactionRepository`
- [ ] `audit_export` regression test passes (byte-identical fixture export)
- [ ] Temporal query benchmark: `<500ms` for "posture at date X for host Y"
- [ ] `transaction-log.spec.yaml` Active with 100% AC coverage
- [ ] Old tables still written to (rollback possible)
- [ ] No performance regression on scan execution (`kensa_scan_tasks` duration within +10%)

---

## Phase 2: Transaction Log UI & Navigation (weeks 4–8) — Q1

**Current state (from assessment):**
- Frontend nav: Dashboard → Scans → Compliance (Drift, Exceptions, Alerts, Audit) → Reports
- `frontend/src/pages/scans/Scans.tsx` + `ScanDetail.tsx` are the primary scan entry points
- `frontend/src/services/adapters/scanAdapter.ts` is the API client
- Role-based dashboards (PR #349) shipped; widgets are swappable per role

### 2.1 New API surface (weeks 4–5)

Create `/api/transactions/*` endpoints in `backend/app/routes/transactions/`:

- `GET /api/transactions` — paginated list, filter by `host_id`, `status`, `framework`, `phase`, `initiator_type`, `started_at` range
- `GET /api/transactions/{id}` — single transaction with full four-phase breakdown
- `GET /api/transactions/{id}/evidence` — evidence envelope (prep for Phase 4 signing)
- `GET /api/hosts/{host_id}/transactions` — per-host timeline (Q2 deliverable, stubbed in Phase 2, fully implemented in Phase 4)

Old `/api/scans/*` endpoints stay live as shims (proxy to transactions repository) with `Deprecation` headers. Remove no earlier than Phase 6.

### 2.2 Frontend refactor (weeks 5–8)

- Rename top-nav **Scans** → **Transactions**
- Create `frontend/src/pages/transactions/Transactions.tsx` (list) and `TransactionDetail.tsx` (detail)
- Four tabs on TransactionDetail: **Execution** (four-phase timeline), **Evidence** (raw envelope), **Controls** (framework mappings), **Related** (other transactions for same host/rule)
- Create `frontend/src/services/adapters/transactionAdapter.ts`; leave `scanAdapter.ts` as a thin re-export during deprecation
- **Findings** becomes a filtered view: `Transactions` with `status=fail`; build `Findings.tsx` as a preset filter on the list page
- **Reports** navigation unchanged; reports re-sourced from `TransactionRepository` (handled in Phase 1 service migration)

### 2.3 Spec updates

Update these specs (from the assessment) to reference the new `transactions` table and four-phase model:

- `pipelines/scan-execution.spec.yaml`
- `pipelines/drift-detection.spec.yaml`
- `services/compliance/temporal-compliance.spec.yaml`
- `services/compliance/audit-query.spec.yaml`
- `services/compliance/compliance-scheduler.spec.yaml`
- `api/scans/scan-results.spec.yaml`
- `api/scans/scan-crud.spec.yaml`
- `api/scans/scan-reports.spec.yaml`
- `frontend/scan-workflow.spec.yaml`
- `frontend/scans-list.spec.yaml`

### 2.4 Exit criteria

- [ ] `/api/transactions/*` live and documented in Swagger
- [ ] Transactions list + detail pages shipped
- [ ] Findings as filtered transaction view
- [ ] Old `/api/scans/*` deprecation headers
- [ ] 10 specs updated, CI coverage enforced
- [ ] Manual QA: end-to-end flow (Kensa scan → transaction row → UI renders four phases)

---

## Phase 3: Heartbeat Completion + Control Plane Tier 1 (weeks 6–12) — Q1

This phase runs in parallel with Phase 2 because it doesn't depend on the transaction log refactor.

### 3.1 Heartbeat: auto-baseline on first scan (week 6)

**Current state:** `PostureSnapshot` model exists; daily snapshots via `create_daily_posture_snapshots`. Manual snapshot creation via `TemporalComplianceService.create_snapshot()`. **No trigger on first scan.**

Wire into `kensa_scan_tasks.py` (the same write path we're refactoring in Phase 1): after a successful scan, if `scan_baselines` has no `is_active=true` row for this host, create one via `BaselineService.establish_baseline(host_id, source_scan_id)`. Idempotent; safe to call on every scan.

### 3.2 Heartbeat: liveness ping separate from scan cadence (weeks 6–7)

**Current state:** "Liveness" = `last_scan_completed` timestamp. At the default 6h–24h scan cadence, liveness signal is too slow for the vision's "15-min detection" target.

Add `host_liveness` table: `host_id, last_ping_at, last_response_ms, reachability_status (reachable/unreachable/unknown)`. New Celery Beat task `ping_managed_hosts` every 5 minutes — for each host, open a TCP connection to the SSH port and record response time. No auth, no command execution; it's a reachability check.

Update `FleetHealthWidget.tsx` (already exists, 336 LOC) to show liveness distinct from scan recency.

### 3.3 Heartbeat: maintenance mode UI (week 7)

Backend exists (`compliance_scheduler.py:508-549`). Frontend needs a toggle in Host Detail + Host List pages. Small change, high user visibility.

### 3.4 Heartbeat: fleet health "at a glance" (week 8)

Extend Dashboard's existing fleet health section with:
- "X hosts up / Y total"
- "Z hosts with drift in last 24h"
- "N failed scans in last 24h"

Queries go against `transactions` table (Phase 1 exit criteria) + `host_liveness`.

> **Revised 2026-04-14** per Kensa Convergence Addendum: the `transactions` PostgreSQL table is now framed as a **derived multi-host aggregation cache over Kensa's SQLite store** (Kensa Day-1 plan §13A). At Kensa Week 25, the event feed for drift counts switches from polling the PostgreSQL table to consuming `Kensa.Subscribe` with `EventKind=DriftDetected`. No API surface change for the frontend; just a backend implementation swap. The PostgreSQL cache survives through Kensa v1.0.0 because multi-fleet aggregation across N Kensa SQLite stores would be too slow to do at query time without a cache.

### 3.5 Control Plane: notification dispatch (weeks 7–9)

**Current state:** `AlertService` + alert thresholds shipped (PR #281). `alert_generator.py` creates alert rows in DB. **No outbound dispatch.** Generic webhook surface exists (`routes/integrations/webhooks.py`) but not wired to alerts.

Create `backend/app/services/notifications/` package with:
- `base.py` — abstract `NotificationChannel` interface
- `slack.py` — uses `slack-sdk`, POST to incoming webhook URL with Block Kit formatting
- `email.py` — SMTP via `aiosmtplib`, templated HTML
- `webhook.py` — thin wrapper over existing webhook service for alert-specific events

Wire `AlertService.create_alert()` to enqueue a notification task per configured channel. Dedupe via the existing 60-min window logic in `alerts.py:137`.

**Jira is deferred to Phase 5.** Jira's bidirectional sync is a larger lift than Slack/email and isn't a Q1 blocker.

### 3.6 Control Plane: SAML/OIDC SSO (weeks 8–12)

**Current state (from assessment):** Zero groundwork. Local users + JWT only. FIPS-compliant Argon2id and RS256 JWT (good), but no federation.

Add `authlib` to `requirements.txt` (authlib handles both OIDC and SAML2 and is actively maintained, FIPS-compatible).

Create `backend/app/services/auth/sso/`:
- `provider.py` — abstract `SSOProvider` with `get_login_url`, `handle_callback`, `map_claims_to_user`
- `oidc.py` — `OIDCProvider` using authlib's OAuth2 client
- `saml.py` — `SAMLProvider` using python3-saml (FedRAMP-approved library)

Database:
- `sso_providers` table: `id, tenant_id (nullable), provider_type, config (JSONB, encrypted), enabled`
- Extend `users` table: `sso_provider_id`, `external_id`, `last_sso_login_at`

Routes:
- `GET /api/auth/sso/login?provider={id}` — redirect to IdP
- `GET /api/auth/sso/callback/{provider_type}` — handle ACS (SAML) or token exchange (OIDC)
- `GET /api/auth/sso/providers` — list configured providers for login screen
- `POST /api/admin/sso/providers` — admin configures new IdP

Claim mapping: `email → users.email`, `groups → users.role` (configurable mapping in provider config). First-login creates a local user record linked to `external_id`. Subsequent logins update claims.

Frontend: extend login page to show "Login with SSO" buttons for configured providers. Small change; authlib does the heavy lifting.

**Load-bearing because:** federal customers cannot buy OpenWatch without SSO. This is the most commercially-urgent item in Q1 after the transaction log.

### 3.7 Exit criteria

- [ ] First-scan baseline auto-established
- [ ] `host_liveness` table + 5-minute ping task running
- [ ] Maintenance mode toggle in Host Detail UI
- [ ] Slack + email notifications firing on alerts
- [ ] At least one OIDC provider (e.g., Okta dev tenant) and one SAML provider (e.g., AD FS test instance) successfully authenticating users
- [ ] Deprecation headers on `/api/auth/login` for customers who need to migrate

---

## Phase 4: Evidence Envelope + Signing + Per-Host Timeline + UIs (weeks 12–18) — Q2

### 4.1 Four-phase evidence capture (weeks 12–14)

**Current state:** Kensa's `Evidence` dataclass captures the validate phase only (method, command, stdout, stderr, exit_code, expected, actual, timestamp). Pre/post-state missing.

For compliance scans (read-only checks), Phase 1 established that `pre_state == post_state` is the common case. For Phase 4, add **explicit structured capture** even for read-only checks:

```python
evidence_envelope = {
    "schema_version": "1.0",
    "kensa_version": "1.2.5",
    "phases": {
        "capture": {"state": {...}, "at": "..."},
        "apply": {"plan": {...}, "executed": False, "at": null},   # read-only
        "validate": {"method": ..., "command": ..., "stdout": ..., "exit_code": ...},
        "commit": {"status": "pass", "post_state": {...}, "at": "..."},
        "rollback": null,
    },
    "framework_refs": {...},
    "rule_metadata": {"id": ..., "title": ..., "severity": ...},
    "host_context": {"host_id": ..., "os": ..., "arch": ...},
}
```

For **remediation** transactions, all four phases populate. Extend `backend/app/plugins/kensa/evidence.py:19-45` (current `_evidence_to_dict`) to return this envelope shape. Coordinate with the Kensa team if upstream changes are needed — per the vision, OpenWatch is the fleet runtime, but if Kensa needs to emit pre-state, that's a Kensa PR.

**Spec:** add AC for envelope schema to `specs/system/transaction-log.spec.yaml` (created in Phase 1).

### 4.2 Ed25519 signing (weeks 13–15)

**Current state (from assessment):** Greenfield. No Ed25519 code. `encryption/service.py` has AES-256-GCM; `auth.py` has RS256 JWT; no signing abstraction.

Create `backend/app/services/signing/`:
- `service.py` — `SigningService` with `sign_envelope(envelope: dict) -> SignedBundle` and `verify(bundle: SignedBundle) -> bool`
- Uses `cryptography.hazmat.primitives.asymmetric.ed25519` (FIPS-compatible, already in deps)
- Signing key stored per-deployment in `deployment_signing_keys` table (encrypted via existing `EncryptionService`)
- Key rotation: new key becomes active, old keys remain verifiable; bundles record `key_id`

Signed bundle format:
```json
{
  "envelope": { ... },
  "signature": "base64(ed25519-sig)",
  "key_id": "uuid",
  "signed_at": "ISO8601",
  "signer": "openwatch@deployment-name"
}
```

Public verification endpoint: `GET /api/signing/public-keys` returns all active + retired public keys so auditors can verify bundles offline.

Documentation: publish `docs/EVIDENCE_VERIFICATION.md` with a standalone Python verification script (20 lines) that auditors can use without an OpenWatch install.

### 4.3 Per-host transaction timeline (weeks 14–16)

**Current state (from assessment):** `TemporalComplianceService.get_posture(host_id, as_of)` exists for point-in-time queries. No "all transactions for host X" timeline.

API: `GET /api/hosts/{host_id}/transactions` with filters `phase`, `status`, `framework`, `rule_id`, date range, full-text search on evidence (using the GIN index on `transactions.evidence_envelope`). Paginated, cursor-based.

Frontend: new tab on `HostDetail.tsx` — **Audit Timeline**. Reverse-chronological list of transactions, click-through to `TransactionDetail`. Export button → queues an audit export job for that host + date range.

### 4.4 Exception workflow UI (weeks 15–17)

**Current state (from assessment):** Backend complete at `routes/compliance/exceptions.py`. Zero frontend.

Create `frontend/src/pages/compliance/Exceptions.tsx`:
- List view (paginated, filter by status/rule/host)
- Request form (justification, risk assessment, expiration date)
- Approval workflow display (approver name, approved_at, justification)
- "Escalate" button — re-routes to higher-role approver (requires Phase 6 multi-approval infra, so in Phase 4 it's a single-level escalation: analyst → officer/admin)
- Button to kick off remediation from an excepted rule

Backend change: add `approval_chain JSONB` to `ComplianceException` table for multi-approval groundwork (populated with single approver for now; Phase 6 extends to N approvers).

### 4.5 Scheduled scan management UI (weeks 16–18)

**Current state:** Backend complete at `routes/compliance/scheduler.py`. No frontend.

Create `frontend/src/pages/scans/ScheduledScans.tsx`:
- Current adaptive-interval config (the 1h/6h/12h/24h/48h tiers) with sliders
- Per-host schedule table: `next_scheduled_scan`, `current_interval_minutes`, `maintenance_mode`
- Preview: histogram of next 48h scans across the fleet
- New backend endpoint `POST /api/compliance/scheduler/preview` that returns "given this config, here are the next 50 scheduled scans"

### 4.6 Exit criteria

- [ ] Evidence envelope schema v1.0 frozen and specced
- [ ] Ed25519 signing service with key rotation
- [ ] Per-host timeline API + Host Detail tab
- [ ] Exception workflow UI shipped
- [ ] Scheduled scan management UI shipped
- [ ] `docs/EVIDENCE_VERIFICATION.md` + standalone verification script

---

## Phase 5: Baseline Auto-Mgmt, Alert Routing, Jira, Retention (weeks 14–20) — Q2

Parallel to Phase 4.

### 5.1 Baseline auto-management (weeks 14–15)

**Current state (from assessment):** Baselines exist as `scan_baselines` rows; daily snapshots via `create_daily_posture_snapshots`. Auto-create on first scan lands in Phase 3. **Missing:** explicit "update baseline" API + rolling baselines for moving targets.

- `POST /api/hosts/{host_id}/baseline/reset` — establish new baseline from most recent scan
- `POST /api/hosts/{host_id}/baseline/promote` — promote current posture to baseline (after legitimate config change)
- Rolling baseline: 7-day moving average for hosts marked `baseline_type=rolling_avg`
- Frontend: button on HostDetail.tsx

### 5.2 Alert routing rules (weeks 15–17)

**Current state:** Alerts fire to a single default channel set. No per-severity routing.

Add `alert_routing_rules` table: `id, severity, alert_type, channel_type, channel_config (JSONB), tenant_id`. Example rule: `CRITICAL + HOST_UNREACHABLE → pagerduty:oncall`.

Extend `AlertService.create_alert()` dispatch loop to query routing rules and fan out to multiple channels. Add PagerDuty channel to `notifications/` package (alongside Slack/email from Phase 3).

Frontend: `frontend/src/pages/compliance/AlertRoutingRules.tsx` — rule table, create/edit form.

### 5.3 Jira bidirectional sync (weeks 16–19)

Deferred from Phase 3 because bidirectional is nontrivial.

- `backend/app/services/notifications/jira.py` — uses `jira` Python SDK
- Outbound: drift events + failed transactions create Jira issues with evidence envelope attached
- Inbound: Jira webhook → `POST /api/integrations/jira/webhook` → update OpenWatch exception or transaction state based on issue state transitions
- Field mapping configurable per Jira project; first customer gets hardcoded mapping

### 5.4 Retention policies (weeks 18–20)

**Current state:** `audit_export.cleanup_expired_exports()` has 7-day retention. `scan_findings` has no TTL.

Add `retention_policies` table: `tenant_id, resource_type, retention_days`. Enforce via `cleanup_old_transactions` Celery task that deletes `transactions` older than policy (default 365 days, configurable per fleet/tenant).

**Critical:** before deletion, emit an "archive" signed bundle to configurable storage (S3 or filesystem). Retention deletion should NEVER be destructive of the audit trail — it moves transactions from hot storage to cold signed archives.

### 5.5 Exit criteria

- [ ] Baseline reset/promote APIs + UI
- [ ] Alert routing rules + PagerDuty channel
- [ ] Jira outbound + inbound (first customer mapping)
- [ ] Retention policy CRUD + enforcement with signed archive emission

---

## Phase 6: Query API, Proactive Remediation, Multi-Approval, Groups, Report (weeks 20–36) — Q3

### 6.1 Transaction log query API (weeks 20–23)

> **REVISED 2026-04-14** per Kensa Convergence Addendum. The endpoint URL + schema + DSL shape are owned by OpenWatch (stable HTTP contract). The **implementation** converges onto Kensa's `api.Kensa.TransactionLog()` at Kensa Week 22. **First slice shipped 2026-04-14 as PR #398**; interim annotation added in PR #399.

The read side we stubbed in Phase 2 becomes a first-class, documented, paginated, filterable HTTP API — which in turn is a thin wrapper over Kensa's `LogQuery` interface (Kensa Day-1 plan §3.5.1).

- `POST /api/transactions/query` accepts a query DSL: filters (`host_id`, `fleet_id`, `date_range`, `status`, `phase`, `framework`, `rule_id`, `initiator_type`), sort, pagination cursor, projection (which fields to return) — **shipped in PR #398**
- Response includes `total_count`, `next_cursor`, paginated results
- Rate limits per API key — **deferred to follow-up PR** (listed in spec's `out_of_scope`)
- OpenAPI spec published, versioned `v1`
- **Target**: historical posture query (`"fleet X compliance state on 2026-03-15"`) in `<500ms` p95 (the vision's KPI) — **deferred to follow-up PR**

At Kensa Week 22, the endpoint's implementation swaps:
- Current: reads PostgreSQL `transactions` table (fed by Python Kensa)
- Post-Week-22: delegates to `kensa.api.Kensa.TransactionLog().Query()` for single-deployment queries; PostgreSQL cache serves multi-fleet aggregate queries that span N Kensa deployments (per Kensa §13A federated-v1.0 / push-v1.1 sequencing).

Spec: `specs/api/transactions/transaction-query.spec.yaml` v1.1 — carries the `interim_implementation:` frontmatter establishing the convergence pattern.

### 6.2 Proactive remediation workflow (weeks 22–26)

> **REVISED 2026-04-14** per Kensa Convergence Addendum. Original draft had OpenWatch generating the plan. Revised architecture: **OpenWatch wraps Kensa.Plan / Kensa.Execute with an approval-workflow UI.** Do not start implementation until Kensa Week 24 (when `Plan` / `Execute` land real).

**Current state (from assessment):** `RemediationService.create_job()` exists with dry-run flag + license enforcement. **Missing:** auto-draft on drift, approval queue UI, integration with Kensa's Plan/Execute API.

**Architecture (revised):**

```
Drift event detected (from Kensa.Subscribe event stream, Week 25)
    ↓
OpenWatch calls kensa.api.Kensa.Plan(host, rule)
    ↓
Returns an opaque Plan blob
    ↓
OpenWatch stores the blob in remediation_jobs.kensa_plan (JSONB) without interpreting it
Row starts at status=draft with approval_chain metadata
    ↓
ApprovalQueue UI renders the plan via Kensa's plan.Preview(PreviewMarkdown)
(canonical preview owned by Kensa — no OpenWatch-side plan rendering)
    ↓
Multi-approval chain (Phase 6.3) progresses draft → approved
    ↓
On full approval, OpenWatch calls kensa.api.Kensa.Execute(host, plan)
    ↓
If PlanStaleError returned: mark remediation_jobs.status=stale,
  prompt for re-plan. The `StaleStepIndex` + `Field` + `Expected`/`Actual`
  fields from Kensa drive the UX ("re-plan because step 2's config_set
  of PermitRootLogin found value 'prohibit-password' but the plan
  captured 'yes'")
    ↓
On success: update remediation_jobs.status=completed,
  store Kensa's returned TransactionResult.TxnID
    ↓
Each state transition writes a transaction row to Kensa's log via Kensa's
engine (not a separate OpenWatch-generated row)
```

**What OpenWatch owns:**
- `remediation_jobs` table schema: `id, host_id, rule_id, kensa_plan (JSONB, opaque), approval_chain_id, status, created_at, approved_at, executed_at, kensa_txn_id (nullable, filled on success)`
- Auto-draft triggering — when `DriftDetected` event arrives from `Kensa.Subscribe` with `drift_type=major`, call `Kensa.Plan` and persist the draft
- ApprovalQueue UI (`frontend/src/pages/remediation/ApprovalQueue.tsx`) listing drafts, routing to detail view
- Approval state machine (`draft → approved → executing → completed | failed | stale`)
- Integration with the Phase 6.3 multi-approval chain
- Re-plan UX when `PlanStaleError` surfaces

**What OpenWatch does NOT own:**
- The `Plan` struct internals — OpenWatch never looks inside the JSONB blob
- The preview rendering — calls `plan.Preview(PreviewMarkdown)` which Kensa owns
- The rollback plan derivation — part of Kensa's Plan
- Staleness detection — Kensa's `PlanStaleError` is the authoritative signal
- The actual execution semantics, capture logic, validation — all Kensa

**Interim-implementation annotation** (to go on `specs/api/compliance/proactive-remediation.spec.yaml` when the spec is written):

```yaml
interim_implementation:
  delegates_to:
    - kensa.api.Kensa.Plan
    - kensa.api.Kensa.Execute
    - kensa.api.Kensa.Subscribe (for DriftDetected event)
  convergence_week: 24
  kensa_plan_ref: kensa/docs/KENSA_GO_DAY1_PLAN.md §3.5.3 Planner/Executor
  notes: |
    Do not implement until Kensa Week 24. Before that, OpenWatch codes
    against api/ signatures returning ErrNotYetImplemented to validate
    the integration shape.
```

**Blocking dependency:** Do not start until Kensa Week 24.

### 6.3 Multi-approval infrastructure (weeks 24–28)

**Current state (from assessment):** Single-approver only. No approval chains.

- New `approval_policies` table: `resource_type, action, required_approvals, approver_roles, conditions (JSONB)`
- Example policy: `transaction, execute, 2, [SECURITY_ADMIN], {"change_type": "grub_param"}`
- `ApprovalService` evaluates policies on every state transition
- Extend `ComplianceException.approval_chain` (introduced in Phase 4) to track N approvals
- Audit each approval as a transaction row in the log (control-plane actions are themselves transactions — this is the vision's "audit log IS the transaction log" principle)

### 6.4 Fleet grouping + per-group policies (weeks 26–30)

**Current state:** Host groups exist as entities (`routes/host_groups/crud.py`). **No policies attached.**

- New `group_compliance_policies` table: `group_id, scan_interval_override, approval_policy_id, drift_threshold_percent, auto_remediate_severities`
- Extend `compliance_scheduler.py` to prefer group policy over default intervals
- Extend `ApprovalService` to apply group-specific policies to hosts in that group
- Frontend: Group Detail page gains a Policies tab

### 6.5 First "State of Production Rollback" report (weeks 30–34)

**Current state:** Zero. The report is the output, not the infrastructure.

- `generate_production_rollback_report` task aggregates anonymized transaction log statistics across lighthouse customers (opt-in telemetry)
- Metrics: rollback frequency by OS/framework, mean-time-to-remediate, drift types most commonly detected, most-failed rules
- Output: public PDF + JSON datasets
- Marketing deliverable, not a product feature — but the infrastructure (query API from 6.1, anonymized telemetry) feeds the Q5 "Agent API + aggregate dataset" milestone

### 6.6 Exit criteria

- [ ] `/api/transactions/query` with published OpenAPI spec
- [ ] Proactive remediation draft → approval → execute flow
- [ ] Multi-approval infrastructure with at least one 2-approval policy in production
- [ ] Group compliance policies enforced by scheduler + approval service
- [ ] First public "State of Production Rollback" report published

---

## Cross-Cutting Concerns

### Testing strategy

Every phase adds regression tests against the existing CI gate (42% coverage floor, 100% AC coverage for Active specs). Specific additions:

- Phase 1: `test_transaction_backfill.py`, `test_audit_export_parity.py` (byte-identical export across schema change), `test_temporal_query_perf.py` (p95 < 500ms)
- Phase 3: `test_sso_oidc_flow.py`, `test_sso_saml_flow.py` with mock IdP
- Phase 4: `test_ed25519_signing.py`, `test_envelope_schema_v1.py`, `test_verification_script.py`
- Phase 6: `test_transaction_query_dsl.py`, `test_approval_policy_evaluation.py`

### Spec governance

Every phase must land its spec updates in the same PR as the code change (existing `check-spec-changes.py` advisory becomes a hard block for new work). Phase 1 creates `specs/system/transaction-log.spec.yaml` which becomes the load-bearing contract for everything else.

### Security review gates

Three mandatory security reviews:
- **End of Phase 1**: schema + write path (before transactions become canonical)
- **End of Phase 3**: SSO (federation is a high-value attack surface)
- **End of Phase 4**: signing (key management + verification)

### Commercial gates

- **End of Phase 3**: first customer can sign up with SSO — unblocks federal sales
- **End of Phase 4**: first auditor can verify a signed bundle offline — unblocks the "signed evidence" trust moat
- **End of Phase 6**: first "State of Production Rollback" report — unblocks the "canonical upstream" trust moat

### Team shape

Plan assumes ~2 backend engineers + 1 frontend engineer + founding engineer oversight. If headcount is smaller, Phase 3's SSO work and Phase 5's Jira sync are the first candidates to slip, in that order. **Do not slip Phase 1** — it blocks everything.

---

## What This Plan Does NOT Do

Per vision doc "What OpenWatch Must Never Become" and the OSCAL deferral:

- **No OSCAL export** — lands in Kensa first, OpenWatch calls into it later
- **No third-party scanner ingestion** — we do not ingest Tenable/Qualys/Rapid7 findings
- **No generic observability dashboards** — Heartbeat is about state, not metrics
- **No cloud-posture features** — we manage Linux hosts, not AWS/Azure/GCP configurations
- **No multi-tenancy exposure** — `tenant_id` columns land in Phase 1 but stay NULL / single-tenant until Q6
- **No Agent API (write)** — Q5/Q6 work; Phase 6's query API is the read-only foundation

---

## Risks & Open Questions

1. **Kensa team coordination on pre-state capture**: if capturing pre-state requires Kensa changes, the Phase 4 envelope work depends on a Kensa PR. **Mitigation**: start the conversation in week 1 of Phase 1; Phase 4 doesn't start until week 12, giving 11 weeks of lead time.

2. **Audit export customer contract**: the Phase 1 regression test locks the CSV/JSON column contract, but customers may depend on undocumented column ordering. **Mitigation**: survey existing customers on audit export usage during Phase 1 week 1.

3. **SAML library choice**: `python3-saml` has C dependencies that complicate RPM/DEB packaging. **Mitigation**: evaluate `pysaml2` as a pure-Python alternative in Phase 3 week 1.

4. **Retention archive storage**: Phase 5.4 requires customer-side cold storage (S3 or filesystem). **Open question**: do we ship a default filesystem archive path, or require configuration?

5. **Proactive remediation trust**: Phase 6.2's "auto-draft → human approve → execute" depends on the remediation job's dry-run accuracy. If drafts are consistently wrong, users disable the feature. **Mitigation**: ship dry-run preview UI before auto-draft; require users to opt into auto-draft per host.

6. **Phase 1 backfill on large deployments**: customers with millions of `scan_findings` rows may have multi-hour backfills. **Mitigation**: chunked task with resumability, progress UI, and the ability to run Phase 2 UI work on dual-written (forward-only) data without full backfill.

---

## Next Steps

1. **Walk this plan with founding team** — confirm phase ordering and Phase 3 parallelism assumption
2. **Create spec `specs/system/transaction-log.spec.yaml`** as the first concrete Phase 1 deliverable
3. **Open tracking epics** in PRD for each phase (E7–E12, following existing E0–E6 convention)
4. **Schedule Kensa team sync** on pre-state capture requirements for Phase 4
5. **Survey audit export customers** to lock the Phase 1 contract
