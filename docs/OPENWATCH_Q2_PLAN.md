# OpenWatch Q2 Implementation Plan

**Date:** 2026-04-13
**Window:** Months 4-6 (~12 weeks)
**Parent:** [OPENWATCH_Q1_Q3_PLAN.md](OPENWATCH_Q1_Q3_PLAN.md)
**Vision:** [OPENWATCH_VISION.md](OPENWATCH_VISION.md) Quarters 2-3
**Predecessor:** [OPENWATCH_Q1_PLAN.md](OPENWATCH_Q1_PLAN.md) (completed 2026-04-13)

---

## Q1 Completed (foundation for Q2)

Everything Q2 builds on was shipped in Q1:
- Transaction log with write-on-change model (host_rule_state + transactions)
- PostgreSQL job queue (Celery + Redis removed, 4 containers)
- Notification channels (Slack, email, webhook)
- SSO federation (OIDC + SAML)
- Host liveness monitoring (5-min TCP ping)
- FreeBSD 15.0 Dockerfiles + packaging skeleton
- 86 specs, 762 ACs, 100% coverage

---

## Q2 Goals (from vision)

| Identity | Milestone |
|---|---|
| **Eye** | Ed25519 signed evidence bundles. Per-host audit timeline. Transaction log retention policy. |
| **Heartbeat** | Drift alerts via Slack/email/webhook. Baseline auto-management (reset/promote). |
| **Control Plane** | Jira bidirectional sync. Scheduled scan management UI. Exception workflow UI. |
| **Platform** | FreeBSD 15.0 container migration (test + validate). XCCDF/lxml removal. |

**Scope note**: OSCAL export remains deferred to Kensa. Evidence signing is OpenWatch-side.

---

## Workstreams

```
Workstream F: Evidence Signing + Audit Timeline     [weeks 1-6]
Workstream G: Control Plane UIs + Jira              [weeks 3-9]
Workstream H: FreeBSD Validation + XCCDF Cleanup    [weeks 1-4]
Workstream I: Baseline Mgmt + Retention Policies    [weeks 4-8]
```

---

## Workstream F — Evidence Signing + Per-Host Audit Timeline (weeks 1-6)

### F1: Ed25519 signing service (weeks 1-3)

**Deliverables:**
- [ ] `backend/app/services/signing/__init__.py`
- [ ] `backend/app/services/signing/service.py` — `SigningService`:
  - `sign_envelope(envelope: dict) -> SignedBundle`
  - `verify(bundle: SignedBundle) -> bool`
  - Uses `cryptography.hazmat.primitives.asymmetric.ed25519`
- [ ] Alembic migration: `deployment_signing_keys` table (key_id, public_key, private_key_encrypted, active, created_at, rotated_at)
- [ ] Key rotation: new key becomes active, old keys remain for verification
- [ ] API: `GET /api/signing/public-keys` — returns all active + retired public keys
- [ ] API: `POST /api/transactions/{id}/sign` — sign a transaction's evidence envelope
- [ ] `docs/EVIDENCE_VERIFICATION.md` — standalone Python verification script (~20 lines)
- [ ] Spec: `specs/services/signing/evidence-signing.spec.yaml`

### F2: Per-host audit timeline (weeks 3-5)

**Deliverables:**
- [ ] `GET /api/hosts/{host_id}/transactions` — full filter surface (phase, status, framework, rule_id, date range)
- [ ] Cursor-based pagination for large timelines
- [ ] Full-text search on `evidence_envelope` via GIN index (already exists)
- [ ] Frontend: new tab on HostDetail — **Audit Timeline**
  - Reverse-chronological list of transactions
  - Click-through to TransactionDetail
  - Export button → queues audit export for that host + date range
- [ ] Spec: update `api/hosts/host-crud.spec.yaml` with timeline AC

### F3: Signed evidence export (weeks 5-6)

**Deliverables:**
- [ ] Extend audit export (CSV/JSON/PDF) to include Ed25519 signature
- [ ] Export includes `signed_bundle` with envelope + signature + key_id
- [ ] Verification endpoint: `POST /api/signing/verify` accepts a bundle, returns valid/invalid
- [ ] Frontend: "Download Signed Evidence" button on TransactionDetail page

---

## Workstream G — Control Plane UIs + Jira (weeks 3-9)

### G1: Exception workflow UI (weeks 3-5)

**Current state:** Backend complete at `routes/compliance/exceptions.py`. Zero frontend.

**Deliverables:**
- [ ] `frontend/src/pages/compliance/Exceptions.tsx` — list view (paginated, filter by status/rule/host)
- [ ] Exception request form (justification, risk assessment, expiration date)
- [ ] Approval workflow display (approver name, approved_at, justification)
- [ ] Escalate button (routes to higher-role approver)
- [ ] Re-remediation button (kick off remediation for excepted rule)
- [ ] Nav item: "Exceptions" under Compliance

### G2: Scheduled scan management UI (weeks 4-6)

**Current state:** Backend complete at `routes/compliance/scheduler.py`. No frontend.

**Deliverables:**
- [ ] `frontend/src/pages/scans/ScheduledScans.tsx` — adaptive interval config with sliders
- [ ] Per-host schedule table: next_scheduled_scan, current_interval, maintenance_mode
- [ ] Preview histogram: "next 48h scans across the fleet"
- [ ] New backend endpoint: `POST /api/compliance/scheduler/preview`

### G3: Jira bidirectional sync (weeks 5-9)

**Deliverables:**
- [ ] `backend/app/services/notifications/jira.py` — uses `jira` Python SDK (add to requirements.txt)
- [ ] Outbound: drift events + failed transactions create Jira issues with evidence
- [ ] Inbound: `POST /api/integrations/jira/webhook` — Jira webhook receiver
  - Issue state transitions update OpenWatch exception or transaction state
- [ ] Field mapping configurable per Jira project
- [ ] Admin UI: Jira integration settings (project, field mapping, webhook URL)
- [ ] Spec: `specs/services/infrastructure/jira-sync.spec.yaml`

---

## Workstream H — FreeBSD Validation + XCCDF Cleanup (weeks 1-4)

> **STATUS UPDATE (2026-04-14):** H1 and H3 (the FreeBSD items) are
> **abandoned**. No path forward — Linux Docker hosts cannot run FreeBSD OCI
> containers, GitHub Actions has no FreeBSD runners, and the native pkg
> deliverable did not justify maintaining the container fork. All FreeBSD
> artifacts removed. **H2 (XCCDF/lxml removal) shipped as planned.**
> See `docs/OPENWATCH_VISION_STATUS.md` for the platform decision details.

### H1: FreeBSD container testing (weeks 1-2) — ABANDONED

**Deliverables:**
- [ ] Test `docker-compose.freebsd.yml` with FreeBSD 15.0 images
- [ ] Verify all Python C extensions compile: psycopg2, cryptography, argon2-cffi
- [ ] Verify job queue worker runs correctly on FreeBSD
- [ ] Verify SSH connections (Paramiko) work from FreeBSD containers
- [ ] Fix any FreeBSD-specific issues (paths, package names, signal handling)
- [ ] CI: add FreeBSD container build job to `.github/workflows/ci.yml`

### H2: XCCDF/lxml removal (weeks 2-4)

**From backlog (P2):** `owca/extraction/xccdf_parser.py` imports lxml at module level via `owca/__init__.py`. Legacy OpenSCAP path.

**Deliverables:**
- [ ] Make XCCDF parser import conditional (lazy import, not at module level)
- [ ] Verify OWCA works without lxml when XCCDF parser is not called
- [ ] If XCCDF parser is never called in the Kensa-only path: remove it entirely
- [ ] Remove `lxml` from `requirements.txt` if no active code paths use it
- [ ] Audit: verify no other module imports lxml

### H3: FreeBSD native package testing (weeks 3-4) — ABANDONED

**Deliverables:**
- [ ] Test `packaging/freebsd/build-pkg.sh` on FreeBSD 15.0
- [ ] Verify rc.d scripts start/stop services correctly
- [ ] Test upgrade path: install pkg, upgrade pkg
- [ ] Document any FreeBSD-specific configuration in `docs/guides/`

---

## Workstream I — Baseline Management + Retention (weeks 4-8)

### I1: Baseline auto-management (weeks 4-5)

**Current state:** Auto-baseline on first scan shipped (Q1). Missing: explicit reset/promote API.

**Deliverables:**
- [ ] `POST /api/hosts/{host_id}/baseline/reset` — establish new baseline from most recent scan
- [ ] `POST /api/hosts/{host_id}/baseline/promote` — promote current posture to baseline
- [ ] Rolling baseline: 7-day moving average for hosts marked `baseline_type=rolling_avg`
- [ ] Frontend: "Reset Baseline" / "Promote to Baseline" buttons on HostDetail

### I2: Alert routing rules (weeks 5-7)

**Deliverables:**
- [ ] `alert_routing_rules` table: severity, alert_type, channel_type, channel_config
- [ ] Example: `CRITICAL + HOST_UNREACHABLE → pagerduty:oncall`
- [ ] Extend `AlertService.create_alert()` to fan out per routing rule
- [ ] PagerDuty channel: `backend/app/services/notifications/pagerduty.py`
- [ ] Frontend: `frontend/src/pages/compliance/AlertRoutingRules.tsx`
- [ ] Add `python-pagerduty` to requirements.txt

### I3: Transaction log retention policies (weeks 6-8)

**Deliverables:**
- [ ] `retention_policies` table: tenant_id, resource_type, retention_days
- [ ] Default: 365 days for transactions, 30 days for host_rule_state check history
- [ ] `cleanup_old_transactions` job queue task (registered in recurring_jobs)
- [ ] Before deletion: emit signed archive bundle to configurable storage (filesystem)
- [ ] Admin API: `GET/PUT /api/admin/retention` — view/update retention config
- [ ] Frontend: retention settings in admin page

---

## Exit Criteria (end of Q2)

### Evidence (Workstream F)
- [ ] Ed25519 signing service with key rotation
- [ ] Per-host audit timeline with full filter/export surface
- [ ] Signed evidence exports downloadable from UI
- [ ] `docs/EVIDENCE_VERIFICATION.md` with standalone verification script

### Control Plane (Workstream G)
- [ ] Exception workflow UI shipped
- [ ] Scheduled scan management UI shipped
- [ ] Jira bidirectional sync (outbound + inbound webhook)

### Platform (Workstream H)
- [ ] FreeBSD 15.0 containers tested and validated
- [ ] XCCDF/lxml dependency removed (or made conditional)
- [ ] FreeBSD pkg package tested

### Heartbeat (Workstream I)
- [ ] Baseline reset/promote API + UI
- [ ] Alert routing rules with PagerDuty channel
- [ ] Transaction retention policy enforced with signed archives

---

## Dependencies and Risks

1. **Kensa team coordination** (F1): If evidence signing requires Kensa to emit different data, that's an upstream PR. Current envelope shape may be sufficient.

2. **Jira SDK packaging** (G3): `jira` Python SDK adds a dependency. Evaluate size vs value. Alternative: raw REST calls to Jira API (no SDK needed).

3. **FreeBSD container availability** (H1): FreeBSD 15.0 OCI images are on Docker Hub but may have quirks with specific Python C extensions. Test early.

4. **lxml removal risk** (H2): OWCA module-level import means removing lxml breaks import chain. Must be lazy-loaded first.

5. **PagerDuty pricing** (I2): PagerDuty integration requires customers to have PagerDuty accounts. May not be relevant for all deployments.

---

## PR Decomposition

| PR | Contents | Workstream | Week |
|---|---|---|---|
| 1 | Signing service + migration + spec | F1 | 1-2 |
| 2 | Signing API endpoints + verification docs | F1 | 2-3 |
| 3 | Per-host audit timeline API + frontend tab | F2 | 3-5 |
| 4 | Signed evidence export + download button | F3 | 5-6 |
| 5 | Exception workflow UI | G1 | 3-5 |
| 6 | Scheduled scan management UI + preview API | G2 | 4-6 |
| 7 | Jira service + outbound + inbound webhook | G3 | 5-8 |
| 8 | Jira admin UI | G3 | 8-9 |
| 9 | FreeBSD container validation + CI | H1 | 1-2 |
| 10 | XCCDF lazy import / removal | H2 | 2-4 |
| 11 | FreeBSD pkg testing | H3 | 3-4 |
| 12 | Baseline reset/promote API + UI | I1 | 4-5 |
| 13 | Alert routing rules + PagerDuty | I2 | 5-7 |
| 14 | Retention policies + signed archives | I3 | 6-8 |

**~14 PRs over 9 weeks.**

---

## Q2 Specs Plan

### New draft specs (8 total, created at Q2 kickoff)

| Spec | Location | Workstream | ACs | Test Stub |
|------|----------|------------|-----|-----------|
| evidence-signing | services/signing/ | F1 | 8 | test_evidence_signing_spec.py |
| jira-sync | services/infrastructure/ | G3 | 8 | test_jira_sync_spec.py |
| baseline-management | services/compliance/ | I1 | 5 | test_baseline_management_spec.py |
| alert-routing | services/compliance/ | I2 | 6 | test_alert_routing_spec.py |
| retention-policy | services/compliance/ | I3 | 6 | test_retention_policy_spec.py |
| exception-workflow (FE) | frontend/ | G1 | 7 | exception-workflow.spec.test.ts |
| scheduled-scans (FE) | frontend/ | G2 | 5 | scheduled-scans.spec.test.ts |
| host-audit-timeline (FE) | frontend/ | F2 | 5 | host-audit-timeline.spec.test.ts |

### Existing specs to update in Q2

| Spec | Change | Version Bump |
|------|--------|-------------|
| api/hosts/host-crud.spec.yaml | Add AC: per-host transaction timeline endpoint | bump |
| services/compliance/alert-thresholds.spec.yaml | Add AC: alert routing rules dispatch | bump |
| frontend/host-detail-behavior.spec.yaml | Add AC: audit timeline tab | bump |

### SPEC_REGISTRY after Q2 kickoff

- Total: 94 specs (80 Active, 14 Draft)
- System: 13 (10 Active, 3 Q1 Draft)
- Services: 29 (21 Active, 3 Q1 Draft, 5 Q2 Draft)
- Frontend: 16 (13 Active, 3 Q2 Draft)
- All others unchanged

### Promotion schedule

- **Q2 week 4**: Promote Q1 draft specs (6) to active once CI validates
- **Q2 week 9**: Promote Q2 draft specs as features ship

---

## Carries from Q1

These Q1 items carry into Q2 as operational gates:

| Item | Status | Q2 action |
|---|---|---|
| SSO security review | Checklist documented, Bandit/Semgrep clean | Complete internal review or engage external reviewer |
| Spec promotions (6 draft → active) | Code landed, tests skip-marked | Unskip tests in CI Docker environment, promote |
| Liveness ping port detection | P2 backlog | Fix: read SSH port from host credential config |
| XCCDF/lxml removal | P2 backlog | Workstream H2 |

---

## Q3 Preview (from Q1-Q3 plan)

Q3 focuses on:
- **Transaction log query API** (REST, filters, pagination) — foundation for Agent API
- **Proactive remediation workflow** (drift → draft remediation → human approve → execute)
- **Multi-approval infrastructure** (2-human approval for sensitive transactions)
- **Fleet grouping + per-group policies** (scan cadence, approval, drift thresholds)
- **Tier 3 decision gate** (Go rewrite viability + Kensa integration path)
- **First "State of Production Rollback" public report**
