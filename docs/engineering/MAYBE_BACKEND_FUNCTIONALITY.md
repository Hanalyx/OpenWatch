# MAYBE — Backend Functionality (Phase 1+ Backlog)

> **Status (2026-06-22):** Historical rebuild-triage input, derived from the
> Python/FastAPI inventory. Deferred-feature backlog for the Go rebuild, not
> Python code. Current SSOT is `specs/` + the Go packages under `internal/`.
> See [BACKEND_FUNCTIONALITY.md](BACKEND_FUNCTIONALITY.md).
> **Source:** `docs/engineering/BACKEND_FUNCTIONALITY.md`, triaged 2026-04-27
> **Rule:** Items here are deferred from Phase 1 unless usage evidence or a specific customer requirement promotes them. They will be considered for Phase 1+ backlog after MVP ships.
> **Method:** Static analysis from inventory. Without telemetry, this list is best-guess; some items may move to MUST or NEVER once usage data arrives.

---

## Triage criteria for MAYBE

An item lands here if **any** of the following holds:

1. **Feature-gated (OpenWatch+)** — only paid customers use it; verify subscription mix before rebuilding.
2. **Planned but incomplete** — scaffolded in current code, never finished. Decide: complete it or drop it.
3. **Moderate usage suspected** — operationally useful but not load-bearing for core compliance loop.
4. **Customer-dependent** — value depends on which customer profile dominates (e.g., Jira vs PagerDuty depends on what the customer runs).
5. **Advanced variant of a MUST item** — the basic version is in MUST; the elaborated version is here.

---

## Each item has a "trigger" — what evidence would promote it to MUST

If telemetry / operator feedback hits the trigger, the item moves to MUST. Otherwise it stays deferred or moves to NEVER after the rebuild ships.

---

## Authentication — advanced

| Component | Trigger to promote | Notes |
|---|---|---|
| FIDO2 / WebAuthn MFA | Customer requirement for hardware-token MFA | Currently scaffolded interface only; no implementation. Decide: ship in Phase 1+ or drop entirely. |
| MFA backup-code regeneration UI flow | Operator usage data on backup-code use | Backup codes themselves are MUST; the regeneration self-service flow can be deferred to admin-driven path |
| API key permission updates (`PUT /api-keys/{id}/permissions`) | Operator demand for fine-grained key permissions | Basic API key CRUD is MUST; granular permission editing deferred |

---

## Compliance workflow — advanced

| Component | Trigger to promote | Notes |
|---|---|---|
| Temporal compliance — historical posture queries | Active OpenWatch+ subscriptions using the feature | Feature-gated today; verify paid usage |
| Posture history endpoint | Same as above | `/api/compliance/posture/history` |
| Posture drift analysis | Same as above | `/api/compliance/posture/drift` |
| Group drift analysis | Same as above | `/api/compliance/posture/drift/group` |
| Drift export | Same as above | `/api/compliance/posture/drift/export` |
| Compliance forecast | Same as above | OWCA-backed predictions; Layer 4 |
| Compliance trends | Same as above | OWCA Layer 3/4 |
| Audit query system (saved queries CRUD) | Active customer usage of saved queries | Feature-gated |
| Audit query preview/execute | Same as above | `/api/compliance/audit/queries/{preview,execute}` |
| Audit ad-hoc query | Same as above | `/api/compliance/audit/queries/execute` (ad-hoc) |
| Audit exports (JSON/CSV/PDF) | Customer audit/regulatory request | Feature-gated; signed bundles incomplete |
| Audit export download | Same as above | `/api/compliance/audit/exports/{id}/download` |
| Baseline rolling-average auto-update | Operator demand for automatic baseline drift | Method exists but not enabled |
| Compliance exceptions — full approval state machine | Enterprise customer demand for multi-stage approval | Basic request/approve/reject/revoke is MUST; advanced workflow (multi-approver, delegation) deferred |
| Alert routing rules (per-severity → channel) | Operator demand for fine-grained routing | Basic dispatch (alert → all configured channels) is MUST |
| Advanced alert types (SCORE_DROP, drift severity tiers, EXCEPTION_EXPIRING, MASS_DRIFT) | Active alert configuration data | Basic 5 alert types are MUST; the other 10+ types deferred |

---

## Remediation (entire subsystem — license-gated)

| Component | Trigger to promote | Notes |
|---|---|---|
| Remediation recommendation engine | Active OpenWatch+ subscriptions using remediation | Feature-gated; depends on whether customers use it |
| Secure automated fixes | Same as above | Command sandboxing, validation, rollback support |
| Command sandbox | Same as above | Required only if remediation is rebuilt |
| Rollback support | Same as above | 30-day snapshot retention |
| Remediation API endpoints (`/automated-fixes/*`, `/remediation/*`) | Same as above | Note: also resolves the §21.2 duplication — collapse into one path |
| Kensa remediation dry-run integration | Same as above | Already exists in Kensa Go side; OpenWatch is the orchestrator |
| Remediation execution task (`execute_remediation`) | Same as above | Job-queue side |
| Rollback execution task (`execute_rollback_job`) | Same as above | Job-queue side |
| Remediation status tracking | Same as above | `RemediationJob`, step-level results |
| Remediation provider listing | Same as above | Multiple executors (Bash, Ansible, Kensa) |

> **Recommendation:** Defer all remediation to Phase 1+. Compliance scanning and reporting is the primary value; remediation is the up-sell. Get core working before paying its rebuild cost.

---

## Discovery — beyond basic

| Component | Trigger to promote | Notes |
|---|---|---|
| Network discovery (interfaces, routes, DNS, firewall) | Customer evidence using network-aware compliance | `services/discovery/network.py` |
| Network topology map | Same as above | Likely low usage |
| Security posture discovery (SELinux, firewalld, audit daemon) | Compliance framework requirement (e.g., STIG audit-daemon checks) | Some Kensa rules already check these; may not need separate discovery |
| Compliance baseline discovery | Operator feedback on baseline auto-detect | Distinct from baseline management |
| Bulk variants of all discovery types | Operator feedback on fleet-scale discovery | Single-host versions are MUST |

---

## Server intelligence (currently incomplete)

| Component | Trigger to promote | Notes |
|---|---|---|
| Package inventory collection | Customer demand for package CVE matching | Schema exists; collection partial |
| Service inventory collection | Same as above | Schema exists |
| User inventory collection | Same as above | Schema exists |
| Network connection collection | Audit trail demand | Likely low value |
| Audit event collection | Compliance audit requirement | Overlaps with Kensa audit-daemon checks |
| Metrics collection | Operational monitoring demand | Likely better solved by Prometheus on the host |
| Compliance baseline collection | Distinct from `scan_baselines`? | Verify scope before promoting |

> **Open question:** Server intelligence is part of the "Compliance OS" direction in `docs/openwatchos/`. It needs explicit go/no-go decision; if go, all of these become MUST.

---

## OWCA — advanced layers

> **Updated 2026-04-28 from static-analysis evidence.** Layer 2 framework
> intelligence and most of Layer 3/4 are confirmed unused by static analysis
> and have been moved to NEVER. Only the items still genuinely deferrable
> remain here.

| Component | Trigger to promote | Notes |
|---|---|---|
| Anomaly detector | Customer evidence of demand | Statistical anomalies in compliance state |
| Risk scoring (custom NIST SP 800-30 weighted) | Customer demand for risk-weighted dashboards | If demand surfaces, build fresh — don't port the current `risk_scorer.py` (now NEVER) |
| Forecast / prediction surface | OpenWatch+ subscriber demand surfaces in telemetry | Same — fresh build if demanded |

**Moved to NEVER (2026-04-28, evidence-backed):**
- OWCA framework intelligence (Layer 2) — `cis.py`, `stig.py`, `nist_800_53.py`, `base.py`, `models.py`. Replaced by Kensa `FrameworkMapper`.
- OWCA fleet aggregator (Layer 3).
- OWCA trend analyzer, predictor, risk scorer, baseline drift detector (Layer 4).

> **Recommendation:** Rebuild only Layers 0–1 in Phase 1 (in MUST: `score_calculator`, `severity_calculator`). Anything more advanced is a fresh build if and when customer demand surfaces — not a port.

---

## Notifications — beyond basic 3

| Component | Trigger to promote | Notes |
|---|---|---|
| Jira channel + Jira service integration | Customer using Jira as ticketing system | Includes Jira webhook receiver and field mapping |
| Jira webhook receiver | Same as above | `/integrations/jira/webhook` |
| Jira field mapping | Same as above | `/integrations/jira/field-mapping` |
| PagerDuty channel | Customer using PagerDuty for incident response | Severity → urgency mapping |
| Channel test endpoint (`/test`) | Operator workflow data | Useful but not core |

---

## Plugins (custom plugin system)

| Component | Trigger to promote | Notes |
|---|---|---|
| Plugin import / install | Customer demand for custom rules / scanners beyond Kensa | `routes/integrations/plugins/` |
| Plugin execution endpoint | Same as above | `/integrations/plugins/{id}/execute` |
| Plugin execution history | Same as above | Audit trail |
| Plugin governance service | Enterprise compliance customer demand | SOC2/HIPAA/ISO-27001 evaluation against plugins |
| Plugin statistics / overview | Operator workflow data | Likely low value |
| Plugin auto-update (Kensa) | Operator workflow data | `tasks/plugin_update_tasks.py` — Kensa Go integration may handle this differently |

> **Open question:** Is the plugin system actually used outside Kensa? If only Kensa is plugged in, the entire system is over-engineered scaffolding and most of this moves to NEVER.

---

## Bulk operations

| Component | Trigger to promote | Notes |
|---|---|---|
| Bulk CSV analysis | Operator workflow data | Pre-import inspection |
| Bulk import with column mapping | Operator workflow data | Advanced variant of basic CSV import |
| Bulk discovery (network/security/compliance) | Operator workflow data | Bulk single-host equivalents are MUST |

> Basic CSV import + export are MUST; the analyze + map workflow is advanced.

---

## Scan engine — secondary paths

| Component | Trigger to promote | Notes |
|---|---|---|
| Local executor | Self-assessment use case (container scans itself) | `services/engine/executors/local.py` |
| Scan orchestrator (multi-scanner) | Customer running both Kensa + custom plugin | Only valuable if multiple ORSA plugins active |
| Scan template clone | Operator workflow data | Useful but not core |
| Scan template default-set | Operator workflow data | Convenience |
| Scan validate endpoint (`/scans/validate`) | Operator workflow data | Pre-flight check |
| Quick scan helpers (`/templates/quick`, `/hosts/{id}/quick-scan`) | Operator workflow data | UX convenience |
| Rescan single rule | Operator workflow data | Targeted re-execution |
| Scan verify endpoint | Operator workflow data | Result verification |

---

## Backfill / admin tooling

| Component | Trigger to promote | Notes |
|---|---|---|
| Transaction backfill | Migration from current OpenWatch instance | Only needed if migrating existing data |
| Posture snapshot backfill | Same as above | Reconstruct historical snapshots |
| Snapshot rule-state backfill | Same as above | Populate JSONB |
| Host rule-state backfill | Same as above | 5000-row chunks |

> **Recommendation:** These are migration tools, not features. If the rebuild is a clean break (no migration of existing customers), all four go to NEVER. If there's a migration path, all four become MUST during the migration window only.

---

## Operational / debug

| Component | Trigger to promote | Notes |
|---|---|---|
| Terminal service (interactive SSH) | Operator demand for debug access via UI | Could be a CLI tool instead |
| SSH debug endpoints (`/api/ssh/debug/*`) | Same as above | Test authentication, paramiko log |
| Discovery acknowledge-failures | Operator workflow data | OS discovery failure management |
| Manual scheduler controls (`/scheduler/start`, `/stop`, `/reset-defaults`) | Operator workflow data | Convenience |

---

## Retention — advanced

| Component | Trigger to promote | Notes |
|---|---|---|
| Signed archive bundles before deletion (AC-4) | Compliance / audit requirement | Currently incomplete; complete or drop |
| Per-resource retention policy granularity | Customer demand for differentiated retention | Basic retention is MUST |

---

## Health & capabilities — advanced

| Component | Trigger to promote | Notes |
|---|---|---|
| Health history (service / content) | Operator demand for health timeline | Current health is MUST |
| Health refresh endpoint | Operator workflow data | On-demand re-check |
| Capabilities by sub-domain (network/security/compliance/discovery capabilities) | Operator UI need | Single `/capabilities` is MUST; per-domain endpoints can collapse via API redesign |

---

## Schema (MAYBE tables)

The following tables back MAYBE features. They are kept in the schema but not actively used by Phase 1 code paths.

- `audit_exports` (only if audit query system promoted)
- `alert_routing_rules` (only if advanced alert routing promoted)
- `posture_snapshot.rule_states` JSONB (only if temporal queries promoted — basic snapshot row stays)
- `system_credentials` (largely unused; per-host encrypted_credentials is the active path) — possible NEVER

---

## What this list captures vs ignores

**Captured:** every feature-gated, partially-implemented, or moderate-usage component from the inventory. The triage assumes Phase 1 ships without these and adds them when usage data justifies.

**Not captured:** items that are clear NEVER (legacy, dead, replaced, duplicated) — those live in `NEVER_BACKEND_FUNCTIONALITY.md`.

**Risk:** without telemetry, this list is overconservative. Real customer usage may move 30–50% of these into NEVER (genuinely unused) or into MUST (load-bearing for the customer mix). Re-triage after Stage 1 telemetry collection.

---

## Action protocol when MAYBE items get promoted

When an item moves MAYBE → MUST during Phase 1+ work:

1. Add it to `MUST_BACKEND_FUNCTIONALITY.md` with the trigger evidence
2. Remove from this file
3. Update `app/docs/openwatch_roadmap.md` decision log
4. Estimate cost; check against the "doable in <2 weeks" bar from roadmap Stage 3

When an item moves MAYBE → NEVER (no demand surfaced):

1. Add it to `NEVER_BACKEND_FUNCTIONALITY.md` with the rationale
2. Remove from this file
3. The deletion is the win — that's the rebuild's whole point
