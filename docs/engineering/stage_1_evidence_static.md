# Stage 1 — Static Analysis Evidence

> **Date collected:** 2026-04-28
> **Method:** Three parallel sub-agents inventoried the current `backend/app/` for dead modules, test coverage gaps, and code-health markers
> **Status:** First-pass evidence; supplements (telemetry, interviews) pending

---

## Summary of findings

| Source | Headline number | Triage impact |
|---|---|---|
| Dead module candidates | 62 modules with 0 inbound imports | ~15 confirmed dead after filtering false positives; rest are dynamic-load false positives |
| Test coverage | 64 untested modules (69.5% overall) | 8 critical gaps in MUST items need test debt entry; SCAP-era engine confirms 32% coverage = LEGACY |
| Code-health markers | 38 DEPRECATED, 19 specific TODOs, 78 vestigial Celery/Redis/MongoDB refs, 584 SCAP/XCCDF/OVAL refs | Q1 cleanup is incomplete; LicenseService is a stub |

Two findings change the rebuild plan materially:

1. **The LicenseService doesn't actually validate licenses today** — three TODO stubs reveal it's a configuration-flag check, not a license-key validator. Treat licensing as a fresh build in the rebuild, not a port.
2. **Q1 Celery/Redis/MongoDB removal stopped at the runtime layer.** 78 references survive in schema (e.g., `celery_task_id` column), config (`redis_*` fields), and shim functions (`*_celery` definitions). The rebuild must intentionally drop these — they won't fall away on their own.

---

## A. Dead module candidates (filtered for false positives)

The agent flagged 62 modules with zero inbound imports. After filtering for dynamic-load patterns (middleware registration, FastAPI auto-include, task auto-discovery, ORSA plugin auto-register), these are the **genuine dead candidates**:

### Confirmed dead

| Module | Path | Reason |
|---|---|---|
| `services/owca/cache/redis_cache.py` | services/owca/cache/redis_cache.py | Redis fully removed; module has no callers |
| `services/utilities/session_migration.py` | services/utilities/session_migration.py | Legacy HS256 session upgrade path |

### Likely dead (need single-confirmation)

| Module | Path | Reason |
|---|---|---|
| `services/owca/framework/cis.py` | OWCA Layer 2 framework intelligence (CIS) | Superseded by Kensa `FrameworkMapper` (PG-backed) |
| `services/owca/framework/stig.py` | OWCA Layer 2 framework intelligence (STIG) | Same as above |
| `services/owca/framework/nist_800_53.py` | OWCA Layer 2 framework intelligence (NIST) | Same as above |
| `services/owca/framework/base.py` | OWCA Layer 2 abstract base | Used only by the framework siblings |
| `services/owca/framework/models.py` | OWCA Layer 2 data models | Possibly used by intelligence siblings; worth verifying |
| `services/owca/intelligence/predictor.py` | OWCA Layer 4 forecast | Feature-gated; possibly never reached in practice |
| `services/owca/intelligence/risk_scorer.py` | OWCA Layer 4 risk | Same as above |
| `services/owca/intelligence/trend_analyzer.py` | OWCA Layer 4 trends | Same as above |
| `services/owca/intelligence/baseline_drift.py` | OWCA Layer 4 drift detector | Duplicate of `services/monitoring/drift.py` (already flagged in NEVER) |
| `services/owca/aggregation/fleet_aggregator.py` | OWCA Layer 3 fleet stats | Possibly orphaned |
| `services/plugins/lifecycle/{models,service}.py` | Plugin lifecycle | Phase 3 future, never shipped |
| `services/plugins/governance/{models,service}.py` | Plugin governance | Phase 3 future, never shipped |

### False positives (filtered — these ARE used dynamically)

| Pattern | Modules affected | Why dynamic |
|---|---|---|
| Middleware via `app.add_middleware()` | `middleware/{authorization,error_handling,metrics,rate_limiting}.py` | Registered, not imported |
| Tasks via job queue registry | `tasks/*.py` (~25 modules) | Auto-discovered |
| Routes via FastAPI auto-include | `routes/*/__init__.py` (~17 modules) | Auto-included |
| ORSA plugin auto-register | `plugins/kensa/orsa_plugin.py` | Self-registers on import |
| Database initialization | `init_database_schema.py`, `init_roles.py` | Called from scripts |
| Job queue subsystem | `services/job_queue/*.py` | Loaded via `python -m app.services.job_queue` entry point |

The agent over-counted these as dead because static grep can't see dynamic patterns. Triage should not act on these.

---

## B. Test coverage gaps

Overall: **64 untested modules, 69.5% coverage.**

### Coverage by area (from Agent 2)

| Area | Modules tested / total | % | Triage signal |
|---|---|---|---|
| `compliance/*` | 20/21 | 95% | Healthy |
| `notifications/*` | 6/6 | 100% | Healthy |
| `infrastructure/*` | 7/8 | 88% | Healthy |
| `auth/*` | 8/10 | 80% | 2 critical gaps |
| `engine/*` (SCAP-era) | 5/16 | 32% | Confirms LEGACY |
| `framework/*` (SCAP-era) | 2/5 | 40% | Confirms LEGACY |
| `job_queue/*` | 2/5 | 40% | Critical gaps on dispatch + registry |
| `owca/*` | 7/11 | 64% | Several Layer 4 modules untested |

### Critical test gaps in MUST items

These modules are MUST per the triage AND have no test coverage. They need explicit "test debt" remediation in the rebuild — Stage 2 must add tests for these from day one of porting.

| Module | Why this matters |
|---|---|
| `services/job_queue/dispatch.py` | Used by 14+ route handlers as the enqueue API. Untested. |
| `services/job_queue/registry.py` | Task name → handler mapping. Untested. |
| `services/auth/credential_handler.py` | Phase 2 host credential refactor. Untested. |
| `services/auth/token_blacklist_pg.py` | JWT revocation. Security-critical. Untested. |
| `services/baseline_service.py` | NIST SP 800-137 drift baseline. Untested. |
| `plugins/kensa/scanner.py` | Core Kensa execution adapter. Untested. |
| `plugins/kensa/evidence.py` | Evidence serialization for audit. Untested. |
| `plugins/kensa/sync_service.py` | Rule sync after Kensa updates. Untested. |

### Coverage that confirms NEVER classification

The 32% coverage in `engine/*` and 40% in `framework/*` adds confidence to the existing NEVER triage of SCAP-era code. Untested + legacy + has explicit DEPRECATED markers = strong NEVER.

---

## C. Code-health markers

### C.1 DEPRECATED markers (38 total)

Concentrated in:
- `routes/scans/templates.py` — **8 endpoints** marked DEPRECATED (MongoDB-backed templates from before PR #295)
- `tasks/background_tasks.py` — **3 tasks** marked DEPRECATED (`enrich_scan_results_celery`, `import_scap_content_celery`, the `_celery` shims)
- `routes/content/__init__.py` — **package** marked DEPRECATED (entire content domain post-MongoDB)
- `services/engine/orchestration/orchestrator.py` — module marked DEPRECATED
- `services/ssh/key_parser.py` — `detect_key_type` and `parse_ssh_key` functions marked DEPRECATED

**Triage update:** All of these are NEVER candidates. Add explicitly to NEVER file:
- All 8 deprecated `routes/scans/templates.py` endpoints (replaced by clean `/scan-templates` resource in scans.yaml)
- The 3 deprecated `_celery` task shims
- The deprecated `content` route package

### C.2 Bug-specific TODOs (19 total)

Concentrated in three areas:

**Kensa integration gaps (4 TODOs):**
- `plugins/kensa/orsa_plugin.py:549` — TODO: Implement rollback via Kensa
- `plugins/kensa/plugin.py:398` — TODO: Implement remediation planning via Kensa
- `plugins/kensa/plugin.py:410` — TODO: Re-run check via Kensa
- `plugins/kensa/plugin.py:419` — TODO: Integrate with OpenWatch license service

> **Triage impact:** These are unfinished Kensa integration features. In the rebuild, treat them as MAYBE — implement only if the corresponding feature (rollback, remediation planning) survives triage.

**License service stubs (3 TODOs):**
- `services/licensing/service.py:190` — TODO: Implement license key validation
- `services/licensing/service.py:219` — TODO: Query database for license (sync version)
- `services/licensing/service.py:247` — TODO: Query database for license

> **Triage impact:** **Major.** The LicenseService doesn't actually validate licenses today — it's a config-flag check pretending to be license validation. The rebuild's licensing component is a fresh build, not a port. Update MUST list accordingly.

**Rules association PostgreSQL migration debt (6 TODOs):**
- `services/rules/association.py:243,268,289,439,449,673` — all "Migrate to PostgreSQL storage"

> **Triage impact:** Rules association service is mid-migration. The rebuild's rule-reference layer should be PostgreSQL-native from day one (which the design already locks in).

**Other TODOs (6):**
- `routes/admin/security.py:402` — Add credential compliance statistics (MAYBE)
- `routes/scans/reports.py:504` — Implement caching or optimize parsing (Phase 2 perf concern)
- `routes/remediation/provider.py:272` — Send cancellation request to provider (MAYBE if remediation rebuilt)
- `routes/remediation/callback.py:146` — Trigger verification scan (MAYBE)
- `routes/system/settings.py:447` — Improve SSH key validation (Phase 1 polish)
- `services/infrastructure/sandbox.py:132` — Implement full containerized execution (MAYBE if sandbox rebuilt)

### C.3 Legacy comments (190 total)

Pervasive. High density in:
- `routes/scans/` — templates, models, crud, validation, reports
- `routes/hosts/` — module-level "fall back to legacy router" comments
- `routes/ssh/` — same fallback pattern
- `services/engine/` — XCCDF 1.1 namespace handling, scanner conditional imports
- `services/utilities/` — `session_migration.py` HS256 legacy support
- `audit_db.py` — legacy SSH audit blocking logic

**Triage impact:** Confirms the migration is incomplete. The rebuild should not preserve the "fallback" pattern; it should replace cleanly.

### C.4 Vestigial Celery / Redis / MongoDB references — 78 total

**This is the biggest surprise of the audit.** Q1's cleanup of these dependencies stopped at the runtime layer. The schema, config, and shim functions still carry references.

**Schema-level survivors:**
- `database.py:252` — `celery_task_id = Column(String(100), nullable=True)` on Scans table
- `database.py:171` — comment `# Used by mongodb_scan_api.py to select platform-specific OVAL`
- `routes/scans/crud.py:322,358,817` — code reads/writes `celery_task_id` field

**Config-level survivors:**
- `config.py:37–44` — `redis_url`, `redis_host`, `redis_port`, `redis_db`, `redis_ssl` config fields still defined and read
- `services/monitoring/health.py:108–117` — health check still attempts `redis_url`
- `services/rules/__init__.py:166–189` — `redis_url` cache service initialization branch

**Code-level survivors (functions still defined, not just commented):**
- `tasks/background_tasks.py:34` — `def enrich_scan_results_celery(scan_id: str)` (DEPRECATED but still defined)
- `tasks/background_tasks.py:84` — `def execute_remediation_celery(remediation_id: str)`
- `tasks/background_tasks.py:162` — `def deliver_webhook_celery(webhook_id: str, delivery_id: str)`
- `tasks/background_tasks.py:180` — `def execute_host_discovery_celery(host_id: str)`
- `tasks/scan_tasks.py:615` — `def execute_scan_celery(scan_id: str, profile_id: str)`
- `services/job_queue/registry.py:192,197,234,241,255` — Celery task wrapping (`bind=True` shim)
- `routes/scans/compliance.py:1035–1040` — `redis_status = "deprecated"` health response

**Triage update for NEVER file:** Add explicit "schema and config cleanup" entries.
- `Scans.celery_task_id` column → drop
- All `redis_*` config fields → drop
- All `*_celery` task functions in `tasks/background_tasks.py` and `tasks/scan_tasks.py` → drop
- Celery wrapping in `services/job_queue/registry.py` → drop in Go rebuild (Go has no equivalent need)
- `mongodb_scan_api.py` reference comment in `database.py` → drop

### C.5 Active SCAP / XCCDF / OVAL references — 584 total

The largest legacy footprint. The Kensa migration replaced the runtime, but the surrounding scaffolding survives:

**Schema:** `scap_content` table is still in the model, still referenced by `Scan.content_id` foreign key.

**Routes:**
- `routes/scans/templates.py` — 8 deprecated MongoDB SCAP template endpoints (the entire file)
- `routes/scans/reports.py:332–550` — XCCDF namespace parsing for legacy report generation
- `routes/scans/validation.py:70–794` — three validation endpoints commented as "Legacy SCAP Content"
- `routes/scans/crud.py` — `POST /legacy` SCAP scan endpoint
- `routes/hosts/discovery.py:1032,1159` — `openscap_tools` discovery, `assess_scap_capability()`

**Schemas:**
- `schemas/xccdf_schemas.py` — XCCDF content schemas

**Services:**
- `services/engine/scanners/__init__.py:77` — `OSCAPScanner = None  # type: ignore`
- `services/engine/dependency_resolver.py:119,291–294` — XCCDF 1.1 legacy format namespace handling
- `services/engine/result_parsers/__init__.py:106` — comment about legacy SCAP parsers removed

**Config:**
- `config.py:49` — `scap_content_dir: str = os.getenv("SCAP_CONTENT_DIR", "/openwatch/data/scap")`

**Triage update for NEVER file:** Add as a single line item: "All SCAP-era schema, routes, schemas, services, and config (584 references)." This is the largest single deletion target in the rebuild.

### C.6 Bare `# type: ignore` (2 total) and `# noqa` (0 total)

Clean. Two bare `type: ignore` directives are localized and low-risk.

---

## Triage updates produced from this evidence

### Add to NEVER (with evidence pointer)

The following items are added to `NEVER_BACKEND_FUNCTIONALITY.md` with this document as evidence:

1. **Schema cleanup:** `Scans.celery_task_id` column, `mongodb_scan_api.py` comment in `database.py`, `scap_content` table (already flagged), entire `xccdf_schemas.py`
2. **Config cleanup:** `redis_url`, `redis_host`, `redis_port`, `redis_db`, `redis_ssl`, `scap_content_dir` config fields
3. **Task cleanup:** `enrich_scan_results_celery`, `execute_remediation_celery`, `deliver_webhook_celery`, `execute_host_discovery_celery`, `execute_scan_celery`, `import_scap_content_celery`
4. **Route cleanup:** all 8 deprecated `routes/scans/templates.py` endpoints, `POST /api/scans/legacy`, the entire deprecated `routes/content/` package
5. **OWCA Layer 2 framework intelligence:** `services/owca/framework/{cis,stig,nist_800_53,base,models}.py` (all 5)
6. **OWCA Layer 4 intelligence (subset):** `baseline_drift.py` (already flagged as duplicate); the others (`predictor`, `risk_scorer`, `trend_analyzer`) move from MAYBE to NEVER pending evidence of customer demand
7. **Plugin Phase-3 future scaffolding:** `services/plugins/lifecycle/`, `services/plugins/governance/`
8. **Session migration:** `services/utilities/session_migration.py`

### Add to MUST as "test debt" attention list (Stage 2 entry criteria)

These MUST items have no test coverage today. Stage 2 must add tests at port time:

1. `services/job_queue/dispatch.py` and `services/job_queue/registry.py`
2. `services/auth/credential_handler.py` and `services/auth/token_blacklist_pg.py`
3. `services/baseline_service.py`
4. `plugins/kensa/scanner.py`, `plugins/kensa/evidence.py`, `plugins/kensa/sync_service.py`

### Critical correction to MUST: Licensing

`services/licensing/service.py` has 3 TODO stubs for license validation. Today's "feature gating" is a config-flag check, NOT license validation. The rebuild's licensing component must be a **fresh build** with proper key validation, not a port of the current stub.

### Items still pending evidence (B telemetry, C interview)

- OWCA Layer 4 (predictor, risk_scorer, trend_analyzer) — likely-dead but not confirmed; needs telemetry or operator confirmation
- All MAYBE items in `MAYBE_BACKEND_FUNCTIONALITY.md` — static analysis can't move these without usage data
- Server intelligence features (packages, services, users, network connections, audit events, metrics) — partially incomplete; needs operator decision on Compliance-OS direction
