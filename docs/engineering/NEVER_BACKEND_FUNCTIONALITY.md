# NEVER — Backend Functionality (Not Rebuilt)

> **Source:** `app/docs/BACKEND_FUNCTIONALITY.md`, triaged 2026-04-27
> **Rule:** Items here will NOT be rebuilt. This file is the deletion log — it makes the discipline of the rebuild visible and answerable.
> **When asked "where's feature X?"** the answer comes from this file, with a date and rationale.

---

## Triage criteria for NEVER

An item lands here if **any** of the following holds:

1. **Legacy / SCAP-era code** explicitly replaced by Kensa.
2. **Dead code** — no inbound calls, marked deprecated, or returns no-op.
3. **Duplicated functionality** where one path is canonical and the other is dropped.
4. **Architectural decisions reversed** by Q1 work (Celery+Redis removal, MongoDB removal, etc.).
5. **Vestigial scaffolding** that was prepared for never-shipped features.

---

## A. SCAP / XCCDF / OpenSCAP — entire chain

Replaced by Kensa (PR #307 onward). Kensa's YAML rule format is the only compliance content path going forward.

| Component | Source | Reason |
|---|---|---|
| SCAP scanner | `services/engine/scanners/scap.py` | Replaced by direct Kensa execution |
| XCCDF result parser | `services/engine/result_parsers/xccdf.py` | Kensa returns structured results directly; no XCCDF parsing needed |
| ARF result parser | `services/engine/result_parsers/arf.py` | Same as above |
| SCAP dependency resolver | `services/engine/dependency_resolver.py` | OVAL/CPE/tailoring file walking is SCAP-only |
| XCCDF→Kensa mapper (legacy bridge) | `services/engine/integration/kensa_mapper.py` | Bridge from SCAP era; no longer needed when Kensa is the only scanner |
| `ComplianceFrameworkMapper` | `services/framework/mapper.py` | SCAP-era in-memory mapper; superseded by Kensa `FrameworkMapper` (PG-backed) |
| Legacy `RuleService` (cache-based, SCAP-era) | `services/rules/service.py` | Superseded by `RuleReferenceService` (Kensa YAML loader) |
| `scap_content` table | model | Stores SCAP benchmark metadata; Kensa rules are file-based |
| `POST /api/scans/legacy` | `routes/scans/` | Explicitly marked legacy; Kensa endpoint supersedes |
| `execute_scan_celery` task | `tasks/scan_tasks.py` | SCAP-era execution task; superseded by `execute_kensa_scan` |
| `enrich_scan_results` task | `tasks/background_tasks.py` | DEPRECATED no-op (SCAP enrichment removed) |
| `import_scap_content_celery` task | `tasks/background_tasks.py` | DEPRECATED dead code |
| `framework_repository.py.disabled` | `repositories/` | Already disabled; legacy artifact |
| All SCAP file path handling in scans | various | `scap_content` foreign key from `scans` becomes vestigial |

**Cleanup wins:** ~10–15 files deleted, 3 dead background tasks gone, 1 entire route prefix retired, schema simplified.

---

## B. Celery / Redis remnants

Celery and Redis were removed in Q1 (PR #295 era). Some references survived as orphaned comments and shim wrappers.

| Component | Source | Reason |
|---|---|---|
| Celery `bind=True` task wrapping in registry | `services/job_queue/registry.py` `_wrap_bound_task` | Mock Celery context for legacy task signatures; Go rebuild uses plain functions |
| Hardcoded `_TASK_QUEUES` routing | `services/job_queue/dispatch.py` | Mirrors legacy `beat_schedule`; rebuild uses `recurring_jobs` table only |
| Auto-discovery comment for `celery_app.py` | `tasks/__init__.py` | Orphaned reference; `celery_app.py` doesn't exist |
| "Translations from celery_app.py beat_schedule" comment | `services/job_queue/seed_schedule.py` | Orphaned reference |
| Redis cache code path in OWCA | `services/owca/cache/redis_cache.py` (Redis branch) | Redis removed; only `cachetools` TTLCache fallback is reachable |
| Memory note about Kensa via pip | (not in code; in CLAUDE.md/memory) | Stale; Kensa is now Go |
| `aiohttp` dependency (if only kept for Kensa updater) | `requirements.txt` | If Kensa Go integration replaces the updater path, drop `aiohttp` entirely |

---

## C. MongoDB references

MongoDB was fully removed in PR #295. No active MongoDB code remains, but verify no string references in:

- Connection-string parsing
- Documentation strings inside service files (auto-generated docstrings sometimes survive)
- Migration comments (cosmetic)

If any survive, they go here.

---

## D. Duplicated functionality (drop one path)

For each pair, the item kept is in `MUST_BACKEND_FUNCTIONALITY.md`. The item dropped is here.

| Dropped path | Kept path (in MUST) | Rationale |
|---|---|---|
| `/api/compliance/remediation/*` (compliance-prefixed remediation) | `/api/remediation/*` and `/api/automated-fixes/*` (which themselves consolidate in API redesign) | One remediation domain, one URL prefix. The redesign collapses three to one. |
| `/api/compliance/scheduler/*` | `/api/system/scheduler/*` (or unified `/api/scheduler/*`) | One scheduler resource, one URL. Final path decided in API redesign. |
| `/api/admin/credentials/*` | `/api/system/credentials/*` (or unified `/api/credentials/*`) | One credentials resource, one URL. |
| OWCA `BaselineDriftDetector` (intelligence/baseline_drift.py) | `services/monitoring/drift.py` `DriftDetectionService` | Two drift implementations. Keep the simpler monitoring path; drop the OWCA Layer-4 duplicate. |
| Legacy SCAP `RuleService` | `RuleReferenceService` (Kensa YAML loader) | Already covered in §A above |
| File-based `SecurityAuditLogger` | DB-based `audit_db.py` | Audit-as-API requires DB-backed log; file path is dev legacy |
| Legacy `ComplianceFrameworkMapper` | Kensa `FrameworkMapper` | Already covered in §A above |

---

## E. Schema artifacts

| Component | Reason |
|---|---|
| `scap_content` table | SCAP era; no Kensa equivalent needed |
| `scan_results` summary table | Legacy summary (kept for backward compat in current code); `host_rule_state` + `transactions` are the canonical sources. Keep `scans` and `scan_findings`; drop `scan_results`. |
| `system_credentials` table | Largely superseded by per-host `encrypted_credentials`; rarely used. Verify zero active usage before final delete. |
| `users.id` as `int` | Schema divergence — rebuild migrates to UUID. The old int-ID column is dropped during migration. |

---

## F. Sync SQLAlchemy / FastAPI seam

Not a "feature" but worth logging: the current backend uses sync SQLAlchemy 2.0 inside async FastAPI handlers. The Go rebuild uses pgx natively (per roadmap), eliminating this seam entirely.

This isn't being "removed" so much as "naturally absent" in the new stack — but log it so the design choice is visible.

---

## G. Endpoint inflation absorbed by API redesign

Per discussion 2026-04-27, ~250 of the ~350 endpoints are duplicated work or RPC-style verbs that proper REST/resource design absorbs. These are not separate feature deletions — they're surface-area reductions that fall out of consolidating MUST features into well-grouped resources.

| Pattern | Example endpoints absorbed | New shape |
|---|---|---|
| Single + bulk variants doubled | 30+ endpoints (discovery, network, security, compliance, validation, etc.) | One endpoint accepting one or many |
| Format-per-endpoint reports | 6+ endpoints (`/report/{html,json,csv}`, `/exports/{format}`) | One endpoint with `Accept` header |
| Action-as-endpoint (RPC verbs) | 40+ endpoints (`/acknowledge`, `/resolve`, `/approve`, `/reject`, `/revoke`, `/start`, `/stop`, `/cancel`, `/recover`, `/toggle`, etc.) | `PATCH /resource/{id}` with target status, OR `POST /resource/{id}:action` for true side-effects |
| Discovery sprawl (`/{id}/discover-os`, `/os-info`, `/detect-platform`, `/system-info`, `/discovery/{basic,network,security,compliance}`, `/intelligence/{services,packages,users,...}`) | 15+ endpoints | `GET /hosts/{id}/intelligence` (snapshot), `POST /hosts/{id}/intelligence:refresh`, `GET /hosts/{id}/intelligence/status` |
| Capabilities/health/summary fragmentation | 20+ endpoints | One `/capabilities`, one `/health`, one `/health/history`, with component query filters |
| Remediation triplication | 4 prefixes | One `/remediation` resource (only built if remediation MAYBE → MUST) |
| Kensa endpoint sprawl under `/scans/kensa` | 12 endpoints | `/rules` and `/frameworks` resources absorb all metadata reads; only execution stays under `/scans` |
| MFA workflow exploded | 6 endpoints | `GET/DELETE /auth/mfa`, `POST /auth/mfa:enroll/:enable/:validate`, `POST /auth/mfa/backup-codes:regenerate` |

> **Net effect:** ~350 endpoints → ~60–80 endpoints with the same MUST capabilities. This is structural reduction, not feature reduction.

---

## H. Incomplete / scaffolded / never-shipped features

For each, the decision: **drop entirely** unless an explicit reason to complete.

| Component | Reason |
|---|---|
| FIDO2 / WebAuthn MFA interface | Scaffolded only, no implementation. Currently in MAYBE; if no customer demand surfaces during Phase 1, move here. |
| Signed archive bundles before retention deletion (AC-4) | Marked future enhancement; never shipped. If audit/compliance requirement doesn't surface, drop. |
| Baseline rolling-average auto-update | Method exists but never enabled. Move here unless operator demand. |
| Plugin system beyond Kensa | If Kensa is the only ORSA plugin actually used, the entire plugin import/execute infrastructure is over-engineered. Plugin governance, plugin statistics, plugin executions all become NEVER. |
| Backfill tasks (transactions, posture, snapshot rule states, host rule state) | If rebuild is a clean break with no data migration, all four go here. If migration is in scope, they stay in MAYBE during the migration window only. |

---

## I. Operational endpoints with low strategic value

These are operator conveniences that an admin CLI tool covers better than an HTTP endpoint.

| Component | Replacement |
|---|---|
| Terminal service (`/infrastructure/terminal.py`) — interactive SSH via UI | SSH directly from the operator's workstation (or a future `openwatch exec <host>` subcommand) |
| SSH debug endpoints (`/api/ssh/debug/test-authentication`, `/debug/paramiko-log`) | A future `openwatch ssh-test <host>` subcommand |
| Manual scheduler controls (`/scheduler/start`, `/stop`, `/reset-defaults`) | `systemctl restart openwatch`; scheduler config via the `openwatch` binary |
| Discovery acknowledge-failures | Owner: investigate failures, not acknowledge them silently |

> **Resolved:** the rebuild ships a single binary whose CLI is the binary itself —
> admin operations are `openwatch` subcommands (`serve`, `worker`, `migrate`,
> `create-admin`, `check-config`), not a separate `owadm` tool. Any commands above
> that are not yet implemented are deferred subcommands, tracked when built.

---

## J. Aggregate counts

Approximate impact of NEVER triage (Phase 1):

- **Files deleted:** ~30–40 Python files (SCAP chain + Celery shims + duplicated services + dead tasks)
- **Tables dropped:** 3 (`scap_content`, `scan_results`, `system_credentials` pending validation)
- **Background tasks removed:** 3 dead (`enrich_scan_results`, `import_scap_content_celery`, `execute_scan_celery`)
- **Endpoints removed (legacy/duplicated):** ~30 explicit
- **Endpoints absorbed via API redesign:** ~250 (not deleted features, just consolidated surface)
- **Net Phase-1 endpoint count target:** ~60–80 (vs ~350 today)

---

## K. Static-analysis evidence additions (2026-04-28)

Added from `app/docs/stage_1_evidence_static.md` after Stage-1 static-analysis pass surfaced concrete dead code, config cruft, and incomplete-removal artifacts beyond what the inventory captured.

### K.1 Schema cleanup (drop these columns / tables)

| Item | Source | Reason |
|---|---|---|
| `Scans.celery_task_id` column | `database.py:252` | Q1 removed Celery runtime; column survived |
| `Scans.content_id` foreign key + `scap_content` table | `database.py:215–241` | SCAP era; Kensa needs neither |
| `xccdf_schemas.py` (entire file) | `schemas/xccdf_schemas.py` | XCCDF report parsing replaced by Kensa native results |
| `mongodb_scan_api.py` reference comment | `database.py:171` | Cosmetic; left from PR #295 |

### K.2 Config cleanup (drop these env-var / config fields)

| Field | Source | Reason |
|---|---|---|
| `redis_url`, `redis_host`, `redis_port`, `redis_db`, `redis_ssl` | `config.py:37–44` | Redis fully removed at runtime; config survived |
| `scap_content_dir` | `config.py:49` | SCAP content path; no Kensa equivalent |

### K.3 Task cleanup (drop these functions entirely)

| Function | Source | Reason |
|---|---|---|
| `enrich_scan_results_celery` | `tasks/background_tasks.py:34` | DEPRECATED; SCAP enrichment was no-op |
| `execute_remediation_celery` | `tasks/background_tasks.py:84` | Celery shim |
| `deliver_webhook_celery` | `tasks/background_tasks.py:162` | Celery shim |
| `execute_host_discovery_celery` | `tasks/background_tasks.py:180` | Celery shim |
| `execute_scan_celery` | `tasks/scan_tasks.py:615` | SCAP-era execution path |
| `import_scap_content_celery` | `tasks/background_tasks.py:124` | DEPRECATED; SCAP import |

### K.4 Route cleanup (drop these endpoints)

| Endpoints | Source | Reason |
|---|---|---|
| 8 endpoints in `routes/scans/templates.py` (all marked DEPRECATED) | `routes/scans/templates.py:206–392` | MongoDB-backed templates; replaced by clean `/scan-templates` resource in `app/api/scans.yaml` |
| `POST /api/scans/legacy` | `routes/scans/crud.py:420` | Legacy SCAP scan create |
| Entire `routes/content/` package | `routes/content/__init__.py:4` | Package marked DEPRECATED post-MongoDB |
| 3 legacy SCAP validation endpoints | `routes/scans/validation.py:70–794` | "Legacy SCAP Content" |

### K.5 OWCA legacy modules (Layer 2 framework intelligence)

| Module | Reason |
|---|---|
| `services/owca/framework/cis.py` | Superseded by Kensa `FrameworkMapper` (PG-backed) |
| `services/owca/framework/stig.py` | Same |
| `services/owca/framework/nist_800_53.py` | Same |
| `services/owca/framework/base.py` | Used only by the framework siblings above |
| `services/owca/framework/models.py` | Used only within the legacy OWCA framework subsystem |

### K.6 OWCA Layer 4 intelligence — promoted from MAYBE to NEVER (pending telemetry override)

The static analysis confirms these are untested and unreachable from active routes. Promoting to NEVER unless telemetry shows customer use:

| Module | Reason |
|---|---|
| `services/owca/intelligence/predictor.py` | Layer 4; feature-gated; not invoked from current routes |
| `services/owca/intelligence/risk_scorer.py` | Same |
| `services/owca/intelligence/trend_analyzer.py` | Same |
| `services/owca/aggregation/fleet_aggregator.py` | Layer 3; possibly orphaned |

### K.7 Phase-3 future scaffolding (never shipped)

| Module | Reason |
|---|---|
| `services/plugins/lifecycle/{models,service}.py` | Plugin lifecycle; never shipped |
| `services/plugins/governance/{models,service}.py` | Plugin governance; never shipped |

### K.8 Other confirmed dead

| Item | Reason |
|---|---|
| `services/utilities/session_migration.py` | Legacy HS256 session upgrade path |
| `services/owca/cache/redis_cache.py` | Redis fully removed |
| `services/engine/orchestration/orchestrator.py` (entire) | Module-header marked DEPRECATED |
| `services/ssh/key_parser.py` `detect_key_type`, `parse_ssh_key` functions | Function-level DEPRECATED markers |

### K.9 Note on residual scope

The static analysis surfaced 584 SCAP/XCCDF/OVAL references across the backend. Most of these die when the items in §A (top of this file) are removed — they are not separate triage items, they are the trailing references to the same SCAP chain that's already in §A. Cleanup verified by absence: after the rebuild ships, `grep -r 'xccdf\|oval\|openscap\|scap_content' app/` should return zero results.

---

## How this list grows

This file is append-only during Phase 1 work. Every "we're not rebuilding X because Y" decision adds an entry with date + rationale.

**Format for new entries:**

```
### YYYY-MM-DD — <Component>

**Source:** path/to/code
**Reason:** Why we're not rebuilding it (telemetry, operator feedback, architectural decision)
**Replacement (if any):** What handles this need now, or "not needed"
**Reversibility:** What evidence would cause us to revisit this decision
```

Six months from now, when someone asks "where's the X feature from old OpenWatch?", the answer is grep this file for X.

---

## How this list shrinks

Items move OUT of this file only when:

1. **Strong evidence emerges** that the feature is needed after all (telemetry, customer demand, regulatory requirement)
2. **Decision is reversed** with explicit rationale documented in `app/docs/openwatch_roadmap.md` decision log

When an item moves OUT, it goes to MUST (with the trigger evidence) or MAYBE (if borderline). It does NOT just get rebuilt without going through triage.

---

## What this discipline buys

Without this file: every old feature has an implicit champion ("but we had it before"), and the rebuild quietly recreates the bloat.

With this file: every deletion is named, dated, sourced, and reversible. Scope creep has to argue past a written record. The rebuild stays honest.
