# Stage 1 — Usage Audit

> **Status:** Active (initial static-analysis pass complete 2026-04-28)
> **Goal:** Ground the MUST / MAYBE / NEVER triage with evidence — not assumptions
> **Estimate:** 3–5 days for the static + interview pass; 60–90 days if real telemetry is available
> **Output:** Updated triage files (MUST/MAYBE/NEVER) with an **Evidence** column citing the source for each move

---

## Why this stage exists

The triage in `MUST_BACKEND_FUNCTIONALITY.md` and the others was authored from architectural reasoning + static inventory. That's a defensible starting point but it carries unknown error. Usage data — even modest evidence — moves the triage from "best guess" to "informed decision."

This stage does NOT block Stage 0. Both run in parallel: Stage 0 builds the new stack, Stage 1 sharpens the requirements list that Stage 2 will work against.

---

## Four evidence sources, in priority order

### A. Static analysis of current backend (✓ initial pass complete 2026-04-28)

What we have today (current Python codebase) is the strongest available signal. Three sub-passes:

1. **Dead module detection** — modules with zero inbound imports
2. **Test coverage gaps** — modules with no test file
3. **Code-health markers** — DEPRECATED, FIXME, HACK, vestigial Celery/Redis/MongoDB/SCAP references

**Output:** `app/docs/stage_1_evidence_static.md` — synthesized from three parallel agent runs.

**Status:** Complete. Findings already integrated into the triage updates.

### B. Backend telemetry (best with real customer data)

If the operator has a live deployment with sufficient log retention, query for:

1. **API endpoint hit counts** (60–90 days, by route + method)
2. **Database table activity** — `pg_stat_user_tables` for read/write rates
3. **Job execution counts** — query `job_queue` history by `task_name`
4. **License/feature gate activations** — count of times each gated feature was actually requested

**Without a live deployment**, fall back entirely to A (static) + C (interviews).

**Status:** Pending operator confirmation of available data.

### C. Operator interviews

Even one operator with real-world deployment experience adds signal that telemetry can't catch — features that are critical-but-quiet (audit export for an annual review, FIPS toggle for a federal customer, FIDO2 for a specific tenant). The interview is the only way to detect these.

**Status:** Script drafted (§Operator interview script below). Pending session.

### D. Frontend telemetry (skip if absent)

If the frontend has analytics, route hit counts complement the backend endpoint counts. Most OpenWatch deployments don't emit frontend analytics — skip if absent.

**Status:** Not pursued.

---

## A. Static analysis — what was found (initial pass)

Three parallel agents inventoried the current `backend/app/`. Full results in `app/docs/stage_1_evidence_static.md`. Headline findings:

### A.1 Dead module candidates (62 modules with 0 inbound imports)

Most are **false positives** caused by dynamic loading patterns:
- Middleware registered in `main.py` via `app.add_middleware()` (4 modules)
- Tasks auto-discovered by job queue registry (~25 modules)
- Routes auto-included by FastAPI (~17 route modules)
- ORSA plugins registered on import (~3 modules)
- Database initialization scripts (~3 modules)

After filtering false positives, the **genuine dead candidates** are:

- `services/owca/framework/` (cis, stig, nist_800_53, base, models) — **5 modules** — OWCA Layer 2 framework intelligence; superseded by Kensa `FrameworkMapper`
- `services/owca/intelligence/` (predictor, risk_scorer, trend_analyzer, baseline_drift) — **4 modules** — Layer 4 OWCA; feature-gated, may not be in active use
- `services/plugins/lifecycle/` (models, service) — **2 modules** — Phase 3 future, never shipped
- `services/plugins/governance/` (service, models) — **2 modules** — Same as above
- `services/owca/cache/redis_cache.py` — confirmed dead (Redis removed)
- `services/owca/aggregation/fleet_aggregator.py` — Layer 3 OWCA, possibly orphaned
- `services/utilities/session_migration.py` — legacy session upgrade path

**Triage signal:** All confirmed-dead modules → NEVER. Phase-3-future modules → NEVER unless customer demand surfaces.

### A.2 Test coverage gaps (64 untested modules, 69.5% overall coverage)

Coverage by area:

| Area | Coverage | Triage signal |
|---|---|---|
| `compliance/*` | 95%+ | Healthy; MUST items well-protected |
| `notifications/*` | 100% | Healthy |
| `infrastructure/*` | 88% | Healthy |
| `auth/*` | 80% | Two critical gaps (token_blacklist_pg, credential_handler) |
| `engine/*` (SCAP-era) | 32% | Confirms LEGACY status; reinforces NEVER |
| `framework/*` (SCAP-era) | 40% | Confirms LEGACY |
| `job_queue/*` | 40% | Critical gap on `dispatch` and `registry` (used by 14+ routes) |

**Triage updates:**
- **Critical test gaps in MUST items:** `job_queue.dispatch`, `job_queue.registry`, `auth.token_blacklist_pg`, `auth.credential_handler`, `baseline_service`, `kensa.scanner`, `kensa.evidence`, `kensa.sync_service`. **Action:** Add to a Stage 2 "test debt" backlog — these need test coverage in the rebuild from day one.
- **SCAP-era engine modules with 32% coverage** — confirms the inventory's NEVER classification.

### A.3 Code-health markers — the biggest surprise

| Category | Count | Triage impact |
|---|---|---|
| DEPRECATED markers | 38 | Mostly in `scans/templates.py` (8 endpoints), `background_tasks.py` (3 tasks). Strong NEVER candidates. |
| Bug-specific TODOs | 19 | **Reveals 4 unfinished Kensa integrations and 3 license-validation stubs** — the LicenseService isn't actually validating licenses today. |
| FIXME / HACK / XXX | 0 | Clean. |
| Legacy mentions in comments | 190 | High; pervasive SCAP/MongoDB/router-fallback migration state. |
| **Vestigial Celery/Redis/MongoDB references** | **78** | **Q1 removal is INCOMPLETE.** `celery_task_id` column still in `Scans` table; `redis_*` config still present; 4 `_celery` task functions still defined. |
| **Active SCAP / XCCDF / OVAL references** | **584** | **Larger legacy footprint than inventory suggested.** Schema (`scap_content` table), reports parser (XCCDF namespaces), validation routes, scanner orchestrator. |

**The two big revelations:**

1. **License validation is a stub.** `services/licensing/service.py` has TODOs for "Implement license key validation" and "Query database for license." This means today's "feature gating" doesn't actually validate the license — it just checks a config flag. **Triage impact:** Licensing is in MUST, but the *validation logic* is essentially a fresh-build in the rebuild, not a port.

2. **Q1 cleanup of Celery/Redis/MongoDB stopped at the runtime layer but didn't reach the schema and config layer.** 78 references survive. **Triage impact:** Add explicit "schema and config cleanup" line items to the NEVER list — they're not features, they're cruft, but they need to be intentionally dropped, not assumed gone.

---

## B. Backend telemetry plan (pending operator data)

If a live deployment exists with sufficient log retention, run these queries.

### B.1 API endpoint hit counts

If structured access logs exist (JSON Lines via `slog` or similar):

```bash
# Top endpoints by hit count, last 90 days
zcat /var/log/openwatch/access-*.jsonl.gz | \
  jq -r 'select(.timestamp > "2026-01-28") | "\(.method) \(.route)"' | \
  sort | uniq -c | sort -rn > endpoint_hits.txt
```

Endpoints with **0 hits in 90 days** are NEVER candidates. Endpoints with **<10 hits in 90 days** are MAYBE candidates.

If only Nginx-style access logs exist, use `goaccess` or a similar tool.

### B.2 Database table activity

```sql
-- Tables ordered by total activity (reads + writes)
SELECT
    relname as table_name,
    n_tup_ins + n_tup_upd + n_tup_del as writes,
    seq_scan + idx_scan as reads,
    n_live_tup as live_rows,
    last_autoanalyze
FROM pg_stat_user_tables
ORDER BY (n_tup_ins + n_tup_upd + n_tup_del + seq_scan + idx_scan) DESC;

-- Tables with zero activity since stats were last reset
SELECT relname FROM pg_stat_user_tables
WHERE n_tup_ins = 0 AND n_tup_upd = 0 AND seq_scan = 0 AND idx_scan = 0;
```

**Tables with zero activity over the observation window** → drop from rebuild schema unless evidence justifies keeping.

### B.3 Job execution counts

```sql
-- Task execution count by name, last 90 days
SELECT
    task_name,
    COUNT(*) AS runs,
    COUNT(*) FILTER (WHERE status = 'completed') AS succeeded,
    COUNT(*) FILTER (WHERE status = 'failed') AS failed,
    AVG(EXTRACT(EPOCH FROM (completed_at - started_at))) AS avg_duration_s
FROM job_queue
WHERE created_at > NOW() - INTERVAL '90 days'
GROUP BY task_name
ORDER BY runs DESC;
```

**Tasks with 0 runs over 90 days** → NEVER. **Tasks with <10 runs over 90 days** → MAYBE.

### B.4 Feature gate activations

If the LicenseService logs each `has_feature()` call:

```bash
zcat /var/log/openwatch/audit-*.jsonl.gz | \
  jq -r 'select(.event == "feature_gate_check") | .feature_id' | \
  sort | uniq -c | sort -rn
```

**Features never requested** → MAYBE (no customer demand) or NEVER (truly unused).

---

## C. Operator interview script

Run as a 30–45 minute conversation. Record answers. The goal is to surface critical-but-quiet features.

### Interview script

#### Section 1 — Daily / weekly use (10 min)

1. In a typical week, what tasks do you actually do in OpenWatch? Walk me through one Monday morning.
2. Which views or pages do you open most often?
3. Which command-line operations do you run most often?
4. What's the last thing you wished worked better? What's the last thing you wished existed?

#### Section 2 — "What would you scream about?" (15 min)

5. If audit query / audit export disappeared tomorrow, what would break?
6. If remediation execution disappeared, what would break?
7. If FIPS-mode toggle disappeared, what would break?
8. If [each MAYBE item from MAYBE_BACKEND_FUNCTIONALITY.md, briefly] disappeared, what would break? (Time-box: 10 min, batch them.)
9. Are there features you've never used but would notice if removed because the auditor asks for them?

#### Section 3 — Hidden / quiet features (10 min)

10. What features in the current OpenWatch do you suspect nobody uses?
11. What features would you bet money are touched at most once a year — but are critical when they're touched?
12. Are there integrations (Jira, PagerDuty, Slack, custom webhooks) you've configured but rarely interact with directly? Which?

#### Section 4 — Pain and risk (10 min)

13. What's a thing OpenWatch does today that scares you when you think about it?
14. What's the part of the codebase you wish nobody had to look at?
15. What's a feature that exists in OpenWatch that exists *because* of a specific customer or compliance requirement? Which?

### Capturing answers

Create `app/docs/stage_1_evidence_interviews.md` and record:
- Date, interviewee role
- Each answer paraphrased (not verbatim — focus on triage signal)
- Triage notes per answer ("AC-X confirmed MUST" or "AC-Y candidate for MAYBE→NEVER")

---

## Synthesis protocol

After A (static), B (telemetry), C (interviews) are gathered:

1. For each item in MUST/MAYBE/NEVER files, note the strongest evidence supporting its current bucket.
2. If evidence justifies a move, update the item:
   - **MAYBE → MUST:** evidence shows real customer demand or critical-infrequent use
   - **MAYBE → NEVER:** zero evidence over 90 days + no operator advocacy
   - **MUST → MAYBE:** unexpected; should be rare. Requires explicit rationale.
   - **NEVER → MAYBE:** evidence surfaces use we didn't know about. Document why we missed it.
3. Add an **Evidence** column to each triage table noting the source (static / telemetry / interview / multi-source).
4. Date every move in the file's change log.

---

## Triage update protocol (post-evidence)

When an item moves between buckets:

1. **Edit the source-of-record file** (MUST/MAYBE/NEVER) — append/move the row.
2. **Add a one-line entry** to `app/docs/openwatch_roadmap.md` decision log with the date and evidence type.
3. **If it affects an OpenAPI domain spec** (`app/api/*.yaml`), update the spec — add or remove the endpoint, with a comment referencing the evidence.
4. **If a Specter spec needs updating**, do that in the same PR.

Don't do triage moves silently. Every move is a recorded decision.

---

## Timeline

| Day | Activity | Output |
|---|---|---|
| 1 | Static analysis (parallel agents) | `stage_1_evidence_static.md` ✓ done 2026-04-28 |
| 2 | Telemetry queries (if data exists) | `stage_1_evidence_telemetry.md` |
| 3 | Operator interview session | `stage_1_evidence_interviews.md` |
| 4 | Synthesis: update triage files | Updated MUST/MAYBE/NEVER files |
| 5 | Affected OpenAPI specs reviewed | Updated `app/api/*.yaml` files |

If real 60–90 day telemetry isn't available, days 2–5 collapse to 2–3 days and rely more heavily on static + interviews.

---

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| No live deployment data → audit relies entirely on static + interview | Honest framing: confidence is lower; flag every triage move that lacked telemetry support |
| Operator over-weights features they personally care about | Run multiple interviews if possible; surface the bias when present |
| Static analysis false positives (dynamic loading) get treated as dead code | The static evidence doc explicitly enumerates dynamic-load patterns to filter |
| Stage 1 findings invalidate Stage 0 architectural decisions | Stage 1 surfaces *features*, not architecture; if it does invalidate something, escalate explicitly to roadmap decision log |
| Interview takes longer than 45 min | Cap and reschedule; partial coverage is better than rushed coverage |

---

## What this stage explicitly does NOT do

- **Does not write code.** No production code is modified during the audit.
- **Does not finalize Phase 1 scope.** Stage 1 informs Phase 1 scope. Final scope is set at Stage 2 entry.
- **Does not rebuild.** Rebuild work is Stage 0 (parallel) and Stage 2 (after both Stage 0 and Stage 1).

---

## After Stage 1

The MUST/MAYBE/NEVER files become the live working triage for Stage 2 and beyond. As Stage 2 progresses, items continue to move buckets based on real implementation experience. The audit framework persists — re-run lightweight versions every quarter to keep the triage current.
