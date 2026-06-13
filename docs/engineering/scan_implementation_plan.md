# Compliance Scan — Implementation Plan

**Status:** Phases 0-2 SHIPPED (branch feat/scan-foundation, 15 commits, live-verified) · **Updated:** 2026-06-12 · **Owner:** TBD

## Status snapshot (2026-06-13)

| Phase | Status | Evidence |
|-------|--------|----------|
| 0 — Foundation | **DONE** | kensa v0.3.2 bound (NewScanner + in-memory transport); R6 multi-valued refs fixed pre-data; scan_runs logbook + audit lifecycle; serve processes scan jobs in-process. Live: 539 rules vs owas-hrm01 in 83s, 0 errors |
| 1 — On-demand scan | **DONE** | POST /hosts/{id}/scans (idempotency, RBAC, 409 single-flight) + Run scan button + scan.completed SSE refresh. Found+fixed a latent platform bug: http.Server WriteTimeout killed ALL SSE streams at 60s |
| 2 — Top failed rules | **DONE** | GET /hosts/{id}/compliance/failed-rules (no-evidence C-02, multi-valued control_ids) + RuleCatalog titles + live card. Verified: hrm01's real 147 failures render with catalog titles |
| 3 — Compliance tab lens | **DONE** | GET /hosts/{id}/compliance (+/frameworks) with C-05 reconciliation; ComplianceTab.tsx lens UI. Live: lens switch recounts 68.1% all-rules -> 71.4% under stig_rhel8 (266 rules exactly). Prototype-fidelity pass done 2026-06-12: per-lens scores on chips + overall aggregate, result-mix/scan panels, duration_seconds, catalog descriptions, search, in-strip Re-scan (specs v1.2.0 / v1.1.0) |
| 4 — Adaptive scheduler + settings | **DONE** (2026-06-12; scan variables shipped in PR #517, surfaced on Settings > Compliance policies) | system-scheduler v3.0.0: ladder from systemconfig (RunManaged per-tick refresh), five bands + migration 0024 backfill, PersistAfterScan after every scan, dispatch logbook rows. api-system-scan-config (6 endpoints incl. scan/variables + scan/schedule + host schedule tile) + wired Settings section. Scan variables SHIPPED (PR #517): VariableCatalog over the 20 corpus-used vars, operator overrides on Settings > Compliance policies, per-scan corpus reload. Live: first tick auto-dispatched all 9 seeded hosts; fleet classified across the five bands; a UI variable override reloaded the corpus on the next scan. **Phase 4 fully DONE.** |
| 5 — Fleet surfaces | **mostly DONE** | Per-host Scan buttons, scan-queue KPI, hosts-list compliance_summary enrichment (real % + tier colors + critical_failing), avg/critical KPIs from real data. Remaining: bulk scan (POST /hosts:scan); the avg-compliance delta shipped with Phase 6 |
| 6 — Trend / posture snapshots | **DONE** (2026-06-12, PR #518) | posture_snapshots daily rollup (hourly cron + boot pass); GET /hosts/{id}/compliance/trend + /fleet/compliance/trend; live trend card + avg-compliance delta. Shipped alongside: the host-detail hero strip went fully live (Auto-scan tile -> GET /compliance/schedule, Watchlist tile -> live active-alerts) and OS-aware framework lens filtering (api-host-compliance v1.3.0 — a RHEL 8 host no longer offers RHEL 9/10 lenses) |
| 7 — Remediation + exceptions | **Exceptions DONE (2026-06-13); remediation NEXT** | **Exception governance complete end to end** (PRs #521 backend, #522 host-detail surfaces, #523 approver queue): DB-backed request->approve/reject->revoke/expire lifecycle, separation of duties, overlay model (never mutates host_rule_state), surfaced on host detail (Watchlist count, intel tile, Compliance-tab Waived/Pending badges + request modal) and the Settings fleet approver queue. **Remediation remains** (its own track): wire kensa.Remediate() behind the in-memory transport (implement Put/Get if needed; transactional apply + rollback per Kensa K-4/K-5). Open Kensa ratification: rule-ordering (depends_on/conflicts/supersedes) is unexported — a new ratification if remediation sequencing needs it |

All risks R1-R6 resolved. Fleet self-scans on the adaptive ladder (9 hosts seeded, classified across all five bands; 3 critical re-scan every 4h). Merged PRs: #515 (Phases 0-3 + scheduler core), #517 (scan variables), #518 (posture trend + live hero tiles + OS-aware lenses), #519 (service-wiring guard), #521/#522/#523 (exception governance: backend + host-detail surfaces + fleet approver queue). All of the above shipped in release **v0.2.0-rc.6** (2026-06-13). **7 of 8 phases complete**; remaining: Phase 7 remediation (the host-mutating half, its own track) + the Phase 5 bulk-scan endpoint.

Operational follow-ups still open (small, not blocking Phase 7):
- Bulk scan endpoint (POST /hosts:scan) — the last Phase 5 item.
- Deadline-free SSE streams outlive graceful shutdown's 30s grace (cancel on shutdown ctx).
- Scan-context Capabilities line needs stored capability data from Kensa.
- Found + fixed during the host-detail tile work: the alerts lifecycle service was never wired in serve (every /api/v1/alerts endpoint 503'd in production); a generic source-test (system-daemon-orchestration AC-11) now guards that EVERY server builder is wired in main.go.

Covers end-to-end compliance scanning for the OpenWatch Go rebuild: wiring the
Kensa engine, triggering scans (on-demand + adaptive auto-scan), persisting and
serving results, and the two operator surfaces in the prototypes —
`docs/engineering/prototypes/openwatch-v1/Host Detail.html` and `Host Management.html`.

> **Design anchor — the lens model.** Kensa runs its **native rules once** per
> host and returns a per-rule verdict plus that rule's normalized
> **framework references**. Every compliance number in the UI (CIS %, STIG %,
> NIST %, the "Top failed rules" list, the per-framework rule view) is a
> **projection of one scan**, regrouped by `framework_refs`. There is never more
> than one scan behind the screen. Build for this from day one.

---

## 1. Current state (verified 2026-06-11)

| Layer | State | Notes |
|-------|-------|-------|
| Kensa dependency | ⚠️ v0.2.1 pinned | bump to **v0.3.0** — it adds the real `ComplianceStatus` verdict (§3) |
| `internal/kensa` executor | ✅ built, **scan stubbed** | `executor.go` has the `WithScanFunc` seam; default is `unwiredScanFunc` which errors. Concurrency guard, credential-resolver hook, audit emission all present |
| Scan worker | ✅ built | `internal/worker/scan_worker.go` consumes `"scan"` jobs → executor → persists via `transactionlog.Writer.Apply()` |
| Result storage | ✅ schema ready | `host_rule_state` (current state per host×rule) + `transactions` (append-on-change). `current_status ∈ {pass,fail,skipped,error}`, `framework_refs JSONB`, `severity`, `evidence`, `skip_reason` |
| Compliance scheduler | ❌ **not booted** | `internal/scheduler` has `Dispatch()`/`UpdateAfterScan()` but `main.go` never instantiates it; `host_compliance_schedule` is never advanced |
| Intelligence scheduler | ✅ running | `internal/intelligence/scheduler` (OS-intel collection) — the working template for the compliance scheduler |
| On-demand scan API | ❌ none | no `/hosts/{id}/scan` or `/scans` in `api/openapi.yaml` |
| Host Detail compliance UI | ⚠️ partial | hero card reads `compliance_summary` (works, shows empty); Top-failed-rules + trend cards are stubs; Compliance tab is a `TabStub` |
| Host Management compliance UI | ⚠️ partial | list shows status/intel; compliance %, last-scan, per-host scan, fleet stats not wired |

**The chain is built but cold:** executor → worker → storage → display all exist;
they're dark because (a) the scan is a placeholder, (b) nothing enqueues scan
jobs, and (c) the read endpoints don't exist yet.

---

## 2. Target experience (extracted from the prototypes)

### Host Detail (`Host Detail.html`)
1. **Header `Run scan`** (on-demand trigger) + a **maintenance toggle** ("Pause scans & alerts").
2. **Offline banner** — "figures below reflect the last completed scan, may be stale."
3. **Overview → Top failed rules card**: rows of `[severity] · title · framework-control-id · category · occurrence-detail · [Remediate]`; footer "View all N failed rules →".
4. **Overview → Compliance trend (30 d)** card — needs posture snapshots.
5. **Compliance tab → lens model**: `scan-context` (last scan time, **auto-detected capabilities**), `Export` + `Re-scan`, a `lens-bar` ("View as" CIS/STIG/NIST/…), and summary + categories + rule-list, **all re-projected from one scan by `framework_refs`**.
6. **Per-rule `Remediate`** action.

### Host Management (`Host Management.html`)
7. **Fleet `Run scan`** (bulk) + per-host `Run scan` (table row + card).
8. **Fleet stats**: Avg. compliance, **Scan queue** depth.
9. **Fleet health banner** (e.g. "compliance dropped 4.2 pts in 24h").
10. **Host list columns**: compliance %, passed/failed/total, **last scan**, status; sorted "down first, then compliance asc".

### Settings → Scanning & monitoring (`Settings.html`, "Compliance scanner" section)
11. **Master toggle** — "Automatic compliance scanning" on/off, with the **48 h hard-ceiling** copy ("per host even when state hasn't changed") and a Running badge.
12. **Next-scan readout** — "Next scan in 2 min · **5 hosts queued**" (live queue depth).
13. **24 h schedule strip** — "What this will run · next 24 hours" visual projection of upcoming scans (the Q2 plan's "preview histogram").
14. **State-interval table** — one row per compliance state with: state name + score band, **hosts-in-state count** ("5 of 7 hosts"), an editable **interval stepper** (minutes), and the computed cadence ("Every 1h · 120 scans/day"). Prototype rows: Critical <20% → 60 m · Low 20–49% → 120 m · Partial 50–69% → 360 m · Mostly compliant 70–89% → 720 m · Compliant ≥90% → 1440 m.
15. The current `ScanningPage.tsx` already renders this section as a **"UI only" placeholder** (`Section title="Compliance scanner" badge="UI only"`, ~lines 457–502) — Phase 4 replaces it with the wired version, alongside the already-wired Connectivity / OS discovery / OS intelligence sections.

---

## 3. The Kensa v0.3.0 contract (foundation)

`k.Scan(ctx, HostConfig, []*Rule)` → `ScanResult{ Outcomes []RuleOutcome }`, where:

```go
type RuleOutcome struct {
    RuleID        string             // native rule id, e.g. "ssh-disable-root-login"
    Status        ComplianceStatus   // pass | fail | skipped | error
    Severity      string             // critical|high|medium|low (copied from rule)
    Detail        string             // UI-suitable explanation of the verdict
    FrameworkRefs []FrameworkRef     // normalized, OS-resolved
    Err           error              // non-nil iff Status==error
}
type FrameworkRef struct { FrameworkID string; ControlID string } // {"cis_rhel9_v2","5.2.3"}
```

The OpenWatch ↔ Kensa mapping is therefore a **field copy**, with zero compliance
logic on our side (this is the whole reason to be on v0.3.0):

```
kensa.RuleOutcome.Status        → host_rule_state.current_status   (1:1: pass/fail/skipped/error)
kensa.RuleOutcome.Severity      → host_rule_state.severity
kensa.RuleOutcome.Detail        → host_rule_state.evidence / .skip_reason
kensa.RuleOutcome.FrameworkRefs → host_rule_state.framework_refs   (map FrameworkID→ControlID)
```

`FrameworkRef` is already OS-resolved (`cis_rhel9_v2` bakes in the OS), which is
exactly the lens data — the Compliance tab groups `framework_refs` by `FrameworkID`.

**Isolation rule:** the `kensa.* → host_rule_state` translation lives in exactly
**one** adapter (`pkg/kensa`). Nothing downstream (worker, DB, API, UI) ever sees
a Kensa type. When Kensa's API evolves, we change one function.

---

## 4. Open risks to resolve before / during Phase 0

| # | Risk | Resolution |
|---|------|-----------|
| R1 | **Rule corpus loader — ✅ RESOLVED (2026-06-11, consensus with Kensa team).** Kensa will ship a public loader in their `pkg/kensa` (small, spec-covered PR): `LoadRules(dir string, paths []string, vars map[string]string) ([]*api.Rule, error)`, plus two discovery functions for the operator UI: `BuiltInVars() map[string]string` and `RuleVariables(dir) map[string][]string`. Decisive facts from their investigation: **23 of 539 rules are `{{ var }}` templates** resolved against an embedded defaults.yml (a copied parser would mis-read them *today*); the loader also does reference normalization, param-contract validation, and draft-tolerant walking; and the corpus ships as the **signed `kensa-rules` OS package** at the loader's default path — vendoring rule files into OpenWatch would fork the corpus and exit the GPG/cosign trust chain. | **OpenWatch consumes, never copies:** `kensa-rules` package on disk → `kensa.LoadRules(dir, nil, mergedVars)` → `Kensa.Scan` → `Outcomes`. Zero copied files, zero private imports. **Ratified boundaries:** (1) `LoadRules` returns parsed rules only — `depends_on`/`conflicts`/`supersedes` ordering stays unexported (revisit as its own ratification when Phase 7 remediation sequencing needs it); (2) per-host/per-group **variable storage lives in OpenWatch's DB** — OpenWatch passes the already-merged map per scan; Kensa stays a single-host resolver (same division as the liveness boundary). **Phase 0 gate is now just the Kensa PR (~a day on their side).** |
| R6 | **`FrameworkRefs` cardinality bug — MUST FIX BEFORE FIRST SCAN DATA (2026-06-11 review).** Kensa's `[]FrameworkRef` allows multiple controls per framework — e.g. `ssh-disable-root-login` maps to **three** NIST controls (`AC-6(2)`, `AC-17(2)`, `IA-2(5)`) and two PCI controls. OpenWatch's `RuleOutcome.FrameworkRefs map[string]string` (`internal/kensa/types.go:96`) holds **one** control per framework — converting silently drops the rest, and `transactionlog.Writer` marshals that lossy map straight into `host_rule_state.framework_refs`. The NIST/PCI lens would under-count. | Change to `map[string][]string` in `internal/kensa/types.go` + adjust `transactionlog/writer.go` marshaling. No migration needed (column is JSONB) and **nothing reads the column yet** — fix lands in Phase 0, before any data exists. Update `system-transaction-log`/`host-rule-state` spec shape notes. |
| R2 | **Transport on-disk key.** Kensa's default `ssh.Factory{}` needs `HostConfig.KeyPath` (a key on disk); OpenWatch decrypts credentials in-memory and must not write them out. **2026-06-11 review: the in-memory adapter does NOT exist** — `internal/kensa/doc.go` documents the intent only; no OpenWatch type implements `api.Transport`. | **Build it in Phase 0** (it is the sprint's largest single code item): implement `api.Transport` on top of `internal/ssh.Dial` (in-memory key auth, known-hosts policy already handled). Scope verified against kensa internals: the **scan path only calls `Run()`** — `Put`/`Get` are used solely by agent bootstrap, so implement `Run` (with `sudo -n sh -c` wrapping per the interface contract), `Close`, `ControlChannelSensitive() → false`, and return explicit not-implemented errors from `Put`/`Get` until remediation (Phase 7) needs them. Do **not** use `pkg/kensa.Default`'s transport. |
| R3 | **`skipped` semantics.** A validated corpus rule always has a default impl, so capability-mismatched rules fall through to pass/fail/error; `skipped` fires only for rules with implementations and no default. | Trust Kensa's verdict verbatim. Do **not** re-derive applicability. The lens denominator = the outcomes Kensa returns. |
| R4 | **Kensa result store.** `pkg/kensa.Default` opens a SQLite store for Kensa's engine/evidence. OpenWatch is the system of record (PostgreSQL). | Give Kensa an ephemeral/throwaway store path; persist authoritative results to `host_rule_state`/`transactions` only. |
| R5 | **Capability detection ownership.** The lens header shows "auto-detected capabilities". Kensa auto-detects; OpenWatch also has intelligence. | Use Kensa's detected capabilities (surface them via scan metadata); don't double-detect. |

---

## 5. Phased plan

Each phase is independently shippable and SDD-disciplined (spec → tests → code →
validate). "Spec" = a new/updated `.spec.yaml` with enforcing tests.

### Phase 0 — Foundation: wire the real Kensa scan ⟶ *unblocks everything*
**Goal:** a manually-enqueued `"scan"` job produces real `host_rule_state` rows.
- **Resolve R1** (corpus loader) and **R2** (in-memory transport) first.
- **Fix R6 first-in-phase:** `FrameworkRefs` → `map[string][]string` (types + writer) before any scan data is written.
- Bump `go.mod` → `github.com/Hanalyx/kensa v0.3.1`; update `KensaModuleVersion` + the pin test in `internal/kensa`. *(v0.3.1 ships the public loader — verified by smoke test 2026-06-11: `LoadRules` returns all 539 rules with zero unresolved templates, operator-var override works, `RuleVariables` reports the 20 corpus vars. Note `LoadRules` is STRICT — any unparseable file or undefined variable fails the whole load, naming the file — the right semantics for a compliance corpus.)*
- New `pkg/kensa` (OpenWatch side) — the production `ScanFunc`:
  - decrypt credential in-memory (existing `internal/credential` resolver) → build OpenWatch `TransportFactory`;
  - construct Kensa with our transport + Kensa's engine/scanner/store;
  - `kensa.LoadRules(rulesDir, nil, vars)` → `Scan()` → copy `Outcomes` into the executor's `RuleOutcome` (the §3 field copy);
  - **Vars in Phase 0: pass `nil`** — every templated rule has a safe embedded default, so scans work out of the box. Operator variable config is Phase 4 scope. Load the corpus once at worker start (and on config change), not per scan — `LoadRules` resolves templates at load time, so per-host variable tiers (future) would force per-scan loads; defer that until a real need.
  - `rulesDir`: default to the `kensa-rules` package path; honor an explicit override (env/config) for dev checkouts where the OS package isn't installed.
  - capture scan metadata (started/finished, capabilities, rule count, engine/policy version).
- Bind it via `WithScanFunc(...)` in the worker subcommand, replacing `unwiredScanFunc`.
- **Spec:** `system-kensa-executor` (close AC-18); `system-scan-execution` (new — verdict mapping, evidence cap, framework-ref copy, error/skip handling).
- **Exit:** enqueue a job by hand against a test host (`id_rsa` + `test_hosts.csv`); rows land in `host_rule_state`/`transactions`; the Host Detail **hero card lights up**. Verify the mapping against a known rule (e.g. `ssh-disable-root-login`).

### Phase 1 — On-demand single-host scan (trigger)
**Goal:** the prototype's `Run scan` button works end-to-end.
- **API:** `POST /api/v1/hosts/{id}/scan` — enqueues one `"scan"` job; **Idempotency-Key** required; RBAC `host:write`; returns the scan/job id + queued status. 404 on unknown host; 409/202 semantics for an in-flight scan per the executor's busy guard.
- **Backend:** thin handler → existing queue enqueue. Audit `scan.requested`.
- **Frontend (Host Detail):** wire the header `Run scan` + the card `Re-scan`/`Run scan` buttons (idempotency-keyed, `host:write`-gated, inline busy/feedback). Invalidate `['host', id]` + compliance keys on completion via SSE (`scan.completed`).
- **Spec:** `api-host-scan` (new); update `frontend-host-detail`.
- **Exit:** click Run scan → job runs → hero card updates without reload.

### Phase 2 — Top failed rules (Host Detail overview)
**Goal:** the "Top failed rules" card renders real data.
- **API:** `GET /api/v1/hosts/{id}/compliance/failed-rules?framework=&limit=` — reads `host_rule_state WHERE current_status='fail'`, ordered by severity desc then last-changed; joins `transactions` for first-seen/last-changed; projects `framework_refs[framework]` for the control-id + category. Returns `{title, native_id, control_id, severity, category, occurrence_detail, first_seen, last_changed}`.
- **Frontend:** replace the `CardTopFailed` stub; "View all N failed rules →" deep-links to the Compliance tab.
- **Spec:** `api-host-compliance` (new); update `frontend-host-detail`.
- **Exit:** card shows the same numbers as the hero; deep-link works.

### Phase 3 — Compliance tab: the lens model
**Goal:** "One scan, viewed through any framework."
- **API:** `GET /api/v1/hosts/{id}/compliance?framework=` — returns, for the selected framework lens: summary (pass/fail/total + %), category breakdown, and the rule list (each with `control_id` from `framework_refs`, severity, status, detail). Also `GET …/compliance/frameworks` → the lens-bar options (frameworks this host's outcomes actually map to) + scan-context (last scan, detected capabilities).
- **Frontend:** build the Compliance tab — `scan-context` header, `lens-bar` (`?framework=` drives the query key, matching the existing host-detail framework-param pattern), `comp-summary` / `comp-cats` / `comp-rules`, `Export`.
- **Spec:** `frontend-host-compliance-tab` (new); extend `api-host-compliance`.
- **Exit:** switching the lens re-scores instantly from one scan; counts reconcile across lenses.

### Phase 4 — Adaptive auto-scan scheduler ⟶ *the originally-planned model*
**Goal:** scans run on their own, state-based cadence (max 48 h).
- *(2026-06-11 review: smaller than originally scoped — `internal/scheduler` already has `Run(ctx, interval)` cron, `Dispatch()` with HMAC-signed `queue.Enqueue("scan")`, `UpdateAfterScan()`, tier ladder, and policy-revocation plumbing. The work is boot wiring + the post-scan callback + seeding, not building the scheduler.)*
- **Backend:** boot `internal/scheduler` in `main.go` (mirror `intelSched`); seed `host_compliance_schedule` on host-create; call `UpdateAfterScan()` after each scan to set `compliance_state` + `next_scheduled_scan`; `Dispatch()` on the cron tick enqueues due hosts. Respect `hosts.maintenance_mode`. Independent backoff (`probe_type='scan'`).
- **Scan-run metadata:** a `scans` (or `scan_runs`) record per run → powers "last scan", "scan queue" depth, scan status/history.

**Settings → Scanning "Compliance scanner" section** (replaces the existing "UI only" placeholder in `ScanningPage.tsx` ~457–502; targets §2 items 11–15):
- **API:** `GET`/`PUT /api/v1/system/scan/config` — `{enabled, interval_mins per state, rate_limit, maintenance_global}` in the established `{config, defaults}` envelope (same systemconfig store + `SystemConfigChanged` audit pattern as connectivity / intelligence / discovery configs). Server clamps to the scheduler's bounds (never below the floor; ceiling 48 h = 2880 m).
- **Read endpoints for the section's live data:**
  - hosts-per-state counts → `GET /api/v1/fleet/compliance/states` (one row per `ComplianceState`, analogous to the fleet connectivity breakdown);
  - "Next scan in X · N hosts queued" → queue depth for `job_type='scan'` + min(`next_scheduled_scan`);
  - 24 h schedule strip → `GET /api/v1/system/scan/schedule:preview` projecting `host_compliance_schedule` forward 24 h (read-only projection, not a dry-run dispatch).
- **Frontend:** wire the section — master toggle, state-interval steppers (per-state minutes), per-state host counts, computed cadence labels, next-scan/queue readout, schedule strip. Section-local Save/Reset, mirroring `OSIntelligenceSection`'s container/pure-view split.
- **Scan variables sub-section (operator config for the 23 templated rules):** key the list off `kensa.RuleVariables(dir)` (the **20 variables actually used** by corpus rules, with "affects N rules" per variable), using `kensa.BuiltInVars()` for the default values — BuiltInVars returns 29 entries, 9 of which no corpus rule uses; don't render those; store operator overrides in OpenWatch (global tier first — systemconfig key `scan_variables`; per-group/per-host tiers are a later phase per the ratified boundary); the worker passes the merged map to `LoadRules`. **Flag the three org-specific placeholders prominently as "configure me"** — `rsyslog_remote_server`, `chrony_ntp_pool`, `banner_text` — since scans against their example defaults produce technically-valid but practically meaningless verdicts for those rules.
- **Spec:** `system-compliance-scheduler` (promote/author); `api-system-scan-config`; `frontend-settings-scan-config` (new, incl. scan variables).

**⚠️ Reconciliation issues found in the 2026-06-11 settings review — resolve at Phase 4 start:**
- **(a) Config source-of-truth conflict.** The built scheduler loads its `TierLadder` from a **signed schedules policy file** (`PolicyTiers` + signature verification + revocation list, wired in `main.go`), while the prototype shows **operator-editable steppers** — i.e. the systemconfig PUT pattern every other section uses. Decide: (i) move the ladder to systemconfig like its sibling configs (drop/repurpose the signing machinery for this knob), or (ii) keep the signed policy and make the Settings UI read-only for intervals. Recommendation: (i) for consistency — signing the cadence config has unclear threat-model value when the same operator can already PUT maintenance toggles that stop scanning entirely.
- **(b) State-band mismatch.** Prototype shows **5 score bands** (Critical <20, Low 20–49, Partial 50–69, Mostly compliant 70–89, Compliant ≥90); the backend `ComplianceState` enum has **4 score states + `unknown`** (`critical`, `non_compliant`, `partial`, `compliant`). Either add a 5th band to the enum/`StateFromScore` (+ migration of the `host_compliance_schedule` CHECK if any) or collapse the UI to 4 bands + an "Unknown / never scanned" row. Decide before authoring `api-system-scan-config`, since the state names are the config keys.

- **Host Detail tie-in:** show `next scan` + last-scan freshness; trend card's "auto-scan resumes" copy becomes real.
- **Exit:** a fresh host gets scanned without anyone clicking; interval adapts to compliance state; the Settings section edits the live ladder and the strip/queue readouts move.

### Phase 5 — Host Management fleet surfaces
**Goal:** the fleet page's scan/compliance columns + bulk scan.
- **API:** extend the hosts list to include `compliance_summary` (%, passed, failed, total) + `last_scan_at` + `scan_status`; `GET /api/v1/fleet/compliance` (avg, distribution, 24 h delta for the health banner); scan-queue depth (from the job queue / scan-runs). `POST /api/v1/hosts:scan` (bulk, selection or whole-fleet, idempotency-keyed).
- **Frontend (Host Management):** compliance column + tier coloring, last-scan cell, per-host + fleet `Run scan`, "Scan queue" + "Avg. compliance" stats, fleet-health banner, "down first / compliance asc" sort.
- **Spec:** `api-fleet-compliance` (new); update `frontend-hosts-list`.
- **Exit:** the fleet table matches the prototype with live data.

### Phase 6 — Compliance trend (posture snapshots)
**Goal:** the 30-day trend card.
- **Backend:** a daily posture-snapshot rollup (per host + fleet) from `transactions`.
- **API:** `GET /api/v1/hosts/{id}/compliance/trend?days=30`; fleet equivalent for the health banner delta.
- **Frontend:** replace the trend empty-state with the chart.
- **Spec:** `system-posture-snapshots` + `api-compliance-trend`.

### Phase 7 — Remediation + exceptions *(larger; separate track)*
**Goal:** the `Remediate` action and `Add exception` flow.
- **Backend:** wire `kensa.Remediate()` behind the same transport/adapter (transactional apply + rollback; Kensa Phase 4 K-4/K-5); exception governance against `host_rule_state` (suppress + `skip_reason`). The transport's `Put`/`Get` stubs get real implementations here if remediation mechanisms need them.
- **Open ratification (flagged by Kensa, deferred to this phase):** `LoadRules` deliberately does not expose `depends_on`/`conflicts`/`supersedes` ordering — if remediation sequencing needs ordering semantics, that's a new Kensa ratification, not something OpenWatch re-implements.
- **API/Frontend:** `POST …/rules/{rule_id}:remediate`, exception request/approve flow, suppressed-rule rendering.
- **Spec:** `system-remediation`, `api-host-remediation`, `frontend-remediation-tab`.

---

## 6. Cross-cutting requirements

- **RBAC:** read = `host:read`/`system:read`; scan trigger + remediation = `host:write` (per `rbac_registry.md`). Anonymous → 401/403.
- **Audit:** `scan.requested`, `scan.started`, `scan.completed`, `scan.failed`, `remediation.*` per `audit_event_taxonomy.md` (executor already emits the started/completed/failed legs).
- **Idempotency:** every mutating scan/remediate endpoint requires `Idempotency-Key` (reuse the connectivity:check pattern).
- **SSE / live refresh:** publish `scan.completed` on the event bus; extend `useLiveEvents` to invalidate `['host', id]`, the compliance keys, and `['hosts']` (fleet). (Tracks the existing Track-B SSE backlog.)
- **OpenAPI-first:** every endpoint lands in `api/openapi.yaml` → `make generate-api` → Go stubs + `frontend/src/api/schema.d.ts`.
- **Packaging (RATIFIED 2026-06-12 — air-gapped installs are the primary deployment target):** the corpus ships as the **signed `kensa-rules` OS package** at the loader's default path. OpenWatch's RPM/DEB MUST declare a dependency on it **and the air-gapped artifact set MUST bundle it** so an offline install is complete with no network fetch. OpenWatch never embeds or forks the rule files. `OPENWATCH_KENSA_RULES_DIR` is a development-only override — both boot paths warn loudly when it is set (spec system-kensa-executor C-16/AC-23), and no production runbook, unit file, or default config may use it; pointing production at a Go module cache or any unpackaged source is prohibited. Fold the dependency + bundling into `packaging/` + the `RELEASING` runbook before the first scan-capable release.

---

## 7. Sequencing & dependencies

```
Phase 0 (foundation) ─┬─→ Phase 1 (on-demand) ─→ Phase 2 (top failed) ─→ Phase 3 (lens tab)
                      └─→ Phase 4 (scheduler) ─→ Phase 5 (fleet) ─→ Phase 6 (trend)
                                                                     Phase 7 (remediation) ⟂ later
```

- **Phase 0 gates everything** and is itself gated on **R1 + R2**.
- Phases 1–3 deliver the Host Detail story on one host; Phase 4 makes it autonomous; Phase 5 scales it to the fleet.
- The lens model (Phase 3) is mostly frontend/SQL over `framework_refs`, since Kensa already normalizes the refs.
- Recommended first PR after this plan is approved: **Phase 0, step 1 only** — bump to v0.3.0, resolve R1's loader question, and prove the build — before writing the `ScanFunc`.

---

## 8. Decisions needed from review

1. ~~**R1** — corpus loader~~ — **RESOLVED 2026-06-11**: Kensa ships `pkg/kensa.LoadRules` + `BuiltInVars` + `RuleVariables`; OpenWatch consumes the signed `kensa-rules` package; both boundary ratifications accepted (no ordering export; per-host/group variable storage in OpenWatch's DB).
2. ~~**Trigger posture**~~ — **RESOLVED 2026-06-12: ship both.** On-demand (`Run scan`/`Re-scan`, shipped in Phases 1-3) stays as the dev/first-contact path; the adaptive scheduler (Phase 4) is the steady-state model.
3. ~~**Scan-run record**~~ — **RESOLVED 2026-06-11: yes, with full scan auditability.** Two complementary records: (a) a `scan_runs` table (Phase 0 migration) — one row per scan attempt: id, host_id, trigger (`on_demand`/`scheduled`), requested_by, queued/started/finished timestamps, status (`queued`/`running`/`completed`/`failed`), rule counts by outcome, policy/engine version, failure reason — powering "last scan", "scan queue", and history; (b) **audit events** for the full lifecycle per the audit taxonomy — `scan.requested` (who triggered, from where), plus the executor's existing `scan.started`/`scan.completed`/`scan.failed` emissions, all correlation-id linked to the run row.
4. ~~**Scheduler config source-of-truth**~~ — **RESOLVED 2026-06-12: systemconfig** (option i). The tier ladder moves to the systemconfig store like every other Settings → Scanning section; the signed-policy/revocation machinery is dropped for this knob (signing the cadence has no threat-model value when the same operator can PUT maintenance toggles that stop scanning entirely).
5. ~~**Compliance state bands**~~ — **RESOLVED 2026-06-12: add the 5th band.** `ComplianceState` gains `mostly_compliant` (70-89) to match the prototype's five bands: `critical` <20, `non_compliant` 20-49, `partial` 50-69, `mostly_compliant` 70-89, `compliant` >=90, plus `unknown` for never-scanned. These names are the config keys and UI labels.
6. *(new, low-priority)* **Per-host / per-group scan variables** — the ratified boundary puts their storage in OpenWatch when we want them; global tier ships in Phase 4. Note: per-host vars force per-host `LoadRules` calls (templates resolve at load time) — defer until a concrete need justifies the load cost.
