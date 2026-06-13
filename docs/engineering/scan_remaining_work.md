# Compliance Scan — Remaining Work (Phase 5 tail + Phase 7 remediation)

> Split out of [`scan_implementation_plan.md`](scan_implementation_plan.md) on
> 2026-06-13. That document is now the record of the **delivered** compliance
> scanning platform (Phases 0–4 and 6 done; Phase 7's **exception** half done;
> all shipped in **v0.2.0-rc.6**). This file holds the **forward-looking
> remainder** — the two items that are not yet built.
>
> **Status: 7 of 8 phases complete.** What is left:
>
> | Item | Size | Touches live hosts? |
> |------|------|---------------------|
> | Phase 5 tail — bulk scan endpoint | small | no |
> | Phase 7 — remediation | large (own track) | **yes** |
>
> **GA scope decision (2026-06-05): remediation ships as a BETA feature in the
> GA release.** It is in-scope for GA but explicitly labelled *beta* — surfaced
> behind a `Beta` badge, gated by the `remediation:*` RBAC perms, and limited to
> the first-slice posture (per-rule manual, approval-gated, snapshot+rollback)
> ratified in the decisions below. The beta label sets the expectation that the
> auto/policy-driven and bulk-sequenced postures are *not* in GA and that the
> blast-radius surface is still hardening. Everything else in this file (the
> five decisions, the likely shape, the sequencing) stands — "beta in GA" is a
> labelling + scope-boundary decision, not a change to the build order.

---

## Phase 5 (tail) — Bulk scan

Everything else in Phase 5 shipped (per-host Scan buttons, scan-queue KPI,
hosts-list `compliance_summary` enrichment, avg/critical KPIs, the fleet
avg-compliance delta from Phase 6). The one remaining piece:

- **API:** `POST /api/v1/hosts:scan` — enqueue a scan for a selection of hosts
  or the whole fleet, idempotency-keyed. Reuses the Phase 1 single-host enqueue
  path per host (same `scan_runs` logbook + `scan.completed` SSE), bounded by the
  scheduler's per-tick rate limit so a whole-fleet click cannot stampede.
- **Frontend (Host Management):** a fleet-level / multi-select "Run scan" action
  feeding the same scan-queue KPI.
- **Spec:** extend `api-host-scan` (or a small `api-fleet-scan`); update
  `frontend-hosts-list`.
- **Risk:** low — no host mutation, just N enqueues of the already-proven scan
  path. A good low-risk warm-up before the remediation track.

---

## Phase 7 — Remediation *(its own track; SCOPING REQUIRED before building)*

Remediation **changes target hosts** (edits configs, installs/removes packages,
restarts services). Unlike everything shipped so far — which only *reads* host
state — this has real blast radius. **Do not start coding until the decisions
below are ratified**, the same discipline used for the scheduler config and the
exception storage choices.

### What exists already

- `kensa.Remediate()` is available (kensa v0.3.2 `DefaultWithTransportFactory`).
- The in-memory SSH transport's `Put`/`Get` are currently not-implemented (the
  scan path only calls `Run`). Remediation may need them to push remediation
  scripts/files — first real implementation lands here.
- Exception governance is **done** and is the natural companion: a rule you
  cannot or will not remediate gets a waiver instead.

### Decisions needed (ratify first)

1. **Execution model.** Three postures, riskiest last:
   - *Manual, per-rule* — operator clicks "Remediate" on one failing rule →
     one fix runs → rescan. **Recommended first slice** (mirrors how on-demand
     scan preceded the adaptive scheduler).
   - *Manual bulk* — apply N fixes together. Needs the rule-ordering question (#4).
   - *Policy-driven / auto* — playbooks on a cadence. Most powerful, most
     dangerous; a separate, later decision.

2. **Approval gating.** The RBAC registry already splits `remediation:request`
   / `:approve` / `:execute` / `:rollback`. A config edit on a production host
   is arguably more consequential than a waiver. **Recommended: gate execution
   behind approval** for anything beyond a dry-run, mirroring the exception
   request→approve workflow.

3. **Rollback + safety.** Kensa K-4/K-5 give transactional apply + rollback.
   **Recommended: snapshot the pre-state, store it, expose a Rollback action.**
   This is the difference between a tool people trust on prod and one they don't.

4. **Open Kensa ratification.** `LoadRules` deliberately does **not** expose
   rule-ordering (`depends_on` / `conflicts` / `supersedes`). If bulk/sequenced
   remediation needs ordering, that is a **new Kensa-team ratification**, not
   something OpenWatch re-implements. Only bites past per-rule-manual.

5. **Transport `Put`/`Get`.** Implement only if a remediation mechanism needs to
   push files; the scan path proves `Run` is enough for command-based checks.

### Likely shape (pending the decisions)

- **Backend:** `remediation` service over the transport (apply + rollback,
  pre-state capture); a `remediations` logbook table mirroring `scan_runs`;
  request→approve→execute→(rollback) lifecycle with the existing RBAC perms +
  audit codes.
- **API:** `POST …/rules/{rule_id}:remediate` (request), the review actions, a
  rollback action; suppressed/remediated-rule rendering.
- **Frontend:** the Remediation tab + per-rule Remediate affordance on the
  Compliance tab (alongside the existing Request-exception action).
- **Spec:** `system-remediation`, `api-host-remediation`, `frontend-remediation-tab`.

### Sequencing recommendation

1. Ratify the five decisions (a short decision doc or a direct answer to #1 + #2).
2. Build **per-rule manual + approval-gated + rollback** as the first slice,
   backend-first then frontend, the same layering as exceptions.
3. Revisit bulk / auto / ordering only after the manual path is trusted on a
   real host.

---

## Cross-cutting follow-ups (small, not blocking either item)

- SSE streams outlive graceful shutdown's 30s grace — cancel streams on the
  shutdown ctx.
- The scan-context **Capabilities** line needs stored capability data from Kensa
  (currently absent).
