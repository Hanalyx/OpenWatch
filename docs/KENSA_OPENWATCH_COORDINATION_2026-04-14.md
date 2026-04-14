# Coordination Memo: OpenWatch ↔ Kensa Go Day-1

**From:** OpenWatch team
**To:** Kensa team
**Date:** 2026-04-14
**Subject:** Duplication review, integration commitments, and interface-freeze asks against `KENSA_GO_DAY1_PLAN.md`
**Status:** Draft for review

---

## 1. What triggered this memo

OpenWatch reviewed `kensa/docs/KENSA_GO_DAY1_PLAN.md` (the Go Day-1 build plan) on 2026-04-14 after recent OpenWatch Q3 work started diverging from the interfaces you've defined in §3.5 and §9. Four confirmed overlaps, one architectural misalignment, and two deferred OpenWatch phases that would build throwaway code if they proceed on current assumptions.

We want to resolve all of this **before** your `api/` surface freezes at Week 1 and before OpenWatch's Phase 6.2 implementation starts.

## 2. The posture OpenWatch is adopting

Per `OPENWATCH_VISION.md`'s framing (git : GitHub :: Kensa : OpenWatch), OpenWatch commits to the following rules:

| Rule | Consequence |
|------|-------------|
| Source of truth for per-transaction data lives in **Kensa's SQLite store**. | OpenWatch's PostgreSQL `transactions` table is demoted to a **derived cache/index**, not a parallel source of truth. |
| Per-transaction cryptographic attestations are **signed by Kensa**. | OpenWatch's per-transaction signing path is deleted. OpenWatch keeps signing only for aggregate artifacts that OpenWatch itself originates (cross-host audit exports, quarterly posture reports, State-of-Production releases). |
| Single-host execution semantics (Plan, Execute, Rollback, atomicity, capture) live in **Kensa**. | OpenWatch's Phase 6.2 "proactive remediation" rewrites from "OpenWatch generates a plan" to "OpenWatch wraps `Kensa.Plan` / `Kensa.Execute` with an approval-workflow UI." |
| Event streams originate in **Kensa**. | OpenWatch's Heartbeat service subscribes to `Kensa.Subscribe(filter)` instead of polling PostgreSQL. |
| OpenWatch codes against **Kensa's `api/` signatures from commit 1**. | `ErrNotYetImplemented` during the stub period is acceptable. Parallel implementations with the intent to "swap later" are not. |

The short form: **OpenWatch is GitHub over Kensa's git.** We present, aggregate, orchestrate, collaborate. We do not re-implement what Kensa already does for a single host.

## 3. Confirmed duplication and OpenWatch's resolution

### 3.1 Transaction log query (Kensa §3.5.1 `LogQuery`)

**Duplication:** OpenWatch merged PR #398 today adding `POST /api/transactions/query` with a DSL whose filter fields mirror your `LogFilter` struct (HostIDs, FleetIDs, RuleIDs, FrameworkRefs, Statuses, Since, Until). Our schema, pagination, and projection shapes were derived independently but the surface is effectively the same read-side contract.

**OpenWatch resolution:**
- Keep the HTTP endpoint URL and schema stable — it's what OpenWatch UI and any third-party customers will call
- Refactor the implementation to delegate to `kensa.TransactionLog().Query()` once your Week 22 milestone lands
- Interim (pre-Week 22): the endpoint queries the PostgreSQL cache (which the Python Kensa presently writes)
- Spec and route file annotated with this "interim implementation" framing in a follow-up PR

**Ask for Kensa:** see §5 interface questions.

### 3.2 Per-transaction Ed25519 signing (Kensa §8.2)

**Duplication:** OpenWatch merged PR #397 earlier today with `backend/app/services/signing/signing_service.py` + a `deployment_signing_keys` table + `POST /api/transactions/{id}/sign`. Your Go plan places Ed25519 signing at the point of evidence capture, which is the correct trust layer — the auditor needs Kensa's attestation ("this execution happened on this host"), not OpenWatch's ("OpenWatch stored this later").

**OpenWatch resolution:**
- Delete `POST /api/transactions/{id}/sign` — per-transaction signing becomes Kensa-only
- Keep the `SigningService` class **but only for aggregate artifacts OpenWatch originates** — cross-host audit export bundles, quarterly posture snapshots, future State-of-Production report
- Update `docs/SIGNING_SECURITY_REVIEW_2026-04-14.md` with an explicit trust-layer diagram
- Bump `specs/services/signing/evidence-signing.spec.yaml` to version 2.0 with the narrowed scope

**Ask for Kensa:** confirm that the signed envelope structure in §8.2 is exposed via the Go `api/` (we'll need to display the envelope + signature in OpenWatch's audit UI and verify it via `Kensa` on client request).

### 3.3 Plan / Execute for remediation (Kensa §3.5.3 `Planner`, `Executor`)

**Duplication (planned, not yet built):** OpenWatch's Q1-Q3 plan §6.2 "Proactive Remediation Workflow" specified *"Draft job is a remediation_jobs row with status=draft + the full proposed transaction plan (capture / apply / validate / rollback)"* — re-implementing your `Plan` type and Execute semantics.

**OpenWatch resolution:**
- Rewrite §6.2 before implementation starts. Revised architecture:
  1. Drift event → OpenWatch calls `Kensa.Plan(host, rule)` → receives an opaque `Plan` blob
  2. OpenWatch stores the blob in `remediation_jobs.kensa_plan` (JSONB) without interpreting it
  3. ApprovalQueue UI renders the plan via a Kensa-provided preview formatter (not OpenWatch's own render)
  4. On N-of-M approval (OpenWatch's approval-chain layer, §6.3), OpenWatch calls `Kensa.Execute(host, plan)`
  5. `PlanStaleError` from Kensa surfaces as "re-plan required" in the UI
- **Do not start 6.2 implementation** until your Week 24 milestone

**Ask for Kensa:** does the `Plan` struct include a human-readable preview string or should OpenWatch render from the `ApplyStep` / `RollbackStep` structures directly? We'd prefer a Kensa-owned formatter (`Plan.Preview()` method or an `api` helper) so the display stays consistent with the CLI's preview.

### 3.4 Event subscription for Heartbeat (Kensa §3.5.2 `EventSubscriber`)

**Duplication (planned, not yet built):** OpenWatch's Phase 3 Heartbeat design called for a PostgreSQL-backed event stream generated by the OpenWatch scheduler/worker.

**OpenWatch resolution:**
- Rewrite Phase 3 before implementation starts. OpenWatch runs a long-lived consumer over `Kensa.Subscribe(EventFilter{...})`
- OpenWatch owns: fleet-level aggregation, alert-routing policy, channel dispatch (Slack/email/webhook/Jira), deduplication, notification-rate-limiting
- Kensa owns: the event stream itself

**Ask for Kensa:** see §5.

### 3.5 Transactions table as "canonical"

**Architectural misalignment, not strict duplication:** OpenWatch's Q1 Phase 1 shipped a `transactions` + `host_rule_state` schema in PostgreSQL. With Kensa's SQLite store becoming the per-deployment source of truth, OpenWatch's PostgreSQL layer needs to be explicitly reframed.

**OpenWatch resolution:**
- Treat the PostgreSQL `transactions` table as a **multi-host aggregation cache** (not a source of truth). It survives because cross-fleet queries against N independent Kensa SQLite stores are too slow for UI response times
- Add prominent comments to the ORM model and to `backend/app/tasks/kensa_scan_tasks.py` making this explicit
- `transaction-log.spec.yaml` updated to bump version and reflect the cache-over-Kensa posture
- Any conflict between PostgreSQL row and Kensa SQLite row: **Kensa wins** (cache invalidation path via `Subscribe` events)

**Ask for Kensa:** confirm that `LogQuery.Query` + `LogQuery.Aggregate` can serve OpenWatch's multi-host aggregate needs at acceptable latency (<500ms p95 for historical posture queries on fleets of ~1000 hosts), or whether OpenWatch should maintain its own aggregation cache. If the former, OpenWatch drops the PostgreSQL `transactions` table entirely in a later phase.

## 4. Work OpenWatch keeps as pure OpenWatch-layer (NON-duplicative)

These are fleet/multi-user/multi-tenant concerns that have no analog in single-host Kensa. OpenWatch continues building them independently:

| OpenWatch feature | Justification |
|---|---|
| Multi-approval chains + approval policies (Phase 6.3) | Orchestrating N approvers is orthogonal to `Kensa.Execute`. Same relationship as GitHub branch-protection rules to `git merge`. |
| Fleet grouping + per-group policies (Phase 6.4) | Kensa has no concept of "a fleet". OpenWatch owns group membership, group-specific scan cadences, group approval policies. |
| Public State-of-Production Rollback report (Phase 6.5) | Aggregated statistics across opt-in customers. Cross-tenant by definition. |
| SSO federation (OIDC + SAML) | User authentication for OpenWatch; not a per-host concern. |
| Notification channels (Slack, email, webhook, Jira) | Fan-out for Kensa events into organization-specific tooling. |
| RBAC, audit logging of OpenWatch user actions, multi-tenant isolation | OpenWatch-specific. |
| Adaptive scan scheduling across a fleet | OpenWatch decides *when* to call `Kensa.Scan` for each host. Kensa scans one host on demand. |
| Audit export (aggregate CSV/JSON/PDF across hosts) + its Ed25519 signing | OpenWatch-originated artifact. |

## 5. Interface review requests (before Week-1 freeze)

We would value a review of the following interface shapes **before `api/` freezes**, because once semver locks you can't adjust without a major-version bump:

### 5.1 `LogFilter` (§3.5.1)

- Add `Phase []Phase` field? OpenWatch UI filters by phase (capture/apply/validate/commit/rollback).
- Add `Severity []string` field? OpenWatch views filter by severity (critical/high/medium/low). Today inferred from `rule_id` — but that's expensive at query time.
- Clarify `FrameworkRef` semantics: is it `(framework_id, control_id)` or an opaque string? OpenWatch filters by control path (`cis_rhel9_v2:5.2.3`).

### 5.2 `AggregateKey` (§3.5.1)

Please support at minimum:
- `by_host`
- `by_rule`
- `by_framework_control`
- `by_host_then_framework_control` (compliance-officer view: which control is failing on which host?)
- `by_rule_then_status_over_time` (drift view: rule X's pass/fail ratio over week buckets)

### 5.3 `EventFilter` (§3.5.2)

- Can OpenWatch subscribe to `DeadmanTimerFired` **alone**? Our alert-routing needs to treat this as a critical-severity event regardless of other subscriptions.
- Is `HeartbeatPulse` rate-limitable in the filter, or does the subscriber drop?

### 5.4 `Plan` (§3.5.3)

- Does `Plan` include a `Preview() string` or `Render() *PreviewDoc` method Kensa owns? OpenWatch would rather display Kensa's rendering than build a second renderer that drifts.
- `PlanStaleError`: what granularity? (Same-host-any-change, or per-file drift?) OpenWatch's UX needs to say "re-plan because X changed," not just "re-plan."

### 5.5 `TransactionRecord` (§3.5.1 `Get`)

- Does it include the full evidence envelope or only its hash? OpenWatch's audit-export path embeds the envelope directly, so we'd need the full payload.

### 5.6 Concurrency / rate limiting

- Is `Kensa.Scan` / `Kensa.Transact` safe to call concurrently against the same host from different OpenWatch workers? OpenWatch's job queue may fan out.
- Any per-host serialization you enforce, or is the caller responsible?

## 6. Timing + coordination

From your build sequence (§11):

| Kensa milestone | OpenWatch action |
|---|---|
| **Week 1** — `api/` surface frozen with stubs | OpenWatch starts coding against signatures immediately. PR #398 spec annotated; signing narrowed; Q1-Q3 plan §6.2 and Phase 3 rewritten to target `api/`. |
| **Week 22** — `LogQuery` real | OpenWatch swaps `POST /api/transactions/query` implementation from PostgreSQL to `Kensa.TransactionLog()`. |
| **Week 24** — `Plan`/`Execute` real | OpenWatch starts §6.2 proactive-remediation implementation. |
| **Week 25** — `Subscribe` real | OpenWatch cuts Heartbeat from PostgreSQL polling to Kensa event stream. |
| **Week 26 (M5)** — all OpenWatch-facing APIs real | OpenWatch runs full integration test: Plan → Subscribe → Execute → Query. Target: parity with Python Kensa on a 50-rule corpus. |
| **Week 40 (M7)** — Kensa Go v1.0.0 | OpenWatch is a pure consumer of Go Kensa. Python Kensa archived. |

Concrete OpenWatch deliverables **this sprint** in direct response to this memo:

1. PR: "docs: align signing scope to OpenWatch-originated artifacts only" (narrows `backend/app/services/signing/`, deletes per-transaction signing endpoint, updates review doc + spec)
2. PR: "docs: rewrite Q1-Q3 plan §6.2 + Phase 3 against Kensa api/" (architecture-only, no code changes)
3. PR: "chore(transactions): reframe query API as interim over Kensa LogQuery" (spec annotation + TODO comment in route; no behavior change)

**Not in this sprint:** Phase 6.2 implementation (waits for Week 24) and Phase 3 Heartbeat (waits for Week 25). Phase 6.3 (multi-approval) and Phase 6.4 (fleet groups) remain scheduled — those are OpenWatch-layer and don't wait.

## 7. Asks summary

In priority order, what OpenWatch needs from Kensa team:

1. **Confirm this memo's resolutions are what you expect.** Any of §3.1–3.5 where our resolution is wrong, flag now.
2. **Review interface questions in §5** and adjust `api/` before Week-1 freeze.
3. **Confirm the Week 1 `api/` stub strategy is real and imminent.** OpenWatch's roadmap assumes we can start coding against it in ~days, not ~months.
4. **Coordinate on the evidence-envelope structure** so OpenWatch's audit UI and the CLI present the same thing.
5. **Shared `kensa-spec` repo for rules/mappings/specs** (your §12.1) — confirm the submodule mechanics so OpenWatch's Kensa rule-reference UI doesn't diverge.

## 8. Open questions

These came up during the review and we want your input, not a pre-baked answer from us:

- **Agent API** (your §3.5 intro says "future AI agents" are a consumer). Is the intent that OpenWatch *also* exposes an HTTP version of Kensa's API to external AI agents, or do agents talk to Kensa directly? This affects whether OpenWatch stands up an `/api/v2/agent` surface or not.
- **Deadman-timer visibility.** Should OpenWatch's UI render a prominent warning when a deadman timer is armed on a host? (We think yes — operators need to know a rollback is scheduled.) What's the UX you envision?
- **Multi-fleet transaction log.** If a transaction on host H_1 in fleet F_1 and another on host H_2 in fleet F_2 need cross-querying (e.g., "show me all remediations for CIS 5.2.3 across both fleets last week"), does `LogQuery` on a single Kensa instance answer this, or does OpenWatch federate across N Kensa instances?

---

**Response requested by:** Kensa team commit-1 timeline (please respond before you freeze `api/`).

**Contacts:**
- OpenWatch: engineering (CLAUDE.md collaborator reviewing this memo, human review pending)
- Kensa: engineering

**Related documents:**
- `/home/rracine/hanalyx/kensa/docs/KENSA_GO_DAY1_PLAN.md`
- `/home/rracine/hanalyx/openwatch/docs/OPENWATCH_VISION.md`
- `/home/rracine/hanalyx/openwatch/docs/OPENWATCH_Q1_Q3_PLAN.md`
- `/home/rracine/hanalyx/openwatch/docs/SIGNING_SECURITY_REVIEW_2026-04-14.md`
