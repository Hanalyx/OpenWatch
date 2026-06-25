# In-App Notifications — Change-Driven Design

**Status:** Proposed
**Last Updated:** 2026-06-25
**Related specs:** `frontend-notifications`, `system-alerts`, `api-alerts`,
`system-transaction-log`, `system-posture-snapshots`, `api-events-stream`,
`system-rbac`

---

## 0. Why this document

The shipped in-app notification MVP (`specs/frontend/notifications.spec.yaml`)
is a session-scoped counter whose only producer is `report.ready`. A bell that
counts finished reports is the least valuable thing the bell could do: a report
completing is not a *change in the world the operator must react to*.

This document repoints the bell at **meaningful state changes** — first and
foremost a compliance regression ("a rule that was passing is now failing"),
plus connectivity loss, drift, failed scans, failed remediation, and governance
items that need a decision. The thesis:

> A notification is a **change in compliance, fleet health, or governance state
> that a specific user should act on** — delivered durably, deduplicated,
> grouped, and deep-linked to the change.

The good news: OpenWatch is built on a **write-on-change** model, so the
change events already exist as first-class records. We are mostly *surfacing*
data, not computing it.

---

## 1. Two surfaces, deliberately different

| | Activity feed (`/activity`) | Notifications (bell) |
|---|---|---|
| Audience | anyone, exploratory | the signed-in user |
| Content | the full chronological log of everything | the **actionable subset** of changes |
| State | stateless stream | **per-user unread / read** |
| Volume | high (includes routine noise) | low, severity-gated |
| Goal | "what happened" | "what needs my attention now" |

The bell is not a second activity feed. It is the **curated, stateful, per-user
slice** of the same change data.

---

## 2. Principles

1. **Change-driven, not event-driven.** The backbone is the write-on-change
   `transactions` log + the `alertrouter` (which already classifies changes,
   assigns severity, and deduplicates). The bell is a *new sink* of that
   stream, not a parallel pipeline.
2. **Severity-ranked.** Every notification carries a severity
   (`critical`/`high`/`medium`/`low`/`info`, the existing `alertrouter.Severity`
   enum). The badge counts **unread high+**, not raw volume.
3. **Group, don't flood.** A scan that flips 30 rules on a host produces **one**
   notification ("web-01: 30 rules regressed, 4 critical"), not 30. Same
   grouping discipline as Activity-readability Phase 4.
4. **Per-user and RBAC-scoped.** A user sees changes for hosts they can see;
   approvers additionally get governance items; security roles get auth/security
   items. Scope mirrors the `host:read` gating already on the SSE stream and
   audit queries.
5. **Durable + read state.** A real per-user table, surviving refresh, with
   mark-read / mark-all-read. (This is exactly what the MVP spec deferred.)
6. **Actionable.** Every notification deep-links to the change:
   `/transactions/rule/:id`, `/hosts/:id`, the scan, or the exception.
7. **Noise is a bug.** If the bell ever shows routine churn, it has failed.
   Reuse the drift thresholds and severity floors that already keep the alert
   stream quiet.

---

## 3. The notification taxonomy

Anchored to real producers and identifiers in the codebase. "Source exists"
means the change is already detected/recorded today; we only need to fan it into
the in-app feed.

### Compliance (the core)
| Change | Severity | Source (identifier) | Exists |
|---|---|---|---|
| Rule **pass → fail**, critical severity | **critical** | `transactions` row `change_kind=state_changed`, `status=fail`, `severity=critical` (`internal/transactionlog`) | yes |
| Rule **pass → fail**, high/medium | high / medium | same, by `severity` | yes |
| New **critical** finding (`first_seen` as fail) | critical | `transactions` `change_kind=first_seen` | yes |
| Host compliance **band drop** (Compliant → At-risk → Critical) | high | `scheduler.StateFromScore` band change / `monitoring.band.changed` | yes |
| **Fleet** compliance **drift** ≥ major threshold (10pp) | high | `alertrouter` `drift_major` (from `drift.detected`) | yes |
| Rule **fail → pass** / band **improvement** | info (batch) | `transactions` `state_changed` to pass / `drift_improvement` | yes |

### Fleet health / connectivity
| Change | Severity | Source | Exists |
|---|---|---|---|
| Host **unreachable** (was reachable) | high | `alertrouter` `host_unreachable` | yes |
| Privilege/auth **degraded** (online but privilege probe failing — the #664 class) | medium | liveness band (`host_liveness.privilege_*`) | yes |
| Host **recovered** | info | `alertrouter` `host_recovered` (auto-resolves the unreachable alert) | yes |

### Scanning
| Change | Severity | Source | Exists |
|---|---|---|---|
| Scan **failed** (connect/auth/error — not a compliance fail) | high | `scan_runs.status=failed` + `failure_reason` | yes |
| Scan completed **with regressions** | — | *fold into the per-host regression group; do not notify "scan done" by itself* | — |

### Remediation
| Change | Severity | Source | Exists |
|---|---|---|---|
| Remediation **failed** / rolled back | high | `remediation.completed` event + `remediation_transactions.status` | yes |
| Remediation **pending approval** (licensed bulk/auto track) | high (approvers) | needs the bulk track | partial |
| Remediation **succeeded** (rule fixed) | info | `remediation.completed` | yes |

### Governance / exceptions
| Change | Severity | Source | Exists |
|---|---|---|---|
| Exception **pending approval** | high (approvers) | exception workflow (request state) | yes |
| Exception **approved / rejected** | medium (requester) | exception workflow | yes |
| Exception **expiring soon / expired** (rules re-enter scope) | medium | exception expiry sweep | yes |

### Security / system (low volume, high importance)
| Change | Severity | Source | Exists |
|---|---|---|---|
| Repeated **failed logins / account lockout** | high | auth audit events | yes (events) |
| **License expiring / entered grace** | medium | `internal/license` status (grace window) | yes |
| **New host discovered** | info | `host.discovered` | yes |
| User **invited / role changed** | info / medium | user-management audit | yes |

### Reports
| Change | Severity | Source | Exists |
|---|---|---|---|
| `report.ready` | info (demoted) | `internal/report/job.go` | yes |

---

## 4. Explicit non-events (never a notification)

These are routine churn. Surfacing them in the bell would recreate the
Activity-feed noise problem (where `scheduler.tick.dispatched` and
`system.package.installed` each run to ~7k rows):

- `scheduler.tick.dispatched`
- routine package inventory deltas (`system.package.installed`, etc.)
- online **heartbeat pulses** for already-online hosts
- a plain `scan.completed` that changed nothing
- **sub-threshold** compliance jitter (the `drift` classifier already suppresses
  moves below `minor=5pp`; the bell inherits that floor)

---

## 5. Architecture — reuse, don't rebuild

The cleanest move is to make the bell **another channel of the existing alert
engine**, not a third notion of "notification."

```
                 ┌────────────────────────────────────────────┐
 event bus  ───► │ alertrouter (classify → severity → dedup)   │
 (heartbeat,     │   AlertType: host_unreachable/recovered,    │
  drift.detected)│   drift_major/minor/improvement, ...        │
                 └───────────────┬────────────────────────────┘
                                 │ fan-out to channels
        ┌────────────────────────┼───────────────────┬───────────────┐
        ▼                        ▼                   ▼               ▼
   stdout channel          Slack channel       email channel   IN-APP channel  ◄── NEW
                                                                    │
 transactions log ──► regression projector ────────────────────────┤  writes
 (state_changed,      (critical pass→fail, band drops, grouped)     │  per-user
  first_seen)                                                       ▼  rows
                                                          notifications table
                                                                    │
                                                  GET /api/v1/notifications
                                                  (+ unread count, :markRead)
                                                                    │
                                              SSE push (api-events-stream) ──► bell drawer
```

Two producers feed the new in-app channel:

1. **The alert stream** (already built): `host_unreachable`, `host_recovered`,
   `drift_major/minor/improvement`. Wiring an in-app channel alongside the
   existing stdout/Slack/email channels makes these light up the bell **for
   free**.
2. **A transaction-log projector** (new, small): turns critical `state_changed`
   → fail and `first_seen` fail rows (and band drops) into grouped notification
   rows. This is the part the alert engine does not cover today — rule-level
   regressions.

**Delivery:** the existing SSE bus (`api-events-stream`) pushes a lightweight
`notification.created` signal so the bell updates live; the drawer pulls the
durable list from `GET /api/v1/notifications`.

---

## 6. Data model

A durable, per-user table (replacing the session-scoped counter):

```
notifications
  id              uuid pk
  user_id         uuid        -- recipient (fan-out: one row per eligible user)
  kind            text        -- 'rule_regression' | 'host_unreachable' | 'drift_major' | 'exception_pending' | ...
  severity        text        -- critical|high|medium|low|info  (alertrouter.Severity)
  title           text        -- "web-01: 30 rules regressed (4 critical)"
  body            text        -- short detail
  host_id         uuid null   -- scope + dedup
  rule_id         text null
  group_key       text        -- dedup/collapse key (e.g. host_id + scan_id + 'regression')
  link            text        -- deep-link target (/transactions/rule/:id, /hosts/:id, ...)
  occurred_at     timestamptz
  read_at         timestamptz null
  created_at      timestamptz default now()

  index (user_id, read_at)            -- unread badge query
  unique (user_id, group_key)         -- collapse a burst into one row, bump a count
```

Grouping is enforced by `group_key` + the unique constraint: a second regression
in the same (host, scan) updates the existing row's count/`occurred_at` instead
of inserting a new one.

---

## 7. RBAC & scoping

Fan-out decides recipients per change:

- **Host-scoped changes** (regressions, unreachable, scan-failed, remediation):
  users who can see that host (`host:read`, plus any group/scope restriction).
- **Governance** (exception pending/expiring): users with the approver
  permission — surfaced as the bell's actionable queue for approvers.
- **Security/system** (lockouts, license): `security_admin` / `admin`.

This mirrors the `host:read` gate already on the SSE stream and audit queries —
no new authorization model.

---

## 8. Grouping & dedup

- **Per-scan collapse:** all regressions from one scan on one host → one row.
- **Flap suppression:** a host that goes unreachable→recovered→unreachable
  within a short window should not produce three bells (the alert engine already
  dedups via `dedup_key`; the in-app channel inherits it).
- **Recoveries batch:** `fail → pass` and `host_recovered` are reassuring but
  low-urgency — collapse into an info-level digest rather than badging.

---

## 9. Phasing

| Slice | Scope | Why first |
|---|---|---|
| **1** | Durable per-user `notifications` table + `GET /api/v1/notifications` + unread count + `:markRead`/mark-all + drawer UI + SSE push. Wire the **in-app alert channel** so existing alerts (`host_unreachable/recovered`, `drift_*`) populate it. | Biggest bang: reuses the entire alert engine; immediately useful; replaces the session-scoped MVP with durable state. |
| **2** | **Rule-regression projector** from the transaction log (critical `pass→fail`, `first_seen` critical, band drops), grouped per host/scan. | The headline use case ("a passing rule now fails"). |
| **3** | Governance (exception pending/expiring, RBAC-scoped to approvers) + remediation failures. | Turns the bell into an action queue. |
| **4** | Security (failed-login/lockout), license expiry, and **info-level digests** (batched recoveries / good news). | Rounds out coverage without adding noise. |

`report.ready` stays wired but is reclassified `info` — one small producer among
many, never the headline.

---

## 10. Open decisions

1. **Fan-out timing:** materialize one row per recipient at write time (simple
   reads, more rows) vs a single row + per-user read state (fewer rows, joins on
   read). Recommend per-recipient rows for small/medium fleets; revisit at
   scale.
2. **Retention:** notifications are derived from durable sources (transactions,
   alerts), so they can be pruned aggressively (e.g. 90 days) without losing the
   system of record. Tie to the audit/host retention sweep already on the
   backlog.
3. **User preferences:** which kinds/severities a user wants in the bell belongs
   in the existing `users.preferences` JSONB (`system-user-preferences`), not a
   new table — same home as the per-user alert-type preferences backlog item.
4. **Alerts vs bell unification:** confirm we treat the bell as a *channel* of
   `alertrouter`, so "Alerts" (Slack/email thresholds) and the in-app bell are
   one configurable stream, not two parallel concepts.
