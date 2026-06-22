# Activity feed + OS Intelligence — design context (deferred)

> **Status**: Deferred. Current focus is frontend GUI direction (post-`feat/daemon-orchestration`).
> This document captures the full design discussion so we can resume cleanly without re-litigating decisions.
>
> **Last updated**: 2026-05-30 (just after PR #430 landed)

---

## TL;DR

A single user-facing page named **`/activity`** that holds five categories of incoming information, role-filtered, with URL-routed filter presets (`/activity/alerts`, `/activity/transactions`, `/activity/intelligence`, etc.). The page is the operator's "Eye on the fleet" — a unified surface for OpenWatch-synthesized signals and host-reported security/configuration events.

The biggest gap is that **OS Intelligence collection does not exist in the Go rebuild yet**. The legacy Python side has it (PR #274 in legacy CLAUDE.md); the Go side has zero. Building `/activity` properly therefore lands in this order:

1. OS Intelligence writer + storage (~1.5 days)
2. Alert persistence amendment (~1 day)
3. Unified activity query API (~half day)
4. Frontend `/activity` page (depends on stack decision)

Roughly **4-5 days of focused backend work** before the frontend page is meaningful.

---

## Why this is deferred (not abandoned)

The current focus is frontend GUI foundational work:

- Frontend architecture ADR (TS framework, state management, API client, build, embed)
- First implemented page (validates the stack)
- `frontend-findings-ui` spec implementation (`/hosts/{id}` detail page)

Building OS Intelligence + activity feed in parallel would dilute both efforts. The frontend foundational work must settle first so the activity page has somewhere to land.

**Resume here when:**

- Frontend architecture ADR is on main
- At least one frontend page is implemented end-to-end (proves the stack works)
- Either customer demand surfaces fleet-wide visibility as a need, OR enough Slice B/C operator surface area accumulates that a unified view becomes necessary

---

## Product vision

A user navigates to `/activity` and sees, time-ordered and severity-colored, every signal the platform has captured about its fleet in the last N hours/days. Filterable, paginated, RBAC-gated. Linked everywhere — clicking a row opens the relevant `/hosts/{id}` or `/transactions/:id`.

The mental model is the "Eye": complete visibility into what's happening across the infrastructure. Not just OpenWatch's own internal events, but real signals from each managed host — account changes, security events, system changes — synthesized into a coherent operator view.

This is a meaningful product differentiator vs. traditional point-in-time compliance scanners: most compliance tools only show you scan results. OpenWatch should show you what *changed* on the host between scans.

---

## Page model — single page, multiple URL routes as filter presets

```
/activity                                  Role-default view
/activity/alerts                           Filter: alerts only
/activity/transactions                     Filter: compliance state changes
/activity/intelligence                     Filter: OS Intelligence events
/activity/intelligence/account             Sub-filter: account events
/activity/intelligence/security            Sub-filter: security events
/activity/intelligence/system              Sub-filter: system changes
/activity/audit                            Filter: who-did-what (admin only)
/activity?host=...&severity=high           Composable query params
```

**URL is the source of truth.** Role gates which filters are available. The page is one component; routes are filter presets baked into nav and bookmarkable.

**Why this design** (rejected alternatives):
- *Separate top-level pages per category* — nav clutter; six items become twelve
- *`/feed` as the name* — too casual for enterprise compliance buyers
- *Stream all four sources without role-gating* — overload for non-admin users

---

## Five data sources on this page

### 1. OS Intelligence events (NEW — does not exist on main)

Host-reported security / account / configuration events captured by the OS Intelligence collection service. **This is the big new piece.**

Three subcategories:

**Account / identity**
- User account locked out
- Password expired or expiring
- New user account created
- User added to privileged group (wheel, sudo, admin)
- SSH key added or removed for a user
- Sudo failure threshold crossed

**Security**
- SSH login from new source IP for a known user
- Failed login attempts threshold crossed
- SELinux / AppArmor denials
- New listening port opened
- Firewall rule changed
- First-time privilege escalation by a user

**System**
- Package installed / updated / removed
- Kernel update applied; reboot pending or completed
- Critical config file changed (`/etc/sudoers`, `/etc/passwd`, `sshd_config`, crontab)
- Service started / stopped / failed
- Disk filesystem mounted or unmounted

### 2. Compliance state transactions (EXISTS on main)

`transactions` table from Slice B (B.1c). Each row is a rule's state change on a host. `change_kind IN ('first_seen', 'state_changed', 'severity_changed')`. Already queryable via `GET /api/v1/fleet/recent-changes`.

### 3. OpenWatch-synthesized alerts (PARTIAL on main)

Slice B's alert router fires `Alert` values via the eventbus. The 5 types on main:

- `host_unreachable` / `host_recovered` (liveness)
- `drift_major` / `drift_minor` / `drift_improvement` (drift detector)

**Persistence gap**: alerts are fire-and-forget today; no `alerts` table. Building `/activity` to show alerts requires the alerts persistence amendment described below.

### 4. Audit events (EXISTS on main)

`audit_events` table. Already queryable via `GET /api/v1/audit/events`. Covers who-did-what for compliance/forensics. RBAC-gated to `audit:read`.

### 5. Future: OS Intelligence-derived alerts

OS Intelligence events that meet a threshold get re-promoted into the alert pipeline. E.g., `security.firewall.rule_changed` on a production host with severity=critical fires `firewall_rule_changed_unattended` if the change wasn't preceded by an approved change-management ticket.

This is the OpenWatch+OS-Intelligence loop: collect → detect → alert → triage → audit.

---

## OS Intelligence — the new backend piece

### Service

A new package: `internal/intelligence` (or `internal/osintel`). Long-lived service, started by `cmd/openwatch serve` alongside the liveness loop.

### Collection model — pull, with same SSH session as Kensa scan

**Decision: pull via SSH on a schedule.** Reuses the existing credential resolution + SSH dial path. Same dial budget the executor uses; can piggyback on the scan SSH session (collect right before or after the scan completes) for efficiency.

Rejected for now: **push via host-side agent.** That would require an enroll/auth flow that doesn't exist; deferred until OpenWatch has a real agent story.

### Granularity model — snapshot delta

**Decision: store full collected state per host in `host_intelligence_state`; emit one event row in `host_intelligence_events` per detected change.**

Same write-on-change discipline as `transactions` + `host_rule_state` (the 99.7% write reduction model from Q1). Avoids unbounded growth from re-emitting "nothing changed" snapshots every collection cycle.

### Storage schema

```sql
CREATE TABLE host_intelligence_state (
    host_id      UUID PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    snapshot     JSONB NOT NULL,  -- last full collected state by category
    collected_at TIMESTAMPTZ NOT NULL,
    collected_by UUID,            -- scan_id when piggybacked on a scan, else NULL
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE host_intelligence_events (
    id            UUID         PRIMARY KEY,
    host_id       UUID         NOT NULL REFERENCES hosts(id) ON DELETE RESTRICT,
    event_code    TEXT         NOT NULL,    -- closed enum; see taxonomy
    severity      TEXT         NOT NULL
                  CHECK (severity IN ('info','low','medium','high','critical')),
    detail        JSONB        NOT NULL,    -- per-code typed schema
    occurred_at   TIMESTAMPTZ  NOT NULL,    -- when the change happened on the host
    detected_at   TIMESTAMPTZ  NOT NULL,    -- when OpenWatch noticed it
    correlation_id TEXT        NOT NULL,    -- chain back to the collection run
    UNIQUE (host_id, event_code, occurred_at)  -- idempotency under retries
);

CREATE INDEX idx_intelligence_events_recent
    ON host_intelligence_events (detected_at DESC);
CREATE INDEX idx_intelligence_events_host_code
    ON host_intelligence_events (host_id, event_code, occurred_at DESC);
```

### Event taxonomy

Closed enum stored in `internal/intelligence/taxonomy.go`, mirrored in `audit/events.yaml` for taxonomy consistency. Roughly 25 codes at v1.0.0:

| Category | Code |
|----------|------|
| Account | `account.user.locked` / `unlocked` |
| Account | `account.user.created` / `deleted` |
| Account | `account.user.privileged_group_added` |
| Account | `account.password.expired` / `expiring` |
| Account | `account.ssh_key.added` / `removed` |
| Account | `account.sudo.failure_threshold` |
| Security | `security.login.new_source_ip` |
| Security | `security.login.failed_threshold` |
| Security | `security.selinux.denied` |
| Security | `security.apparmor.denied` |
| Security | `security.firewall.rule_changed` |
| Security | `security.port.opened` |
| System | `system.package.installed` / `updated` / `removed` |
| System | `system.kernel.updated` |
| System | `system.reboot.required` / `completed` |
| System | `system.config.changed` |
| System | `system.service.started` / `stopped` / `failed` |
| System | `system.filesystem.mounted` / `unmounted` |

Each has a default severity, an actor_types list, and a detail schema (same shape as the existing `audit/events.yaml` entries).

### Collection cadence

Default 1 hour per host, configurable via `policy.Intelligence.IntervalSec`. Clamped to `[5min, 24h]`. Same per-host advisory-lock discipline the scheduler dispatch and the future worker will share.

---

## RBAC model — row-level, not page-level

Today, RBAC is per-endpoint. For `/activity`, the API needs row-level filtering: a `host:read`-less user shouldn't see intelligence events about hosts; an `audit:read`-less user shouldn't see audit rows.

**Per-row permission map:**

| Source | Required permission |
|--------|---------------------|
| Alerts | `alert:read` |
| Compliance transactions | `host:read` AND `compliance:read` (the rule_id is the compliance reference) |
| OS Intelligence | `host:read` AND `intelligence:read` (new permission) |
| Audit | `audit:read` |

The unified `GET /api/v1/activity` endpoint filters rows the caller can't see, AND returns metadata: `{total_visible: N, total_hidden_by_rbac: M}`. The UI honestly tells the user "you have 47 items; 200 more are hidden by your role."

### Default view per role

Surfaced in the role definitions at `internal/auth/roles.gen.go`. New field on `RoleDefinition`: `DefaultActivityView` carrying a default filter URL fragment.

| Role | Default `/activity` view |
|------|--------------------------|
| `admin` | All sources, last 24h, severity ≥ info |
| `security_admin` | Audit + alerts (admin actions, MFA changes), last 7d |
| `ops_lead` | Alerts + transactions + intelligence, severity ≥ medium, last 24h |
| `auditor` | Audit + transactions, last 30d |
| `viewer` | Alerts (high+critical only) + transactions, last 24h |

---

## Pagination — UNION query with seek-cursor

**Decision: single SQL UNION ALL across all four sources, paginated via seek-cursor on `detected_at DESC`.**

```sql
SELECT * FROM (
    SELECT id, 'alert' AS source, severity, host_id, occurred_at AS detected_at, ...
      FROM alerts WHERE state != 'dismissed'
    UNION ALL
    SELECT id, 'transaction' AS source, severity, host_id, occurred_at, ...
      FROM transactions WHERE host_id = ANY($accessible_hosts)
    UNION ALL
    SELECT id, 'intelligence' AS source, severity, host_id, detected_at, ...
      FROM host_intelligence_events
    UNION ALL
    SELECT id, 'audit' AS source, severity, NULL AS host_id, occurred_at, ...
      FROM audit_events WHERE $can_read_audit
) AS activity
WHERE detected_at < $cursor
ORDER BY detected_at DESC
LIMIT 50;
```

Cursor is just the `detected_at` of the last row. Simpler than per-source cursors; trades a slight precision loss at category boundaries for implementation tractability.

Heavier DB query than per-source pagination — UNION + sort + limit. Acceptable at fleet scale; benchmark before assuming so.

---

## Spec / PR sequence — when work resumes

| # | Spec | What lands | Effort |
|---|------|------------|--------|
| 1 | `system-os-intelligence` v1.0.0 | Writer service, collection scheduler, event taxonomy, two new tables | ~1.5 days |
| 2 | `api-os-intelligence` v1.0.0 | `GET /api/v1/intelligence/events`, `GET /api/v1/intelligence/state` | ~half day |
| 3 | `system-alert-router` v1.1.0 | Amendment: persist every routed alert to a new `alerts` table | ~1 hour spec + 2 hours code |
| 4 | `system-alerts` v1.0.0 | Lifecycle service: acknowledge, silence, resolve, dismiss | ~half day |
| 5 | `api-alerts` v1.0.0 | `GET /api/v1/alerts`, lifecycle endpoints, RBAC | ~half day |
| 6 | `system-activity` v1.0.0 | Unified UNION query, RBAC row-filter, seek-cursor | ~half day |
| 7 | `api-activity` v1.0.0 | `GET /api/v1/activity` | ~half day |
| 8 | Role defaults | `roles.gen.go` extended with `DefaultActivityView` field | ~2 hours |
| 9 | Frontend `/activity` page | Depends entirely on frontend stack decision | TBD |

**Backend total: ~4-5 focused days** before the frontend page can start. Each row above is a single PR-sized unit; sequence is hard-ordered above the line at row 6 (1+2 parallel; 3+4+5 parallel after 1; 6 after all of 1-5; 7+8 after 6).

---

## Open decisions when work resumes

These remained open at time of writing. None are urgent now; all need an answer before implementation starts.

1. **Snapshot detail size cap**. The `snapshot` JSONB on `host_intelligence_state` could blow up on hosts with many packages. Cap at 10MB? Compress? Split per category into separate columns? Recommendation: 10MB hard cap with truncation marker, same pattern as `kensa.MaxEvidenceBytes`.

2. **OS Intelligence collection failure handling**. If collection times out on a host, do we mark `host_backoff_state.suppress_until` the same way kensa scan failures do? Risk: one bad host suppresses ALL its scan AND intelligence cycles. Probably need a per-probe-type backoff: `(host_id, probe_type)` where probe_type is `scan` or `intelligence`. The current `host_backoff_state` already has `probe_type` — extend it.

3. **Retention policy**. `host_intelligence_events` will accumulate fast. Default retention? Per-severity (`critical` keeps longest)? Configurable via policy?

4. **Multi-instance dedup**. The alert router's dedup gate is in-memory per-process. If two `serve` instances ever run, they each fire the same alert. The persistence amendment opens an attractive shared-state path: move dedup to a Postgres-backed `alert_dedup` table. Decide before multi-instance is a real deployment topology.

5. **Auto-resolve hooks**. When `host_recovered` arrives, it should auto-resolve the matching open `host_unreachable` alert. Similar for `drift_improvement` → close prior `drift_major`. The pattern is: every alert has a `resolves_when` predicate; the router checks it on every event. Concrete enough to spec; deferred to alert-lifecycle spec.

6. **`/activity` query performance**. UNION ALL across four tables sorted by timestamp with seek-cursor. Acceptable on dev fleet. Needs a benchmark on the first ~100k-row fleet before committing to it for production.

7. **Notification fanout**. If an OS Intelligence event needs to fire an alert, does the intelligence service publish to the eventbus (same path Slice B uses) or call alertrouter directly? Cleaner: publish typed events to the bus, let the alert router (which already subscribes to the bus) handle routing. Needs a new EventKind on the eventbus.

---

## How this composes with what's already on main

These specs are stable on main and inform the design:

- `system-event-bus` v1.0.0 — typed pub/sub; we add a new EventKind for intelligence events
- `system-alert-router` v1.0.0 — the persistence amendment is item 3 in the sequence above
- `system-transaction-log-writer` v1.0.0 — same write-on-change discipline we'd reuse for intelligence
- `system-liveness-loop` v1.1.0 — the cron-driven loop pattern (`Service.Run(ctx)`) is the model for the intelligence collection loop
- `system-kensa-executor` v2.0.0 — its SSH session is the piggyback target for collection
- `system-host-inventory` v1.0.0 — defines the active hosts the loop walks

These do NOT exist on main yet and are prerequisites OR siblings:

- `system-worker-subcommand` (drafted at `/tmp/worker-spec-polished.yaml`, not landed) — needs to land first so the scan path is complete, but technically orthogonal to OS Intelligence
- `frontend-architecture` (not drafted) — needed before any frontend page can land

---

## Why this isn't a copy of `docs/openwatchos/04-SERVER-INTELLIGENCE.md`

That document covers the **legacy Python** server-intelligence collection (PR #274). The Go rebuild has none of that code. The design in this document deliberately reuses concepts and the operational mental model from that doc but is the Go-rebuild-native version:

- New Go package, new specs, new storage tables
- Same write-on-change discipline established by Slice B
- Same SSH session reuse as the kensa executor
- Aligned with the framework-at-query-time architecture from Slice B/C work

When this work starts, reading the legacy doc gives operational context; the implementation is fresh.

---

## When you (or future-me) come back here

The first action is **not** to start implementing. The first action is to re-read this doc end-to-end, verify the open decisions section against any decisions that have settled in the meantime, and then write `system-os-intelligence` v1.0.0 spec (item 1 in the sequence). The spec drives the implementation, per SDD discipline.

Estimated 30 minutes to re-orient. Then proceed.
