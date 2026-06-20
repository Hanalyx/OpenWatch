# Activity & Audit Readability — Implementation Plan

> **Status:** planning (approved direction, 2026-06-20). Tracks the initiative
> to make every activity/log surface human-readable, and to make the audit
> trail a first-class, exportable, compliance-grade record.
>
> **Decisions on file** (from the planning discussion):
> - The settings **Audit log stays** as the dedicated *forensic* surface
>   (distinct from the operational `/activity` feed), made readable + a detail
>   drawer + export. It is **not** redundant with `/activity`.
> - An immutable, exportable audit trail is a **committed compliance
>   requirement** (FedRAMP / CMMC / NIST 800-53 **AU** control family).
> - Readability target depth: **plain-English sentences + clickable context +
>   detail drawers + grouping/dedup** (the full tier).
> - Sequencing: **ship Phases 0-3 first** (the complete readability + exportable
>   audit win), then pick up Phase 4 (grouping/dedup) and Phase 5 (compliance
>   hardening) as fast-follow tracks, each with its own go-ahead.
>
> Related docs: [`audit_event_taxonomy.md`](audit_event_taxonomy.md) (canonical
> audit taxonomy, ~70 codes), [`activity_page_scope.md`](activity_page_scope.md)
> (the original `/activity` MVP scoping).

---

## 1. Why this initiative

The architecture is already sound — this is **not** a rebuild. There is one
unified feed, `GET /api/v1/activity`, backed by a single `UNION ALL` across the
five categories (`internal/activity/service.go`). The problem is two specific
gaps:

1. **Three of the five feed legs emit raw codes as the row `title`** (the
   backend hands the UI machine codes instead of sentences).
2. **There is no shared frontend formatter** — all six surfaces independently
   render fields, so the same raw enum/UUID leaks differently in each place.

### Current state of the five legs (the feed already gets 2/5 right)

| Category | Source table | `title` today | `summary` today | Human-readable? |
|----------|--------------|---------------|-----------------|-----------------|
| **Alerts** | `alerts` | pre-formatted in Go (alert router) | pre-formatted body | **Yes** |
| **Monitoring** | `host_monitoring_history` | built in SQL ("Host became unreachable") | error_message / failed layer | **Yes** |
| **Compliance** | `transactions` | raw `rule_id` ("CIS.6.1.1") | `change_kind` enum | **No** |
| **Intelligence** | `host_intelligence_events` | raw `event_code` ("system.package.updated") | **empty** (detail JSONB unused) | **No** |
| **Audit** | `audit_events` | raw `action` ("auth.login.success") | bare `resource_id` UUID | **No** |

### The six surfaces (all consume the same feed except the settings audit log)

| Surface | Component | Endpoint | Today |
|---------|-----------|----------|-------|
| `/activity` (central) | `pages/activity/ActivityPage.tsx` | `/api/v1/activity` | partial; leaks `source` enum |
| Dashboard "Recent Activity" | `pages/dashboard/widgets.tsx` | `/api/v1/activity?limit=8` | worst: prints `source` + `severity` raw |
| Host-detail "Recent Activity" | `pages/HostDetailPage.tsx` | `/api/v1/activity?host_id=` | cleanest (icon + title + summary) |
| Host-detail "Activity" tab | `HostDetailPage.tsx` TabStub | — | **stub** (deferred) |
| Host-detail "Audit log" tab | `HostDetailPage.tsx` TabStub | — | **stub** (deferred) |
| Settings "Audit log" | `pages/settings/AuditPage.tsx` | `/api/v1/audit/events` | leaks raw `action`, actor/resource **UUIDs**, JSON |

---

## 2. Architecture decision — where the sentence is built

**The backend builds the sentence; the frontend owns only display chrome.**

Rationale (evidence-first):
- Only the backend can resolve codes→sentences and IDs→names correctly: the
  rule catalog, the audit taxonomy registry, the intelligence `detail` payload,
  and host/user label lookups all live server-side. A frontend mapping would
  hard-code ~70 audit codes + the intelligence codes and **drift** from the
  server the moment a new event type is added.
- The feed already works this way for alerts + monitoring — we are *finishing*
  the pattern, not inventing one.
- Every consumer (all six surfaces, the SSE stream, future exports) gets
  readable text for free.

The frontend keeps a single thin helper (`eventDisplay.ts`) for the chrome only:
source label, severity label, icon, relative time.

### Audit vs activity — two lenses over one store

Both read `audit_events`, but they are **semantically distinct**, not duplicates:
- **`/activity?source=audit`** is a *lossy projection* — it drops `actor`,
  `outcome`, `correlation_id`, `detail`, `redactions`, `parent_event_id`. It is
  the operational headline.
- **`/api/v1/audit/events`** is the *full forensic envelope* — who/what/outcome,
  the causal chain, the redaction record. It is the compliance record.

Removing the dedicated audit surface would be a compliance regression (AU
controls), not a cleanup — hence "keep + improve."

---

## 3. Phases

### Phase 0 — Backend: human sentences for all five feed legs *(highest leverage)*

Finish the three weak legs so `title`/`summary` are real sentences. This alone
makes `/activity`, the dashboard widget, and host-detail Recent Activity
readable, because they already render those fields.

- **Compliance leg** (`transactions`): resolve `rule_id` → rule title (the rule
  catalog used by the host compliance lens) and `change_kind` → verb.
  → *"Ensure auditd is enabled: Pass → Fail."*
- **Intelligence leg** (`host_intelligence_events`): map `event_code` → a
  description, and build the currently-empty `summary` from the stored `detail`
  JSONB. → *"curl updated: 7.64 → 7.81."*
- **Audit leg** (`audit_events`): map `action` → a description, and **project the
  `actor_label` / `resource_label` columns the UNION query currently drops** into
  the row. → *"Alice created host web-01."*
- Likely needs a small runtime description registry for audit + intelligence
  codes (the audit taxonomy is compile-time only today).

Specs: bump `system-activity` (currently v1.1.0); `api-activity` may stay (shape
unchanged — only field *content* improves), confirm during implementation.

### Phase 1 — Frontend: one shared display helper, adopt on all surfaces

- New `frontend/src/api/eventDisplay.ts`: `sourceLabel`, `severityLabel`,
  `iconFor`, `relativeTime`.
- Refactor `ActivityPage`, the dashboard widget, host-detail Recent Activity,
  and the settings Audit log onto it.
- Delete the raw `source` / `severity` / UUID renders (dashboard widget first).

Specs: `frontend-activity` (v1.0.0) + the dashboard/host-detail specs.

### Phase 2 — Detail drawers + finish the deferred stubs

- Backend: `GET /api/v1/audit/events/{id}`, `GET /api/v1/intelligence/events/{id}`
  (and transactions) returning the full structured payload.
- Frontend: row-expand drawer showing that payload + **clickable host/user
  context** (links to the host / user pages).
- Host-detail **Activity** tab → render the host-scoped feed (it is the "View
  all" target from the Recent Activity card).
- Host-detail **Audit log** tab → **drop it**. Audit events carry no `host_id`,
  so a host-scoped audit tab is empty by design; surface host-relevant audit via
  `resource = host` inside the host Activity tab instead.

### Phase 3 — Settings Audit log → the forensic / compliance view

- Readable rows: action description, actor/resource **names** (not UUIDs),
  outcome.
- Detail drawer over `GET /audit/events/{id}` (full envelope + redactions +
  correlation chain).
- **CSV / JSON export** of a filtered audit query.
- AU alignment: AU-3 (record content), AU-6 (review/analysis), AU-7
  (reduction/report generation).

> **End of the committed body of work.** After Phase 3 every surface is
> readable, the audit trail is a complete, exportable, name-resolved record, and
> the two deferred host tabs are resolved. Phases 4-5 below are fast-follow
> tracks, each gated on a separate go-ahead.

### Phase 4 — Grouping / dedup / noise control *(fast-follow)*

- Collapse bursts: *"12 packages updated on web-01"* instead of 12 rows.
- Suppress monitoring flaps (e.g. the dev-restart NULL→online noise already
  noted in BACKLOG), severity rollups, "N similar events."
- Design fork to settle: group at **query time** (backend, scales to large
  fleets) vs **client-side** (simpler, limited to the current page).
  Recommendation: backend.

### Phase 5 — Compliance hardening *(fast-follow, committed track)*

- Tamper-evidence: the `signature` field already reserved in the audit taxonomy
  (Ed25519 per-event signing or a hash-chain over the log).
- Retention / archival policy.
- An explicit AU-control mapping doc (which capability satisfies AU-2 / AU-3 /
  AU-6 / AU-7 / AU-9 / AU-12).

---

## 4. Sequencing summary

| Phase | Scope | Track |
|-------|-------|-------|
| 0 | Backend sentences for all 5 legs | **Committed** (do first) |
| 1 | Shared frontend formatter, adopt everywhere | **Committed** |
| 2 | Detail endpoints + drawers; finish host tabs | **Committed** |
| 3 | Settings audit log: readable + export | **Committed** |
| 4 | Grouping / dedup / noise control | Fast-follow (separate go-ahead) |
| 5 | Tamper-evidence + retention + AU mapping | Fast-follow (separate go-ahead) |

Each phase ships incrementally (spec → tests → code, normal PR flow). Phase 0
delivers the largest visible win on its own.

---

## 5. Key files (anchors for the work)

- Feed service / UNION: `internal/activity/service.go`
- Feed handler: `internal/server/activity_handler.go`
- Audit emission + registry: `internal/audit/` (`emit.go`, `events.gen.go`)
- Audit query handler: `internal/server/handlers.go` (`GET /audit/events`)
- Taxonomy: `docs/engineering/audit_event_taxonomy.md`
- Frontend surfaces: `pages/activity/ActivityPage.tsx`,
  `pages/dashboard/widgets.tsx`, `pages/HostDetailPage.tsx`,
  `pages/settings/AuditPage.tsx`
- Specs: `specs/system/activity.spec.yaml` (v1.1.0),
  `specs/system/audit-emission.spec.yaml` (v1.0.0),
  `specs/api/activity.spec.yaml` (v1.0.0),
  `specs/api/audit-events-query.spec.yaml` (v1.1.0),
  `specs/frontend/activity.spec.yaml` (v1.0.0)
