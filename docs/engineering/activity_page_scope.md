# Activity Page — Backend Scope + MVP

**Created**: 2026-06-13
**Status**: Scoping (informs the `frontend-activity` MVP and a backend backlog)
**Prototype**: [`prototypes/openwatch-v1/Activity.html`](prototypes/openwatch-v1/Activity.html)

> The `Activity.html` prototype is far richer than the live feed can back.
> This doc records, per prototype feature, what ships **now** (zero new backend)
> versus what is **backend-gated** (and how much backend each needs), so the MVP
> is honest about its boundaries.

---

## The backend reality

`GET /api/v1/activity` (`internal/activity/service.go`) is a **read-only UNION
projection** of five sources — `alert`, `transaction`, `intelligence`, `audit`,
`monitoring` — flattened to:

```
Activity { id, source, severity, host_id?, title, summary?, occurred_at }
ActivityPage { items[], hidden_count, next_cursor }
```

- **Filters**: `source`, `severity` (info/low/medium/high/critical), `host_id`,
  `since`, `until`, `cursor`, `limit` (default 50, max 200). **No** text-search
  (`q`) param. **No** aggregate/histogram endpoint.
- **RBAC**: per-source gating inside the service (alert→`alert:read`,
  transaction/intelligence/monitoring→`host:read`, audit→`audit:read`).
  `hidden_count` is the count of rows suppressed by the caller's missing
  permissions (not a pagination remainder).
- **Order**: `occurred_at DESC`, cursor-seek pagination.

**The key structural fact**: the activity row `id` is the *real* underlying id
**only for `source: "alert"`** (`service.go:159` — `SELECT id::text AS id ...
FROM alerts`). Monitoring synthesizes a fake UUID (`service.go:251`); the other
legs pass their row id but those tables have no per-id detail/mutation API. So
**`alert` is the only source an activity row can act on or fetch detail for by
id today.**

---

## Per-feature scope

| Prototype feature | Status | What it needs |
|---|---|---|
| Day-grouped event stream | **READY** | The flat feed |
| Source + severity filters | **READY** | Existing query params |
| Host filter / deep-link | **READY** | `host_id` param |
| Cursor "Load more" | **READY** | `next_cursor` |
| `hidden_count` surfaced | **READY** | Response field |
| Ack / Silence(Mute) / Resolve / Dismiss | **READY — alert rows only** | Lifecycle + endpoints + RBAC exist (`alerts/{id}:acknowledge\|silence\|resolve\|dismiss`, `main.go:543`); the activity id is the alert id. The other four sources are immutable logs |
| Detail drawer — basic fields | **READY (all sources)** | Render the activity item's own title/summary/source/severity/host/time; no fetch |
| Detail drawer — rich payload (alert) | **READY** | `GET /api/v1/alerts/{id}` returns tags/body/lifecycle |
| Detail drawer — rich payload (audit) | **GATED (small)** | `detail` JSONB exists on `audit_events` but only via the list API; needs `GET /api/v1/audit/events/{id}` |
| Detail drawer — rich payload (intelligence) | **GATED (small)** | `detail` JSONB on `host_intelligence_events`, list-only; needs `GET …/intelligence/events/{id}` |
| Detail drawer — rich payload (transaction) | **GATED (medium)** | `evidence` + `framework_refs` JSONB on `transactions`; needs `GET …/transactions/{id}` |
| Detail drawer — rich payload (monitoring) | **GATED (medium)** | per-layer flags + `error_*` on `host_monitoring_history`; needs a per-id GET |
| "Routed to" delivery panel | **GREENFIELD (medium–large)** | `notifications.yaml` is spec-only: **no tables, no service, no persistence**. Needs `notification_channels` + `notification_deliveries` schema, dispatch-outcome capture in `internal/alertrouter`, and a `GET …/notifications/deliveries?alert_id=` endpoint |
| Severity histogram | **GREENFIELD (small–medium)** | No aggregate endpoint. Either an `/activity/histogram` bucketed-count endpoint, or client-side over the loaded page (approximate only) |
| Text search | **GATED (small)** | No `q` param; add server-side search or client-side filter over the loaded page |
| Live tail | **PARTIAL** | SSE (`/api/v1/events`) carries monitoring/intelligence/heartbeat/drift/scan — **not** alert/audit/transaction state. A true activity tail needs those on the bus; a cheap version refetches on an SSE pulse |
| Category chip | **substitute** | No category column; `source` is the closest grouping |
| Group filter | **GREENFIELD** | Depends on the Groups entity (itself greenfield) |
| Dedup ×N count | **GATED** | The feed has no per-event count; needs a dedup-count column |

---

## MVP (shipping now — zero new backend)

1. `/activity` route + `ActivityPage`.
2. Day-grouped stream: time · source · severity · title · summary · host link.
3. Filters: **source** + **severity** dropdowns + **host_id** (deep-link), wired
   to the real query params.
4. Cursor **Load more**; surface **`hidden_count`** ("N hidden by permissions").
5. **Alert-source row actions** — Acknowledge / Silence / Resolve, shown only
   when `source === 'alert'` and the caller has `alert:write`, calling the
   existing `/alerts/{id}:action` endpoints.
6. **Detail drawer** — basic activity fields for every source, **enriched for
   `alert`** via `GET /alerts/{id}` (tags, body, lifecycle, and the same
   actions).

Deferred but cheap follow-ups (small backend each), in priority order:

1. `GET /audit/events/{id}` + `GET /intelligence/events/{id}` → rich drawer for
   those two sources (the JSONB is already stored).
2. `GET /transactions/{id}` + monitoring per-id GET → rich drawer for the
   remaining two.
3. Server-side text search (`q`) on the activity feed.

Larger, genuinely new backend (own tracks, not part of Activity MVP):

- **Notifications persistence** (channels + deliveries) → the "Routed to" panel.
- **Activity histogram** aggregate endpoint.
- **Live activity tail** (alert/audit/transaction events on the SSE bus).
- Generic **ack/mute for non-alert sources** — would need an
  `activity_event_state` table. **Recommendation: do not build this.** Keep
  ack/mute semantics on alerts (their natural home); the other four sources are
  immutable logs by design.

---

## Recommendation

Ship the MVP above. It delivers the stream, real filtering, the honest
`hidden_count`, and — because the alert lifecycle is already complete and
reachable from activity rows — a real slice of the prototype's interaction model
(ack/silence/resolve + an alert detail drawer) with **no backend work**. Treat
the two small per-id detail GETs (audit, intelligence) as the first fast-follow
if the richer drawer is wanted for those sources. Keep "Routed to", the
histogram, and live-tail as separate backend tracks.
