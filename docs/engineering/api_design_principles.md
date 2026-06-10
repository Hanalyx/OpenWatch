# OpenWatch API Design Principles

> **Status:** Locked 2026-04-27
> **Authority:** This document is the rulebook for `api/openapi.yaml`. If the spec violates a rule here, the spec is wrong.
> **Audience:** Anyone designing or reviewing OpenAPI 3.1 endpoints for OpenWatch.

---

## Why this document exists

Today's backend has ~350 endpoints. Roughly 250 of those are not separate features — they are the same features exposed via inflated surface area: bulk variants doubled, format-per-endpoint, RPC-style action verbs, fragmented health/capabilities/stats, triplicated prefixes for the same workflow.

Proper API design absorbs the inflation. With these rules applied, the same MUST capabilities cover **~60–80 endpoints**, not 350. This is structural reduction, not feature reduction.

---

## Section 1 — Resources, not actions

### 1.1 Resources are nouns, plural, kebab-case

```
/hosts                      ✓
/host-groups                ✓
/scan-templates             ✓
/notification-channels      ✓

/createHost                 ✗  (verb, not noun)
/host_groups                ✗  (snake_case)
/HostGroup                  ✗  (PascalCase)
/host                       ✗  (singular)
```

Every URL segment that names a resource is a noun. The HTTP method is the verb.

### 1.2 The seven canonical operations

For every resource:

| Operation | Method + Path | Notes |
|---|---|---|
| List | `GET /resources` | Cursor-paginated, filterable, sortable |
| Get one | `GET /resources/{id}` | Single resource read |
| Create | `POST /resources` | Body is the resource (or array; see §3) |
| Replace | `PUT /resources/{id}` | Full replacement; rare in practice |
| Update | `PATCH /resources/{id}` | Partial update; preferred for changes |
| Delete | `DELETE /resources/{id}` | Soft-delete by default; hard-delete via flag |
| Sub-resource read | `GET /resources/{id}/sub-resource` | For natural compositions |

If you find yourself writing an eighth operation, you probably need a **state transition** (§2) or a **specialized resource** (§4), not a new verb.

### 1.3 Identifiers are UUIDs

All resource IDs are UUIDs. No integer IDs in the rebuild — including `users`. This eliminates the current `users.id is int while everything else is UUID` divergence.

URL path: `/hosts/{host_id}` where `{host_id}` is `{type: string, format: uuid}`.

---

## Section 2 — State transitions, not RPC verbs

### 2.1 Default: PATCH with target status

When a resource has a status field and the operation is "change that status":

```
✓  PATCH /alerts/{alert_id}     body: {"status": "acknowledged"}
✓  PATCH /alerts/{alert_id}     body: {"status": "resolved", "resolution_note": "..."}

✗  POST /alerts/{alert_id}/acknowledge
✗  POST /alerts/{alert_id}/resolve
```

The handler validates the transition is legal for the current status (state machine) and rejects illegal transitions with `error.code = "transition.invalid"`.

### 2.2 Exception: side-effect operations use `:action`

When the operation has side effects beyond changing the resource's own status — running a scan, sending a test notification, triggering a discovery probe, refreshing a cache — use the colon-action form:

```
✓  POST /scans/{scan_id}:cancel
✓  POST /notification-channels/{channel_id}:test
✓  POST /hosts/{host_id}/intelligence:refresh
✓  POST /auth/mfa:enroll
✓  POST /auth/mfa:enable
```

The colon makes the action explicit and visually distinct from a sub-resource. (Convention borrowed from Google AIP and gRPC-Gateway.)

**Test for which form to use:**
- Does the operation only change this resource's status? → PATCH
- Does the operation trigger work elsewhere (a job, a network call, an external side effect)? → `:action`

### 2.3 State machines are documented

For every stateful resource, the OpenAPI spec includes a `x-state-machine` extension showing valid statuses and legal transitions:

```yaml
components:
  schemas:
    Alert:
      x-state-machine:
        states: [active, acknowledged, resolved, expired]
        transitions:
          - from: active, to: acknowledged
          - from: active, to: resolved
          - from: acknowledged, to: resolved
          - from: active, to: expired       # automatic, not via API
```

Auto-only transitions are noted but not exposed as API operations.

---

## Section 3 — Bulk operations as collection-level POST

### 3.1 The default rule: one endpoint, one or many

```
✓  POST /hosts                           body: {host}            → returns 201 + {host}
✓  POST /hosts                           body: {hosts: [{...}]}  → returns 207 multi-status

✗  POST /hosts        body: {host}
✗  POST /hosts/bulk   body: {hosts: [...]}
```

The request body shape signals single vs many. Response status is `201 Created` for single, `207 Multi-Status` for many (with per-item results).

### 3.2 Three legitimate exceptions

Keep separate endpoints when **any** of:

1. **Different RBAC permissions** — `read` vs `bulk-read` may have different permission requirements
2. **Different rate limits** — bulk operations get a separate rate-limit bucket that single ops shouldn't share
3. **Different async semantics** — single returns synchronously; bulk returns a job ID for polling

When this applies, name explicitly: `POST /hosts:bulk-import` (action form, not `/hosts/bulk`).

### 3.3 Async bulk pattern

For bulk operations that fan out to background jobs:

```
POST /hosts:bulk-import     body: {csv: "..."}
→ 202 Accepted
→ body: {job_id: "uuid", status: "queued", _links: {self: "/jobs/{id}"}}

GET /jobs/{job_id}
→ 200 OK
→ body: {id, status, progress: {total, completed, failed}, result: {...}}
```

Polling is via `/jobs/{id}`, never via the original endpoint.

---

## Section 4 — Specialized resources over specialized endpoints

When you find yourself with many endpoints under one resource doing different things, consider whether the "things" are themselves resources.

### 4.1 Example: Scans

Today: `/scans/kensa`, `/scans/kensa/frameworks`, `/scans/kensa/health`, `/scans/kensa/rules/...`, `/scans/kensa/controls/...`, `/scans/kensa/sync-stats`, `/scans/kensa/sync` (12 endpoints).

Properly modeled:
- `POST /scans` — execute a scan (Kensa is the default and only engine; no `kensa/` prefix needed)
- `GET /rules` + `GET /rules/{rule_id}` — rule reference (already exists at `/api/rules/reference/`; consolidate)
- `GET /frameworks` + `GET /frameworks/{framework_id}` — framework metadata
- `GET /frameworks/{framework_id}/coverage` — coverage stats (sub-resource)
- `GET /frameworks/{framework_id}/rules` — rules in framework (sub-resource)
- `GET /controls/{framework_id}/{control_id}` — control resource
- `POST /admin/operations:sync-rules` — admin operation (different resource entirely)

12 endpoints → 7 endpoints across 4 well-defined resources.

### 4.2 Example: Discovery / Intelligence

Today: 15+ endpoints (`/{id}/discover-os`, `/{id}/os-info`, `/{id}/detect-platform`, `/{id}/system-info`, `/{id}/discovery/{basic,network,security,compliance}`, plus bulk variants, plus `/{id}/intelligence/{services,packages,users,audit,network,baseline}`).

Properly modeled:
- `GET /hosts/{host_id}/intelligence` — full snapshot (filter via `?include=services,packages,...`)
- `POST /hosts/{host_id}/intelligence:refresh` — trigger collection (sync flag for single, async for bulk)
- `GET /hosts/{host_id}/intelligence/status` — last collection state

15 endpoints → 3 endpoints. Same capability surface.

---

## Section 5 — Pagination

### 5.1 Cursor-based, never offset-based

Every list endpoint is cursor-paginated:

```
GET /hosts?limit=50&cursor=eyJpZCI6Ii4uLiJ9

→ 200 OK
{
  "items": [...],
  "next_cursor": "eyJpZCI6Ii4uLiJ9",  // null if no more
  "total_estimate": 1247,              // optional, may be omitted for cost
  "_links": {
    "next": "/hosts?limit=50&cursor=eyJpZCI6Ii4uLiJ9"
  }
}
```

**Why cursor:** offset pagination drifts under concurrent writes. The compliance surface has constant background updates (job queue writes transactions, scheduler updates host_compliance_schedule). Offset gives wrong results; cursor doesn't.

### 5.2 Cursor is opaque

Clients treat cursors as opaque strings. Server may encode `(last_id, last_sort_value)` or similar. Never document cursor internals.

### 5.3 Default limit, max limit

- Default `limit`: 50
- Max `limit`: 500 (returns 400 with `error.code = "pagination.limit_exceeded"` if higher)
- No way to say "give me everything" — clients must page

---

## Section 6 — Filtering, sorting, field selection

### 6.1 Filtering via query params

Simple equality and ranges as query params:

```
GET /hosts?status=active&os_family=rhel&created_after=2026-04-01
GET /scans?status=completed&host_id=abc-...&framework=cis-rhel9-v2.0.0
GET /alerts?severity=critical&status=active&since=2026-04-20T00:00:00Z
```

Multi-value filters use repeated keys (RFC-recommended) or comma-separated (pick one and document):

```
GET /hosts?os_family=rhel&os_family=ubuntu          # repeated keys
GET /hosts?os_family=rhel,ubuntu                    # comma-separated
```

**Choice for OpenWatch: comma-separated.** Easier to read, simpler to URL-encode in agent code. Document in spec.

### 6.2 Complex filters: structured query body

For queries beyond simple equality (Boolean combinations, full-text search, date arithmetic), use a `POST /resources:query` action with a structured body. Don't pretend GraphQL via overloaded query strings.

```
POST /transactions:query
body:
{
  "filter": {
    "and": [
      {"field": "status", "op": "in", "values": ["fail", "skip"]},
      {"field": "severity", "op": "in", "values": ["high", "critical"]},
      {"field": "applied_at", "op": "gte", "value": "2026-04-01T00:00:00Z"}
    ]
  },
  "sort": [{"field": "applied_at", "direction": "desc"}],
  "limit": 100
}
```

This is already prototyped in OpenWatch (`POST /api/transactions/query`) — extend the pattern.

### 6.3 Sort

Single param, comma-separated, `field:direction`:

```
GET /hosts?sort=hostname:asc
GET /hosts?sort=created_at:desc,hostname:asc
```

Default sort is documented per resource. Stability under concurrent writes is required (cursor pagination relies on it).

### 6.4 Field selection (sparse responses)

For agent efficiency, `?fields=id,hostname,status` returns only those fields.

```
GET /hosts?fields=id,hostname,compliance_score

→ 200 OK
{
  "items": [
    {"id": "...", "hostname": "...", "compliance_score": 87.4}
  ]
}
```

Default response includes a documented "default field set" — typically the most-used 80%, not everything.

### 6.5 Inclusion of related resources

For agent composition, `?include=` follows references:

```
GET /scans/{scan_id}?include=host,findings.rule

→ 200 OK
{
  "id": "...",
  "host_id": "...",
  "host": {"id": "...", "hostname": "...", ...},  // included
  "findings": [
    {"rule_id": "...", "rule": {"id": "...", "title": "...", ...}, ...}
  ]
}
```

`include` paths are documented per resource. Maximum depth: 2 levels. (Deeper nesting suggests a query-API endpoint instead.)

---

## Section 7 — Content negotiation

### 7.1 Output format via `Accept` header, not URL

```
GET /scans/{scan_id}/report
Accept: application/json     → JSON
Accept: text/html            → HTML
Accept: text/csv             → CSV
Accept: application/pdf      → PDF (only if implemented)

✗  GET /scans/{scan_id}/report/json
✗  GET /scans/{scan_id}/report/html
✗  GET /scans/{scan_id}/report/csv
```

Same for audit exports, posture exports, anything that has multiple representations.

### 7.2 Default representation

When no `Accept` header is sent, default to `application/json`. Never silently return HTML.

### 7.3 Supported formats are documented

Each endpoint that supports content negotiation lists supported media types in its OpenAPI `responses` section.

---

## Section 8 — Errors

### 8.1 The error envelope (locked in roadmap)

All error responses (4xx, 5xx) use the same shape:

```json
{
  "error": {
    "code": "host.unreachable",
    "fault": "external",
    "retryable": true,
    "human_message": "Host 1.2.3.4 did not respond on port 22 within 5 seconds.",
    "detail": {
      "host_id": "...",
      "address": "1.2.3.4",
      "timeout_seconds": 5
    },
    "correlation_id": "req-...-..."
  }
}
```

Fields:

- `code` — stable string, dotted hierarchy. Never changes meaning across versions. Examples: `auth.token_expired`, `host.unreachable`, `policy.version_mismatch`, `transition.invalid`, `pagination.limit_exceeded`, `idempotency.key_reused`. Sourced from the registry (§8.4).
- `fault` — who is at fault: `client` (caller's input/perms), `server` (our bug), `policy` (denied by policy/license/RBAC), `external` (downstream system — host SSH, plugin, OIDC IdP). Drives agent retry/abort logic.
- `retryable` — boolean. Tells agents whether the *same call* may succeed later without modification. False on validation/policy errors (caller must change something first).
- `human_message` — for UI/log display. May be localized later.
- `detail` — structured object with operation-specific context. When the registry defines a `detail_schema` for the code, the response MUST conform.
- `correlation_id` — same `X-Correlation-Id` returned in headers; included in body for log-grep.

> **Naming note (2026-04-29):** The `fault` field was previously named `category`, which collided with the registry's namespace grouping (`auth`, `host`, `scan`, ...). Renamed before any code shipped.

### 8.2 HTTP status alone is not enough

`409 Conflict` means many things in HTTP. The `error.code` disambiguates:

- `409` + `policy.version_mismatch` → caller used stale policy version
- `409` + `transition.invalid` → caller tried illegal state transition
- `409` + `idempotency.key_reused` → idempotency key collision

Agents key off `error.code`, never the HTTP status alone.

### 8.3 Error code naming convention

Dotted hierarchy: `<category>.<failure>`. Category is the namespace (defined in the registry's `categories` block). Failure is the kind of thing that went wrong.

```
auth.token_expired         host.unreachable           scan.already_running
auth.mfa_required          host.ssh_authentication_failed   scan.kensa_error
authz.permission_denied    host.duplicate             policy.version_mismatch
validation.field_required  pagination.limit_exceeded  transition.invalid
license.feature_unavailable  quota.max_hosts_exceeded   audit.query_invalid
rate_limit.exceeded        server.internal            server.timeout
```

See `api/error_codes.yaml` for the full registry.

### 8.4 The registry is the source of truth

All error codes live in `api/error_codes.yaml`. The registry is the **only** place a code is defined. Codegen produces:

- `internal/errors/codes.gen.go` — typed Go constants (e.g., `errors.HostUnreachable`) and a `Code -> metadata` map for runtime lookup of `http_status`, `fault`, `retryable`, and `detail_schema`.
- A reference document rendered into the OpenAPI bundle so consumers can see all codes in one place.

Build invariants enforced by `scripts/validate-error-codes.go` (run in CI):

- Every code matches `^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`.
- Every code's prefix references a defined `categories[].id`.
- `http_status` is a valid 4xx/5xx (or `402`/`503` for soft denials).
- `fault` is one of `client | server | policy | external`.
- `detail_schema` (when present) is valid JSON Schema.
- No duplicates between `errors` and `deprecated_errors`.

**Workflow for adding a new code:**

1. Add the entry to `api/error_codes.yaml` (PR review required).
2. Run codegen: `go generate ./internal/errors/...`.
3. Reference the generated constant from handler code: `errors.New(errors.HostUnreachable, "...")`.
4. CI fails the build if a handler emits a string literal that does not match a registry entry.

**Deprecation:** Move retired codes from `errors:` to `deprecated_errors:` (preserved for log/audit-history compatibility). Build fails if a deprecated code is emitted from new code.

**OpenAPI references:** Domain specs (e.g., `hosts.yaml`, `scans.yaml`) declare `4xx`/`5xx` responses with a `$ref` to the shared `ErrorEnvelope` schema. The list of *possible* codes per endpoint is surfaced via `x-possible-error-codes` (advisory; the registry remains authoritative).

---

## Section 9 — Idempotency

### 9.1 Required on POST, PUT, PATCH, DELETE

Every mutating endpoint accepts and respects `Idempotency-Key` header:

```
POST /scans
Idempotency-Key: 5f8e9a0b-...
body: {host_id: "...", template_id: "..."}

(replay the exact same request with the same key)
→ Returns the same response that the original call returned. Does not double-execute.
```

### 9.2 Storage and TTL

Idempotency keys + their result envelopes are stored for **24 hours**. Replays within that window return cached results. Replays after that window are treated as new requests.

### 9.3 Key collision

If two requests have the same `Idempotency-Key` but different bodies, return `409` with `error.code = "idempotency.key_reused"`. Caller used the same key for a different operation — they need a new key.

### 9.4 GET is naturally idempotent

`GET` and `HEAD` don't accept idempotency keys. They're already safe to retry by definition.

---

## Section 10 — Correlation and tracing

### 10.1 X-Correlation-Id end-to-end

Every request:

1. Server checks for `X-Correlation-Id` header. If present, use it. If absent, generate a UUID.
2. Correlation ID is added to `context.Context` and propagated through all downstream calls (DB, Kensa, webhook delivery).
3. Logged on every line of the request lifecycle.
4. Returned in response headers: `X-Correlation-Id: req-<uuid>`.
5. Recorded in audit log entry for any mutating operation.
6. Included in error envelope `error.correlation_id`.

### 10.2 Format

`req-<uuid-v4>` for server-generated. Caller-provided values are accepted as-is (don't validate format aggressively — agents may use their own conventions).

---

## Section 11 — Auth (transport)

### 11.1 Auth mechanisms

- `Authorization: Bearer <jwt>` — user JWT
- `Authorization: Bearer owk_<api-key>` — API key (prefix-distinguished)
- mTLS — for ORSA plugin / agent-to-OpenWatch (deferred to Phase 1+)

### 11.2 Anonymous endpoints are explicit

The OpenAPI spec marks anonymous endpoints with `security: []`. Anything not marked requires auth. Default-secure.

### 11.3 RBAC requirements in spec

Every endpoint declares its required permission via `x-required-permission`:

```yaml
/hosts:
  get:
    x-required-permission: host:read
  post:
    x-required-permission: host:write

/hosts/{host_id}:
  delete:
    x-required-permission: host:delete       # registry has dangerous: true
    x-audit-events: [host.deleted]            # MUST be non-empty for dangerous

# Multi-permission (rare; most endpoints use the single form above):
/some/endpoint:
  get:
    x-required-permission:
      any_of: [host:read, host:write]
```

The values are **registry-validated** against `auth/permissions.yaml`. The build fails if a spec references an unknown permission. See `docs/engineering/rbac_registry.md` for the full registry model and the registry-first workflow for adding permissions.

`oapi-codegen` generates middleware that enforces these from the spec. No hand-written `@require_permission()` decorators in handler code.

> **Naming note (2026-04-30):** values are lowercase `resource:action` (e.g., `host:read`), not `HOST_READ`. The earlier all-caps form predates the registry; only the registry-validated form is accepted. Drift is a build error.

### 11.4 License feature gating in spec

Every endpoint that requires an OpenWatch+ license feature declares it via `x-required-feature`:

```yaml
/compliance/audit/queries:execute:
  post:
    x-required-permission: audit:read
    x-required-feature: audit_query
```

The feature ID must exist in `licensing/features.yaml`. The build fails if a spec references an unknown feature ID. See `docs/engineering/licensing_foundation.md` for the full feature gating model.

**Cross-validation with the RBAC registry:** if the permission has `license_gated: X` in `permissions.yaml`, the operation MUST declare `x-required-feature: X` (or omit the permission entirely). Mismatch — declaring a license-gated permission without the matching feature, or vice versa — fails the build. This prevents the failure mode where the permission says "license needed" but the operation forgets to declare it.

When both `x-required-permission` and `x-required-feature` are declared, **both** must pass for the request to reach the handler. The combined middleware (per `docs/engineering/rbac_registry.md` §6) checks RBAC first (denial → `403`), then license (denial → `402`). One middleware, one denial path, one audit event.

### 11.5 Audit events declared in spec

Every mutating endpoint (POST/PUT/PATCH/DELETE) declares the audit events it may emit via `x-audit-events`:

```yaml
/hosts:
  post:
    x-required-permission: HOST_WRITE
    x-audit-events: [host.created]
```

The build verifies:
- All declared codes exist in `audit/events.yaml`
- Every mutating endpoint declares at least one audit event

`x-audit-events` is documentation, not codegen — it does not generate the emission. Handlers explicitly call `audit.Emit(ctx, audit.HostCreated, ...)` using typed constants. The spec declaration is the contract that the handler must honor.

See `docs/engineering/audit_event_taxonomy.md` for the full taxonomy, redaction discipline, and emission patterns.

---

## Section 12 — Health, capabilities, and admin

### 12.1 One health, one capabilities, one analytics root

```
GET /health                              # current health, optional ?component=
GET /health/history                      # timeline, optional ?component=, ?since=
GET /capabilities                        # what this server supports, optional ?component=
GET /analytics/{domain}                  # rolled-up stats per domain
```

No more `/scanner/health`, `/health/integrations`, `/health/service`, `/health/content`, `/system/capabilities`, `/discovery/network/capabilities`, etc. Component filter absorbs all of them.

### 12.2 Admin operations are operations, not endpoints

Long-running or system-wide actions (sync rules, enforce retention, backfill state) are `POST /admin/operations:<name>` returning a job ID:

```
POST /admin/operations:sync-rules
→ 202 Accepted
→ body: {job_id: "...", status: "queued"}
```

Track via `GET /jobs/{job_id}`. Don't expose them as one-off endpoints.

---

## Section 13 — Sub-resources, not flattened paths

When a relationship exists, use sub-resource paths:

```
✓  GET /hosts/{host_id}/transactions          # transactions for a host
✓  GET /hosts/{host_id}/findings              # findings for a host
✓  GET /scans/{scan_id}/findings              # findings for a scan
✓  GET /host-groups/{group_id}/hosts          # hosts in a group
✓  GET /webhooks/{webhook_id}/deliveries      # deliveries for a webhook

✗  GET /transactions?host_id=...              # works but less discoverable
✗  GET /scan-findings?scan_id=...             # awkward
```

The `?host_id=` filter form is also acceptable for cross-cutting queries (e.g., "all findings for this host across all scans"). Both patterns can coexist when each is more natural in its context.

**Rule of thumb:** if the relationship is "one-to-many and the parent owns the children", use sub-resource. If the children exist independently and you're querying across parents, use filter.

---

## Section 14 — Versioning

### 14.1 Version in URL: `/api/v1/...`

Major version in the URL path. `/api/v1/hosts`, `/api/v2/hosts`, etc.

### 14.2 What forces a v2

- Removing a field from a default response
- Changing the meaning of an existing field
- Removing an endpoint
- Changing required parameters

What does NOT force a v2:

- Adding a new field (clients must ignore unknown fields)
- Adding a new endpoint
- Adding a new optional parameter
- Adding a new error code (registered in `error_codes.yaml`)
- Adding a new value to an enum (clients must handle unknown enum values gracefully)

### 14.3 OpenAPI is the version source of truth

`info.version` in `openapi.yaml` is the API version. Changes to it follow semver. Major bumps require a separate spec file (e.g., `api/openapi-v2.yaml`).

---

## Section 15 — Deprecation

Endpoints being removed are marked `deprecated: true` in the spec for one minor version, then removed in the next major version.

```yaml
/old-endpoint:
  get:
    deprecated: true
    description: |
      Deprecated since v1.4.0. Use `/new-endpoint` instead.
      Removed in v2.0.0.
```

Deprecated endpoints return a `Deprecation` header (RFC 8594) with a sunset date.

---

## Section 16 — Specter and OpenAPI

OpenAPI describes **HTTP contracts** — request/response shapes, status codes, error structures.

Specter describes **behavioral contracts** — what guarantees the system makes (postconditions, invariants, side effects).

Both are checked into git. Both are agent-readable. They reference each other but don't overlap.

Example:

- OpenAPI for `POST /scans/{scan_id}:cancel`: defines the request, response, error codes, idempotency key handling
- Specter spec for the same operation: defines what state changes happen (scan goes to `cancelled`), what audit events emit, what guarantees about in-flight Kensa subprocess termination

---

## Section 17 — The "don't collapse" exceptions

Sometimes preserving two endpoints is correct, even if they look similar. Three legitimate reasons:

1. **Different RBAC permissions.** `GET /audit/events` (any auditor) and `POST /audit/log` (requires `AUDIT_WRITE`) — different verbs, different permissions, different endpoints. Correct.

2. **Different rate limits.** Bulk operations may need a separate rate-limit bucket from single ops. Document the bucket in the spec via `x-rate-limit-bucket`.

3. **Different async semantics.** Sync single-host operation (returns result) vs bulk fan-out (returns job ID, poll for status) are genuinely different contracts. One endpoint with conditional response shape is worse, not better.

**Rule:** collapse unless one of the three applies. When you don't collapse, document the reason in `description`.

---

## Section 18 — Reviewing a draft endpoint

Checklist for any new or modified endpoint:

- [ ] Path uses kebab-case nouns, plural?
- [ ] HTTP method matches the canonical operation?
- [ ] If status change, is it PATCH-with-status (default) or `:action` (with reason documented)?
- [ ] If RPC-style verb, is one of the §17 exceptions documented?
- [ ] List endpoints have cursor pagination, filters, sort, fields, include?
- [ ] Mutating endpoints accept `Idempotency-Key`?
- [ ] Error responses use the canonical error envelope?
- [ ] All error codes registered in `error_codes.yaml`?
- [ ] `X-Correlation-Id` propagation documented?
- [ ] `x-required-permission` declared?
- [ ] `x-state-machine` declared (if stateful resource)?
- [ ] Content negotiation via `Accept`, not URL suffix?
- [ ] Sub-resource pattern used for parent-child relationships?

If any item is "no, because...", document the because in the spec.

---

## Section 19 — Anti-pattern catalog

Patterns that should never appear in `openapi.yaml`:

| Anti-pattern | Why bad |
|---|---|
| `/createFoo`, `/updateFoo`, `/deleteFoo` | Verbs in URL; HTTP methods exist |
| `POST /foo/{id}/acknowledge` (when not a true side effect) | Status change should be PATCH |
| `GET /foo/{id}/report/json`, `/report/html`, `/report/csv` | Use `Accept` header |
| `POST /foo/bulk` and `POST /foo` doing the same thing | Collapse to one |
| `?page=3&per_page=50` | Offset pagination drifts under concurrent writes |
| `GET /scanner/health`, `GET /worker/health`, `GET /db/health` | Use `GET /health?component=...` |
| `POST /foo/{id}/start`, `POST /foo/{id}/stop`, `POST /foo/{id}/cancel` | Status transitions; PATCH with target status |
| Returning 200 OK with `{success: false, error: "..."}` | Use proper HTTP status + error envelope |
| Different endpoints for "with details" vs "without details" | Use `?fields=` or `?include=` |
| Endpoints whose only difference is auth requirement | Different auth on the same endpoint is fine via spec |

---

## Section 20 — Living document

This file is updated when a real case forces a clarification. Updates are dated:

- 2026-04-27 — Initial version. Locked baseline rules.

When a rule is added or changed, every existing OpenAPI domain spec must be re-checked for compliance. The principles document leads; the spec follows.
