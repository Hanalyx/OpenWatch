# Audit Event Taxonomy Foundation

> **Status:** Locked design 2026-04-29
> **Authority:** This document is the architectural foundation for audit events in the Go rebuild. Implementation in Stage 0 must conform.
> **Why now:** Audit events are referenced from licensing (6 events already), authentication, host management, scans, compliance, system lifecycle, and remediation. Without a stable taxonomy, every component invents its own naming. Drift starts on day one.

---

## 1. Why audit events are foundation

Audit events cross every seam:

- **Compliance posture** — audit log is a regulated artifact (NIST 800-53 AU-2 / AU-3, ISO 27001 A.12.4)
- **Agent orchestration** — agents verify operation effects via audit log, not back-channel
- **Forensics** — incident response queries the audit log
- **Operator visibility** — operators investigate "what happened?" through audit
- **Compliance reporting** — audit events support attestation
- **Audit-as-API** — first-class queryable resource per agent-first §1

Today's Python codebase has **two competing audit implementations**: file-based (`SecurityAuditLogger`) and DB-based (`audit_db.py`). Static analysis flagged this as a duplication to consolidate. The rebuild commits to **DB-based as the canonical path** — and gets the taxonomy right from day one.

If audit events are added ad-hoc per-component, three things break:

1. **Drift.** `auth.success` vs `auth.login_success` vs `login.successful` — same event, three names. Agents and queries need to handle all three forever.
2. **Untyped detail blobs.** Every event has different fields in `detail`; aggregation is impossible.
3. **Hidden-secret leaks.** Without a redaction discipline, passwords / tokens / SSH keys end up in logs.

Doing it once, properly, in Stage 0 Day 5 is roughly half a day. Retrofitting it later costs 1–2 weeks plus the bugs from inconsistent past data.

---

## 2. Core requirements

### 2.1 Functional

1. **Stable, registered taxonomy** — every event type has a stable string code, defined in a single registry
2. **Structured envelope** — every event has the same top-level shape; only `detail` varies
3. **Type-safe emission** — emitting an event uses generated Go code, not raw strings
4. **Queryable API** — events are queryable via REST (filters, pagination, time range, structured search)
5. **Correlation** — every event ties to a request, session, and (where applicable) parent event
6. **Redaction** — sensitive fields are explicitly scrubbed before write
7. **Performance** — emission is async; never blocks the request path
8. **Tamper-evidence** — events are append-only with optional signature chain

### 2.2 Non-functional

1. **Schema stability** — event codes never rename; new ones add without breaking old queries
2. **Cardinality bounded** — taxonomy stays at ~100 event types, not 1000
3. **Compliance-aligned** — meets NIST 800-53 AU-3 (Content of Audit Records) and ISO 27001 A.12.4
4. **Storage efficient** — JSONB detail with GIN index; bulk-insertable
5. **Always emit, never crash** — audit failures degrade gracefully (log error, continue)

---

## 3. Event envelope (canonical schema)

Every audit event has this shape. Only `detail` varies per event type.

```json
{
  "id": "uuid-v7",
  "occurred_at": "2026-04-29T14:32:01.123Z",
  "recorded_at": "2026-04-29T14:32:01.156Z",
  "action": "auth.login.success",
  "severity": "info",
  "outcome": "success",

  "actor": {
    "type": "user",
    "id": "uuid",
    "label": "alice@example.com",
    "ip_address": "10.0.0.42",
    "user_agent": "openwatch/1.0.0",
    "session_id": "uuid"
  },

  "resource": {
    "type": "host",
    "id": "uuid",
    "label": "web-prod-01.example.com"
  },

  "correlation_id": "req-018f3c5d-...",
  "parent_event_id": "uuid-of-causally-prior-event",

  "policy_version": "exception-policy-v1.2.0",

  "detail": {
    "auth_method": "password",
    "mfa_used": true
  },

  "redactions": ["password_hash"],
  "signature": "ed25519-sig-of-canonical-form"
}
```

### 3.1 Field semantics

| Field | Required | Notes |
|---|---|---|
| `id` | yes | UUIDv7 — sortable by time, globally unique |
| `occurred_at` | yes | When the event actually happened (operation timestamp) |
| `recorded_at` | yes | When we wrote it. Always ≥ `occurred_at`. Lag = how far behind the writer is. |
| `action` | yes | Stable code from registry. Dotted hierarchy. |
| `severity` | yes | `info` / `warning` / `error` / `critical` |
| `outcome` | yes | `success` / `failure` / `denied` |
| `actor` | yes | Who/what did this. `type` ∈ `{user, api_key, agent, system, scheduler}`. |
| `actor.id` | mostly | Required for `user` and `api_key`; `system`/`scheduler` may omit |
| `actor.label` | yes | Human-readable identifier (username, key name, "scheduler", etc.) |
| `actor.ip_address` | when known | IP from request; null for `system`/`scheduler` |
| `actor.user_agent` | when known | UA from request |
| `actor.session_id` | when applicable | Session UUID |
| `resource` | mostly | What was acted on. Omit only for events with no resource (e.g., `system.startup`). |
| `correlation_id` | yes | Request correlation ID from middleware |
| `parent_event_id` | optional | Causally prior event (e.g., scan.completed parent for findings) |
| `policy_version` | when applicable | Which policy version applied (per agent-first principle 2) |
| `detail` | optional | Per-action structured fields. Schema documented per event in registry. |
| `redactions` | when applicable | Field names that were scrubbed before storage (`["password", "ssh_key"]`) |
| `signature` | optional | Ed25519 signature of canonical form (for tamper-evidence; high-assurance deployments) |

### 3.2 Why UUIDv7

- Time-sortable by primary key (no need for `(occurred_at, id)` composite index for ordering)
- Globally unique without coordination
- Natural fit for cursor pagination (UUIDv7 IS the cursor)
- Replaces "UUID + timestamp" patterns with one field

---

## 4. Taxonomy registry

The registry is the source of truth. Lives at `app/audit/events.yaml`. Format:

```yaml
# app/audit/events.yaml
version: 1

categories:
  - id: auth
    description: Authentication and session lifecycle
  - id: authz
    description: Authorization decisions and RBAC
  - id: host
    description: Host management and discovery
  - id: scan
    description: Scan execution and lifecycle
  - id: compliance
    description: Compliance state, exceptions, baselines, drift
  - id: alert
    description: Alert generation and lifecycle
  - id: notification
    description: Notification dispatch and delivery
  - id: license
    description: License install, expiry, feature gating
  - id: policy
    description: Policy load, validation, application (Principle 2)
  - id: remediation
    description: Remediation requests and execution
  - id: integration
    description: External system integration (Jira, webhooks, plugins)
  - id: system
    description: Service lifecycle and configuration
  - id: admin
    description: Administrative operations

events:
  # ----- auth -----
  - code: auth.login.success
    severity: info
    description: User authenticated successfully
    actor_types: [user]
    detail_schema:
      auth_method: {type: string, enum: [password, sso, api_key]}
      mfa_used: {type: boolean}

  - code: auth.login.failure
    severity: warning
    description: Authentication attempt failed
    actor_types: [user]
    detail_schema:
      reason: {type: string, enum: [invalid_credentials, account_locked, mfa_required, mfa_failed]}
      auth_method: {type: string}

  - code: auth.logout
    severity: info
    description: User explicitly logged out
    actor_types: [user]

  - code: auth.token.refreshed
    severity: info
    description: Refresh token used to issue new access token
    actor_types: [user, api_key]

  - code: auth.token.revoked
    severity: warning
    description: Token added to revocation blacklist
    actor_types: [user, system]
    detail_schema:
      reason: {type: string, enum: [user_logout, admin_revoke, suspicious_activity, token_rotation]}

  - code: auth.mfa.enrolled
    severity: info
    description: User completed MFA enrollment
    detail_schema:
      method: {type: string, enum: [totp, fido2]}

  - code: auth.mfa.validated
    severity: info
    description: MFA challenge passed during login

  - code: auth.mfa.failed
    severity: warning
    description: MFA challenge failed

  - code: auth.session.expired
    severity: info
    description: Session timed out (idle or absolute)

  - code: auth.api_key.created
    severity: info
    description: API key issued

  - code: auth.api_key.revoked
    severity: warning
    description: API key invalidated

  # ----- authz -----
  - code: authz.permission.denied
    severity: warning
    description: RBAC denied an authenticated request
    detail_schema:
      required_permission: {type: string}
      route: {type: string}

  - code: authz.role.assigned
    severity: info
    description: Role assigned to user

  - code: authz.role.removed
    severity: warning
    description: Role removed from user

  # ----- host -----
  - code: host.created
    severity: info

  - code: host.updated
    severity: info

  - code: host.deleted
    severity: warning

  - code: host.connectivity.checked
    severity: info
    detail_schema:
      ping_success: {type: boolean}
      ssh_accessible: {type: boolean}
      response_time_ms: {type: integer}

  - code: host.platform.detected
    severity: info
    detail_schema:
      os_family: {type: string}
      os_version: {type: string}

  # ----- scan -----
  - code: scan.queued
    severity: info
    detail_schema:
      framework: {type: string}
      template_id: {type: [string, 'null']}

  - code: scan.started
    severity: info

  - code: scan.completed
    severity: info
    detail_schema:
      compliance_score: {type: number}
      passed: {type: integer}
      failed: {type: integer}

  - code: scan.failed
    severity: error
    detail_schema:
      error_code: {type: string}
      error_message: {type: string}

  - code: scan.cancelled
    severity: warning
    detail_schema:
      cancellation_reason: {type: string}

  - code: scan.session.created
    severity: info
    detail_schema:
      total_hosts: {type: integer}

  # ----- compliance -----
  - code: compliance.state.changed
    severity: info
    description: Rule state transition (write-on-change)
    detail_schema:
      rule_id: {type: string}
      previous_status: {type: string}
      new_status: {type: string}

  - code: compliance.exception.requested
    severity: info

  - code: compliance.exception.approved
    severity: warning

  - code: compliance.exception.rejected
    severity: info

  - code: compliance.exception.revoked
    severity: warning

  - code: compliance.exception.expired
    severity: info

  - code: compliance.baseline.established
    severity: info

  - code: compliance.baseline.cleared
    severity: warning

  - code: compliance.drift.detected
    severity: warning
    detail_schema:
      drift_type: {type: string, enum: [major, minor, improvement]}
      score_delta: {type: number}

  - code: compliance.snapshot.created
    severity: info

  # ----- alert -----
  - code: alert.created
    severity: info
    detail_schema:
      alert_type: {type: string}
      alert_severity: {type: string}

  - code: alert.acknowledged
    severity: info

  - code: alert.resolved
    severity: info

  # ----- notification -----
  - code: notification.dispatched
    severity: info
    detail_schema:
      channel_type: {type: string, enum: [slack, email, webhook, jira, pagerduty]}
      delivery_id: {type: string}

  - code: notification.delivery.failed
    severity: error

  - code: notification.delivery.succeeded
    severity: info

  # ----- license -----
  - code: license.installed
    severity: info

  - code: license.invalid
    severity: error

  - code: license.expiring_soon
    severity: warning

  - code: license.expired
    severity: error

  - code: license.feature_check_denied
    severity: warning
    detail_schema:
      feature: {type: string}
      suppressed_count: {type: integer, description: Events deduped within 1-min window}

  - code: license.quota_exceeded
    severity: warning
    detail_schema:
      quota: {type: string}
      limit: {type: integer}
      current: {type: integer}

  - code: license.clock_rollback_detected
    severity: critical

  - code: license.tampered
    severity: critical

  # ----- policy (Principle 2) -----
  - code: policy.loaded
    severity: info
    detail_schema:
      policy_type: {type: string}
      policy_version: {type: string}

  - code: policy.invalid
    severity: error

  - code: policy.applied
    severity: info
    description: Operation evaluated against a versioned policy
    detail_schema:
      policy_type: {type: string}
      policy_version: {type: string}
      decision: {type: string, enum: [allow, deny, defer]}

  # ----- remediation -----
  - code: remediation.requested
    severity: info

  - code: remediation.approved
    severity: warning

  - code: remediation.executed
    severity: warning
    detail_schema:
      dry_run: {type: boolean}
      steps_succeeded: {type: integer}
      steps_failed: {type: integer}

  - code: remediation.rolled_back
    severity: warning

  # ----- integration -----
  - code: integration.webhook.delivered
    severity: info

  - code: integration.webhook.failed
    severity: error

  - code: integration.plugin.installed
    severity: info

  - code: integration.plugin.executed
    severity: info

  # ----- system -----
  - code: system.startup
    severity: info
    actor_types: [system]

  - code: system.shutdown
    severity: info
    actor_types: [system]

  - code: system.config.changed
    severity: warning
    detail_schema:
      config_key: {type: string}

  - code: system.migration.applied
    severity: info
    detail_schema:
      migration_id: {type: string}

  - code: system.health.degraded
    severity: error
    detail_schema:
      component: {type: string}

  # ----- admin -----
  - code: admin.user.created
    severity: warning

  - code: admin.user.deleted
    severity: warning

  - code: admin.role.changed
    severity: warning

  - code: admin.system_setting.changed
    severity: warning

  - code: admin.retention_policy.changed
    severity: warning

# Deprecated codes kept for backward-compatible reads:
deprecated_events:
  - code: auth.login_attempt
    deprecated_in: "1.0.0"
    replaced_by: [auth.login.success, auth.login.failure]
```

**Initial registry: ~70 event codes** across 13 categories. This is the cap target — if it grows past ~150, the taxonomy is becoming a free-form bag rather than a controlled vocabulary.

### 4.1 Naming convention rules

1. **Lowercase, dotted hierarchy.** `domain.resource.action` (3 levels) or `domain.action` (2 levels).
2. **Action verbs are past-tense indicative.** `created`, `failed`, `denied`, `expired` — never `create`, `fail`, `denying`.
3. **Outcomes are in the field, not the name.** `auth.login.success` and `auth.login.failure` differ by outcome — but since they have meaningfully different `detail` schemas, they get separate codes. This is the exception that proves the rule: split when schemas diverge, merge when they don't.
4. **Resource names match API path nouns.** If the API has `/host-groups`, the audit code is `host_group.created`, not `hostgroup.created`. (Underscore replaces hyphen since dots are reserved for hierarchy.)
5. **Never rename.** Removing requires deprecation; renaming is forbidden. Add a new code, deprecate the old.

### 4.2 Adding a new event code

PR adds a row to `app/audit/events.yaml`. The build verifies:

- Code matches `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,2}$`
- Category exists
- `detail_schema` (if present) is valid JSON Schema
- Code is not in `deprecated_events`

Codegen produces a typed constant in `internal/audit/events.gen.go`:

```go
package audit

// AUTO-GENERATED — DO NOT EDIT

const (
    AuthLoginSuccess  EventCode = "auth.login.success"
    AuthLoginFailure  EventCode = "auth.login.failure"
    HostCreated       EventCode = "host.created"
    // ...
)
```

Emitting code uses these constants:

```go
audit.Emit(ctx, audit.AuthLoginSuccess, audit.Event{
    Outcome: audit.Success,
    Actor: audit.ActorFromContext(ctx),
    Detail: map[string]any{"auth_method": "password", "mfa_used": true},
})
```

**Drift becomes a compile error** — you can't emit `audit.AuthLoginSucessful` because the constant doesn't exist.

---

## 5. Architecture

### 5.1 Package layout (as built)

```
internal/audit/
├── types.go            # Event, Actor, Resource enums + Code type
├── events.gen.go       # Generated from app/audit/events.yaml (Code constants + Meta)
├── emit.go             # Public Emit() + EmitSync() API
├── writer.go           # Async batched writer (channel + goroutine + flush ticker)
├── redact.go           # Redaction helpers
├── store.go            # PostgreSQL persistence (sqlc-generated Store)
└── emit_test.go, redact_test.go
```

Deferred (not yet implemented in Stage 0):
- `registry.go` — runtime YAML validation; codegen output is the registry today
- `signer.go` — Ed25519 per-event signing (Phase 2+)
- `query.go` — split out from the server handler when query API grows beyond a single endpoint

### 5.2 Emission API (as built)

Two functions, one shape — no typed-helper subpackages yet.

**Async `Emit`** (default; non-blocking, dropped on overflow):

```go
audit.Emit(ctx, audit.AuthLoginSuccess, audit.Event{
    ActorType: "user",
    ActorID:   user.ID,
    Detail:    map[string]any{"method": "password", "mfa_used": mfaUsed},
})
```

**Sync `EmitSync`** (returns error; reserved for events that must be
durable before the request returns):

```go
if err := audit.EmitSync(ctx, audit.SystemStartup, audit.Event{
    ActorType: "system",
    Detail:    map[string]any{"version": cfg.Version},
}); err != nil {
    return fmt.Errorf("startup audit: %w", err)
}
```

Both fill in `ID` (UUIDv7), `OccurredAt`, and `CorrelationID` (from ctx)
before persistence. Per-event-code typed wrappers (the `audit.Auth.LoginSuccess`
shape from earlier drafts) are deferred — the generic shape covers all
current callers and avoids registry duplication.

### 5.3 Async batching

Emission is non-blocking:

```go
// emit.go
func Emit(ctx context.Context, code EventCode, e Event) {
    e.populate(ctx, code)              // fill correlation_id, recorded_at, etc.
    select {
    case eventChan <- e:               // buffered channel, default 10000
    default:
        droppedCounter.Inc()           // back-pressure: log + count drops
        // Critical events (severity=critical) bypass back-pressure
        if e.Severity == Critical {
            blockingWrite(e)           // sync write; rare path
        }
    }
}
```

A dedicated writer goroutine consumes `eventChan` and batches:
- Up to 100 events per `INSERT`
- Or every 100ms, whichever first
- Single transaction per batch

**Failure mode:** if the DB write fails, log to stderr (visible in `journalctl`) and increment a `audit_write_failures` Prometheus counter. **Never fail the originating request.** Audit failures are operational concerns, not request-blocking. Compliance is the platform's value; an audit log full disk should not deny scans.

### 5.4 Critical-event sync option

Some events are too important to drop:

- `system.startup`, `system.shutdown`
- `license.installed`, `license.tampered`, `license.clock_rollback_detected`
- `auth.token.revoked` with `reason=admin_revoke`
- `compliance.exception.approved`

For these, `audit.EmitSync(ctx, code, event)` writes synchronously and returns the error. Caller can decide whether to retry. Maximum ~5 events per minute use this path; the 95% case stays async.

---

## 6. Storage

### 6.1 `audit_events` table

```sql
CREATE TABLE audit_events (
    id                UUID PRIMARY KEY,           -- UUIDv7
    occurred_at       TIMESTAMPTZ NOT NULL,
    recorded_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    action            TEXT NOT NULL,
    severity          TEXT NOT NULL DEFAULT 'info',
    outcome           TEXT NOT NULL,

    actor_type        TEXT NOT NULL,              -- user/api_key/agent/system/scheduler
    actor_id          TEXT,
    actor_label       TEXT,
    actor_ip          INET,
    actor_user_agent  TEXT,
    actor_session_id  UUID,

    resource_type     TEXT,
    resource_id       TEXT,
    resource_label    TEXT,

    correlation_id    TEXT NOT NULL,
    parent_event_id   UUID REFERENCES audit_events(id),

    policy_version    TEXT,
    detail            JSONB,
    redactions        TEXT[],
    signature         TEXT
);
```

### 6.2 Indexes

```sql
-- Time-ordered scan
CREATE INDEX idx_audit_occurred ON audit_events (occurred_at DESC);

-- Per-actor history
CREATE INDEX idx_audit_actor ON audit_events (actor_id, occurred_at DESC) WHERE actor_id IS NOT NULL;

-- Per-action queries
CREATE INDEX idx_audit_action ON audit_events (action, occurred_at DESC);

-- Per-resource history
CREATE INDEX idx_audit_resource ON audit_events (resource_type, resource_id, occurred_at DESC) WHERE resource_id IS NOT NULL;

-- Correlation ID grouping
CREATE INDEX idx_audit_correlation ON audit_events (correlation_id);

-- Severity filters (for "show me errors/criticals")
CREATE INDEX idx_audit_severity ON audit_events (severity, occurred_at DESC) WHERE severity IN ('error', 'critical');

-- Detail JSON search
CREATE INDEX idx_audit_detail_gin ON audit_events USING GIN (detail);

-- Action-prefix search (e.g., 'license.*')
-- Use action LIKE 'license.%' which uses idx_audit_action btree.
```

### 6.3 Partitioning (deferred to Phase 1+)

For deployments with >100M events/year, partition by month:

```sql
-- Phase 1+ migration
CREATE TABLE audit_events PARTITION OF ...
PARTITION BY RANGE (occurred_at);
```

Stage 0 ships unpartitioned; the migration is non-breaking.

### 6.4 Retention

Driven by `retention_policies` table (already in MUST). Defaults:

- Standard events: 365 days
- High-severity (error/critical): 730 days
- Compliance-required events (auth, authz, license, admin): 2555 days (7 years; many regulatory baselines)

Retention enforcement is a daily cron job (`enforce_retention` task) that runs `DELETE` in batches.

**Pre-deletion archive (planned, MAYBE):** sign + bundle events about to be deleted into `audit_archive_<period>.tar.gz.sig` for offline retention.

---

## 7. Query API

The `audit.yaml` OpenAPI spec covers the queryable surface. Headline endpoints:

- `GET /audit/events` — list with filters, cursor pagination, sort *(Stage 0)*
- `GET /audit/events/{event_id}` — single event *(deferred to Phase 1)*
- `POST /audit/events:query` — complex queries via DSL (see scans.yaml `:query` precedent) *(deferred to Phase 1)*
- `GET /audit/events:export` — CSV/JSON/PDF (gated on `audit_export` feature) *(deferred to Phase 1)*
- `GET /audit/events:taxonomy` — read the registry (for UI rendering of filters) *(deferred to Phase 1; the registry is embedded in `events.gen.go` and can be exposed when the frontend needs it)*

**As-built in Stage 0:** only `GET /audit/events` is wired. The other endpoints are
declared in `api/audit.yaml` for contract design but have no handler yet.

Filters include `action` (with prefix support), `actor_id`, `resource_id/type`, `correlation_id`, `severity`, `outcome`, time range.

**Per-resource convenience endpoints** in domain specs include:

- `GET /hosts/{host_id}/audit-events`
- `GET /scans/{scan_id}/audit-events`
- `GET /users/{user_id}/audit-events`

These are sugar over `GET /audit/events?resource_type=host&resource_id=...`. Same backing query.

---

## 8. Redaction discipline

### 8.1 Forbidden in audit `detail`

These fields **must never** be in `detail`. Period.

- Passwords (any form — plaintext, hashed, base64'd, anything)
- API key secret values (the `owk_<key>` part after the prefix)
- SSH private keys
- License JWTs (the raw signed token)
- TLS private keys
- MFA TOTP secrets
- Session tokens (JWTs)
- OAuth client secrets
- SAML signing keys

If any of these appear in `detail`, the redactor pre-write replaces them with `"<REDACTED>"` and adds the field name to the `redactions` array.

### 8.2 Redaction helpers

```go
// Redact removes/replaces sensitive fields before audit write.
func (e *Event) Redact() *Event {
    for _, k := range []string{"password", "ssh_key", "api_key", "token", "secret", "license_jwt"} {
        if _, ok := e.Detail[k]; ok {
            e.Detail[k] = "<REDACTED>"
            e.Redactions = append(e.Redactions, k)
        }
    }
    return e
}
```

### 8.3 Allowed (with caveats)

- IP addresses — yes; network metadata is auditable
- Hostnames — yes
- Usernames — yes; but only the username, never password attempts
- Email addresses — yes; PII concerns handled at retention level, not at write time
- Resource IDs (UUIDs) — yes
- Timestamps — yes
- Status codes — yes
- Configuration keys (not values) — yes; e.g., `config.changed { config_key: "session_timeout" }` but not the new value if it's sensitive

### 8.4 PII handling

For deployments with PII concerns (GDPR, HIPAA), an additional retention policy can pseudonymize old events:

```sql
UPDATE audit_events SET actor_label = 'user-' || md5(actor_id), actor_ip = NULL
WHERE occurred_at < NOW() - INTERVAL '180 days';
```

This is opt-in per-deployment. Off by default.

---

## 9. Tamper-evidence (optional, for high-assurance deployments)

### 9.1 Per-event Ed25519 signature

Each event can carry a signature over its canonical JSON form, signed by an audit-specific Ed25519 key. Verify at read time on demand.

The signing key is held by the running service (not embedded in binary). On rotation, old events keep their old signature; new events get the new key.

### 9.2 Hash chain (deferred)

Inspired by Certificate Transparency. Each event's record includes the hash of the previous event's full record. Daily, the latest hash is published to a separate audit log destination (or signed and exposed via API).

This is **deferred to Phase 1+**. Not needed for Stage 0 walking skeleton; designed in so the schema accommodates `parent_hash` field if added later.

### 9.3 Honest framing

Tamper-evidence is best-effort. A determined attacker with database root access can rewrite any log. The point of these mechanisms is to:

- **Catch accidents** (e.g., wrong query in a maintenance script)
- **Raise the cost** of evidence tampering
- **Detect tampering after the fact** (compromise indicators)
- **Support compliance attestations** that require log integrity

It is not — and cannot be — proof against every adversary.

---

## 10. Performance and capacity

### 10.1 Sizing

Estimated rates per active deployment:

- Compliance scanning of 1000 hosts every hour: ~50K `compliance.state.changed` events/hour, but only when state actually changes (write-on-change). Realistic steady-state: ~5K/hour.
- Auth events (logins, refreshes, sessions): ~200/hour for a typical operator team.
- Scan events: ~20K/day for a 1000-host fleet.
- Misc (notification, alert, license, system): ~500/day baseline.

**Steady state: ~10K events/day for a small fleet, ~500K events/day for a large fleet.** At 365-day retention, the table is 3.6M to 180M rows. PostgreSQL handles this comfortably with the planned indexes.

### 10.2 Emission performance

- Async path: ~5µs per `Emit()` call (channel send only)
- Async batch write: 100 events / 100ms → 1000 events/second sustained throughput
- Sync path: ~200µs per `EmitSync()` (single insert)
- Memory: 10000 buffered events × ~500 bytes = ~5MB headroom

These numbers comfortably exceed expected throughput for any production deployment.

### 10.3 Drop policy

If the buffer fills (back-pressure):

1. Increment `audit_dropped_total{severity}` counter
2. Drop `info` and `warning` events
3. Block-write `error` and `critical` events synchronously
4. Page on `audit_dropped_total{severity="critical"} > 0`

---

## 11. OpenAPI integration

### 11.1 Per-endpoint audit declarations

Endpoints declare which audit events they emit:

```yaml
/hosts:
  post:
    x-required-permission: HOST_WRITE
    x-audit-events: [host.created]
    summary: Create host
    ...
```

This is documentation only (does not generate code), but it's checked: every endpoint that's a mutating operation must declare at least one audit event in `x-audit-events`. The build fails if a `POST/PUT/PATCH/DELETE` endpoint has no audit events declared.

### 11.2 Error code: audit failure

`audit.write_failed` (500 Internal Server Error) — emitted only when sync writes fail and the request specifically required audit-before-response. Most endpoints don't.

---

## 12. Stage 0 integration

Stage 0 already includes audit events lightly:

- Day 5 — first endpoints emit audit events
- Day 7 — licensing emits 8+ audit event types

**Refined Stage 0 Day 5 deliverables:**

- `app/audit/events.yaml` registered with the initial 70+ codes
- `internal/audit/events.gen.go` produced by codegen
- `internal/audit/{emit,writer,redact}.go` implementations
- `audit_events` table migration (`0003_audit_events.sql`)
- Async writer goroutine wired into server lifecycle (started on boot, drained on shutdown)
- The Day 5 demo `:echo` endpoint emits `system.diagnostic_echo` event using the typed pattern

**Acceptance:**
- Service boots, writer goroutine starts
- `:echo` produces one audit event with proper envelope
- `GET /audit/events` returns the event with all canonical fields populated
- `GET /audit/events:taxonomy` returns the registry *(deferred to Phase 1)*
- Emit benchmark confirms <10µs async; <500µs sync
- Bench: 1000 emit calls → 1000 events written within 200ms

This adds roughly half a day to Day 5 vs the original Stage 0 plan. Net Stage 0 estimate stays at 7–11 days.

---

## 13. Anti-patterns (never do these)

| Anti-pattern | Why bad |
|---|---|
| Free-form `action` strings (`audit.Emit(ctx, "auth_login_OK", ...)`) | Drift; queries break |
| Logging passwords / tokens in `detail` even once | Once logged, forever in DB; compliance violation |
| Synchronous emission on hot paths | Adds DB latency to every request |
| Crashing on audit write failure | Compliance product can't deny operations because audit storage is full |
| Catch-all `audit.LogEvent("something happened")` | Defeats taxonomy; review can't aggregate |
| Reusing event codes for different shapes | A code's `detail` schema is part of its contract |
| Adding events without registering in `events.yaml` | Build fails — but only because of the spec lock |

---

## 14. Acceptance criteria for "foundation is built"

Stage 0 ships with audit foundation when:

- [ ] `app/audit/events.yaml` exists with ~70 initial codes across 13 categories
- [ ] `internal/audit/events.gen.go` produced by codegen
- [ ] `internal/audit/` package complete per §5.1
- [ ] `audit_events` table migration applied
- [ ] Async writer with batching, back-pressure, drop policy
- [ ] Sync writer for critical events
- [ ] Redaction discipline tested (sensitive fields scrubbed)
- [ ] Codegen validates code naming convention regex
- [ ] Codegen validates category references
- [ ] Codegen validates `detail_schema` JSON Schema validity
- [ ] OpenAPI build check: every mutating endpoint declares `x-audit-events`
- [ ] `GET /audit/events` returns canonical envelope
- [ ] `GET /audit/events:taxonomy` returns the registry *(deferred to Phase 1)*
- [ ] Per-resource sub-resource paths work (`/hosts/{id}/audit-events`) *(deferred to Phase 1)*
- [ ] Emit benchmark: async <10µs, sync <500µs
- [ ] Documentation: `app/docs/audit_event_taxonomy.md` referenced from CLAUDE.md / README

Once these are checked, every subsequent feature can emit audit events with a typed constant and trust the foundation.

---

## 15. Why this matters more than it looks

Three concrete failure modes the foundation prevents:

1. **The ad-hoc taxonomy graveyard.** Without a registry, ten developers invent ten naming conventions. After a year, the audit log has 200+ unique action strings, no one queries them all, and "show me failed logins" becomes a regex archaeology project.

2. **The accidental secret leak.** Without enforced redaction, someone someday writes `detail: {"password": req.Password}` "just for debugging." That row sits in the database for 365 days. Compliance failure. By the time it's caught, it's in backups too.

3. **The audit-as-side-channel anti-pattern.** Without a clear emission API, components start writing to `stderr` because "the audit log is too slow / unreliable." Now there are two places to look. Operators search both. Audit logs miss events. Compliance attestations can't prove completeness.

Half a day in Stage 0 prevents weeks of cleanup later — and several of these failure modes are only catchable in retrospect, not retrofittable.
