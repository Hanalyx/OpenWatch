# Policies as Data — Design Specification

**Status:** Foundation, locked 2026-04-29
**Owner:** Backend platform
**Spec:** `specs/system/policies.spec.yaml` (to be authored at Specter migration)
**Source-of-truth files:**
- `policies/*.yaml` — versioned, Ed25519-signed policy documents
- `internal/policy/types/*.go` — per-type schema validators (codegen + hand-written semantics)

---

## 1. Why this exists

OpenWatch's domain logic — *when a finding can be excepted, who can approve a remediation, how often a host is scanned, what compliance score triggers an alert* — has, historically, lived inside service code. That model fails for an agent-first platform for three reasons:

1. **Agents ask "what's the rule?" not "trace the code."** When a remediation request returns `403`, an agent needs to read a structured reason — not infer it from HTTP status. If the rule lives in a YAML file with a version, the agent can quote it back.
2. **Operators tune policies more often than they ship code.** Today "compliance score < 80 fires an alert" is hardcoded. Tomorrow the customer wants `< 70 for production, < 90 for dev`. Without policies-as-data, that's a code change + redeploy + release notes. With it, it's a YAML edit and a SIGHUP.
3. **Audit answers "who decided" not "what code ran."** A `policy.applied` event with `policy_type: alert_thresholds` and `policy_version: 2.1.0` is forensically useful. "Service X line 1247" is not.

This is not "make every `if` a policy." It's "the small set of decisions that operators tune, auditors review, and agents query." Section 2 defines the test.

---

## 2. The "is it a policy?" test

A piece of logic is a policy if **all four** are true:

1. **An operator (not a developer) would change it.** Compliance score thresholds, exception expiry, approval requirements: yes. JSON parsing, retry timing, connection pool size: no.
2. **Auditors care about its history.** "What was our scan cadence policy on March 15?" is a real question. "What was our HTTP timeout?" is not.
3. **Agents would benefit from quoting it.** Returning `error.code = "policy.denied"` with `detail.policy_type = "remediation_approval"` and `detail.policy_version = "1.4.0"` is actionable. "Permission denied" is not.
4. **It's a runtime decision, not a startup config.** Database URL is config (loaded once, restart to change). Alert thresholds are policy (evaluated per scan, hot-reload).

Five domains pass the test in OpenWatch:

| Domain | Policy type ID | Evaluated at |
|--------|----------------|--------------|
| Compliance exceptions | `exceptions` | Exception request submission, exception revalidation |
| Operation approvals | `approvals` | Any operation declared `x-requires-approval` in OpenAPI |
| Scan scheduling | `schedules` | Scheduler tick (every 60s), per host per framework |
| Alert thresholds | `alert_thresholds` | Scan completion, drift detection, host state change |
| Remediation rules | `remediation` | Remediation request enqueue, before execution |

Anything else that "feels like a policy" should be reviewed against the four-part test before being added. Adding policies is cheap; removing them — once handlers depend on `policy.Evaluate(ctx, "thing", ...)` — is expensive.

---

## 3. Anti-patterns (what policies-as-data is NOT)

- **Configuration in disguise.** A YAML file that lists "max upload size" is config, not policy. Configs go in `ow.yml`.
- **Generic rules engine.** No `if score < {{value}} then alert` evaluator. Each policy type has a typed Go schema and a dedicated evaluator. Generic engines fail silently when the YAML drifts from what the evaluator expects; typed schemas fail at load time.
- **Workflow engine.** Approvals are simple state machines (`pending → approved | rejected | expired`), not BPMN. If a workflow needs branching, parallel paths, or sub-processes, it belongs in code.
- **Specter target.** Specter validates that behavioral specs have enforcing tests. Specs describe *what the code does*; policies describe *operator-tunable rules*. They live in different files for different audiences.
- **Replacement for code.** A 400-line YAML with 30 conditional branches is worse than a 50-line Go function. If a policy reaches that complexity, it's no longer operator-tunable — break the operator-tunable bits out and put the rest in code.

---

## 4. Core design

### 4.1 Policy document envelope

Every policy file conforms to this outer shape:

```yaml
# policies/exceptions.yaml
policy_type: exceptions          # one of: exceptions | approvals | schedules | alert_thresholds | remediation
version: 2.1.0                   # semver; advances on any change to `rules`
metadata:
  description: Compliance exception lifecycle rules
  effective_from: 2026-05-01T00:00:00Z
  superseded_by: null            # set when this version is retired
  signed_by: ops-admin@hanalyx.com
  signed_at: 2026-04-29T14:32:11Z
rules:
  # type-specific schema; see Section 5
signature:                       # Ed25519 signature over the entire document MINUS this field
  algorithm: ed25519
  key_id: ops-admin-2026         # references admin signing key
  value: base64(64 bytes)
```

**Invariants:**
- `policy_type` must match the filename stem (`exceptions.yaml` → `policy_type: exceptions`).
- `version` must be a valid semver string, monotonically increasing across loads of the same `policy_type`. Loading `2.0.0` after `2.1.0` is rejected.
- `signature` is verified against an embedded Ed25519 admin public key set (separate from license keys). Unsigned policy files load only if `OPENWATCH_DEV_MODE=true`.
- `effective_from` is a wall-clock timestamp; the policy is inert before that time even if loaded.

### 4.2 Why Ed25519, not just file permissions

File-permission protection assumes an attacker who can write `/opt/openwatch/policies/` cannot execute `openwatch policy install` (which checks signatures). Most real attackers who can do the first can do the second. Ed25519 with embedded public keys raises the bar: an attacker must possess the admin private key, which is held offline.

Same primitive as license signing and audit chain signing — one crypto surface, fewer keys to rotate.

### 4.3 Versioning rules

- **Semver strict.** Patch (`2.1.0 → 2.1.1`) for descriptive changes (typo, comment). Minor (`2.1.0 → 2.2.0`) for adding new rules without changing existing decisions. Major (`2.1.0 → 3.0.0`) for any change that could flip a decision (raising a threshold, removing an exception class).
- **Monotonic.** The runtime tracks `current_version` per `policy_type`. Loading a lower version is rejected (`policy.invalid` audit event). Rolling back requires republishing as a new higher version — no version reuse, ever.
- **Multiple versions on disk allowed for forensics.** `policies/exceptions.v2.1.0.yaml` archived; `policies/exceptions.yaml` is the active symlink. Audit history references the version that was active at evaluation time.

### 4.4 Loading and evaluation pipeline

```
                       ┌──────────────────────────────────────┐
                       │ policies/{type}.yaml on disk         │
                       │ + admin public keys (embedded)       │
                       └──────────────┬───────────────────────┘
                                      │ openwatch policy install
                                      │     OR startup
                                      │     OR SIGHUP
                                      ▼
            ┌──────────────────────────────────────────────────┐
            │ internal/policy/loader.Load(policyType)          │
            │   1. Read file                                   │
            │   2. Verify Ed25519 signature                    │
            │   3. Parse against type-specific Go struct       │
            │   4. Run validator (refs, ranges, mutex rules)   │
            │   5. Compare version with runtime state         │
            │   6. Atomic swap into atomic.Pointer[State]      │
            └──────────────┬───────────────────────────────────┘
                           │  emit audit:
                           │    policy.loaded   (success)
                           │    policy.invalid  (any failure)
                           ▼
            ┌──────────────────────────────────────────────────┐
            │ internal/policy/{type}/evaluate.go               │
            │                                                   │
            │ Decision Evaluate(ctx, input) Decision           │
            │   - input is a typed struct per policy type      │
            │   - reads atomic.Pointer[State] (lock-free)      │
            │   - returns: allow | deny | defer | tier-of-action│
            │   - emits policy.applied audit on every call    │
            └──────────────────────────────────────────────────┘
```

Evaluation is lock-free for hot-path throughput: `atomic.Pointer[*State]` swap on reload, readers see either the old or new state with no locks.

### 4.5 The Decision type

```go
// internal/policy/types.go

type Decision struct {
    Outcome       Outcome           // allow | deny | defer | <type-specific>
    PolicyType    string            // e.g., "exceptions"
    PolicyVersion string            // e.g., "2.1.0"
    Reason        string            // machine-stable reason string (e.g., "expired", "out_of_scope")
    HumanMessage  string            // for UI/log display
    Detail        map[string]any    // type-specific context
    AppliedAt     time.Time
}

type Outcome string

const (
    OutcomeAllow Outcome = "allow"
    OutcomeDeny  Outcome = "deny"
    OutcomeDefer Outcome = "defer"
    // Type-specific outcomes (e.g., scheduling) extend this set.
)
```

When a handler turns a `Decision` into an HTTP response, `OutcomeDeny` maps to `error.code = "policy.denied"` with the policy type and version in `detail` (see error_codes.yaml).

---

## 5. The five policy types

Each subsection defines: (a) the YAML schema, (b) the Go evaluation input, (c) decision outcomes, (d) where it's evaluated.

### 5.1 Exceptions

**Purpose:** Govern when a compliance finding can be marked as "accepted risk" / "false positive" / "compensating control" without re-firing. Currently the backend has an exception model but no policy gating — anyone with the role can grant an exception of any duration. This policy adds bounds.

```yaml
policy_type: exceptions
version: 2.1.0
metadata: {...}
rules:
  defaults:
    max_duration_days: 90
    requires_justification: true
    auto_revalidate_on_drift: true
  classes:
    - id: false_positive
      max_duration_days: 365
      requires_approval_roles: [auditor, security_admin]
    - id: accepted_risk
      max_duration_days: 90
      requires_approval_roles: [security_admin]
      requires_justification_min_chars: 100
    - id: compensating_control
      max_duration_days: 180
      requires_approval_roles: [security_admin]
      requires_evidence_url: true
  scope:
    framework_blocklist: []        # frameworks where ALL exceptions are denied
    rule_blocklist:                # specific rule IDs that can never be excepted
      - cis_rhel9_3.7.1            # SELinux disabled
      - cis_rhel9_5.2.4            # SSH PermitRootLogin=yes
signature: {...}
```

**Evaluation input:**
```go
type ExceptionRequest struct {
    RuleID         string
    Framework      string
    Class          string  // "false_positive" | "accepted_risk" | "compensating_control"
    DurationDays   int
    RequesterRole  string
    Justification  string
    EvidenceURL    string  // optional
}
```

**Outcomes:** `allow` (request may proceed to approval workflow), `deny` (rejected at request time — bad class, blocklisted rule, duration exceeds class limit, missing justification).

**Evaluated at:** `POST /compliance/exceptions` (request handler), and on revalidation (every 24h cron, on drift detection).

### 5.2 Approvals

**Purpose:** Declare which operations require human approval, who can approve, and approval-quorum rules. This is the "two-person rule" / "change control" surface.

```yaml
policy_type: approvals
version: 1.0.0
metadata: {...}
rules:
  operations:
    - id: remediation.execute
      approvers_required: 1
      approver_roles: [security_admin, ops_lead]
      same_role_can_self_approve: false   # requester != approver
      timeout_hours: 24
      auto_reject_on_timeout: false        # null = stays pending
    - id: host.delete
      approvers_required: 0                # no approval needed (RBAC alone)
    - id: license.install
      approvers_required: 2
      approver_roles: [security_admin]
      timeout_hours: 168
      reminder_intervals_hours: [24, 72, 144]
    - id: admin.user.delete
      approvers_required: 1
      approver_roles: [security_admin]
      timeout_hours: 24
signature: {...}
```

**Evaluation input:**
```go
type ApprovalRequest struct {
    Operation     string  // matches an operations[].id
    RequesterID   uuid.UUID
    RequesterRole string
}
```

**Outcomes:**
- `allow` — operation may execute immediately (`approvers_required = 0`).
- `defer` — operation enters pending state with `approval_id`. Handler returns `202 Accepted` with `approval_id`.
- `deny` — operation forbidden by policy (no matching operation entry, or requester role not allowed to even request).

**Evaluated at:** Any handler whose OpenAPI operation declares `x-requires-approval: <operation_id>`. Codegen wraps the handler with the approval middleware.

### 5.3 Schedules

**Purpose:** Adaptive Compliance Scheduler — how often to scan each host, by current state. Replaces fixed-interval scanning.

```yaml
policy_type: schedules
version: 1.2.0
metadata: {...}
rules:
  defaults:
    interval_compliant_hours: 168         # weekly when fully compliant
    interval_drifted_hours: 24            # daily when drift detected
    interval_failed_hours: 6              # 4x/day when actively failing
    interval_first_scan_hours: 1          # near-immediate after host registration
    max_interval_hours: 168               # ceiling — even compliant hosts scan weekly
    jitter_percent: 10                    # ±10% randomization to avoid thundering herd
  per_framework:
    - framework: cis-rhel9-v2.0.0
      interval_compliant_hours: 168
    - framework: stig-rhel9-v2r7
      interval_compliant_hours: 24        # STIG re-scans daily even when compliant
      interval_failed_hours: 1
  per_host_tag:
    - tag: production
      interval_compliant_hours: 24
    - tag: dev
      interval_compliant_hours: 336       # 14 days
signature: {...}
```

**Evaluation input:**
```go
type ScheduleQuery struct {
    HostID         uuid.UUID
    Framework      string
    HostTags       []string
    LastScanAt     time.Time
    LastScanStatus ScanStatus  // compliant | drifted | failed
    HostCreatedAt  time.Time
}
```

**Outcome (type-specific):**
```go
type ScheduleDecision struct {
    NextScanAt time.Time
    Interval   time.Duration
    Source     string  // which rule matched: "default" | "framework:cis-rhel9-v2.0.0" | "tag:production"
}
```

**Evaluated at:** Scheduler tick (every 60s). For each `(host, framework)` pair: compute `NextScanAt`, enqueue scan if `now() >= NextScanAt`.

**Conflict resolution:** When multiple rules match (e.g., a host has tag `production` AND framework `stig-rhel9-v2r7`), the **shortest** interval wins (most aggressive scanning). This is safe-by-default — the operator can lengthen intervals via tag rules without worrying about framework rules being silently overridden.

### 5.4 Alert thresholds

**Purpose:** When a scan completes or drift is detected, decide whether to fire an alert and at what severity.

```yaml
policy_type: alert_thresholds
version: 1.0.0
metadata: {...}
rules:
  compliance_score:
    - condition: score < 70
      severity: critical
      debounce_minutes: 60
    - condition: score < 80
      severity: warning
      debounce_minutes: 240
    - condition: score < 90
      severity: info
      debounce_minutes: 1440
  drift:
    - condition: pass_to_fail_count > 5
      severity: critical
      debounce_minutes: 60
    - condition: pass_to_fail_count > 0
      severity: warning
      debounce_minutes: 60
  per_host_tag:
    - tag: production
      compliance_score:
        - condition: score < 90
          severity: critical
        - condition: score < 95
          severity: warning
  channels_default: [slack, email]
  channels_critical_override: [slack, email, pagerduty]
signature: {...}
```

**Note on `condition`:** The string `score < 70` is **not** parsed as a generic expression. The schema validator constrains it to a small allowlist: `score < N`, `score > N`, `pass_to_fail_count > N`, `pass_to_fail_count > N`. This stays out of "generic rules engine" territory — the validator can be ~30 lines of Go.

**Evaluation input:**
```go
type AlertEvaluation struct {
    HostID            uuid.UUID
    Framework         string
    HostTags          []string
    ComplianceScore   float64
    PassToFailCount   int
    LastAlertAt       map[Severity]time.Time  // for debounce
}
```

**Outcome:**
```go
type AlertDecision struct {
    Fire         bool
    Severity     Severity
    Channels     []string
    DebounceUntil time.Time  // populated even when Fire=false, to short-circuit re-evaluation
    MatchedRule  string
}
```

**Evaluated at:** Scan completion; drift detection job.

### 5.5 Remediation

**Purpose:** Govern auto-remediation. License-gated (Phase 4), but the policy machinery exists in Stage 0 so the gate is not a retrofit.

```yaml
policy_type: remediation
version: 1.0.0
metadata: {...}
rules:
  global:
    require_dry_run_first: true
    max_concurrent_executions: 5
    rollback_on_step_failure: true
  rule_classes:
    - rule_pattern: "cis_rhel9_1\\..*"     # config files, low risk
      auto_execute_allowed: true
      requires_approval: false
    - rule_pattern: "cis_rhel9_3\\..*"     # network, medium risk
      auto_execute_allowed: false           # dry-run only without approval
      requires_approval: true
    - rule_pattern: "cis_rhel9_5\\..*"     # SSH/access, high risk
      auto_execute_allowed: false
      requires_approval: true
      requires_dual_approval: true
  blocklist:
    - cis_rhel9_3.7.1                      # SELinux changes — never auto-remediate
signature: {...}
```

**Evaluation input:**
```go
type RemediationRequest struct {
    RuleID       string
    HostID       uuid.UUID
    DryRun       bool
    HasApproval  bool
}
```

**Outcomes:**
- `allow` — proceed with remediation.
- `defer` — needs approval; route through approval policy.
- `deny` — blocklisted rule, or pattern requires dry-run first and `DryRun=false`.

**Evaluated at:** `POST /remediation/requests` and at worker dequeue (re-check, in case policy changed since enqueue).

---

## 6. Storage and runtime state

### 6.1 On-disk layout

```
/opt/openwatch/policies/
├── exceptions.yaml              # active version (symlink or current file)
├── exceptions.v2.1.0.yaml       # archived
├── exceptions.v2.0.0.yaml       # archived
├── approvals.yaml
├── schedules.yaml
├── alert_thresholds.yaml
└── remediation.yaml
```

Archived versions are read-only. They support audit forensics: "show me the exceptions policy as of 2026-03-15" reads the file from a backup or the policy_history table (Section 6.3).

### 6.2 Runtime state

```go
// internal/policy/state.go

type State struct {
    LoadedAt time.Time
    Policies map[string]*LoadedPolicy  // key: policy_type
}

type LoadedPolicy struct {
    Type            string
    Version         string  // semver
    Rules           any     // type-asserted to per-type struct
    SignatureValid  bool
    EffectiveFrom   time.Time
    SourceFile      string
    SourceHash      string  // SHA-256 of file contents
}

var current atomic.Pointer[State]

func IsActive(policyType string) bool {
    s := current.Load()
    p, ok := s.Policies[policyType]
    return ok && p.SignatureValid && time.Now().After(p.EffectiveFrom)
}

func Get(policyType string) (*LoadedPolicy, bool) {
    s := current.Load()
    p, ok := s.Policies[policyType]
    return p, ok
}
```

Hot-path evaluation never takes a lock; readers see either old or new state during a swap, never a partial state.

### 6.3 Database snapshot table

```sql
CREATE TABLE policy_history (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid_v7(),
    policy_type  TEXT NOT NULL,
    version      TEXT NOT NULL,
    source_hash  TEXT NOT NULL,
    rules        JSONB NOT NULL,
    metadata     JSONB NOT NULL,
    signature    JSONB NOT NULL,
    loaded_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    superseded_at TIMESTAMPTZ,
    UNIQUE(policy_type, version)
);

CREATE INDEX idx_policy_history_type_loaded ON policy_history(policy_type, loaded_at DESC);
```

Every successful policy load inserts a row. The `superseded_at` column is set when a newer version of the same `policy_type` loads. This is the audit trail for "what was the active policy at time T."

`policy.applied` audit events reference `(policy_type, version)`; the snapshot table provides full text of that version forever.

---

## 7. Loading lifecycle

### 7.1 Startup

```
1. Read embedded admin public keys.
2. For each policy_type in {exceptions, approvals, schedules, alert_thresholds, remediation}:
     a. Read /opt/openwatch/policies/{type}.yaml.
     b. If missing → use built-in default policy (described in §7.4); emit policy.loaded with version=0.0.0.
     c. Verify signature; if invalid:
        - production:  refuse to start; exit non-zero with audit policy.invalid (sync).
        - dev mode:    log warning; load with SignatureValid=false.
     d. Validate against type-specific schema; on failure → exit (production).
     e. Compare version with policy_history; reject if not monotonic.
     f. Insert into policy_history; mark prior version superseded.
     g. Atomic swap into State.
     h. Emit audit policy.loaded.
3. State is non-nil before any handler accepts traffic.
```

### 7.2 Hot reload (SIGHUP)

```
1. Receive SIGHUP.
2. For each policy_type, re-run steps 2a–2h from §7.1.
3. Reload is best-effort: failure of one policy_type does not roll back others.
4. Each successful reload emits policy.loaded; each failure emits policy.invalid.
5. The previous State is the fallback if all reloads fail (no atomic swap performed).
```

### 7.3 Admin endpoint reload

```
POST /admin/policies:reload
Idempotency-Key: required

Body: {} (reload all) or { "types": ["exceptions", "approvals"] }

Response:
  200 OK { "results": [{"policy_type": "exceptions", "version": "2.2.0", "outcome": "loaded"}, ...] }
  207 Multi-Status when some succeeded and some failed
  503 if reload deferred (another reload in progress)
```

Required permission: `admin.policies.reload` (declared via `x-required-permission`).

### 7.4 Built-in defaults

If a policy file is missing from disk, the loader uses a hardcoded conservative default with `version: 0.0.0`. The defaults are intentionally **strict** — operators must opt in to looser policies by writing a file. Examples:

- `exceptions` default: max 30 days, all classes require security_admin approval, no blocklist.
- `approvals` default: every operation that *can* require approval *does*; default approver_roles = `[security_admin]`.
- `schedules` default: weekly for compliant hosts, daily otherwise, no per-tag overrides.
- `alert_thresholds` default: warning at <80, critical at <70.
- `remediation` default: `auto_execute_allowed: false` for everything; dry-run only.

---

## 8. Audit integration

The audit registry already defines (`app/audit/events.yaml`):

- `policy.loaded` — emitted on successful load (startup or reload).
- `policy.invalid` — emitted when load fails (signature, schema, version regression).
- `policy.applied` — emitted on **every** call to `Evaluate()`.

Detail schemas for each:

**`policy.loaded.detail`:**
```yaml
policy_type: string
policy_version: string         # the now-active version
previous_version: string|null  # what was replaced
source_hash: string
load_source: string            # "startup" | "sighup" | "admin_reload"
```

**`policy.invalid.detail`:**
```yaml
policy_type: string
attempted_version: string|null
errors: array of strings
load_source: string
```

**`policy.applied.detail`:**
```yaml
policy_type: string
policy_version: string
decision: string               # "allow" | "deny" | "defer" | type-specific
reason: string                 # machine-stable
input_summary: object          # type-specific; redacted (no secrets)
```

**Volume note:** `policy.applied` is the highest-volume audit event in the system — every API call that hits a policy emits one. Two mitigations:

1. **Async path.** `policy.applied` always uses the async batched writer (never `EmitSync`). Drop on overflow is acceptable; the absence of an apply event does not affect correctness.
2. **Coalescing for schedules.** The scheduler evaluates *every host × framework* every minute. Emitting one event per evaluation is wasteful (most are "stay the course"). The scheduler emits `policy.applied` only when the decision *changes* the next-scan time materially (>5% delta) or fires a scan. The summary event `scan.queued` references the policy version, providing the audit chain.

---

## 9. OpenAPI integration

Two extensions tie policies into the API spec.

### 9.1 `x-requires-approval`

Declared per operation. Codegen generates middleware that wraps the handler.

```yaml
paths:
  /remediation/requests/{id}:execute:
    post:
      operationId: executeRemediation
      x-required-permission: remediation:execute
      x-required-feature: remediation_execution
      x-requires-approval: remediation.execute
      x-audit-events: [remediation.requested, remediation.executed]
      responses:
        '202':
          description: Approval required; returns approval_id
          content:
            application/json:
              schema: {$ref: '#/components/schemas/ApprovalPending'}
        '200':
          description: Executed (approval policy returned allow)
```

The `202` response is the `defer` outcome of the approvals policy. Agents key off `error.code` (none in 2xx) and the response body shape.

### 9.2 `x-policy-evaluated` (informational)

Declared per operation when a non-approval policy may produce a denial. This is documentation-only — the spec consumer can see which policy types govern the endpoint.

```yaml
paths:
  /compliance/exceptions:
    post:
      operationId: requestException
      x-policy-evaluated: [exceptions]
      x-audit-events: [compliance.exception.requested]
```

CI does not enforce that the handler actually evaluates the listed policies — that's a behavioral spec concern (Specter), not a spec-time concern.

---

## 10. Code organization

```
internal/
└── policy/
    ├── state.go              # atomic.Pointer[State], Get/IsActive
    ├── loader.go             # ReadFile, VerifySignature, Validate, Apply
    ├── reload.go             # SIGHUP handler, admin endpoint glue
    ├── history.go            # snapshot to policy_history table
    ├── audit.go              # policy.loaded / .invalid / .applied helpers
    ├── types/
    │   ├── exceptions.go     # struct + JSON Schema validator
    │   ├── approvals.go
    │   ├── schedules.go
    │   ├── alert_thresholds.go
    │   └── remediation.go
    └── eval/
        ├── exceptions.go     # Evaluate(ctx, ExceptionRequest) Decision
        ├── approvals.go
        ├── schedules.go
        ├── alert_thresholds.go
        └── remediation.go
```

Each evaluator is plain Go, fully unit-testable with table-driven tests. No DSL, no AST, no expression evaluator — just typed inputs into typed decisions.

---

## 11. Failure modes and edge cases

| Scenario | Behavior |
|----------|----------|
| Policy file deleted while running | Existing in-memory state continues; on next reload, missing file → built-in default loaded; emit `policy.loaded` with `previous_version` populated. |
| Policy file edited but signature stale | Signature check fails on reload; `policy.invalid` emitted; previous in-memory state retained (no swap). |
| Policy file references unknown rule ID | Schema validator rejects at load; `policy.invalid` emitted with the unknown reference in `errors[]`. |
| Two policies with the same `policy_type` and same `version` on disk | Filename precedence: `{type}.yaml` (active symlink) wins. Other files are ignored. |
| Clock skew makes `effective_from` invalid | Loaded but inert until `now() >= effective_from`. Evaluations during this window use the previous policy. |
| Database snapshot insert fails | Policy still loads into memory; warning logged; reconciliation job retries snapshot. The in-memory state is authoritative for evaluation. |
| Evaluator panic (bug in eval code) | Recovered by middleware; returns `error.code = "server.internal"`; emits `policy.invalid` (yes, the *evaluator* failed, not the policy itself — the audit code captures the bug); request retries are not safe. |
| Policy version downgrade attempted | Loader rejects; `policy.invalid` with `errors: ["version regression: 2.0.0 < 2.1.0"]`. |

---

## 12. Performance targets

| Metric | Target | Rationale |
|--------|--------|-----------|
| `Evaluate()` p99 (any type) | < 50µs | Hot-path; lock-free atomic read + struct evaluation |
| Schedule evaluator full sweep (1000 hosts × 3 frameworks) | < 100ms | Runs every 60s; must finish before the next tick |
| Policy reload (single type) | < 100ms | SIGHUP reload; signature verify + validate + DB insert |
| `policy.applied` audit volume | ~10K/sec sustained | Async path absorbs without backpressure |

---

## 13. Stage 0 work

Day 8 of the walking skeleton (after audit foundation Day 5, idempotency Day 6, and licensing Day 7) folds in policies-as-data:

1. **`internal/policy/` package** — state, loader, history (no eval logic).
2. **Type schema scaffolding** — Go structs and JSON-Schema validators for all 5 types. Evaluator stubs return built-in defaults.
3. **`policy_history` table** — migration + repository.
4. **`/admin/policies:reload` endpoint** — admin auth, returns the reload outcome map.
5. **SIGHUP handler** — wired in.
6. **Audit integration** — `policy.loaded`/`.invalid`/`.applied` emit helpers.
7. **OpenAPI extensions** — codegen support for `x-requires-approval` and `x-policy-evaluated` (parsing only; middleware in Stage 2).
8. **Built-in default policies** — checked in as `policies/{type}.default.yaml` (version `0.0.0`, unsigned in dev mode).

What is **not** in Stage 0:
- Approval state machine (Stage 2 — needs approvals table, notification dispatch).
- Adaptive scheduler implementation (Stage 2 — needs scan execution).
- Alert dispatch (Stage 2 — needs notification channels).
- Remediation evaluator integration (Phase 4).

The framework loads, validates, snapshots, and emits audit events on Day 6. Type-specific evaluators come online as their consumers do.

---

## 14. Testing strategy

| Layer | Test type | What it asserts |
|-------|-----------|-----------------|
| Schema validators | Table-driven unit | Bad inputs rejected with the expected error string |
| Loader | Integration | Real file → real signature verify → real DB insert; covers the happy path and 5 failure modes from §11 |
| Evaluators | Table-driven unit | (input, expected Decision) pairs; one per outcome and reason |
| Hot reload | Integration | SIGHUP triggers reload; concurrent evaluators see consistent state |
| Performance | Benchmark | `BenchmarkEvaluate*` — fail CI if p99 > 50µs |
| Audit emission | Integration | Every Evaluate call produces a `policy.applied` event |
| End-to-end | Behavioral spec (post-Specter) | "If exception class is `accepted_risk` and duration > 90 days, request returns `policy.denied`" |

---

## 15. Open questions

1. **Per-tenant policies.** The current design is single-tenant per OpenWatch deployment. Multi-tenant would require namespacing files and snapshot rows by tenant. Defer to multi-tenant epic.
2. **Policy diff/preview UI.** Operators will want to see "what would change if I install this version?" before installing. Out of Stage 0 scope.
3. **Policy linting beyond schema.** E.g., "you have a `class: accepted_risk` rule with `max_duration_days: 9999` — is that intentional?" Defer; can be added as a separate `openwatch policy lint` subcommand.
4. **Cross-policy invariants.** E.g., the `approvals` policy declares `host.delete` requires no approval, but the `remediation` policy declares it does. Today each policy is validated independently. Cross-checks deferred until we hit a real conflict.
5. **Policy expression evaluator scope.** §5.4 uses string conditions like `score < 70`. The schema validator allowlists patterns. If operators ever want richer expressions (e.g., `score < 70 AND host.tag == "production"`), we either grow the allowlist or write a tiny CEL-style evaluator. Expressions in the allowlist stay restricted in v1.

---

## Cross-references

- Error codes: `app/api/error_codes.yaml` — `policy.invalid`, `policy.version_mismatch`, `policy.denied`, `policy.not_found` are already registered.
- Audit events: `app/audit/events.yaml` — `policy.loaded`, `policy.invalid`, `policy.applied` already registered with detail schemas.
- API design: `app/docs/api_design_principles.md` §11 (extensions), §15 (idempotency on `/admin/policies:reload`).
- RBAC registry: `app/docs/rbac_registry.md` — the `approvals` policy's `approver_roles` field cross-validates against the active role set (built-in + custom). Unknown role at policy load → `policy.invalid` audit event with the unknown role in `errors[]`; previous in-memory state retained.
- Roadmap: 2026-04-27 entry on policies-as-data; 2026-04-29 entry on this design doc; 2026-04-30 entry on RBAC cross-validation.
