# OpenWatch+ Licensing Foundation

> **Status:** Locked design 2026-04-28
> **Authority:** This document is the architectural foundation for license validation, feature gating, and quota enforcement in the Go rebuild. Implementation in Stage 0 must conform.
> **Why now:** Today's `LicenseService` is a config-flag stub (3 TODOs in `services/licensing/service.py`). The rebuild has a clean opportunity to design the licensing foundation properly. Bolting it on later — when several Phase-2 features depend on it — will be expensive.

---

## 1. Why this is foundation work, not feature work

Licensing crosses every architectural seam in the system:

- **HTTP routes** — many endpoints are gated on a license feature
- **Service layer** — quotas enforced at points of use (host count, scan rate)
- **Frontend** — UI hides or marks features the customer's license doesn't include
- **Audit log** — license events (install, expiry, denial) are first-class audit events
- **Errors** — `license.feature_unavailable` is a documented error code with `402 Payment Required`
- **Operational** — license install / renew / verify is a CLI flow operators run
- **Spec layer** — Specter validates behavioral contracts about expiry, grace periods, tamper detection
- **Build** — public key for signature verification is compiled into the binary

If licensing is added later, every one of these seams has to be retrofitted — and retrofits leak. Doing it once, now, with the architecture decisions still fluid, is the cheap path.

---

## 2. Core requirements

### 2.1 Functional

1. **Validate license authenticity** — cryptographically signed, tamper-resistant
2. **Determine feature availability** — per feature ID, fast (hot path)
3. **Enforce quota limits** — host count, scan rate, user count
4. **Handle expiry gracefully** — grace period before lockout
5. **Reload without restart** — operators install a new license file and signal the service
6. **Air-gapped deployment** — no phone-home; license validation is fully offline
7. **Audit every license event** — install, reload, expiry, feature check denial, quota exceeded

### 2.2 Non-functional

1. **Hot-path performance** — `IsEnabled(featureID)` must be O(1) and lock-free
2. **Tamper resistance** — best-effort against license file modification and clock rollback; not against process patching (unwinnable)
3. **Operational simplicity** — single `.lic` file, single CLI command to install
4. **Free tier always works** — service boots and runs without any license file (free features only)
5. **Forward compatibility** — adding a new feature ID doesn't break existing licenses
6. **Backward compatibility** — removing a feature ID is a versioning event; old licenses keep working

---

## 3. License model

### 3.1 License is a signed JWT

A license is a JWT with `EdDSA` algorithm (Ed25519), payload as documented below. Distributed as a single file: `license.lic` (literal JWT compact serialization).

**Why JWT:**
- Standard format with mature Go library support (`golang-jwt/jwt` v5 — already locked in roadmap)
- Single file, no out-of-band signature
- Header carries algorithm + key ID, enabling key rotation
- Compact, base64url-safe, suitable for email distribution

**Why Ed25519:**
- Same primitive used elsewhere in the platform (Kensa rule signing, evidence signing) — one algorithm, fewer surfaces
- Stdlib (`crypto/ed25519`) — no external dependency
- Fast verification, small signatures, FIPS-compliant via `microsoft/go`

### 3.2 License JWT claims

```json
{
  "iss": "openwatch-licensing@hanalyx.com",
  "sub": "customer-uuid-or-name",
  "jti": "license-uuid",
  "iat": 1700000000,
  "nbf": 1700000000,
  "exp": 1731622400,
  "aud": "openwatch",
  "license": {
    "tier": "openwatch_plus",
    "customer_name": "Acme Corp",
    "customer_id": "cust-uuid",
    "features": [
      "audit_query",
      "audit_export",
      "temporal_queries",
      "remediation_execution",
      "structured_exceptions",
      "priority_updates",
      "sso_saml",
      "fido2_mfa"
    ],
    "quotas": {
      "max_hosts": 5000,
      "max_scans_per_day": 50000,
      "max_users": 500,
      "max_concurrent_scans": 100
    },
    "deployment_fingerprint": null,
    "support_contact": "support@example.com"
  }
}
```

**Field semantics:**

| Field | Meaning |
|---|---|
| `iss` | License issuer. Pinned per build via embedded public key + issuer string. |
| `sub` | Customer subject. Used for audit/logging only (not validation). |
| `jti` | Unique license ID. Stored in DB on install for revocation tracking. |
| `iat` / `nbf` / `exp` | Standard JWT timestamps. `nbf` and `exp` enforce the validity window. |
| `aud` | Always `openwatch`. Rejected if mismatched. |
| `license.tier` | `free` or `openwatch_plus`. Free licenses can be issued explicitly to override default Free tier (for trials, partners). |
| `license.features` | Authoritative list of enabled feature IDs. Anything not in this list is denied. |
| `license.quotas` | Numeric limits. `null` or absent = unlimited for that quota. |
| `license.deployment_fingerprint` | Optional SHA-256 of `(machine_id + install_id)`. If set, license is bound to that deployment. Most customers: `null`. |
| `license.support_contact` | Embedded for operator convenience; never used in validation. |

### 3.3 Feature ID registry

Feature IDs are stable strings. Registry lives at `licensing/features.yaml` and is checked into source.

```yaml
# licensing/features.yaml
version: 1
features:
  - id: compliance_check
    tier: free
    description: Run compliance scans against hosts
    introduced: "1.0.0"

  - id: audit_query
    tier: openwatch_plus
    description: Saved and ad-hoc audit query system
    introduced: "1.0.0"

  - id: audit_export
    tier: openwatch_plus
    description: Export audit data as JSON/CSV/PDF with signed bundles
    introduced: "1.0.0"

  - id: temporal_queries
    tier: openwatch_plus
    description: Point-in-time compliance posture, drift, forecasts
    introduced: "1.0.0"

  - id: remediation_execution
    tier: openwatch_plus
    description: Apply remediation via Kensa with rollback support
    introduced: "1.0.0"

  - id: structured_exceptions
    tier: openwatch_plus
    description: Multi-stage exception approval workflow
    introduced: "1.0.0"

  - id: priority_updates
    tier: openwatch_plus
    description: Early access to Kensa rule updates
    introduced: "1.0.0"

  - id: sso_saml
    tier: openwatch_plus
    description: SAML 2.0 single sign-on
    introduced: "1.0.0"

  - id: fido2_mfa
    tier: openwatch_plus
    description: FIDO2/WebAuthn second factor
    introduced: "1.0.0"

# Deprecated features kept for backwards compatibility:
deprecated_features:
  - id: legacy_csv_export
    deprecated_in: "1.0.0"
    removed_in: "2.0.0"
    description: Legacy flat CSV report export (replaced by signed report faces)
```

**Rules:**

1. **Adding a feature** is non-breaking. Existing licenses without it default to denied. New licenses include it as needed.
2. **Removing a feature** requires deprecation period (one minor version) then removal. Old licenses including the removed feature are unaffected (the registry is the source of truth, not the license).
3. **Renaming a feature** is forbidden. Add a new ID and deprecate the old one.
4. **Tier changes** (e.g., promoting a feature from `openwatch_plus` to `free`) are allowed and take effect on next license reload.
5. **Free-tier features are never gated.** They're listed for completeness; the gate logic short-circuits on `tier=free`.

### 3.4 Quotas

Quotas are advisory limits enforced at point of use:

| Quota | Enforcement point | Behavior at limit |
|---|---|---|
| `max_hosts` | Host create/import | Reject new host with `quota.max_hosts_exceeded` |
| `max_scans_per_day` | Scan enqueue | Reject scan with `quota.daily_scan_limit` |
| `max_users` | User create | Reject with `quota.max_users_exceeded` |
| `max_concurrent_scans` | Scan dequeue | Defer scan with `quota.concurrent_scan_limit` (queued, not failed) |

Free tier defaults (compiled into binary as fallbacks):

```go
var FreeTierQuotas = Quotas{
    MaxHosts:            100,
    MaxScansPerDay:      1000,
    MaxUsers:            10,
    MaxConcurrentScans:  10,
}
```

These can be overridden by an explicit free-tier license.

---

## 4. Validation logic

### 4.1 Verification order (all must pass)

1. **JWT structure** — three base64url segments separated by dots
2. **Algorithm** — header `alg` must be `EdDSA`. No exceptions. Reject `none`, `HS256`, etc.
3. **Key ID match** — header `kid` must match an embedded public key
4. **Signature** — Ed25519 verify with the resolved public key
5. **Issuer** — `iss` must match the embedded issuer string
6. **Audience** — `aud` must equal `openwatch`
7. **Validity window** — current monotonic-cross-checked time must be within `[nbf, exp]`
8. **Deployment fingerprint** (if set) — SHA-256(machine_id + install_id) must match
9. **Clock rollback check** — current time must be ≥ last_known_good_time stored in DB

If any fails: license is rejected, service falls back to Free tier, audit event emitted with the specific failure.

### 4.2 Public key distribution

Public keys are **compiled into the binary** at build time. Three keys minimum (current + 2 historical) embedded for rotation support:

```go
//go:embed keys/license-pubkey-current.pem
var licensePubKeyCurrent []byte

//go:embed keys/license-pubkey-prev.pem
var licensePubKeyPrev []byte

//go:embed keys/license-pubkey-deprecated.pem
var licensePubKeyDeprecated []byte
```

**Why embedded, not config:**
- Tampering with config files is easier than tampering with the binary
- Embedded keys cannot be replaced without re-shipping the binary
- Customers can verify integrity by checking binary signatures (RPM/DEB signing)

**Key rotation procedure:**
1. New key pair generated by issuer
2. Next OpenWatch release embeds the new key as `current`, old key as `prev`
3. New licenses signed with new key
4. Old licenses signed with old key continue to validate (until `prev` is rotated out)
5. After 12 months, the once-`prev` key becomes `deprecated` (still validates but emits warning) and is rotated out one release later

### 4.3 Clock rollback detection

System clocks can be tampered with. Mitigation:

1. On license install / reload, store `last_known_good_time = max(now, exp_minus_grace_period)` in the `licenses` table
2. On every validation, check `now >= last_known_good_time - tolerance` (where tolerance = 1 hour for NTP drift)
3. If `now < last_known_good_time - tolerance`: clock rollback detected, license invalidated, audit event emitted, fall back to Free tier

This is best-effort — a determined attacker with root can defeat it. The point is to catch accidents and obvious tampering.

### 4.4 Grace period on expiry

Licenses don't go from "active" to "free tier" instantly on expiry:

| Time relative to `exp` | State | Behavior |
|---|---|---|
| Before `exp` | active | All licensed features available |
| `exp` to `exp + 30 days` | grace | All features still available; `Warning` header on every API response; banner on UI; `license.expiring_soon` audit event daily |
| After `exp + 30 days` | expired | Free tier only; `license.expired` audit event on first denial; UI shows expired banner |

**Operational pressure during grace:** the warning headers and audit events make expiry visible long before the lockout. Operators have 30 days to install a renewal.

### 4.5 Reload model

License is loaded:

1. **At startup** — read `/etc/openwatch/license.lic`, validate, populate in-memory state
2. **On SIGHUP** — re-read, re-validate, swap in-memory state atomically
3. **On schedule** — every hour, re-validate the in-memory license against current time (catches expiry transitions without restart)

The in-memory state is `*atomic.Pointer[LicenseState]` — readers (the hot-path `IsEnabled` check) load the pointer with a single atomic op; reload publishes a new pointer atomically. No locks on the read path.

---

## 5. Architecture

### 5.1 Package layout (as built)

```
internal/license/
├── types.go           # License, Feature, Tier, State structs
├── features.gen.go    # Codegen output from specs (Feature constants, FeatureRegistry)
├── validator.go       # JWT parsing + Ed25519 signature verification + claims
├── state.go           # In-memory state + atomic.Pointer[State]; IsEnabled hot path
├── middleware.go      # RequireFeature/EnforceFeature/DenyFeature + denial dedup
├── service.go         # GET /license, GET /license/features handlers
├── audit.go           # License event emission helpers
├── keys.go            # Embedded public key ring loader
├── keys/              # Embedded public keys (.pem) via go:embed
│   └── license-pubkey-current.pem
├── testdata/          # Test private key (NOT shipped in releases)
└── features_test.go, validator_test.go
```

Deferred to a later stage (not yet implemented):
- `loader.go` — file-based license install path (currently env-var only)
- `reload.go` — SIGHUP-driven re-validation
- `cli.go` — `openwatch license install/verify/info` subcommands
- Quotas (`Quotas` struct + `RequireQuota` middleware) — Phase 2

### 5.2 Hot path: `IsEnabled`

```go
package license

import (
    "sync/atomic"
)

type State struct {
    Tier         Tier
    Features     map[string]struct{}  // O(1) lookup
    Quotas       Quotas
    ExpiresAt    time.Time
    GraceUntil   time.Time
    LicenseID    string
    InstalledAt  time.Time
}

var current atomic.Pointer[State]

// IsEnabled is the hot-path check. Lock-free, O(1).
func IsEnabled(featureID string) bool {
    s := current.Load()
    if s == nil {
        return isFreeTierFeature(featureID)
    }
    _, ok := s.Features[featureID]
    return ok
}

// IsExpired returns true if license is past grace period.
func IsExpired() bool {
    s := current.Load()
    if s == nil {
        return false  // No license = Free tier, not expired
    }
    return time.Now().After(s.GraceUntil)
}
```

Performance: ~20ns per check. Safe to call from every HTTP request without measurable overhead.

### 5.3 Middleware (as built)

The implementation takes a typed `Feature` (not a `string`) and uses the
error envelope schema fixed by `error_codes.spec.yaml` (`fault`, not
`category`). Dedup on denial events is enforced per
`(feature, actor)` within a 60s window — see `denialMap` in
`internal/license/middleware.go`.

```go
// RequireFeature: chi middleware for routes wired directly via chi.
func RequireFeature(f Feature) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            if EnforceFeature(w, r, f) {
                return // denied; response already written
            }
            next.ServeHTTP(w, r)
        })
    }
}

// EnforceFeature: called inside oapi-codegen-generated handlers where
// per-route middleware injection is awkward. Returns true if denied
// (handler should return immediately).
func EnforceFeature(w http.ResponseWriter, r *http.Request, f Feature) (denied bool) {
    if IsEnabled(f) {
        return false
    }
    DenyFeature(w, r, f)
    return true
}
```

Denial envelope (`fault: "policy"`, retryable: false):
```json
{"error":{"code":"license.feature_unavailable","fault":"policy","retryable":false,
          "human_message":"this feature requires an OpenWatch+ license",
          "detail":{"feature":"premium_diagnostics"}}}
```

Grace-period Warning header support is on the roadmap; not yet implemented.

### 5.4 OpenAPI integration: `x-required-feature` (as built)

Endpoints that require a license feature declare it in the OpenAPI spec:

```yaml
paths:
  /diagnostics:premium-echo:
    post:
      x-required-feature: premium_diagnostics    # License gate
      summary: Premium-tier echo (license-gated)
      ...
```

`x-required-feature` is documentation only — oapi-codegen does not auto-wire
license enforcement. Handlers call `license.EnforceFeature(w, r, f)` at the
top of the function body (`internal/server/handlers.go:PostDiagnosticsPremiumEcho`).
The `x-required-feature` extension is the source of truth for which routes are
gated and which Feature ID gates them; an audit script can cross-check this
against the handler code.

RBAC integration (`x-required-permission`) is planned but not yet implemented
(deferred to the RBAC milestone — Day 8 in the Stage-0 plan).

If an endpoint declares `x-required-feature` for a feature ID not in `features.yaml`, the build fails. This prevents silent drift.

### 5.5 Service-layer quota enforcement

For things that don't map cleanly to a single HTTP route (e.g., concurrent scan limit hits the worker, not the route):

```go
package license

func CheckQuota(q QuotaName, current int64) error {
    state := current.Load()
    limit := state.Quotas.Get(q)
    if limit == 0 {
        return nil  // unlimited
    }
    if current >= limit {
        audit.Emit(ctx, audit.Event{
            Action:   "license.quota_exceeded",
            Resource: string(q),
            Detail:   map[string]any{"limit": limit, "current": current},
        })
        return &Error{
            Code:         "quota." + string(q) + "_exceeded",
            HumanMessage: fmt.Sprintf("%s limit reached (%d).", q.Description(), limit),
        }
    }
    return nil
}

// Call sites:
func (s *HostService) Create(ctx context.Context, req HostCreate) (*Host, error) {
    count, _ := s.repo.CountActiveHosts(ctx)
    if err := license.CheckQuota(license.QuotaMaxHosts, count); err != nil {
        return nil, err
    }
    return s.repo.Insert(ctx, req)
}
```

---

## 6. Data model

### 6.1 `licenses` table

```sql
CREATE TABLE licenses (
    id              UUID PRIMARY KEY,            -- license JTI claim
    tier            TEXT NOT NULL,               -- 'free' | 'openwatch_plus'
    customer_id     TEXT NOT NULL,
    customer_name   TEXT,
    issued_at       TIMESTAMPTZ NOT NULL,
    not_before      TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    features        JSONB NOT NULL,              -- string array
    quotas          JSONB NOT NULL,              -- {max_hosts: int, ...}
    fingerprint     TEXT,                        -- nullable
    raw_jwt         TEXT NOT NULL,               -- the original JWT for re-validation
    installed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    installed_by    UUID REFERENCES users(id),
    superseded_at   TIMESTAMPTZ,                 -- null = active; set when replaced
    last_validated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_known_good_time TIMESTAMPTZ NOT NULL DEFAULT now()  -- clock rollback baseline
);

CREATE INDEX idx_licenses_active ON licenses (installed_at DESC) WHERE superseded_at IS NULL;
```

**Why store the raw JWT:** allows the service to re-verify the license on every reload without re-reading the file. Also enables forensic review of past licenses.

**Only one active license at a time** — install supersedes the previous (sets `superseded_at`).

### 6.2 Audit events

License-related audit events use a stable namespace:

| Action | When emitted |
|---|---|
| `license.installed` | New license loaded (startup or SIGHUP) |
| `license.invalid` | License file failed validation |
| `license.expiring_soon` | Within 30 days of expiry (daily) |
| `license.expired` | First feature denial after grace period ended |
| `license.feature_check_denied` | Per-request denial (high-volume; rate-limit logging) |
| `license.quota_exceeded` | Quota limit hit |
| `license.clock_rollback_detected` | System clock < last_known_good_time |
| `license.tampered` | Fingerprint mismatch or signature failure on reload |

Per the audit-as-API contract, these are queryable via `/api/v1/audit/events?action=license.*`.

> **Rate limiting `license.feature_check_denied`:** if every denied request emits an audit event, a misbehaving client floods the audit log. Mitigation: deduplicate by `(actor_id, feature_id)` within a 1-minute window, emit at most one event per window. Counts in `detail.suppressed_count`.

---

## 7. CLI: `openwatch license`

Three subcommands cover the operator flow:

### 7.1 `openwatch license info`

Show current license state.

```
$ openwatch license info
License ID:        e21f5a8d-...
Customer:          Acme Corp
Tier:              openwatch_plus
Status:            active
Expires:           2027-01-15 (262 days)
Features:          audit_query, audit_export, temporal_queries, remediation_execution,
                   structured_exceptions, priority_updates, sso_saml, fido2_mfa
Quotas:
  max_hosts:               5000 (currently using 1247)
  max_scans_per_day:       50000
  max_users:               500 (currently using 23)
  max_concurrent_scans:    100
Installed:         2026-03-01 by admin@example.com
Last validated:    2026-04-28 14:32:00 UTC
Support contact:   support@hanalyx.com
```

### 7.2 `openwatch license verify <file>`

Verify a license file without installing. Useful before sending to a customer.

```
$ openwatch license verify /tmp/new-license.lic
✓ JWT structure valid
✓ Signature verified (key: license-pubkey-current.pem)
✓ Issuer matches
✓ Audience matches
✓ Validity window: 2026-05-01 → 2027-05-01 (active in 3 days)
✓ Features: 8 declared, all known
✓ Quotas: max_hosts=5000, max_scans_per_day=50000, max_users=500, max_concurrent_scans=100
- Deployment fingerprint: not bound

License is valid.
```

### 7.3 `openwatch license install <file>`

Verify and install. Sends SIGHUP to running service so reload happens without restart.

```
$ sudo openwatch license install /tmp/new-license.lic
Verifying license... ✓
Backup: /etc/openwatch/license.lic.bak (previous license)
Installing: /etc/openwatch/license.lic
Permissions: 0640 root:openwatch
Reloading openwatch service... ✓
Audit event: license.installed (license_id=e21f5a8d-...)

License installed successfully.
```

---

## 8. Spec coverage (Specter)

Behavioral specs live at `specs/system/license-validation.spec.yaml`,
`specs/system/license-features.spec.yaml`, and `specs/api/license.spec.yaml`.
The acceptance criteria below capture the design intent (the shipped specs
split these across the files above and may use updated AC ids):

```yaml
spec_id: system/licensing
status: active
version: 1.0
acceptance_criteria:
  - id: AC-1
    description: Service boots without license file in Free tier
  - id: AC-2
    description: Valid signed license unlocks declared features
  - id: AC-3
    description: Invalid signature is rejected; service falls back to Free tier; emits license.invalid
  - id: AC-4
    description: Expired license enters 30-day grace period before falling back to Free tier
  - id: AC-5
    description: Grace-period responses include Warning header
  - id: AC-6
    description: SIGHUP reload picks up new license without restart; emits license.installed
  - id: AC-7
    description: Each feature_check_denied emits a structured audit event (rate-limited per (actor, feature))
  - id: AC-8
    description: Clock rollback (>1h) is detected and license invalidated; emits license.clock_rollback_detected
  - id: AC-9
    description: Quota limits enforced at service boundaries with quota.<name>_exceeded error
  - id: AC-10
    description: alg=none, alg=HS256, and other non-EdDSA JWTs are rejected
  - id: AC-11
    description: License with deployment_fingerprint validates only on matching deployment
  - id: AC-12
    description: Public key rotation (current → prev → deprecated) preserves validation for old licenses
  - id: AC-13
    description: Adding a feature ID is non-breaking for existing licenses
```

13 ACs. Each one has at least one enforcing test. `specter coverage --enforce-active` blocks merge if any AC lacks coverage.

---

## 9. Frontend integration

The frontend is human-first, but it must respect license state. Pattern:

1. **On app load:** `GET /api/v1/capabilities` returns features and quotas
2. **Frontend caches** capabilities for the session
3. **UI rendering:**
   - Features not in the license: hide, OR show with "Upgrade to OpenWatch+" badge (operator-configurable)
   - Quota approaching limit (>80% used): show warning indicator
   - Quota at limit: disable creation UI, show "Limit reached" message
4. **Grace period:** banner at top of every page with expiry date and renewal CTA
5. **Expired:** banner persists; UI degrades gracefully to Free tier features only

This matches the principle from the Agent-First architecture: **frontend is human-first, API is agent-first**. The same `/capabilities` endpoint feeds both.

---

## 10. Failure modes and operator experience

| Scenario | System behavior | Operator experience |
|---|---|---|
| No license file at startup | Boot to Free tier; no audit event (this is normal for Free-tier deployments) | UI shows Free tier, no warnings |
| Invalid license file (bad signature, malformed JWT) | Boot to Free tier; emit `license.invalid` audit event; log error | UI banner: "License file invalid. Contact support." |
| Expired license at startup | If within grace period: load with grace flag. If past grace: load to Free tier; emit `license.expired` | UI banner: "License expired N days ago. Some features unavailable." |
| Quota exceeded at install | License loads; quota enforcement kicks in immediately; existing-state operations succeed but new ones fail | UI shows quota indicators; new creates fail with `quota.*_exceeded` error |
| Deployment fingerprint mismatch | License rejected; emit `license.tampered`; fall back to Free tier | UI banner: "License is bound to a different deployment. Contact support." |
| Clock rolled back | License rejected; emit `license.clock_rollback_detected`; fall back to Free tier | UI banner: "System time appears incorrect. License validation paused." |
| Public key rotated; old license signed with deprecated key | License loads with deprecation warning; emit `license.using_deprecated_key`; ask operator to renew | UI banner: "License signed with deprecated key. Please renew." |

The pattern: **always boot, never crash on license issues.** A bad license never prevents the service from starting. It just degrades to Free tier. Compliance scanning is operationally critical; the licensing layer must not become a single point of failure.

---

## 11. Build-time issuance flow (separate tool)

License generation lives in a separate small tool (`owlicgen`), not in OpenWatch itself:

```
$ owlicgen \
    --signing-key /vault/license-signing-key.pem \
    --customer-id cust-uuid-... \
    --customer-name "Acme Corp" \
    --tier openwatch_plus \
    --features audit_query,audit_export,temporal_queries,remediation_execution \
    --max-hosts 5000 \
    --max-scans-per-day 50000 \
    --valid-from 2026-05-01 \
    --valid-until 2027-05-01 \
    --output /tmp/acme-license.lic

Generated license: e21f5a8d-3c7a-4b1f-9e8d-...
File: /tmp/acme-license.lic (1247 bytes)
SHA256: 7a8b9c...

Verify with: openwatch license verify /tmp/acme-license.lic
```

`owlicgen` lives at `cmd/owlicgen/`. It is not shipped to customers. It uses the **private** signing key, which never leaves Hanalyx infrastructure. Customers never see this tool.

---

## 12. Stage 0 integration

Stage 0 (walking skeleton) currently includes:
- Audit log endpoint
- Idempotency middleware
- Correlation ID middleware

**Add to Stage 0 (Day 7 or new Day 8):**

- Load `/etc/openwatch/license.lic` at startup (or run Free tier if absent)
- Validate JWT signature against embedded public key
- Populate `license.State` atomic pointer
- Implement `license.IsEnabled` and `license.RequireFeature` middleware
- Add a single demo gated endpoint: `POST /api/v1/diagnostics:premium-echo` with `x-required-feature: premium_diagnostics`
- Without a license file, that endpoint returns `402 Payment Required` with `error.code = "license.feature_unavailable"`
- With a test license signed by a test key, the endpoint works
- Audit event `license.feature_check_denied` is emitted on the failed call

This is the minimum to prove the licensing seam works end-to-end before any real feature builds on it.

---

## 13. What this document does NOT address (yet)

These are licensing concerns deferred to later stages. Each one has a known answer; they're cataloged here so they don't get rediscovered as problems.

| Topic | Deferred to | Rationale |
|---|---|---|
| License revocation list (CRL) | Phase 2+ | Air-gapped doesn't support online CRL; if needed, ship CRL via signed update bundle |
| Trial license self-service | Phase 2+ | Today: customer talks to sales for a trial license. Self-service registration form is a marketing project, not a platform project |
| Floating / concurrent licenses | Not planned | OpenWatch is per-deployment, not per-user. Not a fit for the model |
| Usage-based billing telemetry | Not planned | Hanalyx model is fixed-tier subscriptions. If usage-based ever becomes a thing, telemetry is a separate workstream |
| License upgrade in place (Free → +) | Phase 1 | Implicit: operator just installs the new license. No migration needed |
| Multi-license aggregation | Not planned | One license per deployment, period |

---

## 14. Acceptance criteria for "foundation is built"

Stage 0 ships with the licensing foundation when:

- [ ] `internal/license/` package exists with all files listed in §5.1
- [ ] `licensing/features.yaml` exists with the 9 initial feature IDs
- [ ] Public key embedded in binary via `//go:embed`
- [ ] `IsEnabled(featureID)` is lock-free, O(1), and tested
- [ ] `RequireFeature(featureID)` middleware works in chi
- [ ] `:premium-echo` demo endpoint validates the end-to-end seam
- [ ] License loads at startup; SIGHUP triggers reload
- [ ] Audit events emit for install, invalid, denied, quota_exceeded
- [ ] `openwatch license info / verify / install` CLI works
- [ ] `owlicgen` tool generates valid licenses signed by the test key
- [ ] Specter specs `system/license-validation.spec.yaml`, `system/license-features.spec.yaml`, and `api/license.spec.yaml` exist covering the ACs above
- [ ] OpenAPI extension `x-required-feature` is documented in `docs/engineering/api_design_principles.md`
- [ ] Frontend `/capabilities` response includes the active feature set
- [ ] `licenses` table migration is in place

Once all 14 boxes are checked, downstream Phase-2 features can declare `x-required-feature` confidently and the gating "just works."

---

## 15. Why this is worth doing now, in detail

Three concrete failure modes are avoided by getting this right in Stage 0:

1. **The "decorator graveyard."** The current Python codebase has `@require_license(...)` calls scattered across handlers, with the actual `LicenseService.has_feature()` doing nothing meaningful (3 TODO stubs). When real validation gets added, every decorator has to be re-checked — but because `has_feature()` always returned `True`, no one wrote tests against the `False` branch. Hidden bugs everywhere. Doing it once, properly, in Stage 0, eliminates this class.

2. **The "schema-after" tax.** If licensing is added in Phase 2, the `licenses` table is a Phase-2 migration. But Phase-2 features depend on it for gating, which means the migration order has to be carefully sequenced. Doing it in Stage 0 means licensing is just... there, like the audit log.

3. **The "silent denial" failure mode.** Without proper audit events on denial, customers can't tell why a feature isn't working. Support tickets pile up: "is it a bug?" "is it a permission issue?" "is it the license?" Audit events make this answerable in seconds. Adding audit events later requires retrofitting every gate — easy to miss one. Build it in once.

The licensing foundation is roughly 1 extra day of Stage 0 work (15% of the budget). The cost of bolting it on later is at minimum 2 weeks of cross-cutting refactor, and at worst a class of latent bugs that surface only in production.

The roadmap budget can absorb 1 day. It cannot absorb 2 weeks.
