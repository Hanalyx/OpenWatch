# RBAC Registry — Design Specification

**Status:** Foundation, locked 2026-04-30
**Owner:** Backend platform
**Spec:** `specs/system/rbac.spec.yaml` (to be authored at Specter migration)
**Source-of-truth files:**
- `app/auth/permissions.yaml` — registry of permissions and built-in roles
- `internal/auth/permissions.gen.go` — codegen-typed Go constants
- `internal/auth/roles.gen.go` — codegen-typed built-in role definitions

---

## 1. Why this exists

OpenWatch enforces access control at three layers:

1. **Spec layer** — OpenAPI declares `x-required-permission: host:read` per operation.
2. **Handler layer** — Go middleware checks `user.HasPermission(perms.HostRead)`.
3. **Role layer** — A user's role has a list of permissions; the union of their roles' permissions is their effective set.

In a string-literal world (today's Python codebase), all three layers refer to permissions by free-form string. Drift arrives within a release:

- The spec says `host:read`. The handler checks `hosts:read`. The role grants `host.read`. All three are slightly different. Tests pass because fixtures grant superusers everything. Production fails when a real `auditor` role tries to list hosts and gets `403`.
- A new dangerous permission gets added to a handler but never to the registry. There is no audit hook that says "this permission was added"; reviewers don't know the surface grew.
- License-gated permissions (`remediation:execute` requires OpenWatch+) are gated in some places and not others — gating is a per-handler decoration that goes stale.

A registry collapses all three layers onto one source. The OpenAPI validator, the handler middleware, and the role definitions all read from the same file. Misspell a permission anywhere → build fails. License gating co-locates with permission definition → middleware enforces both in one pass. Custom roles created at runtime validate every permission against the registry → no silent grant of a permission that doesn't exist.

---

## 2. The one-line contract

> **Permissions are a registry, not a vocabulary. Every reference to a permission — in OpenAPI, in handler code, in built-in role definitions, in custom roles created at runtime — resolves through the registry. Drift becomes a build error.**

The registry has two sections:

- **Permissions** — immutable at runtime. Adding one is a code+spec change.
- **Built-in roles** — extensible via migration only. Updates ship in product releases.

**Custom roles** (Stage 2) are a third concept: runtime-mutable, DB-stored, but constrained by the registry — every permission they grant must be a registry permission.

---

## 3. Permission schema

Every entry in `app/auth/permissions.yaml` `permissions:` section conforms to:

```yaml
- id: host:read
  category: host
  description: View host details, list hosts, view host audit history
  dangerous: false           # optional; default false
  license_gated: null        # optional; default null
```

**Field semantics:**

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `id` | string | yes | `^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$` (resource:action). Stable across versions; never changes meaning. |
| `category` | string | yes | Must reference a `categories[].id`. The category is implied by the `id` prefix; this field exists for explicitness in tooling. |
| `description` | string | yes | One-line human description. Surfaced in admin UI and `/auth/permissions:registry`. |
| `dangerous` | boolean | no | `true` for destructive ops, license install, or anything that would warrant a "are you sure?" confirmation. UI uses for confirmation dialogs; audit middleware records as a high-priority denial. |
| `license_gated` | string | no | Feature ID from `app/license/features.yaml`. Permission is inert if the license doesn't include the feature. Combined RBAC+license check happens in one middleware pass. |

**Build invariants** (enforced by `scripts/validate-rbac.go`, run in CI):

- Every `id` matches the regex.
- Every `id`'s prefix matches a defined `categories[].id`.
- Every `license_gated` value matches a `feature.id` in `app/license/features.yaml`.
- `dangerous` is a boolean.
- No duplicates between `permissions:` and `deprecated_permissions:`.

### 3.1 Naming convention

Always **resource:action**, both lowercase, both underscore-separated within tokens:

```
host:read           ✓
host:connectivity_check ✓
scan_template:write ✓
remediation:execute ✓
```

Anti-patterns:

```
hosts:read          ✗ plural noun
host.read           ✗ dot separator (collides with audit codes)
host:Read           ✗ capitals
host_read           ✗ no separator
host:write_all      ✗ multi-token action
```

The action vocabulary is small: `read`, `write`, `delete`, `execute`, plus operation-specific verbs where appropriate (`approve`, `revoke`, `acknowledge`, `resolve`, `cancel`, `request`, `comment`, `connectivity_check`, `intelligence_refresh`, `test`, `rollback`, `install`, `reload`).

---

## 4. Codegen

### 4.1 Output

```go
// internal/auth/permissions.gen.go (DO NOT EDIT)

package auth

type Permission string

const (
    AuthRead             Permission = "auth:read"
    AuthWrite            Permission = "auth:write"
    UserRead             Permission = "user:read"
    UserWrite            Permission = "user:write"
    UserDelete           Permission = "user:delete"
    HostRead             Permission = "host:read"
    HostWrite            Permission = "host:write"
    HostDelete           Permission = "host:delete"
    HostConnectivityCheck    Permission = "host:connectivity_check"
    HostIntelligenceRefresh  Permission = "host:intelligence_refresh"
    // ... ~50 more ...
    RemediationExecute   Permission = "remediation:execute"
    AuditExport          Permission = "audit:export"
)

type PermissionMeta struct {
    Category     string
    Description  string
    Dangerous    bool
    LicenseGated string  // empty if not gated
}

var Permissions = map[Permission]PermissionMeta{
    HostRead: {Category: "host", Description: "View host details...", Dangerous: false, LicenseGated: ""},
    RemediationExecute: {Category: "remediation", Description: "Execute...", Dangerous: true, LicenseGated: "remediation_execution"},
    // ...
}

// AllPermissions returns every active permission id.
func AllPermissions() []Permission { ... }

// IsDangerous reports whether p is marked dangerous.
func IsDangerous(p Permission) bool { ... }

// LicenseGate returns the feature id required for p, or "" if none.
func LicenseGate(p Permission) string { ... }
```

```go
// internal/auth/roles.gen.go (DO NOT EDIT)

package auth

type RoleID string

const (
    RoleViewer        RoleID = "viewer"
    RoleAuditor       RoleID = "auditor"
    RoleOpsLead       RoleID = "ops_lead"
    RoleSecurityAdmin RoleID = "security_admin"
    RoleAdmin         RoleID = "admin"
)

// BuiltInRoles resolves wildcards at codegen time so the runtime never expands.
var BuiltInRoles = map[RoleID]RoleDefinition{
    RoleViewer: {ID: "viewer", Description: "...", Permissions: []Permission{
        AuthRead, HostRead, ScanRead, /* ... explicit list ... */
    }},
    // ...
}
```

### 4.2 Workflow for adding a permission

1. Add the entry to `app/auth/permissions.yaml`.
2. Run codegen: `go generate ./internal/auth/...`.
3. Add `x-required-permission: <id>` to the relevant OpenAPI operations.
4. Reference the typed constant from handler code: `requireAuth(perms.HostRead)`.
5. CI fails the build if an OpenAPI spec uses an unknown permission, or if a handler emits a string literal that doesn't match a constant.

### 4.3 Adding a built-in role

Built-in roles are extensible only via product release:

1. Add the entry to `app/auth/permissions.yaml` `roles:` section.
2. Author a migration that inserts the new row into `roles` with `is_built_in: true`.
3. Existing custom roles unaffected.

Modifying a built-in role's permission list is the same process. The migration UPDATEs the row; release notes call out the change. Customers running an older release see the older permission set.

### 4.4 Deprecation

Move retired permissions from `permissions:` to `deprecated_permissions:`:

```yaml
deprecated_permissions:
  - id: scan:legacy_export
    deprecated_at: 2026-04-30
    successor: audit:export
    notes: Replaced by unified audit export
```

While deprecated:

- OpenAPI specs cannot reference it (build fails).
- Handler code cannot reference it (constant removed; lint catches string literals).
- Existing custom roles in DB still work — the read endpoint surfaces a `deprecated_permissions: ["scan:legacy_export"]` warning attribute.
- After one product release, hard-remove from `deprecated_permissions:`. Custom roles auto-prune on next read; `admin.role.changed` audit event emitted with `detail.removed: ["scan:legacy_export"]`.

---

## 5. OpenAPI integration

### 5.1 The `x-required-permission` extension

```yaml
paths:
  /api/v1/hosts/{host_id}:
    get:
      operationId: getHost
      x-required-permission: host:read
      x-audit-events: []                    # reads don't emit audit (per audit taxonomy)
      responses: {...}

    delete:
      operationId: deleteHost
      x-required-permission: host:delete    # registry validates this is dangerous=true
      x-audit-events: [host.deleted]
      responses: {...}

  /api/v1/remediation/requests/{id}:execute:
    post:
      operationId: executeRemediation
      x-required-permission: remediation:execute  # registry validates license_gated
      x-required-feature: remediation_execution   # MUST match permissions.yaml license_gated
      x-requires-approval: remediation.execute
      x-audit-events: [remediation.requested, remediation.executed]
      responses: {...}
```

### 5.2 Cross-validation

The OpenAPI build validator enforces:

1. Every `x-required-permission` value is in the active permissions registry.
2. If a permission has `license_gated: X`, the operation must declare `x-required-feature: X` (or omit the permission). Mismatch → build fails.
3. If `x-required-permission` is `dangerous: true`, the operation MUST emit at least one audit event (`x-audit-events` non-empty). Dangerous ops without audit are a contradiction.

### 5.3 Multiple permissions per operation

A handler may require *any of* or *all of* multiple permissions. The extension supports both shapes:

```yaml
# Single permission (most common)
x-required-permission: host:read

# Any-of (rare; one of these is sufficient)
x-required-permission:
  any_of: [host:read, host:write]

# All-of (rare; user must have all)
x-required-permission:
  all_of: [host:write, scan:execute]
```

The vast majority of operations use the single-permission form.

---

## 6. The combined middleware

The same middleware that enforces the permission also enforces the license gate. One pass, one denial path, one audit event.

```go
// internal/auth/middleware.go

func RequirePermission(p Permission) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            ctx := r.Context()
            user, ok := UserFrom(ctx)
            if !ok {
                writeError(w, http.StatusUnauthorized, errors.AuthTokenMissing)
                return
            }

            // 1. Permission check
            if !user.HasPermission(p) {
                audit.Emit(ctx, audit.Event{
                    Action: audit.AuthzPermissionDenied,
                    Detail: map[string]any{
                        "required_permission": string(p),
                        "route":               r.URL.Path,
                    },
                })
                writeError(w, http.StatusForbidden, errors.AuthzPermissionDenied)
                return
            }

            // 2. License gate (if applicable)
            if feature := LicenseGate(p); feature != "" {
                if !license.IsEnabled(feature) {
                    audit.Emit(ctx, audit.Event{
                        Action: audit.LicenseFeatureCheckDenied,
                        Detail: map[string]any{"feature": feature, "permission": string(p)},
                    })
                    writeError(w, http.StatusPaymentRequired, errors.LicenseFeatureUnavailable)
                    return
                }
            }

            next.ServeHTTP(w, r)
        })
    }
}
```

**Order matters.** Auth (who are you?) → idempotency → RBAC+license → handler. The full chain:

```
correlation → auth → idempotency → RBAC+license → handler → audit emit
```

`oapi-codegen` produces this wiring from the `x-required-permission` extension. Handlers do not call `RequirePermission` themselves; the middleware is generated.

---

## 7. The user's effective permissions

```go
type User struct {
    ID    uuid.UUID
    Roles []RoleID
    // ...
}

func (u *User) HasPermission(p Permission) bool {
    for _, roleID := range u.Roles {
        role, ok := lookupRole(roleID)
        if !ok {
            continue
        }
        if role.HasPermission(p) {
            return true
        }
    }
    return false
}

func (r *RoleDefinition) HasPermission(p Permission) bool {
    for _, granted := range r.Permissions {
        if granted == "*" {
            return true
        }
        if matchesWildcard(granted, p) {
            return true
        }
        if granted == p {
            return true
        }
    }
    return false
}

func matchesWildcard(granted, p Permission) bool {
    // granted is "host:*"; p is "host:read"
    if !strings.HasSuffix(string(granted), ":*") {
        return false
    }
    grantedCategory := strings.TrimSuffix(string(granted), ":*")
    pCategory, _, ok := strings.Cut(string(p), ":")
    return ok && grantedCategory == pCategory
}
```

**Built-in roles have wildcards expanded at codegen time** (per `BuiltInRoles` in `roles.gen.go`); the runtime check never expands. **Custom roles store wildcards as-is** (so a category-level grant continues to cover newly added permissions in that category); the runtime expands per-call.

### 7.1 The bare wildcard `*`

Reserved for the built-in `admin` role. The validation rule:

```go
func validateRolePermissions(roleID RoleID, perms []Permission, isBuiltIn bool) error {
    for _, p := range perms {
        if p == "*" && (!isBuiltIn || roleID != RoleAdmin) {
            return fmt.Errorf("bare wildcard '*' is reserved for the built-in admin role")
        }
        // ... category-wildcard and exact-match validations ...
    }
    return nil
}
```

A custom role that wants "everything" must list permissions explicitly (or use category wildcards like `host:*`, `scan:*`, etc.). This is a deliberate friction: cloning admin without code review sidesteps the audit trail of "who is the most privileged role in the system."

---

## 8. Custom roles (Stage 2 preview)

Stage 0 ships the registry, built-in roles, and the lookup endpoints. Stage 2 ships custom-role CRUD when user management lands.

### 8.1 The `roles` table

```sql
CREATE TABLE roles (
    id              TEXT PRIMARY KEY,
    description     TEXT NOT NULL,
    is_built_in     BOOLEAN NOT NULL DEFAULT false,
    permissions     TEXT[] NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by      UUID REFERENCES users(id)
);

CREATE TABLE user_roles (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id    TEXT NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    granted_by UUID REFERENCES users(id),
    PRIMARY KEY (user_id, role_id)
);
```

### 8.2 The custom-role API (Stage 2)

```
POST   /api/v1/admin/roles                  # create custom role
PUT    /api/v1/admin/roles/{id}             # update custom role; built-ins → 405
DELETE /api/v1/admin/roles/{id}             # delete custom role; built-ins → 405
POST   /api/v1/admin/roles/{id}:assign      # assign to user
POST   /api/v1/admin/roles/{id}:unassign    # remove from user
POST   /api/v1/admin/roles/{id}:clone       # sugar: clone built-in to custom
```

All declare `x-required-permission: admin:role_manage`.

### 8.3 Validation at custom-role create

The handler:

1. Validates `id` matches `^[a-z][a-z0-9_]{1,63}$`, not a built-in role name.
2. **Validates every permission against the registry.** Unknown permission → `400` with `error.code = "validation.field_unknown"` and `detail.invalid_permissions: [...]`.
3. Validates wildcards: bare `*` rejected; category wildcards expanded for the response (so the admin sees what they granted).
4. Counts dangerous permissions and includes a warning array in the response.
5. Counts license-gated permissions; warns if the license currently doesn't enable them.
6. Inserts; emits `admin.role.changed` audit event.

### 8.4 Custom roles and license-gated permissions

A custom role with `remediation:execute` is **allowed** even if the license does not enable `remediation_execution`. The permission is inert at runtime — the combined middleware denies. This means:

- Admins can pre-stage roles before purchasing OpenWatch+ (the role exists; activates when license arrives).
- License downgrade does not require role cleanup. Roles continue to grant the permission; runtime simply denies until license re-enables.

### 8.5 Custom roles and policy cross-validation

The `approvals` policy declares `approver_roles: [security_admin, ops_lead]`. The policy loader validates these against the active role set (built-in + custom). An unknown role → `policy.invalid` audit event; previous policy state retained. Custom roles can therefore appear in approver lists once they exist.

---

## 9. The lookup endpoints

### 9.1 `GET /api/v1/auth/me/permissions` (Stage 0)

Returns the calling user's effective permissions (union of all their roles' permissions, wildcards expanded against the current registry).

```json
{
  "user_id": "018f3c2a-...",
  "roles": ["ops_lead"],
  "permissions": [
    "auth:read", "auth:write",
    "host:read", "host:write", "host:connectivity_check", "host:intelligence_refresh",
    "scan:read", "scan:execute", "scan:cancel",
    "..."
  ],
  "license_gated_unavailable": ["audit:export"]
}
```

`license_gated_unavailable` lists permissions the user technically has via their role but the license currently denies. Helps the frontend hide buttons that would always 402.

`x-required-permission: auth:read` (every authenticated user can see their own).

### 9.2 `GET /api/v1/auth/permissions:registry` (Stage 0)

Returns the full registry — categories, permissions, built-in roles. Frontend uses to render permission selectors and role editors.

```json
{
  "version": 1,
  "categories": [
    {"id": "host", "description": "Host management permissions"},
    "..."
  ],
  "permissions": [
    {"id": "host:read", "category": "host", "description": "...", "dangerous": false, "license_gated": null},
    "..."
  ],
  "built_in_roles": [
    {"id": "viewer", "description": "...", "permissions": ["auth:read", "..."]},
    "..."
  ],
  "deprecated_permissions": []
}
```

`x-required-permission: auth:read` (the registry is non-secret; any authenticated user can read it to render their own UI).

### 9.3 `GET /api/v1/admin/roles` (Stage 0; Stage 2 expands)

Stage 0: returns the built-in roles only.
Stage 2: returns built-in + custom roles, with `is_built_in: bool` per row.

`x-required-permission: admin:role_manage`.

---

## 10. CI enforcement

Three layers (parallel to correlation, audit, policy patterns):

### 10.1 Forbidigo lint

```yaml
# .golangci.yml
linters-settings:
  forbidigo:
    forbid:
      - p: '"[a-z_]+:[a-z_]+"'
        msg: "Use auth.<PermissionConstant> from internal/auth/permissions.gen.go — raw permission strings drift"
        # exclusions: internal/auth/* (the registry-loading code itself)
```

The pattern is intentionally broad and triggers on string literals that *look like* permissions. Reviewers add `//nolint:forbidigo` annotations on legitimate exceptions (test fixtures, schema validators).

### 10.2 OpenAPI validator extension

`scripts/validate-openapi.go` walks every operation:

- Every `x-required-permission` value (or any-of/all-of list) resolves to a registry permission.
- License-gated permissions co-declare `x-required-feature` matching the registry's `license_gated`.
- Dangerous permissions co-declare `x-audit-events` non-empty.

### 10.3 Behavioral spec

`specs/system/rbac.spec.yaml` (post-Specter migration):

```yaml
spec_id: system/rbac
status: active
acceptance_criteria:
  - id: AC-1
    description: Permission registry validates against schema (ids, categories, license_gated cross-refs)
  - id: AC-2
    description: Built-in role wildcards expand at codegen time
  - id: AC-3
    description: Custom role create rejects unknown permissions
  - id: AC-4
    description: Custom role create rejects bare wildcard "*"
  - id: AC-5
    description: Combined RBAC+license middleware denies when license missing feature
  - id: AC-6
    description: HasPermission honors category wildcards in custom roles
  - id: AC-7
    description: Deprecated permissions are pruned from custom roles on next read
  - id: AC-8
    description: Built-in roles cannot be modified via API (PUT/DELETE return 405)
  - id: AC-9
    description: GET /auth/me/permissions includes license_gated_unavailable
```

---

## 11. Anti-patterns

| Anti-pattern | What's wrong | What to do instead |
|--------------|--------------|---------------------|
| `if user.HasPermission("host:read")` | Raw string literal; drifts from the registry. | `user.HasPermission(auth.HostRead)`. Lint enforces. |
| Hardcoding role names in handler logic (`if user.RoleID == "admin"`) | Couples handler logic to a specific role; breaks when admins create custom roles with similar capability. | Check permissions, not roles. `if user.HasPermission(auth.AdminRoleManage)` is what you actually mean. |
| Adding a permission to a built-in role via DB UPDATE in production | Built-in role definitions are migration-driven. A direct UPDATE is invisible to release notes and may be reverted by the next migration. | Author a migration; ship in the next release. Or create a custom role for the customer's edge case. |
| Granting `*` to a custom role to "make it work" | Bare wildcard is reserved. Granting it via direct DB write bypasses validation but makes the role indistinguishable from `admin`. | Either use `admin` or list permissions explicitly. |
| Checking RBAC inside the handler instead of via middleware | Bypasses the codegen-driven license-gate co-check; surfaces inconsistent denial paths. | Declare `x-required-permission` in OpenAPI; let codegen wire the middleware. |
| Treating permissions as feature flags | They aren't. License features (`features.yaml`) are the feature-flag layer; permissions are RBAC. A permission says "user may do X"; a feature says "this build can do X." | Use both: license-gated permissions co-locate them. |

---

## 12. Failure modes and edge cases

| Scenario | Behavior |
|----------|----------|
| Permission added to registry but no handler references it | Build passes; the permission is dormant. UI permission selectors show it. Acceptable — not every registered permission must have a handler in the same release. |
| Permission referenced in OpenAPI but not in registry | Build fails with `unknown permission: foo:bar` |
| Built-in role definition references a permission that doesn't exist | Build fails at codegen. |
| Custom role in DB references a deprecated permission | Read endpoint returns the role with `deprecated_permissions: [...]`. Permission still works during deprecation window. After hard removal: pruned with audit event. |
| Custom role in DB references a permission that was hard-removed | Pruned at read time; `admin.role.changed` audit event with `detail.removed: [...]`. Role continues to function with remaining permissions. |
| User has zero roles assigned | `user.HasPermission(*)` always returns false. All non-public endpoints return 403. Audit event `authz.permission_denied`. |
| User assigned a role that was deleted | `lookupRole` returns false; that role contributes zero permissions. Other roles still apply. |
| License downgraded mid-session; user's role had `remediation:execute` | Permission check passes (role grants it); license check fails; user gets `402` with `error.code = "license.feature_unavailable"`. Per-call enforcement, no session invalidation. |
| Admin tries to update built-in role via PUT /admin/roles/admin | `405 Method Not Allowed` with `error.code = "resource.builtin"`. |
| Custom role create with 200 permissions including 50 dangerous | Allowed if all in registry, but warning array lists all 50 dangerous IDs; UI shows confirmation dialog before submit. |
| Two admins simultaneously create roles with the same id | First wins (`UNIQUE(id)`); second gets `409` with `error.code = "resource.conflict"`. |
| Wildcard `host:*` granted at time T; new permission `host:reboot` added at time T+1 | Custom role retains the wildcard, so it now also grants `host:reboot`. Built-in roles, having codegen-expanded lists, do NOT pick up the new permission until the next migration. This is a deliberate asymmetry: built-in role updates ship as releases (auditable), custom role updates are admin actions (auditable per assignment, but the permission set follows the wildcard semantics that were declared at creation). |

---

## 13. Stage 0 vs Stage 2 split

### Stage 0 ships (Day 8, after licensing on Day 7):

- `app/auth/permissions.yaml` registry
- `internal/auth/permissions.gen.go` and `roles.gen.go` codegen
- Permission validator (`scripts/validate-rbac.go`) wired into CI
- `RequirePermission` middleware (with combined license-gate logic)
- OpenAPI validator extension for `x-required-permission` and cross-checks
- Migration `0004_roles.sql`: creates `roles` and `user_roles` tables; inserts the 5 built-in roles with `is_built_in=true`
- `GET /api/v1/auth/me/permissions` (returns built-in role expansion for current user; user model is stub until Stage 2 auth)
- `GET /api/v1/auth/permissions:registry`
- `GET /api/v1/admin/roles` (built-ins only)
- Forbidigo lint config for raw permission-string literals
- Stage 0 demo endpoint `POST /api/v1/diagnostics:require-host-read` declared with `x-required-permission: host:read` to verify the middleware fires

### Stage 0 does NOT ship:

- User model (Stage 2 auth slice)
- Custom-role CRUD (`POST/PUT/DELETE /admin/roles`)
- `:assign`/`:unassign` endpoints
- `:clone` sugar
- Role-management audit events tied to real users (the events exist in the audit registry; they emit when Stage 2 user management lands)

The Stage 0 work is small (~600 LOC + registry + migration + lint config) but locks the contract before any consumer exists. Every Stage-2 endpoint that declares `x-required-permission` lands into a working middleware.

---

## 14. Performance

| Operation | Target | Notes |
|-----------|--------|-------|
| `RequirePermission` middleware overhead | < 1µs | Two map lookups (user → roles, role → permissions); no DB round-trip — user struct loaded by auth middleware upstream |
| Built-in role lookup | < 50ns | Compile-time map |
| Custom role lookup | < 100µs | Cached in process; cache invalidation on `admin.role.changed` audit event (Stage 2) |
| Wildcard match in custom role | < 200ns | `strings.HasSuffix` + `strings.Cut`; no regex |
| `GET /auth/me/permissions` | < 5ms | One DB read for user_roles join, one cache read for role definitions |

The middleware is hot-path; it must not allocate. Codegen-expanded built-in role permissions are slices indexed by RoleID; the slice is read directly without copying.

---

## 15. Open questions

1. **Per-resource scoping** (data-level authorization). "User can read host X but not host Y." This is row-level / attribute-based access control; the registry handles role-level only. Defer to a separate ABAC design when needed; scoping logic lives in repository layer, not handlers.
2. **Permission groupings for UI** (e.g., "all host-management permissions" as a single checkbox in the role editor). The UI can render groupings from `categories`; no registry change needed.
3. **Time-bounded role assignments** ("user is `security_admin` until 2026-06-01"). Useful for short-term escalation. Defer; for now, admin manually unassigns. If demanded, add `expires_at` to `user_roles`.
4. **Permission usage telemetry** ("which permissions are never used in production?"). Helpful for retiring unused permissions. Out of scope for Stage 0; telemetry collection is its own initiative.
5. **Role inheritance** (`security_admin` inherits from `ops_lead` plus extras). Rejected for v1: clone-and-extend is simpler and the explicit permission list is what reviewers want to read. Revisit if role definitions grow past ~30 permissions and clone-drift becomes painful.
6. **Permissions for self-actions vs others** (e.g., `auth:write` is changing your own password; `user:write` is changing someone else's). The current design uses category separation (`auth:*` for self, `user:*` for admin-managed). Acceptable for now; revisit if self-vs-other surface grows.

---

## Cross-references

- License features: `app/license/features.yaml` — `license_gated` permissions reference these IDs.
- Audit events: `app/audit/events.yaml` — `authz.permission_denied`, `authz.role.assigned`, `authz.role.removed`, `admin.role.changed`, `license.feature_check_denied`.
- Error codes: `app/api/error_codes.yaml` — `authz.permission_denied`, `authz.role_required`, `license.feature_unavailable`, `validation.field_unknown`, `resource.conflict`, `resource.builtin` (to be added).
- Policies: `app/docs/policies_as_data.md` §5.2 — `approver_roles` cross-validates against active role set.
- API design: `app/docs/api_design_principles.md` §11 (extensions including `x-required-permission`).
- Roadmap: 2026-04-30 entries on this design.
- Stage 0: Day 8 (after licensing Day 7, before policies Day 9).
