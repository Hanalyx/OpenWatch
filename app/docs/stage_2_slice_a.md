# Stage 2 — Slice A: Auth + Add a Host

> **Status:** Plan (locked 2026-05-25)
> **Goal:** Replace the `X-Stub-Role` shim with real identity. Add the first real product object — a host you can scan against — including the credentials needed to reach it.
> **Estimate:** 3–5 weeks of focused work
> **Pre-req:** `stage-0-complete` tag (18/18 specs at 100% strict, all foundations wired)
> **Output:** ~6 new specs at 100% strict coverage, ~15 new endpoints, real auth on every existing endpoint, two new database scopes (users + hosts) with full RBAC + audit integration

---

## Why this slice exists

Stage 0 proved every foundation works. Stage 2 Slice A is the first time an operator can actually USE the platform: log in, prove who you are, register a host, verify the platform can reach it. Every Stage-0 endpoint is still gated by the `X-Stub-Role` header today; Slice A replaces that with real identity bound from a real credential. After Slice A, the demo header is gone and any caller without a session token gets 401.

This slice deliberately does NOT include scans, findings, or compliance state — those land in Slice B. The scope discipline is: **the platform can authenticate a user and reach a host**. That's it.

---

## Locked design decisions

These are the answers from the 2026-05-25 scoping conversation. Every implementation decision rolls up to one of these:

### 1. Auth surface

- **Both** JWT and sessions. JWT for API consumers (tools, automation, the frontend's API client). Sessions for browser sign-in (cookie-bound, CSRF-protected). The same `users` row backs both.
- **TOTP MFA** ships with the slice. Required for every user; first login enrolls. Free-tier feature.
- **OIDC + SAML** declared in the registry but **license-gated** (`sso_saml` feature on the openwatch_plus tier). Wired in Slice A as stubs that return 402 without the license; full implementation lands in a follow-up slice. The free-tier baseline is local username + password + TOTP.

### 2. Password policy: NIST SP 800-63B

| Requirement | Value |
|---|---|
| Min length | 8 chars (15 for users with the `admin` role) |
| Max length | 64 chars enforced; 128 chars accepted (longer truncated to 128) |
| Character class rules | **None** — length is the signal |
| Forced rotation | **Prohibited** — rotation only on suspected compromise |
| Breach corpus check | **Required** — local SHA-1 prefix list (top 1M compromised passwords), refreshed offline |
| Lockout | Rate-limit attempts (10/min/IP and 5/min/user), not hard lockout |
| Password hints | Forbidden — `hint` field never present in schema |
| KDF | Argon2id, 64 MiB memory, 3 iterations, 1 lane (matches Stage-0 spec for license signing strength) |

### 3. Session timeouts

- Inactivity: 15 minutes (matches Python backend)
- Absolute: 12 hours (matches Python backend)
- Refresh token: 7 days, rotated on every use
- JWT access token: 30 minutes
- Stored sessions persisted in `sessions` table (server-side; can be revoked individually)

### 4. Identity model

- `users.id` is `UUID` (server-assigned, stable across renames)
- `users.username` is the human handle; unique
- `users.email` is informational; unique; used for MFA-recovery flows later
- No `(hostname, environment)`-style natural key on users — username is the natural key

### 5. Host inventory (Slice-A subset)

Columns shipped in Slice A:

| Field | Type | Notes |
|---|---|---|
| `id` | UUID PK | Server-assigned |
| `hostname` | TEXT NOT NULL | FQDN; unique with environment |
| `ip_address` | INET NOT NULL | IPv4 or IPv6 |
| `port` | INTEGER NOT NULL DEFAULT 22 | SSH port |
| `display_name` | TEXT | Operator-friendly label |
| `description` | TEXT | |
| `environment` | TEXT NOT NULL DEFAULT 'production' | Label string (`production` / `staging` / etc.) |
| `tags` | TEXT[] NOT NULL DEFAULT '{}' | GIN-indexed |
| `group_id` | UUID NULL | Forward-compatibility — groups land in a later slice |
| `username` | TEXT NULL | Per-host override; null = fall back to system credential |
| `created_by` | UUID NOT NULL REFERENCES users(id) | |
| `created_at` | TIMESTAMPTZ NOT NULL DEFAULT now() | |
| `updated_at` | TIMESTAMPTZ NOT NULL DEFAULT now() | |
| `deleted_at` | TIMESTAMPTZ NULL | Soft delete; partial unique index `WHERE deleted_at IS NULL` |

Columns **deferred** to later slices (each lands with its producer):
- `operating_system`, `os_family`, `os_version`, `architecture`, `platform_identifier` — discovered by Kensa (Slice B)
- `status`, `last_check`, `next_check_time`, consecutive-failure/success counters — populated by the adaptive scheduler (post-Slice-B)

Unique constraints:
- `UNIQUE (hostname, environment) WHERE deleted_at IS NULL`

### 6. SSH credentials — symmetric tier model (Option B)

One `credentials` table for both scopes:

| Field | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `scope` | TEXT NOT NULL CHECK IN ('system','host') | Slice A: these two only; `host_group` reserved |
| `scope_id` | UUID NULL | NULL for `scope=system`; host UUID for `scope=host` |
| `name` | TEXT NOT NULL | e.g. "default ops account" |
| `description` | TEXT | |
| `username` | TEXT NOT NULL | |
| `auth_method` | TEXT NOT NULL CHECK IN ('ssh_key','password','both') | |
| `encrypted_password` | BYTEA NULL | AES-256-GCM |
| `encrypted_private_key` | BYTEA NULL | AES-256-GCM |
| `encrypted_private_key_passphrase` | BYTEA NULL | AES-256-GCM |
| `ssh_key_fingerprint` | TEXT NULL | SHA256:base64 — display metadata |
| `ssh_key_type` | TEXT NULL | ed25519, rsa, ecdsa |
| `ssh_key_bits` | INTEGER NULL | |
| `ssh_key_comment` | TEXT NULL | |
| `is_default` | BOOLEAN NOT NULL DEFAULT false | Only one row WHERE scope='system' AND is_default=true |
| `is_active` | BOOLEAN NOT NULL DEFAULT true | |
| `created_by` | UUID NOT NULL REFERENCES users(id) | |
| `created_at`, `updated_at` | TIMESTAMPTZ | |

Unique constraints + invariants:
- `UNIQUE (scope, scope_id, name) WHERE is_active = true`
- Partial unique index: `UNIQUE WHERE scope='system' AND is_default=true` (only one system default)
- CHECK: `scope='system' → scope_id IS NULL`
- CHECK: `scope='host' → scope_id IS NOT NULL`
- CHECK: `auth_method IN ('ssh_key','both') → encrypted_private_key IS NOT NULL`
- CHECK: `auth_method IN ('password','both') → encrypted_password IS NOT NULL`

Resolver (`internal/credential/resolve.go`):
```
Resolve(ctx, hostID) →
    1. SELECT credentials WHERE scope='host' AND scope_id=hostID AND is_active=true
       Return if found (highest precedence).
    2. SELECT credentials WHERE scope='system' AND is_default=true AND is_active=true
       Return if found.
    3. Return ErrNoCredential.
```

The resolver returns *one* fully-formed credential — never blends fields across tiers. Mixed-tier credentials are a footgun.

### 7. Encryption key for credentials

`credentials.*` fields are encrypted at rest with AES-256-GCM. The data-encryption key (DEK) is loaded from `/etc/openwatch/secrets/credential-key` (32 random bytes, mode 0600, owner openwatch). The key path is configurable via `OPENWATCH_CREDENTIAL_KEY_FILE`. **Out of scope for Slice A**: KMS / Vault integration — that lands as a Slice-A.5 if needed.

The DEK is **separate** from the license signing key. License keys are public-key crypto (Ed25519) verifying signed JWTs; credential keys are symmetric AES for encrypting secrets at rest. Same operator-managed file, different key.

### 8. Audit additions

New audit codes (added to `audit/events.yaml`, codegen regenerated):

- `auth.login.success`, `auth.login.failure` (exist)
- `auth.logout` (exist)
- `auth.session.created`, `auth.session.revoked`, `auth.session.expired`
- `auth.password.changed`, `auth.password.policy_failed`
- `auth.mfa.enrolled`, `auth.mfa.challenged`, `auth.mfa.failed` (some exist)
- `user.created`, `user.updated`, `user.deleted`, `user.role_assigned`, `user.role_removed`
- `host.created`, `host.updated`, `host.deleted`
- `host.connectivity_check` (success/failure carried via `Event.Outcome`)
- `credential.created`, `credential.updated`, `credential.deleted`, `credential.used`

Pre-store redaction (already in place from Stage 0) handles `password`, `ssh_key`, `private_key_passphrase`, `secret`, `token`, `license_jwt`. We add `credential_dek` to the redaction list to be safe; the DEK itself never appears in any code path that emits audit, but defense in depth.

---

## New specs (writing order)

Each spec gets ~10-15 ACs. Total ~80-100 ACs across the slice.

| Order | Spec | Tier | Scope |
|---|---|---|---|
| 1 | `system-auth-identity` | T1 | Password hashing, password policy enforcement, breach corpus check, session token issue/verify/revoke, JWT issue/verify/refresh, MFA TOTP enrollment + challenge |
| 2 | `system-user-management` | T1 | `users`+`user_roles` schemas, user CRUD service layer, role assignment with custom-role validation |
| 3 | `system-credential-store` | T1 | `credentials` schema, AES-256-GCM at rest, resolver with system→host fallback, key file loading + validation |
| 4 | `system-host-inventory` | T2 | `hosts` schema, host CRUD service layer, soft delete, tag array index |
| 5 | `system-ssh-connectivity` | T2 | SSH dial against a host's resolved credential, known-hosts policy, NIST SP 800-57 key bit checks (RSA ≥2048, Ed25519 always OK), timeout enforcement |
| 6 | `api-auth` | T1 | `POST /auth/login`, `POST /auth/logout`, `POST /auth/refresh`, `GET /auth/me`, `POST /auth/mfa:enroll`, `POST /auth/mfa:verify`, `POST /auth/password:change` |
| 7 | `api-users` | T2 | `GET/POST/GET-by-id/PUT/DELETE /admin/users`, `POST /admin/users/{id}/roles:assign`, `:unassign`, `POST /admin/roles` (custom-role create — finally lands per `docs/rbac_registry.md §8`) |
| 8 | `api-credentials` | T2 | `GET/POST/PUT/DELETE /admin/credentials` (scope=system), `GET/POST/PUT/DELETE /hosts/{id}/credentials` (scope=host) |
| 9 | `api-hosts` | T2 | `GET/POST/GET-by-id/PUT/DELETE /hosts`, `POST /hosts/{id}:connectivity-check`, `GET /hosts/{id}/audit-events` |

Specs 1-5 are "system" (foundation behavior); 6-9 are "api" (HTTP surface). Implementation order matches.

---

## Implementation plan (week-by-week)

### Week 1 — Auth foundation

| Day | Deliverable |
|---|---|
| 1 | `internal/identity/` package: password hashing (Argon2id), password policy validator (NIST 800-63B), breach corpus check (local SHA-1 prefix list, no network) |
| 2 | `users` table migration; `users` repository; CRUD service |
| 3 | TOTP enrollment + verify; `auth_mfa_secrets` table; QR-code provisioning URI generation |
| 4 | Session token mint/verify/revoke; `sessions` table; refresh-token rotation; absolute-timeout enforcement |
| 5 | JWT mint (RS256) and verify; the same `users` row issues both — JWT for API, session cookie for browser |

By Friday: `internal/identity/` is feature-complete, fully tested at 100% strict spec coverage. No HTTP yet.

### Week 2 — Credentials + host model

| Day | Deliverable |
|---|---|
| 1 | `internal/credential/` package: AES-256-GCM encrypt/decrypt; DEK loader from configurable path |
| 2 | `credentials` table migration; `credentials` repository; CRUD service; resolver with fallback |
| 3 | `hosts` table migration; `hosts` repository; CRUD service with soft delete |
| 4 | `internal/ssh/` package: dial, known-hosts policy, key-bit validator, timeout-bound connectivity check |
| 5 | Buffer day; load testing of resolver hot path; bench the credential decrypt + dial chain end-to-end |

### Week 3 — HTTP surface

| Day | Deliverable |
|---|---|
| 1 | `api/auth.yaml` OpenAPI subspec; `POST /auth/login`, `/logout`, `/refresh`, `GET /auth/me`. Replace `auth.StubIdentityBinder` with the real identity binder. Every existing endpoint now gets real `auth.Identity` from the session/JWT. |
| 2 | `POST /auth/mfa:enroll`, `/auth/mfa:verify`, `POST /auth/password:change`. Login flow enforces MFA challenge. |
| 3 | `api/users.yaml`; user CRUD endpoints; role-assignment endpoints; custom-role CRUD finally ships (per `rbac_registry.md §8`) |
| 4 | `api/credentials.yaml`; system + host credential CRUD; on read the encrypted fields are NEVER returned — only metadata (fingerprint, key type, key bits). The plaintext only leaves the DB into an SSH dial; the API surface returns null for the secrets. |
| 5 | `api/hosts.yaml`; host CRUD endpoints; `POST /hosts/{id}:connectivity-check` performs a real SSH dial via the resolved credential and returns success/failure + diagnostic detail (NEVER the credential itself) |

### Week 4 — Wire-through + integration

| Day | Deliverable |
|---|---|
| 1 | Remove `auth.StubIdentityBinder` from production code path; tests still use it via a build-tag-isolated test helper. Every API integration test now uses a real login + token. |
| 2 | OIDC + SAML stubs: handler endpoints exist, return 402 license.feature_unavailable when called, audit-log the attempt. Real implementations are a follow-up. |
| 3 | Update `docs/install_guide.md` with the first-run flow: bootstrap-admin command, login, MFA enrollment, replace demo cert (which already exists), add a host. |
| 4 | Re-run the 19-step DoD from `release-stage-0-signoff` — every step still passes, but now via real auth instead of stub roles. Update DoD with the new step list (no more `X-Stub-Role`). |
| 5 | `make check` clean; specter sync clean; `slice-a-complete` tag candidate |

### Week 5 — Buffer / cleanup

Reality buffer. Estimated days are honest but real engineering surfaces unknown-unknowns. Use this week to:
- Fix anything that surfaced under load
- Tighten any flaky tests
- Pay any test debt (the 4 Stage-1 modules `auth.token_blacklist_pg`, `auth.credential_handler` that Stage-1 evidence called out for Slice A entry)
- Documentation passes
- Code review cycle

If Week 5 is genuinely empty: ship and move to Slice B early.

---

## What replaces the `X-Stub-Role` header at the end

```go
// Before (Stage 0):
r.Use(auth.StubIdentityBinder)  // reads X-Stub-Role

// After (Slice A):
r.Use(auth.IdentityBinder(identityService))  // reads session cookie or JWT bearer
```

Same `auth.Identity` shape on the request context. Same `RequirePermission` / `EnforcePermission` middleware. Same RBAC + license-gate ordering. The Identity is just *real* now.

Test fixtures get a build-tag isolated helper: `auth_test_helpers.go` under `//go:build test` (or similar) that lets tests mint sessions without going through the full login flow. Production builds physically cannot import the helper.

---

## Stage-2 entry criteria (from Stage 1 evidence)

From `docs/MUST_BACKEND_FUNCTIONALITY.md §Correction 2`, **Slice A cannot ship without test coverage for**:

- `services/auth/credential_handler.py` — equivalent functionality lives in `internal/credential/` (spec `system-credential-store`)
- `services/auth/token_blacklist_pg.py` — equivalent functionality lives in `internal/identity/sessions.go` (spec `system-auth-identity` AC covering "revoked session rejects subsequent requests")

These are entry criteria. The specs above already cover them — flagging here so the test debt list from Stage 1 is explicitly closed.

---

## Out of scope (explicit deferrals)

Calling these out so they don't accidentally creep in:

- **OIDC / SAML full implementation** — handlers exist as 402-stubs in Slice A; real flows are a follow-up slice (call it Slice A.5 — SSO providers).
- **Host groups** — `hosts.group_id` column exists but no `host_groups` table yet. Group CRUD and group-level credentials land with Slice B or A.5 (TBD by which one needs it first).
- **OS discovery / fingerprinting** — Kensa does that. Lands in Slice B.
- **Adaptive scheduler** — has its own spec doc (`docs/openwatchos/02-ADAPTIVE-COMPLIANCE-SCHEDULER.md`); needs scans to exist. Lands post-Slice-B.
- **KMS / Vault credential keys** — file-based DEK in Slice A. KMS integration is operator-driven; lands if/when a customer needs it.
- **WebAuthn / FIDO2** — `fido2_mfa` license feature is in the registry; TOTP is the Slice-A MFA baseline. FIDO2 lands as a follow-up MFA method behind the license gate.
- **API keys** (for automation that doesn't want JWT lifecycle) — useful but not in Slice A. Slice B if there's demand.
- **Self-service signup** — no operator has asked for this. Admin creates accounts; that's it for Slice A. Slice A.5 (or never) for self-service.

---

## What "Slice A done" means concretely

The 19-step Definition of Done from Stage 0 is updated:

| # | Step | Status after Slice A |
|---|------|----------------------|
| 1-5 | Build + install + service start | Unchanged |
| 6 | `systemctl start openwatch` | Unchanged |
| 7-10 | health, echo, audit, replay | Now require Bearer token from a real login |
| 11-15 | RBAC + license demo endpoints | `X-Stub-Role` removed; role comes from the user's `user_roles` |
| 16 | Enqueue test job | Same |
| 17 | `specter sync` | Same — strict mode passes |
| 18 | Cert hot-reload | Same |
| 19 | DB persistence across restart | Same |
| **NEW 20** | `POST /auth/login` with valid creds + TOTP returns access + refresh tokens | Slice A |
| **NEW 21** | `GET /auth/me` with token returns identity + role | Slice A |
| **NEW 22** | `POST /admin/users` with admin role creates a user | Slice A |
| **NEW 23** | `POST /hosts` with valid body creates a host | Slice A |
| **NEW 24** | `POST /admin/credentials` creates a system credential | Slice A |
| **NEW 25** | `POST /hosts/{id}:connectivity-check` successfully dials the test host | Slice A |
| **NEW 26** | `OIDC/SAML` initiate endpoint returns 402 license.feature_unavailable | Slice A |

Total: 26 steps. The new spec `release-slice-a-signoff` carries this list.

---

## Why this slice is the right size

It's tempting to expand. Examples of expansion I've already filtered out:
- **"Add API keys too"** — same auth surface, but a distinct lifecycle. Adds 3-4 days. Not asked for.
- **"Add host groups"** — adds 3-5 days. Useful, but no scan-time consumer of groups in this slice (no scans yet).
- **"Add WebAuthn / FIDO2"** — license-gated; TOTP gets us 95% of the value at 30% of the effort. FIDO2 is a follow-up.
- **"Add full OIDC/SAML"** — 2-3 weeks alone. The 402-stubs preserve the option without paying the cost yet.

Slice A is "auth + add a host." The decisions above are the minimum viable cut. If anything below 3 weeks is forced, my recommendation is to drop the custom-role CRUD (defer to A.5) — built-in roles cover Slice-A demos. Custom roles are operator-pleasing but no Slice-A capability depends on them.

---

## What I need before starting implementation

Nothing. The decisions above are locked. Once you've read this doc and agreed (or pushed back on anything), I:

1. Write specs 1-9 in order
2. Each spec lands with its tests (the tests fail at first; that's the point)
3. Implement to make the tests pass
4. `make check` clean after each spec
5. `specter sync` strict-mode clean after the slice ends

The first commit on this slice is `app/specs/system/auth-identity.spec.yaml`. After you approve this plan, that's where I start.

---

## Slice A — Completion notes (2026-05-25)

All 9 specs shipped. `specter sync` reports 28/28 at 100% strict coverage
(19 pre-existing + 9 new). Full module test suite green, `golangci-lint`
clean across the module.

| Spec | ACs | Implementation |
|---|---|---|
| `system-auth-identity` | 20 | `internal/identity/{password,sessions,jwt,refresh,mfa,binder}.go` |
| `system-user-management` | 12 | `internal/users/users.go`, migration 0005 |
| `system-credential-store` | 12 | `internal/credential/credential.go`, migration 0007 |
| `system-host-inventory` | 12 | `internal/host/host.go`, migration 0008 |
| `system-ssh-connectivity` | 10 | `internal/ssh/{validate,known_hosts,dial}.go` |
| `api-auth` | 12 | `internal/server/auth_handlers.go` |
| `api-users` | 12 | `internal/server/users_handlers.go`, migration 0009 |
| `api-credentials` | 12 | `internal/server/credentials_handlers.go`, `internal/credential/api.go` |
| `api-hosts` | 12 | `internal/server/hosts_handlers.go` |

### Deltas from the plan

- **DEK source** is `internal/secretkey` shared by MFA + credential
  encryption (file-based for Slice A; KMS/Vault deferred to a later
  slice). MFA secrets, credential password/private-key/passphrase all
  encrypted with AES-256-GCM under the same DEK.
- **Stub identity binder retained** with a `X-Stub-User-Id` header
  override so admin endpoints whose handlers persist `created_by` FKs
  can be exercised in tests without the full session cookie dance.
  The stub binder is no-op when the production binder has already set
  a non-anonymous identity (see `auth.StubIdentityBinder` for the
  coexistence rule). Removal of the stub is a Slice-B item.
- **`api-credentials` C-01 enforced via a metadata-only struct**:
  `credential.Metadata` carries no plaintext or ciphertext secret
  fields; the dial path uses `credential.Credential` with decrypted
  secrets but that struct never crosses the HTTP layer.
- **`api-hosts` PATCH** is supported; PUT is not. The PR plan allowed
  either; PATCH is cleaner since most callers only mutate a subset.
- **Spec 25 (`connectivity-check`) is NOT in Slice A**. The plan
  reserved it for "POST /hosts/{id}:connectivity-check"; the executor
  + audit event for connectivity probes is sized for Slice B with the
  scan executor. No connectivity-check endpoint ships in Slice A.
- **OIDC/SAML 402 stubs** declared in the permissions registry
  (`admin:sso_provider`) but no SSO endpoints land in Slice A. The
  Slice B plan picks them up alongside the SCIM bridge work.

### Wire-through

End-to-end coverage lives at `internal/server/api_slice_a_e2e_test.go`
(`TestSliceA_WireThrough_RealIdentity`). The flow:
bootstrap admin → `/auth/login` (real session cookie) → `/auth/me` →
create host → create system + host credentials → resolve (host-scope
wins) → soft-delete host cred → resolve (falls back to system default)
→ soft-delete host → confirm `host.created` / `host.deleted` /
`credential.created` / `credential.deleted` audit events landed. The
test uses no `X-Stub-*` header after step 1, proving the production
identity binder threads through every layer.

### Drive-bys

- `internal/credential/credential_test.go`: `TestResolve_HostScopeWins`
  was inserting a host-scope credential against a UUID the `hosts`
  table didn't have, violating the deferred FK from migration 0008.
  Fixed with a `seedHost` helper.
- Test fixture `freshAPIServer` clears custom roles between tests so
  `api-users` AC-11 doesn't collide with leftover `field_auditor` rows.
- Test fixture seeds a "stub-admin" user and pins its UUID into
  `stubAdminUserID`; the `asRole` helper attaches `X-Stub-User-Id` so
  handlers writing `created_by` FK columns resolve to a real
  `users.id`.

### Slice-A signoff steps (revised tally)

Of the 26 signoff steps the plan listed, 25 are reachable today —
step 25 (`POST /hosts/{id}:connectivity-check`) moves to Slice B with
the scan executor. The `release-slice-a-signoff` spec is not yet
written; that's the Slice-A closer alongside whatever doc/changelog
work the release process needs.
