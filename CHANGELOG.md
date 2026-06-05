# OpenWatch (Go rebuild) — Changelog

Changelog for the OpenWatch Go rebuild under `app/`. The legacy Python
project at the repo root has its own `CHANGELOG.md` and `VERSION`.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.2.0-rc.3] Eyrie — 2026-05-25

API hygiene pass driven by manual testing of the rc.2 surface. Three
related cleanups that all surfaced from the same underlying issue —
inconsistent naming between API paths/fields and the role/permission
model behind them.

### Added

- `GET /api/v1/openapi.yaml` — serves the embedded OpenAPI 3 spec.
- `GET /docs/` — Swagger UI mounted from the binary (assets embedded
  via go:embed; no CDN dependency, air-gap clean).
- New spec `api-openapi-docs` with 4 ACs pinning the spec/UI endpoints,
  same-origin asset constraint, and byte-identical embed.
- Build-time copy: `make build` now syncs `api/openapi.yaml` into
  `internal/server/openapi_embed.yaml` (gitignored) before compiling.
- Migration 0010 — drops the `users.is_admin` column.

### Changed

**Path rename: resource CRUD moves off `/admin/`.**

The design doc (`docs/api_design_principles.md` §12.2) reserves the
`/admin/` namespace for system operations (`POST /admin/operations:*`),
not resource CRUD. Slice A inadvertently put resource endpoints under
`/admin/` which read as a role gate but isn't — `host:read` for example
is held by `viewer`. The rename collapses the disconnect:

| Before | After |
|---|---|
| `/api/v1/admin/users` | `/api/v1/users` |
| `/api/v1/admin/users/{id}` | `/api/v1/users/{id}` |
| `/api/v1/admin/users/{id}/roles:{assign,unassign}` | `/api/v1/users/{id}/roles:{assign,unassign}` |
| `/api/v1/admin/roles` | `/api/v1/roles` |
| `/api/v1/admin/roles:create` | `/api/v1/roles:create` |
| `/api/v1/admin/credentials*` | `/api/v1/credentials*` |
| `/api/v1/admin/hosts*` | `/api/v1/hosts*` |

Genuine operations stay where they belong:
- `/api/v1/admin/license:verify` (unchanged)
- `/api/v1/admin/policies:reload` (unchanged)

`operationId`s renamed in parallel (`postAdminUsers` → `postUsers`,
etc.) so the Swagger UI labels match.

**`users.is_admin` removed entirely.**

The column only ever drove password-policy selection but the API
exposed it as if it were a permission marker. Manual testing showed
the resulting drift case: unassigning the admin role left
`users.is_admin = true` because the column and `user_roles` had
independent lifecycles. The inverse case (assign admin role to a user
created with `is_admin: false`) was also possible and represented a
security gap (admin-tier user, default-tier password policy).

Replacement: password policy now derives from one source. At creation,
`CreateUser` takes an explicit `AdminPolicy` flag (the `create-admin`
CLI sets it true; the HTTP `POST /users` does not). On password
change, `UpdatePassword` looks up the user's primary role: admin role
→ AdminPolicy (15-char minimum), other → DefaultPolicy. No second
column to drift.

Wire response changes:
- `/auth/me` no longer carries `is_admin`. Admin status is implicit
  in `role == "admin"`.
- `/users/{id}` and `/users` response items no longer carry `is_admin`.
- `POST /users` request body no longer accepts `is_admin`.

### Fixed

- Test fixture `freshAPIServer` no longer sets the obsolete `is_admin`
  column when seeding role users.
- `seedAuthUser` test helper renamed parameter `isAdmin` → `adminPolicy`
  to reflect its actual effect.

### Lessons captured

Two API-design issues caught in two sessions of manual testing (the
`/admin/*` prefix overload and the `is_admin` drift) — both
semantic-conflation bugs that 100% per-spec coverage missed because
each individual behavior was tested in isolation. The Slice B spec
template will add a meta-AC pattern requiring that any wire field
naming a permission/role/state declare whether it's the SSOT or
documents how it stays in sync with the underlying data.

---

## [0.2.0-rc.2] Eyrie — 2026-05-25

Boot-wiring fixes for the admin surface. `rc.1` shipped a binary whose
JWT signing key and credential DEK were never loaded at boot, so every
`/auth/login` returned 500 and every credential / MFA action failed. The
tests passed because fixtures installed ephemeral keys directly; the
binary's `main.go` did not.

### Added

- `[identity]` config section with `jwt_private_key` and
  `credential_key_file` paths. Both are required for `openwatch serve` —
  no silent fallback to ephemeral keys.
- Env-var overrides: `OPENWATCH_IDENTITY_JWT_PRIVATE_KEY`,
  `OPENWATCH_IDENTITY_CREDENTIAL_KEY_FILE`.
- `openwatch create-admin --username --email --password` subcommand.
  Closes the chicken-and-egg in the bootstrap flow (`/admin/users`
  requires an existing admin).
- `release-admin-signoff` AC-14 + `TestRuntimeBoot_LoginEndToEnd` in
  `packaging/tests/runtime_boot_test.go`. Spawns the actual
  `dist/openwatch` binary against a real Postgres and exercises
  migrate → create-admin → serve → login → POST host. Catches the
  "tests pass but binary broken" class of bug that produced `rc.1`.

### Fixed

- `cmd/openwatch/main.go` now calls `identity.LoadJWTKey()` and
  `secretkey.LoadFromFile()` at boot. Missing or unreadable keys fail
  the server with an explicit error instead of allowing the binary to
  serve traffic that 500s on the first login.

### Security note

The `rc.1` regression was not a security issue (`/auth/login` 500-ed
rather than admitted attackers) but it was a release-blocking
correctness gap that 100% spec coverage missed. The new AC-14 binds
sign-off to the artifact, not just the unit tests.

---

## [0.2.0-rc.1] Eyrie — 2026-05-25 (yanked)

Tagged locally, never pushed. Superseded by 0.2.0-rc.2 — `cmd/openwatch/main.go`
did not load the JWT signing key or credential DEK at boot, so login
returned 500 against the actual binary. See 0.2.0-rc.2 entry for the
fix. Original deliverable details preserved below for traceability.

Release-candidate sign-off for real identity, user CRUD, host inventory,
credential store, the SSH dial layer, and the four admin HTTP surfaces
that knit them together.

### Added

**Specs (9 new, all 100% strict coverage):**
- `system-auth-identity` — Argon2id password hashing, NIST SP 800-63B
  policy, sessions, JWT (RS256), refresh-token rotation with reuse
  detection, TOTP MFA, production identity binder.
- `system-user-management` — users + user_roles + custom roles tables
  with the highest-privilege-wins resolver and `identity.Lookups`
  adapter.
- `system-credential-store` — credentials table (system + host scope),
  AES-256-GCM via the shared `internal/secretkey` DEK, host→system
  resolver, partial unique index for the "one system default" rule.
- `system-host-inventory` — hosts table with INET addresses, TEXT[]
  tags + GIN index, soft delete via `deleted_at`.
- `system-ssh-connectivity` — SSH dial (`golang.org/x/crypto/ssh`),
  known-hosts store, strict / trust-on-first-use modes, NIST SP 800-57
  key strength validation.
- `api-auth` — `/auth/login`, `/auth/me`, `/auth/logout`,
  `/auth/refresh`, `/auth/mfa:enroll`, `/auth/mfa:validate`,
  `/auth/password:change`.
- `api-users` — `/admin/users` (GET/POST), `/admin/users/{id}`
  (GET/DELETE), `/admin/users/{id}/roles:{assign,unassign}`,
  `/admin/roles:create`.
- `api-credentials` — `/admin/credentials` (GET/POST),
  `/admin/credentials/{id}` (GET/DELETE),
  `/admin/hosts/{host_id}/credentials:resolve`. Metadata-only at the
  wire; plaintext + ciphertext never cross the HTTP layer.
- `api-hosts` — `/admin/hosts` (GET/POST), `/admin/hosts/{id}`
  (GET/PATCH/DELETE) with environment + tag filters.

**RBAC additions:**
- New permissions: `credential:read`, `credential:write`,
  `credential:delete`.
- Assigned: `credential:read` to `ops_lead`; `credential:*` to
  `security_admin` and `admin` (via `*` wildcard).

**Audit additions:**
- New event codes: `credential.created`, `credential.deleted`,
  `host.created`, `host.updated`, `host.deleted` (host codes already
  existed; credential codes added in this release).

**End-to-end:**
- `TestAdminE2E_RealIdentity` exercises the full admin flow through a
  real session cookie: login → host create → system credential →
  host-scope credential → resolve (host wins) → soft-delete cred →
  resolve (system fallback) → soft-delete host → confirm audit
  pipeline emitted the expected rows.

**Sign-off:**
- `release-0.2.0-signoff` spec with 13 ACs; the 9 release specs are
  registered in `specter.yaml`.

### Security

- **Removed `X-Stub-Role` / `X-Stub-User-Id` header-based identity
  bypass** (previously inherited from the walking-skeleton phase).
  No exported symbol in `internal/auth`, no middleware mount in
  `server.go`. Identity is now bound exclusively by the production
  binder via session cookie or Bearer JWT. The previous binder was an
  authentication-bypass vector against unauthenticated callers; its
  removal is enforced by source-inspection tests
  (`system-rbac` AC-12 and `release-0.2.0-signoff` AC-13).
- Test fixture seeds one user per built-in role and mints a real
  session via `identity.IssueSession`; `asRole(t, ..., role, ...)`
  attaches the corresponding session cookie. No header-based identity
  short-circuit exists in the test path either.

### Fixed

- `TestResolve_HostScopeWins` in `internal/credential/credential_test.go`
  now seeds a host row before creating a host-scope credential — the
  deferred FK from migration 0008 had previously made the test order
  fragile.
- `release-package-build` AC-12 test now reads the Go-rebuild's own
  `packaging/version.env` first, falling back to the repo-root
  `VERSION`.

### Deferred (not in 0.2.0)

- `POST /hosts/{id}:connectivity-check` — moves to the next release
  with the scan executor.
- OIDC/SAML initiate endpoint that returns 402 — license feature
  `sso_saml` is in the registry; the endpoint lands with the SSO
  implementation work.
- PUT-style full updates on hosts and users — only PATCH ships in
  0.2.0.
- Bulk host import and cursor-paginated list — next release.

---

## [0.1.0-stage-0] — pre-2026-05-25

Walking-skeleton phase (pre-0.2.0). See
`docs/stage_0_walking_skeleton.md` and the `release-stage-0-signoff`
spec for the Definition of Done.
