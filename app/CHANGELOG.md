# OpenWatch (Go rebuild) — Changelog

Changelog for the OpenWatch Go rebuild under `app/`. The legacy Python
project at the repo root has its own `CHANGELOG.md` and `VERSION`.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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
