# OpenWatch (Go rebuild) — Changelog

Changelog for the OpenWatch Go rebuild, which lives at the repo root. The
legacy Python project was archived out of the repo on 2026-06-05.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.2.0-rc.7] Eyrie — 2026-06-14

The navigable-application candidate: rc.6 made compliance scanning work, and
rc.7 makes it a product you move through. The full app shell came alive (a
public Radar homepage, a live fleet dashboard, an activity feed, a scans
overview, and Groups + Reports), historical scan evidence is now durable and
exportable as OSCAL, and the ~539-rule Kensa corpus is browsable. Still a
pre-release, pending the GA fleet-verification gate.

### Added

- **Durable per-scan compliance evidence + `/scans` surface** (#535). The
  write-on-change model (`host_rule_state` + `transactions`) overwrote a
  superseded scan's per-rule evidence, leaving historical proof unrecoverable.
  A content-addressed `scan_results` store (migration 0029, `internal/scanresult/`)
  now retains every rule's outcome and evidence per scan, deduped by content
  hash. New `scan:read`-gated API under `/api/v1/scans`: scan history by host,
  scan detail (per-rule verdicts with catalog title/category/description),
  per-rule evidence, and per-rule + whole-scan OSCAL 1.0.6 export reconstructed
  on demand via Kensa. A scan-detail page is reached from `/scans` (host
  history -> scan detail -> per-rule Formatted / Evidence / OSCAL drill-down,
  Evidence and OSCAL shown as raw JSON). Specs `system-scan-results-store`,
  `api-scans`, `frontend-scan-detail`.
- **Kensa rule-library browser** as the Rules tab on `/scans` (#536). The full
  ~539-rule corpus is browsable with search and severity / category / framework
  filters, framework-reference tags, and a remediation column (manual / atomic /
  staged, with reboot and service-restart hints), plus CSV export. Built on the
  Kensa v0.4.3 read model (`pkg/kensa.LoadRuleSummaries`). `scan:read`-gated.
  Specs `api-rules`, `frontend-rules-library`.
- **Per-rule evidence/OSCAL drill-down on the host Compliance tab** (#537). Each
  rule row on the host-detail Compliance tab expands into the same Formatted /
  Evidence / OSCAL panel as the scan-detail page. The host-compliance API stays
  evidence-free: the drill-down reaches the `scan:read`-gated `/scans` evidence
  endpoints for the host's latest scan, and the control shows only to callers
  holding `scan:read`. Spec `frontend-host-compliance-tab` v1.3.0.
- **Public Radar homepage + enhanced login** (#528). An unauthenticated landing
  page at `/`; the authenticated dashboard moved to `/dashboard`.
- **Fleet dashboard MVP** at `/dashboard`, wired to the live fleet endpoints
  (#529).
- **Activity feed MVP** at `/activity` (#530).
- **Scans overview MVP** at `/scans` — the home for scan history and the rule
  library (#531).
- **Groups + Reports MVP** (#533): Groups organizes the fleet by site and OS
  category; Reports is a reports library. Specs `api-groups`, `frontend-groups`,
  `api-reports`, `frontend-reports`.

### Changed

- Remediation is documented as shipping **beta in GA**; remaining scan-platform
  work split into its own tracking file and reconciled for the release
  (#525, #526).

### Fixed

- The topbar breadcrumb is now set on every navigation page instead of going
  stale after the first route (#534).
- Unrouted sidebar links are disabled rather than navigating to a 404 (#527).
- The frontend's synthesized role->permission baseline omitted `scan:read`,
  which would have redirected every user away from the new scan-detail route
  even though the backend grants `scan:read` to all built-in roles (#535).

---

## [0.2.0-rc.6] Eyrie — 2026-06-13

The compliance-scanning candidate: this RC turns OpenWatch from a scanner
shell into a working compliance platform. Kensa now scans real hosts on an
adaptive schedule, results are viewable through any framework lens, posture
trends accumulate, and operators can govern failing rules with approved
exceptions. Still a pre-release, pending the GA fleet-verification gate.

### Added

- **End-to-end compliance scanning.** On-demand scans (`POST
  /hosts/{id}/scans`, the Run scan button) run the full ~539-rule Kensa
  corpus against a host over an in-memory SSH transport (no private key on
  disk), persist results write-on-change to `transactions` + `host_rule_state`,
  and refresh the UI over the live event stream. (#515)
- **Lens model on the Compliance tab.** One scan, viewed through any
  framework: `GET /hosts/{id}/compliance` (+ `/frameworks`) projects the
  per-rule results through CIS / STIG / NIST / PCI / SRG at query time. The
  lens bar is OS-aware — a RHEL 8 host no longer offers RHEL 9/10 lenses,
  while OS-neutral frameworks always appear. (#515, #518)
- **Adaptive compliance scheduler.** Hosts auto-scan on a five-band,
  state-driven cadence (critical 4h … compliant 48h), operator-editable per
  band under Settings → Scanning & monitoring. Scan-queue depth, fleet
  per-state counts, and a 24-hour schedule strip are exposed. (#515)
- **Scan variables.** Operator overrides for the corpus's templated rule
  variables (Settings → Compliance policies), reloaded into the rule corpus
  on the next scan. (#517)
- **Posture trends.** A daily posture-snapshot rollup powers the 30-day
  per-host trend card and the fleet average-compliance delta on the hosts
  list. (#518)
- **Live host-detail hero tiles.** Auto-scan (next scan + cadence),
  Watchlist (active alerts + waived-rule count), and Connectivity now render
  real data instead of placeholders. (#518)
- **Compliance exception governance.** Operator-approved rule waivers with a
  request → approve/reject → revoke/expire lifecycle, separation of duties,
  and an audit trail. An exception never changes a rule's raw verdict (a
  waived failure stays failing); it is a read-time overlay marking accepted
  risk. Surfaced on the host detail (Waived/Pending badges + a request modal)
  and a fleet approver queue under Settings → Compliance policies.
  (#521, #522, #523)
- **New migrations** 0023–0026: `scan_runs` (scan logbook), compliance-state
  five-band CHECK + backfill, `posture_snapshots`, `compliance_exceptions`.

### Changed

- All tracked documentation reconciled with the Go codebase, including the
  Scanning & Compliance operator guide and the bannered legacy guides; the
  backlog rewritten for the Go rebuild. (#505, #507, #508, #520, #481)

### Fixed

- SSE event streams were silently killed at the HTTP server's 60-second
  write timeout; per-stream write deadlines are now cleared. (#515)
- The alerts lifecycle service was never wired into the serve path, so every
  `/api/v1/alerts*` endpoint returned 503 in production while passing tests.
  Wired, plus a generic guard that every server builder is registered in
  `main.go`. (#518, #519)
- Correlation-ID generation now reads the clock under the lock, restoring
  per-ID uniqueness under concurrency. (#503)
- Cleared the live CodeQL warnings; prototype mockups excluded from scans. (#514)

### CI / tooling

- `specter check --test` annotation-hygiene gate and a pre-push annotation
  hook; restored four dropped connectivity API specs; perf latency budgets
  made non-gating to stop CI flakes. (#512, #509, #510, #506)

### Dependencies

- npm production and development group bumps. (#489, #513)

---

## [0.2.0-rc.5] Eyrie — 2026-06-08

Package-refresh candidate: re-cuts the signed RPM/DEB from `main` so the
published artifacts include the version-endpoint and auth-redirect fixes
that landed after rc.4. Still a pre-release — not GA.

### Added

- `GET /api/v1/version` (anonymous) reporting the OpenWatch, Kensa, and Go
  versions plus commit/build-time, all sourced from build metadata rather
  than constants. Settings → About now renders these live instead of
  hardcoded strings (#500).

### Fixed

- Frontend: an expired/invalid session now always redirects to `/login`
  instead of leaving the user on a raw error envelope. A global, code-aware
  QueryCache/MutationCache handler covers every query and mutation;
  authorization (permission) errors are excluded so they never log a user
  out (#501).
- Release: `v*` tags with a pre-release suffix now publish as GitHub
  pre-releases (a bare `vX.Y.Z` is GA) (#499).

---

## [0.2.0-rc.4] Eyrie — 2026-06-08

The release-readiness candidate: OpenWatch Go is now a single, installable
product. `dnf install ./openwatch-*.rpm` / `apt install ./openwatch_*.deb`
lays down one binary that serves both the API and the built UI, with a
tag-driven, signed release pipeline behind it. This RC also folds in the
host-detail / OS-intelligence / discovery suite that accumulated since the
early rc.3 cut.

### Added

**Distribution & supply chain**

- Native multi-arch packages — RPM (CentOS Stream 9) and DEB (Ubuntu 24.04),
  each built for amd64 and arm64 via `CGO_ENABLED=0` cross-compile (#490).
- The React SPA is embedded into the binary via `go:embed` and served by the
  Go server (static assets + `index.html` fallback; `/api/` paths still 404),
  so one artifact is the whole product — air-gap clean, no separate web tier
  (#486).
- `release.yml` — on a `v*` tag, builds all four packages, generates a
  CycloneDX 1.5 SBOM per artifact (syft), writes `SHA256SUMS`, and publishes
  a GitHub Release (#491).
- Release signing — each RPM (`rpmsign`) and DEB (`dpkg-sig`) is GPG-signed,
  and `SHA256SUMS` gets both a detached GPG signature and a cosign sigstore
  signature; the Hanalyx public key ships as `KEYS`. Every signing layer is
  gated on its key secret and skipped gracefully when absent (#493, #494).
- `package-smoke.yml` — installs the built RPM on Rocky/Alma/Fedora/Oracle and
  the DEB on Ubuntu/Debian, then smoke-tests the binary (#492).
- `docs/runbooks/RELEASING.md` — the gated release process (docs freeze →
  RC → verification gate → GA), including signing-key setup (#492).
- Go module supply-chain spec + depguard allowlist + Dependabot for the
  module set (#416).

**Product features (since rc.3)**

- OS discovery — scheduler, first-contact policy, and fleet sweep that learns
  each host's distro over SSH and persists it to `hosts.os_family` (#467, #471).
- Server intelligence — packages/services/users/network/system collected over
  SSH and surfaced as a host-detail snapshot grid, with a settings page to
  tune collection (#455, #472).
- Host liveness — adaptive, per-state probe intervals and a fleet-health
  surface (#421, #434, #435).
- Alerts — router, persistence, and lifecycle (#424, #444, #445, #420).
- Fleet observability API — read-only fleet endpoints and `hosts/{id}`
  enrichment (liveness + compliance summary) (#427, #428).
- React 19 + MUI v7 + TanStack frontend for auth, hosts, host-detail,
  settings, and an activity feed, with five approved frontend specs at 100%
  AC coverage (#433, #436, #437, #468).
- 16 database migrations (`0007`–`0022`): credentials, compliance schedule,
  transaction log, host liveness, system config, multilayer monitoring,
  system info, intelligence, alerts. **`openwatch migrate` is required on
  upgrade.**

### Changed

- The admin CLI is retired: `openwatch` is the single binary and command
  (`serve`/`worker`/`migrate`/`create-admin`/`check-config`); lifecycle is
  managed by systemd, not a separate `owadm` (#487).
- Repository restructure — the Python backend/frontend were archived out of
  the repo and the Go tree was promoted from `app/` to the repo root (#482).
- Tooling — Prettier + a flat ESLint config for the frontend, with the lint
  pre-commit hook re-enabled; `.env` templates rewritten for the Go server
  (#483, #484, #485).
- Dependabot retargeted for the post-promotion layout (`gomod` at `/`, dead
  `backend`/`docker` ecosystems dropped) (#495).
- SSH connectivity — credential-password sudo fallback extended across
  liveness probes and discovery queries; auth offers both key and password
  methods when configured for both (#460, #469, #470).
- Frontend surfaces the backend's `human_message` instead of a generic HTTP
  error, and retries 401s transparently against the HttpOnly refresh cookie
  (#456, #466).

### Fixed

- Discovery persists the distro ID into `hosts.os_family` rather than the
  family rollup (#471, #022 migration).
- Firewall-rule probe records `0` (not `-1`) when the engine is present but
  inactive (#459).
- Activity feed no longer crashes on a `host_id`-filtered union and wires the
  service in `main` (#477, #478).

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
