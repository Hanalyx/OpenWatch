# OpenWatch (Go rebuild) — Changelog

Changelog for the OpenWatch Go rebuild, which lives at the repo root. The
legacy Python project was archived out of the repo on 2026-06-05.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Fixed
- Operator-guide truthfulness + accuracy pass (`docs/guides/`): verified every
  documented `openwatch` CLI subcommand, REST endpoint, file path, env var, and
  systemd unit against the binary, `api/openapi.yaml`, and `packaging/`. Fixed
  the verified defects: the RBAC permission counts (`ops_lead` 30 to 32,
  `security_admin` 51 to 56), the scan-trigger endpoint (was the nonexistent
  `/api/v1/scans/kensa/`; the real on-demand trigger is
  `POST /api/v1/hosts/{id}/scans`, also corrected in the Quickstart, which had
  wrongly said no run-scan action exists), stale example versions
  (`0.2.0-rc.11` to `rc.13`), the migration-count example (22 to 46), the
  Kensa rule count (508 to 539), and password-policy claims (12-char to the
  real 8/15). Added "Last Updated" headers to every guide.

---

## [0.2.0-rc.13] Eyrie — 2026-06-22

The Reports surface is now a complete compliance-artifact platform, spanning
the executive summary, an auditor/GRC bulk path, two new GRC read-model
kinds, and recurring email delivery.

### Added
- **Framework Attestation report kind** (auditor/GRC): a point-in-time,
  signed attestation that freezes the latest completed scan per in-scope
  host. Faces: a fleet **OSCAL 1.0.6 assessment-results (SAR)** with
  evidence referenced by content hash, a per-(host, rule) **CSV** evidence
  extract, a bounded one-page **PDF cover**, and the canonical **JSON**.
  A frozen, signed compliance rollup (compliance %, pass/fail, top-failing)
  is shown in-app and on the PDF cover.
- **Exception Register report kind** (Compliance/GRC): a point-in-time
  read-model of compliance waivers — counts by state (active, pending,
  expiring-soon) plus the register rows — with CSV + PDF + JSON faces.
- **Remediation Activity report kind** (Operations): a read-model of
  remediation requests over a look-back window (last 7/30/90 days), with
  an outcome summary and CSV + PDF + JSON faces.
- **Scheduled reports + email delivery**: a daily/weekly/monthly schedule
  generates a report and emails its rendered PDF (MIME attachment) through
  an email notification channel. Managed from a live **Scheduled** tab
  (create / pause-resume / delete). Endpoints under
  `/api/v1/reports/schedules`.
- **Asynchronous report rendering** + a new `report.ready` event on the
  event bus — the first producer of the in-app **notification bell**.
- **Ed25519 report signing** with an in-browser **offline Verify**, a
  fleet **framework catalog** endpoint, and a kind selector + scope/period
  pickers on the Library tab.
- Report kinds are admitted by `report_snapshots.kind` (migrations
  0043–0045); `report_schedules` lands in migration 0046.

### Audit
- Report generation and report-schedule create/delete/enable-disable now
  emit audit events (`report.generated`, `report.schedule.*`).

### Security / hardening
- The scheduled-report dispatcher claims due schedules with
  `FOR UPDATE SKIP LOCKED`, so concurrent dispatchers never double-send.
- Report-email subjects are CRLF-sanitized (header-injection defense).

### Docs
- Consolidated the operator/admin/end-user guides under `docs/guides/`
  (install guide, the operator runbooks, supported-distros), merged the two
  upgrade docs into one, and left `docs/engineering/` for internal design docs.
- Archived completed/Python-era docs out of the repo (legacy install guide,
  stage plans, the Q1 plan, the backend-functionality inventories) and fixed
  the stale Go API examples in the Hosts/Remediation guide (real `/api/v1`
  routes on `:8443`).
- Removed residual OpenSCAP/SCAP references from the Go-native docs (the
  engine is Kensa, SSH-based native YAML rules).

### Fixed
- Favicon: `index.html` referenced a missing `/favicon.svg` (404 on every
  page). Now ships the OpenWatch logo favicon set (`.ico` + PNG sizes +
  apple-touch-icon + web manifest), embedded in the single binary.

---

## [0.2.0-rc.12] Eyrie — 2026-06-20

The fleet activity stream and audit trail are now readable end to end: every
event renders a plain-language title instead of a raw dotted code, enum, or
resource UUID. Host detail gains live Activity and Audit tabs, Settings shows
readable audit rows, and the filtered audit trail can be exported to CSV or
JSON (NIST 800-53 AU-7). The Host Management page got its scan link, Group, and
Filters working with a server-persisted view preference, and a pre-release
security pass hardened the new export and fixed a cursor data-loss bug.

### Added

- Activity & audit readability: the unified feed and the audit list now render
  a server-built, human-readable title + summary for all five legs. The three
  legs that previously leaked machine codes (compliance/transaction,
  intelligence, audit) are humanized — a rule's catalog title instead of its
  id, "Package updated" instead of `system.package.updated`, "alice@example.com
  created a host" instead of `host.created` over a UUID. Unmapped codes degrade
  structurally (dots/underscores to spaces) so a newly-added code can never
  surface as a raw dotted enum. (#616, #617)
- Host detail: a live **Activity** tab (host-scoped unified feed) and a
  readable **Audit log** tab, with audit `message`/`resource` filters so you can
  pull one host's lifecycle trail. (#618, #619)
- Settings: a readable **Audit log** view with plain-language rows. (#622)
- Audit export: `GET /api/v1/audit/events/export` streams the filtered audit
  trail as a downloadable CSV (default) or JSON attachment, capped at 10000
  rows, `audit:read`-gated (NIST 800-53 AU-7). (#623)

### Changed

- Host Management: the host card's scan link now opens the latest scan, Group
  and Filters work, and the list/grid view toggle is persisted **per user**
  server-side instead of per browser. (#611)
- Scan detail: the header shows the host's hostname (falling back to its IP)
  instead of a raw host UUID. (#613)
- Automated, schedule-driven events are now attributed to **"The system"**
  instead of the misleading "Someone", which implied a logged-in operator
  clicked a button. (#620)

### Security

- Hardened the audit CSV export against spreadsheet formula injection
  (CWE-1236): a cell beginning with `=`, `+`, `-`, `@`, tab, or CR is prefixed
  with a single quote so it renders as literal text. A truncated export (at the
  10000-row cap) now sets an `X-OpenWatch-Export-Truncated` header and logs a
  warning, so a capped export is never mistaken for the complete trail. (#625)
- Fixed a cursor-pagination data-loss bug in the activity feed and audit list:
  the cursor encoded `occurred_at` alone, so rows sharing a boundary timestamp
  could be silently skipped on the next page (likely on the 5-leg UNION with
  batch inserts). Both now use a compound keyset cursor `(occurred_at, id)` with
  a row-value predicate. Bounded the attacker-controlled User-Agent and
  submitted-username strings recorded in audit detail (256-rune cap +
  control-char strip), neutralizing log forging. (#626)

---

## [0.2.0-rc.11] Eyrie — 2026-06-19

The bundled Kensa scan engine moves to v0.5.2, which corrects a class of false
compliance FAILs on TAB-delimited rules. Single-operator remediation no longer
deadlocks (free-core fixes auto-approve), the Remediation tab updates live and
serializes concurrent fixes, an expired session now redirects cleanly to login,
and the GA-readiness pass hardened CI and the release workflow.

### Added

- Remediation: free-core single-rule remediation is now **auto-approved** on
  request, so an operator can apply a fix without a separate approver. This
  removes the self-review deadlock for single-operator workspaces (you could
  request a fix but never approve your own request). The request lifecycle and
  the approve/reject flow with separation of duties are retained for the
  licensed bulk/automated remediation track (which requests with approval
  required). See `docs/engineering/remediation_governance_adr.md` ("A-keep").

### Changed

- Updated the bundled Kensa scan engine and rule corpus to v0.5.2. v0.5.2 fixes
  a `config_value` matching bug so a `" "` delimiter matches any whitespace
  (including TAB), correcting a class of false FAILs on TAB-delimited rules such
  as RHEL `login.defs` — affected hosts may see their compliance score improve.
  It also adds rule-engine correctness gates (check-method parameter contracts,
  value-domain validation, a comparator + delimiter engine, and a schema/engine
  parity gate). The corpus stays at 539 rules and the engine's frozen API
  surface is unchanged, so OpenWatch's library integration is unaffected
  (kensa v0.5.2).
- Documented remediation/exception governance: a remediation-approval ADR and a
  role matrix covering who can request versus approve a fix or exception, plus a
  self-review rule, and an RBAC spec that drift-locks the role/permission map.
- CI release safety: the release workflow now fails closed on a `v*` tag push
  when no GPG signing key is configured, rather than publishing unsigned
  packages. Manual `workflow_dispatch` trial builds stay permissive (warn +
  publish unsigned).
- CI frontend gate: a failing frontend Vitest suite now hard-fails the build.
  Results are still ingested by specter first (so coverage is reported), then a
  dedicated enforcement step aborts on a real test failure.
- `make lint` now warns when the locally installed `golangci-lint` does not
  match the version pinned in CI, so local runs reproduce CI.

### Fixed

- Auth: an anonymous request to a protected endpoint (no credentials, or a
  session cookie that expired in the browser and is no longer sent) now returns
  **401 `auth.required`** instead of 403. The SPA redirects to login on a 401,
  so an expired session surfaces as a clean re-login prompt rather than a
  dead-end "failed to load." An authenticated caller whose role lacks the
  permission still gets 403 `authz.permission_denied`.
- Remediation now updates live. The Remediation tab and the compliance score
  refresh automatically when a queued fix or rollback finishes, over the SSE
  event stream (new `remediation.completed` topic), instead of requiring a
  manual page refresh.
- Applying several fixes on the same host at once no longer fails the extra
  ones. Concurrent remediations on a host now serialize: a fix whose host is
  busy backs off and requeues (with a short delay, via a new delayed-visibility
  column on the job queue) until the host is free, instead of colliding on the
  per-host SSH guard and being marked failed.
- Documentation version drift: operator guides referenced `0.2.0-rc.5` while
  `packaging/version.env` was `0.2.0-rc.10`; all guides now match.
- SPA static-delivery tests are self-contained (in-memory fixture) instead of
  depending on a magic staged asset filename, so `go test ./internal/server/`
  passes against a real `vite build`, the Makefile stub, or no staged tree.
- Repository hygiene: a stray 34 MB root build artifact was removed and the
  root-level `openwatch` binary path is now gitignored; placeholder credentials
  were stripped from the prototype login page.

---

## [0.2.0-rc.10] Eyrie — 2026-06-17

Per-host SSH credentials become directly manageable from the UI, the bundled
Kensa engine moves to v0.5.0, and a packaging fix stops upgrades from
overwriting an operator's TLS certificate.

### Added

- SSH credentials can now be edited in place. The Settings credentials page
  updates a credential directly instead of deleting and recreating it, so
  changing a name, username, or authentication method no longer forces you to
  re-enter the key or password. Leave a secret field blank to keep the stored
  one (#595).
- Per-host SSH credential management from the host detail page. A host can be
  given its own credential, have that credential edited in place, or be reverted
  to the workspace default, all from the host Edit dialog and the Connectivity
  card's Edit credentials link (#595).
- A Reconnect action on the host Connectivity card runs OS discovery
  immediately, ahead of the scan queue, so you can confirm a host is reachable
  and its SSH credential works right after changing it (#595).

### Changed

- The host Connectivity card now shows the credential the host actually uses
  (its own override or the workspace default) instead of a fixed label (#595).
- Updated the bundled Kensa scan engine and rule corpus to v0.5.0. v0.5.0 adds
  native sudo-with-password support for hosts where passwordless sudo is
  disallowed (a common CIS/STIG control); the change is backward-compatible and
  OpenWatch's existing scan behavior is unchanged. The corpus stays at 539
  rules. The `kensa-rules` package version tracks the engine, so it becomes
  0.5.0 in the next build (#594).

### Fixed

- A package upgrade no longer overwrites your TLS certificate. The demo
  certificate previously shipped inside the package at the production path, so
  `dnf update` or `apt upgrade` silently replaced an operator-installed
  certificate with a fresh self-signed demo on every upgrade. The demo
  certificate is now generated at install time only when the TLS files are
  absent (the same generate-if-absent model already used for the server's
  identity keys), so a certificate you put in place survives upgrades untouched
  (#596). This also covers the one-time upgrade from an earlier build that did
  ship the demo certificate (rc.9 and before): your certificate is preserved
  rather than removed during that transition too (#598).

---

## [0.2.0-rc.9] Eyrie — 2026-06-17

Two fixes that came out of production hardening: password login now works on
PAM-hardened hosts, and compliance scans run across the fleet in parallel
instead of one host at a time.

### Changed

- Compliance scans now run several hosts at once instead of strictly one at a
  time. A new `scan_concurrency` setting (under `[server]`, default 4) controls
  how many hosts scan in parallel; different hosts run concurrently while two
  scans of the same host never overlap. Clearing a large fleet that used to take
  many hours of serial scanning now finishes far sooner (#592).

### Fixed

- Password authentication now works against hardened hosts that accept passwords
  only through PAM keyboard-interactive (servers with `PasswordAuthentication no`
  but `UsePAM yes`). Such a host advertised only `keyboard-interactive`, so a
  password credential previously failed the handshake with "no supported methods
  remain" even though the password was correct (SSH-key auth was unaffected, and
  development hosts that offer plain password auth were never affected) (#591).

---

## [0.2.0-rc.8] Eyrie — 2026-06-17

Settings became a working control panel, OpenWatch started learning how to
reach each host over SSH, package upgrades became a single safe command, and a
pre-release security review closed a batch of perimeter and access-control
gaps.

### Added

- Settings > Users now lets you invite people, manage their accounts, and
  assign roles from the UI instead of showing a placeholder (#552, #553).
- Settings > Notifications can now send compliance alerts to Slack, a generic
  webhook, or email over SMTP, and each channel can be edited after creation
  (#554, #555).
- Settings > Security is live end to end: scoped API tokens you can create and
  revoke, an authentication policy (password strength and session timeouts),
  and single sign-on through an OIDC identity provider (#556, #557, #558).
- Settings > Audit and About now browse the audit log in-app and show the live
  license and build details instead of static text (#552).
- Each host's actions menu now has Edit and Delete entries so you can correct
  or remove a host without leaving the list (#560).
- OpenWatch now learns how to reach each host: it records which SSH
  authentication method and sudo style actually worked and reuses them on the
  next discovery, intelligence, and liveness pass, so it stops retrying
  combinations that already failed (#566, #575, #576).

### Changed

- Upgrading is now one command. `dnf update` (or `apt upgrade`) applies any
  pending database migrations automatically, takes a full database backup
  first, and on a failed migration leaves the service stopped with clear
  recovery steps instead of running against a half-migrated schema. The
  PostgreSQL engine upgrade itself stays an operator-supervised step (#569).
- Web fonts now ship inside the application instead of loading from a font CDN,
  so the interface renders completely in air-gapped deployments (#561).
- Updated the frontend build and CI tooling (Vite, Vitest, lucide-react, zod,
  and several GitHub Actions) to current major versions (#571, #572, #573).
- The web UI now loads faster with no extra infrastructure: the embedded
  single-page app is gzip-compressed and its content-hashed assets are served
  with long-lived immutable caching, so the browser fetches each one only once
  (#582).
- Seven database migrations land this cycle (0030 through 0036: notification
  channels, API tokens, authentication policy, SSO, per-host connection profile,
  and the SSH known-hosts store); the one-command upgrade applies them
  automatically with a pre-upgrade backup (#552 through #558, #566, #584).

### Fixed

- A fresh install now boots on the first try: the Kensa rule corpus and the
  server identity keys are provisioned during installation rather than failing
  at first startup (#564).
- The SMTP notification channel edit form now pre-fills its current settings
  instead of opening blank (#561).
- Removed leftover demo and sample data that could appear on the dashboard,
  the activity feed, and the host lists (#562).
- An expired or invalid session now redirects you to the login page instead of
  leaving you on a page that silently fails to load (#583).

### Security

A pre-release security review (six parallel audit dimensions, every
high-severity finding re-verified by hand) closed eight findings (#584):

- State-changing requests made with a session cookie are now CSRF-protected
  with a double-submit token; a request without a matching token is rejected.
- The login and MFA-verify endpoints are now rate-limited per client address
  to slow online password and one-time-code guessing.
- Every response now carries security headers: HSTS, a content-security policy
  that forbids framing, no-sniff, and a strict referrer policy.
- SSH host keys learned on first connection are now stored in the database, so
  a restart no longer re-trusts every host and a changed host key is detected
  across restarts.
- New passwords are now screened against a built-in list of common and breached
  passwords, with an option to point at a full breach corpus; the check now
  runs in production instead of being silently skipped.
- Reading the audit-event API now requires the audit-read permission instead of
  being open to any caller.
- Creating an API token or assigning a role can no longer grant more access
  than the caller already holds.

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
