# BACKLOG.md — OpenWatch Go Prioritized Work Queue

> **Purpose**: Single source of truth for **pending** work in the OpenWatch Go rebuild (repo root).
> Completed work is removed from this file; provenance lives in the commit history + `SESSION_LOG.md`.

**Last Updated**: 2026-06-21
**Active Tree**: repo root (Go backend `cmd/`+`internal/`, React/TypeScript `frontend/`)
**Frozen Tree**: the legacy Python/FastAPI backend was archived out of the repo on 2026-06-05 to `~/hanalyx/OWAR/openwatch-python/` (see CLAUDE.md)

---

## Priority Legend

| Priority | Meaning |
|----------|---------|
| P0 | Blocker — must ship before next milestone |
| P1 | High — needed for parity with the Python release |
| P2 | Medium — improves quality, can defer |
| P3 | Low — nice to have |

---

## Active Work — Host Detail

| Item | Priority | Status | Notes |
|------|----------|--------|-------|
| Updates-pending count on Server intelligence tile #1 | P2 | Placeholder | `CardServerIntel.tsx:185` hardcodes "No updates pending". Needs: collector to surface an `available_updates` field on the snapshot (apt/dnf unattended-upgrades parsing) — no such field exists in `collector` types today |
| Terminal tab | P3 | Stub | Disabled "deferred" stub (`HostDetailPage.tsx:658`). Browser-based SSH terminal: web-terminal lib + SSH-WS bridge needed. Post-GA |

> **Host Detail tabs — shipped (verified live 2026-06-21).** Six tabs the
> backlog still listed as Stub/Partial are fully implemented: **Compliance**
> (`ComplianceTab.tsx`, per-host `host_rule_state` summary with score donut +
> framework lens + rules table), **Packages / Services / Users / Network**
> (`InventoryTabs.tsx`, render the collector snapshot), **Activity**
> (`HostDetailPage.tsx:2565`, host-scoped unified feed with source filter +
> cursor paging, PR #618), and **Audit log** (`HostDetailPage.tsx:2694`,
> host-scoped `audit_events` via `resource_type=host`, PR #619). Only the two
> rows above (Updates-pending count, Terminal) remain.
>
> **Remediation tab — shipped (v0.2.0-rc.11).** Free-core single-rule apply +
> rollback from the host Remediation tab; concurrent fixes serialize per host;
> status updates live over SSE; free-core requests auto-approve. Landed via
> #601 (execute/rollback + governance), #606 (conditional approval, "A-keep"),
> #607 (serialize + live status). Licensed bulk/automated remediation remains a
> follow-on track (see `docs/engineering/scan_remaining_work.md`).
>
> **Host Management page fixes — shipped (PR #611).** Host-card chart icon
> links to `/scans/{latest_scan_id}`; Group (None/Status/OS) + a real Filters
> popover (Status/Compliance/OS) now work; per-user view default persists
> server-side (`users.preferences` JSONB, `/api/v1/users/me/preferences`).
> Browser-verified live (the chart icon on `owas-tst01` navigates to its
> `/scans/{uuid}` report; the icon is correctly hidden on never-scanned
> hosts).
>
> **Scan detail host label — shipped (PR #613).** The `/scans/{id}` detail
> header showed a truncated host UUID; it now shows hostname (else IP, else
> short UUID), resolved server-side from the `hosts` table
> (`api-scans` v1.1.0). Browser-verified (`owas-tst01`).

---

## Activity Feed Follow-ups

| Item | Priority | Notes |
|------|----------|-------|
| SSE auto-refresh of `host_activity` query key | P2 | `useLiveEvents.ts` invalidates `['host_intelligence_events', hostId]` + `['intelligence_state', hostId]` on `intelligence.event`. Should also invalidate `['host_activity', hostId]` on any of: `intelligence.event`, `monitoring.band.changed`, `alert.fired`, `scan.completed` |
| Filter NULL→online transitions on first-contact | P3 | Dev-fleet backend restarts wipe `previous_state` so every reboot writes a NULL→online row, dominating the feed. Real fleets won't see this pattern — defer until production reports it |
| Show the actual username on user-triggered audit events | P2 | PR #620 attributes operator-triggered events (Reconnect / "Run now" / add host) as `actor_type=user`, but they render **"A user …"** not the actual name. `auth.Identity` carries the user's ID + role but **not** their username/email — the identity binder (`internal/identity/binder.go`) looks up the role (`Lookups.RoleForUser`) but not the label. To show "alice@example.com …": add a `Label` (display name) field to `auth.Identity`, extend the `Lookups` interface to resolve it, populate it in the binder (session + JWT paths), set `ev.ActorLabel` from `auth.FromContext` at the discovery (and other user-triggered) emission sites. Security-sensitive (Tier-1 auth code, `system-auth-identity` spec) — scope carefully. The formatter already prefers `actor_label` over the `actor_type` word, so once the label flows, "A user" becomes the real name with no formatter change |
| **Activity readability Phase 4 — grouping / dedup / noise control** | P2 | Fast-follow to the merged Phases 0-3 (`docs/engineering/activity_readability_plan.md` §Phase 4). Collapse bursts (e.g. "12 packages updated on web-01" instead of 12 rows), suppress monitoring flaps (the NULL→online dev-restart noise above is one case), severity rollups, "N similar events". **Most visible target:** the feed + settings audit log are dominated by `scheduler.tick.dispatched` (~7k) and `system.package.installed` (~7k). Design fork to settle: group at query time (backend, scales) vs client-side (page-only) — recommend backend. **Coupled taxonomy question:** should routine `scheduler.tick.dispatched` be an *audit* event at all? It bloats the AU-compliance audit trail; consider demoting it to a non-audit metric/log |
| **Activity readability Phase 5 — audit compliance hardening** | P2 | Fast-follow, committed track (`activity_readability_plan.md` §Phase 5), for the FedRAMP/CMMC/NIST-800-53 **AU** family. (a) **Tamper-evidence**: populate the `signature` column already reserved on `audit_events` (Ed25519 per-event signing or a hash-chain over the log) — AU-9. (b) **Retention/archival** policy for `audit_events` (none today; relate to the host soft-delete sweep below) — AU-11. (c) An explicit **AU-control mapping doc** stating which capability satisfies AU-2/3/6/7/9/12 (export already covers AU-7) |
| Dashboard "Top failing hosts" widget shows a host UUID | P3 | `WidgetTopFailingHosts` (`frontend/src/pages/dashboard/widgets.tsx`) renders `nameOf(h.host_id)` which falls back to a truncated UUID (`019eccd8…`) when the host isn't in the loaded hosts list. Same "no UUIDs" goal as the activity-readability work, but a non-activity widget. Resolve the name (the widget already has, or can fetch, the host list) so it never shows a UUID |

---

## OpenWatch OS Remaining Work

| Item | Priority | Status | Notes |
|------|----------|--------|-------|
| Per-user alert-type preferences | P2 | Partial | **Dispatch-on-fire is now LIVE** — `notification.NewDispatchChannel` is registered with the alert router (`cmd/openwatch/main.go:326`) and `DispatchChannel.Send` (`internal/notification/delivery.go:204`) fans fired alerts to enabled Slack/email/webhook channels, filtered by the channel's `tag_filter.severity`. **Remaining:** per-USER alert-type preferences (which alert types each user wants), RBAC-gated — only channel-level severity tags exist today. The general `users.preferences` JSONB + `internal/userpref` + `/api/v1/users/me/preferences` (system-user-preferences, PR #611) is the natural home — extend the typed `UserPreferences` contract rather than a new table |
| In-app notifications | P1 | Planned | Bell icon with unread count, drawer, mark-as-read. Sources: alerts, scan completions, exception approvals, system events. RBAC-filtered. WebSocket or SSE delivery (the existing SSE bus can carry it). **Coupled to Reports below** — async report "ready" is the bell's first concrete producer (see `reports_design.md` §7) |
| Reports — full build-out (snapshot-with-faces) | P1 | Planned | Today `/reports` is one `executive` kind, JSON only, synchronous, no export/sign/schedule (Templates + Scheduled tabs are `ComingSoon`). Design doc: **`docs/engineering/reports_design.md`** — a report is one immutable signed point-in-time **snapshot** with multiple rendered **faces** (PDF/CSV/OSCAL/JSON/in-app); format follows audience × cardinality so the 1000-page PDF is structurally impossible (PDF bounded by construction; bulk evidence is CSV/OSCAL, async + content-addressed). Serves operator/CISO/auditor/GRC. All inputs already exist (fleetrollup, posture_snapshots, scan_results+OSCAL, exceptions, remediation transactions, queue, notification dispatch). **Phasing:** A) signed exec PDF + scope picker + coverage caveat + migrate `reports`→`report_snapshots`/`report_faces`; B) fleet OSCAL SAR + CSV async (the scale-correct bulk path); C) scheduled + emailed + bell "ready" signal + Exception Register/Remediation kinds; D) POA&M + Host Evidence Pack + Drift&Trend. Recommend starting Phase A |
| Dashboard layout customization (drag/drop) | P2 | Planned | 3 tiers per spec AC-12: full (admins), limited (analysts), none (auditor). Preset structure ready, needs `@dnd-kit/core` + persistence |
| Kensa Phase 5 OTA Updates | P3 | Not Started | OTA delivery of rule updates |

---

## OpenWatch+ Subscription

| Item | Priority | Status | Notes |
|------|----------|--------|-------|
| Subscription matrix | P1 | Partial | The feature/tier matrix is **already encoded in code** — `internal/license/features.gen.go` defines 10 gated features across free / openwatch_plus / enterprise tiers. Remaining is the product/marketing decision layer: host-count limits, priority support, multi-tenant, custom frameworks, and the customer-facing matrix doc |
| License key system | P1 | **Mostly built** | Core mechanism is LIVE, not Planned: `cmd/owlicgen` generates Ed25519-signed keys (tier/features/customer/expiry); `internal/license/validator.go` verifies with 30-day grace, clock-rollback detection, and fingerprint binding; `service.go` loads from file or JWT. Remaining: renewal flow + air-gapped re-issue UX |
| Payment + activation flow | P1 | Planned | Purchase channel, delivery (email/portal), activation (`owadm activate` CLI / UI / API). Air-gapped path: manual key upload. (The key *format* + validation it activates against already exists — see above) |
| License enforcement | P1 | Partial | **Backend is LIVE**: `internal/license/middleware.go` `RequireFeature`/`EnforceFeature` gate routes and return 402 Payment Required with an audit trail. Remaining: host-count checks (no count enforcement yet), graceful degradation on expiry, and the **frontend** (upgrade prompts, lock UI, Settings license status) |
| Sales + distribution | P2 | Planned | Per-host vs per-seat vs flat tier. Trial. Volume discounts. Self-serve vs sales-assisted |

---

## Kensa Integration Gaps

Gaps identified comparing `docs/KENSA_OPENWATCH_BOUNDARY.md` against current OpenWatch implementation.

### Not Implemented

| ID | Item | Priority | Notes |
|----|------|----------|-------|
| K-4 | Risk-aware remediation policies | P2 | Kensa classifies remediation as high/medium/low risk. Use for approval gates (auto-approve low-risk, require human for GRUB/PAM/fstab) |
| K-5 | Snapshot retention / pruning | P3 | Kensa has 7-day active / 90-day archive lifecycle for pre-state snapshots. Depends on K-3 |
| K-6 | `get_applicable_mappings()` | P3 | Platform filtering on mappings (RHEL 8 vs 9). Currently load all without filtering |
| K-7 | `build_rule_to_section_map()` | P3 | Kensa utility; we use DB queries instead. Low impact |
| K-8 | Inventory file support | P3 | Kensa accepts INI/YAML/text. Our SSH-per-host model is correct — skip |

### Partially Implemented

| ID | Item | Priority | Current State | Missing |
|----|------|----------|---------------|---------|
| K-10 | Platform filtering | P2 | `detect_platform()` called | `rule_applies_to_platform()` not used to filter before evaluation |
| K-11 | Host context in evidence | P2 | `SystemInfoCollector` gathers facts | Not stored alongside findings; groups + effective vars missing |
| K-12 | Bulk scan via Kensa ThreadPoolExecutor | P3 | One Kensa invocation per host | Kensa has `--workers N` (max 50) parallelizing across hosts on one SSH thread each. Needs inventory file generation + result fan-out |

---

## Go Rebuild — Deferred Features

| Item | Priority | Status | Notes |
|------|----------|--------|-------|
| Retention sweep for soft-deleted hosts | P3 | Not started | Soft-deleted hosts (`hosts.deleted_at` set by `internal/host/host.go:298 SoftDelete`) are retained **indefinitely** — no purge job exists anywhere, confirmed by a soft-deleted row from 2026-05-25 still present in the dev DB. The row stays for scan-history/audit integrity but is hidden from every query (`WHERE deleted_at IS NULL`). Add an optional retention sweep (a daemon-orchestration tick that hard-deletes `hosts WHERE deleted_at < now() - $window`, cascading scan history), with an operator-configurable window that defaults to disabled (keep forever). Low urgency — host volume is trivial — but closes unbounded soft-deleted-row growth and gives operators a real "forget this host" path |
| `POST /api/v1/bulk/hosts/analyze-csv` + `import-with-mapping` | P2 | Deferred | Today the wizard runs CSV analysis client-side and submits row-by-row — no atomic semantics, no "update existing", no row caps |
| Standalone SSH-key vault | P3 | Deferred | Today every credential owns its own key material; no first-class "SSH key" resource. Worth doing when rotation cadence forces N-credentials-share-1-key |
| Track B SSE: invalidate `['scans']` / `['transactions']` / `['groups']` query keys | P2 | Now actionable | The pages have landed, but `useLiveEvents.ts` still doesn't invalidate them: `scan.completed` invalidates `['hosts']` + `['host', hostId]` only, never `['scans']`; no handler touches `['transactions']` or `['groups']`. Wire these now (no longer blocked on the pages) |
| Track B SSE: `Last-Event-ID` resume cursor | P3 | Deferred | Events published while disconnected are lost. Needs persistent event ring; defer until operators report missed transitions |
| Track B SSE: bus drop counter on a metrics endpoint | P3 | Deferred | `eventbus.Bus.Metrics()` exposes counters but nothing scrapes them. Plumb `/api/v1/system/eventbus/metrics` or merge into existing metrics endpoint |
| Specter `sync` ignores `settings.tests_glob` | P3 | Worked around | CI passes `--tests '**/*'`; upstream bug. Documented in `specter.yaml` |
| Strip redundant header `// @ac` traceability blocks (~185 `unreachable_annotation` warnings) | P3 | Deferred | `specter check --test` is at 0 errors and gated in CI, but still emits ~185 warnings from top-of-file `// @ac` summary blocks that duplicate per-test annotations. Non-blocking under the non-strict gate. Can't be a mechanical sweep: de-annotating risks dropping source-walk coverage for any AC covered *only* via its header block — needs a per-AC check first. Once clean, the gate could be tightened to fail on warnings too |

---

## Documentation

| ID | Item | Priority | Status | Notes |
|----|------|----------|--------|-------|
| DOC-1 | CLAUDE.md "Packaging Infrastructure" describes a Python-era layout that doesn't exist in the Go native package | P2 | Open | The section claims package contents include `/opt/openwatch/backend/` (Python backend + requirements.txt), `/opt/openwatch/frontend/` (built SPA), and `/opt/openwatch/backend/kensa/` (rules, mappings, config, 508 rules), plus systemd units `openwatch-api`/`openwatch-worker@`/`openwatch-beat` and an nginx reverse proxy. None of that matches the rc7 Go RPM/DEB: the payload is a single `openwatch` Go binary (with embedded SPA), `openwatch.toml`, `openwatch.service`, and demo TLS certs (`packaging/rpm/openwatch.spec` + `build-rpm.sh`). The Kensa-rules-bundled claim is the same gap tracked in PKG-2. Fix: rewrite the section to match the Go packaging, or banner it as historical Python-era reference like the other frozen sections |

---

## Deferred Dependency Upgrades

Dependabot major bumps closed (skipped) 2026-06-16, with the reason + revisit path. Dependabot re-raises each on its next version bump.

| Dependency | Bump | Why deferred |
|------------|------|--------------|
| `@mui/material` | 7 → 9 | Two majors (Grid v2 API + theme/styling breaking changes). Real component migration; do as a dedicated PR (test empirically first) |
| `eslint` + `@eslint/js` + `eslint-plugin-react-hooks` | 9 → 10 / 5 → 7 | **Blocked upstream** — `typescript-eslint@8.61` / `eslint-plugin-react@7.37` peer-dep on eslint ≤9, so eslint 10 won't install (`ERESOLVE`). Revisit when the lint ecosystem supports eslint 10; land as one combined PR |
| `sigstore/cosign-installer` | 3.7 → 4.x | Installs cosign 3.0.5, which **breaks our offline key-based release signing** (`--tlog-upload` removed; default `--new-bundle-format` ignores `--output-signature`; `verify-blob` wants the rekor tlog). When done: pin `with: cosign-release: v2.6.1` (keep current signing) OR migrate to the bundle format + update `RELEASING.md`/`KEYS` verify steps |

---

## CI / Quality

| Item | Priority | Notes |
|------|----------|-------|
| CI gate speed: split the monolith into parallel jobs | P3 | The `Quality + security gates` job runs lint/vuln/test/frontend sequentially (wall-clock = sum). Split into concurrent jobs (lint+vet+vuln vs. test+coverage vs. frontend) so wall-clock = max. **Needs a branch-protection change**: only one job is the required `Quality + security gates` check today, so splitting means updating the required-checks list in the GitHub UI (operator action, not code). Prep the workflow, then flip required checks. |

### Flakes

> **Largely mitigated (verified 2026-06-21).** All three now run through the
> non-gating `perftest.Budgetf()` helper with race-aware budgets
> (`internalrace.Multiplier()`), so a slow p99 no longer fails the build — they
> emit a budget note instead of gating merges. The rows below are kept only as a
> trend watch; none currently blocks CI.

| Item | Priority | Notes |
|------|----------|-------|
| `internal/license.TestVerify_P99Latency` | P3 | 1ms p99 budget, non-gating via `perftest.Budgetf()`. No `-race` skip needed (helper absorbs it). Watch only |
| `internal/audit.TestEmitSync_Latency` | P3 | `10ms * internalrace.Multiplier()` budget, non-gating. Watch only |
| `internal/queue.TestEnqueue_LatencyP99` | P3 | 10ms budget (spec target 5ms), non-gating. Watch only |

---

## Testing / Regression Coverage

Gaps where working functionality can break without an automated test failing (identified 2026-06-15). The suite is strong for specced logic + DB integration (988 Go test funcs, race detector, real Postgres) but blind on live execution and full UI flows.

| Item | Priority | Notes |
|------|----------|-------|
| Live-host SSH/sudo integration test (gated) | P2 | **Mostly done** | Delivered `internal/ssh/livehost_test.go` — opt-in (`OPENWATCH_LIVE_HOSTS` CSV + `OPENWATCH_LIVE_KEY`), self-skipping, drives the REAL `ssh.Dial` + `ssh.RunSudo`. Per host it asserts the machinery for whatever the host supports: key auth → `ObservedAuth=="key"`, password auth → `"password"`, sudo mode confirmed via `true`, and the real `sudo -S` password-on-stdin path. Validated against the dev fleet (5 key+NOPASSWD hosts pass; key-rejecting / unreachable hosts skip). **Gap:** the password-AUTH branch (`ObservedAuth=="password"`) is unverified live because the dev fleet has `PasswordAuthentication no` everywhere — needs one host with password SSH enabled to exercise it. Optional next: add a `connprofile.Store` round-trip (record→read-back) assertion against a gated DB. |
| Frontend E2E (Playwright) for critical flows | P2 | **Zero E2E tests** — the `@playwright/test` + `@axe-core/playwright` deps and a `test:e2e` script are in `package.json`, but there is **no `playwright.config.*` and no `*.spec.ts` E2E file**, and nothing runs in CI. Component-level vitest only, so a wired-up page can be green in vitest and broken in the browser. Stand up the config + cover the critical flows: login, the activated Settings pages (Users, Notifications, Security/API tokens, SSO), and host CRUD (add / edit / delete). |
| Negative-path ACs for security gates | P2 | The scan kill-switch bug this session passed all 988 tests + the specter gate because the scan path simply had **no AC requiring it to honor the switch** — the suite tests specced behavior, so gaps *between* specs slip through. Generalize the pattern of `system-connection-profile/AC-07` (asserts "kill-switch off / key-only cred → no `sudo -S`") across the other security gates: every gate should have a spec'd AC + test for the **disallowed** path, not just the happy path. |

---

## How to Use This File

1. **Starting a session**: Read this file alongside `CLAUDE.md` and `SESSION_LOG.md`
2. **Picking work**: Default to the highest-priority "Active Work" + Packaging (P0) items, then the OpenWatch OS or OpenWatch+ planned items
3. **Completing work**: **Remove** the row from this file; record the PR in the commit message and `SESSION_LOG.md` (this file tracks only pending work)
4. **Discovering new work**: Add to the most appropriate section
5. **Ending a session**: Update statuses, remove completed rows, prepend `SESSION_LOG.md`, create a handoff file in `docs/handoff/` if the next session will be a different operator
