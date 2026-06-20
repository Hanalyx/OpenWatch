# BACKLOG.md — OpenWatch Go Prioritized Work Queue

> **Purpose**: Single source of truth for **pending** work in the OpenWatch Go rebuild (repo root).
> Completed work is removed from this file; provenance lives in the commit history + `SESSION_LOG.md`.

**Last Updated**: 2026-06-20
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
| Updates-pending count on Server intelligence tile #1 | P2 | Placeholder | Renders "No updates pending" always. Needs: collector to surface `available_updates` field on the snapshot (apt/dnf unattended-upgrades parsing) |
| Compliance tab | P1 | Stub | TabStub placeholder. Needs: per-host compliance summary from `host_rule_state` |
| Packages tab | P1 | Partial | Reads `intelligenceStateQuery.data.packages` — works when collector has run. UI exists in `pages/host-detail/InventoryTabs.tsx` |
| Services tab | P1 | Partial | Same shape as Packages — reads `intelligenceStateQuery.data.services` |
| Users tab | P1 | Partial | Same shape — reads `intelligenceStateQuery.data.users` |
| Audit log tab | P2 | Stub | Needs host-scoped `audit_events` API hook |
| Activity tab | P1 | Stub | **Where "View all" on the Recent activity card lands today.** Needs full-feed renderer with cursor pagination + source/severity filters on the unified `/api/v1/activity?host_id=X` endpoint |
| Terminal tab | P3 | Stub | Browser-based SSH terminal. Web terminal lib + SSH-WS bridge needed |

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

---

## OpenWatch OS Remaining Work

| Item | Priority | Status | Notes |
|------|----------|--------|-------|
| Email alert notifications (dispatch on alert) | P1 | Partial | The notification **channel** layer (Slack/email/webhook CRUD + test) shipped. Remaining: dispatch fired alerts through channels by type + per-user alert-type preferences (which alert types per user), RBAC-gated. **Infra now exists**: the general `users.preferences` JSONB + `internal/userpref` + `/api/v1/users/me/preferences` (system-user-preferences, PR #611) is the natural home for per-user alert prefs — extend the typed `UserPreferences` contract rather than a new table |
| In-app notifications | P1 | Planned | Bell icon with unread count, drawer, mark-as-read. Sources: alerts, scan completions, exception approvals, system events. RBAC-filtered. WebSocket or SSE delivery (the existing SSE bus can carry it) |
| Dashboard layout customization (drag/drop) | P2 | Planned | 3 tiers per spec AC-12: full (admins), limited (analysts), none (auditor). Preset structure ready, needs `@dnd-kit/core` + persistence |
| Kensa Phase 5 OTA Updates | P3 | Not Started | OTA delivery of rule updates |

---

## OpenWatch+ Subscription

| Item | Priority | Status | Notes |
|------|----------|--------|-------|
| Subscription matrix | P1 | Planned | Free vs OpenWatch+ feature matrix. Candidates: host count limits, advanced reporting/export, email alerts, priority support, OTA rule updates, multi-tenant, custom frameworks |
| License key system | P1 | Planned | Offline file (air-gapped) vs online activation vs hybrid. `internal/license` exists; extend. Format, expiry, renewal, grace period |
| Payment + activation flow | P1 | Planned | Purchase channel, delivery (email/portal), activation (`owadm activate` CLI / UI / API). Air-gapped path: manual key upload |
| License enforcement | P1 | Planned | Backend: feature-gate decorators, host count checks, graceful degradation on expiry. Frontend: upgrade prompts, lock UI, Settings status |
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
| `PATCH /api/v1/credentials/{id}` — in-place credential update | P2 | Deferred | Frontend uses replace-on-save (`<ReplaceCredentialModal>` runs `POST → DELETE`). Real PATCH would close the orphan-credential failure mode |
| `POST /api/v1/bulk/hosts/analyze-csv` + `import-with-mapping` | P2 | Deferred | Today the wizard runs CSV analysis client-side and submits row-by-row — no atomic semantics, no "update existing", no row caps |
| Standalone SSH-key vault | P3 | Deferred | Today every credential owns its own key material; no first-class "SSH key" resource. Worth doing when rotation cadence forces N-credentials-share-1-key |
| Track B SSE: invalidate `['scans']` / `['transactions']` / `['groups']` query keys | P2 | Deferred | Depends on those pages landing. Wire alongside the pages, don't retrofit |
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

| Item | Priority | Notes |
|------|----------|-------|
| `internal/license.TestVerify_P99Latency` flake under `-race` | P3 | Tight <1ms p99 budget. Bump to 2ms, skip under `-race`, or pre-warm verifier |
| `internal/audit.TestEmitSync_Latency` flake | P3 | p99 latency assertion, sensitive to CI runner load. Single rerun cleared |
| `internal/queue.TestEnqueue_LatencyP99` flake | P3 | Same shape — single rerun cleared. Trend: consider widening all p99 budgets or moving them to a perf-suite that doesn't gate merges |

---

## Testing / Regression Coverage

Gaps where working functionality can break without an automated test failing (identified 2026-06-15). The suite is strong for specced logic + DB integration (988 Go test funcs, race detector, real Postgres) but blind on live execution and full UI flows.

| Item | Priority | Notes |
|------|----------|-------|
| Live-host SSH/sudo integration test (gated) | P2 | **Mostly done** | Delivered `internal/ssh/livehost_test.go` — opt-in (`OPENWATCH_LIVE_HOSTS` CSV + `OPENWATCH_LIVE_KEY`), self-skipping, drives the REAL `ssh.Dial` + `ssh.RunSudo`. Per host it asserts the machinery for whatever the host supports: key auth → `ObservedAuth=="key"`, password auth → `"password"`, sudo mode confirmed via `true`, and the real `sudo -S` password-on-stdin path. Validated against the dev fleet (5 key+NOPASSWD hosts pass; key-rejecting / unreachable hosts skip). **Gap:** the password-AUTH branch (`ObservedAuth=="password"`) is unverified live because the dev fleet has `PasswordAuthentication no` everywhere — needs one host with password SSH enabled to exercise it. Optional next: add a `connprofile.Store` round-trip (record→read-back) assertion against a gated DB. |
| Frontend E2E (Playwright) for critical flows | P2 | **Zero E2E tests** — `0` Playwright files, no config (the CLAUDE.md Playwright note is Python-era). Component-level vitest only, so a wired-up page can be green in vitest and broken in the browser. Stand up Playwright + cover the critical flows: login, the activated Settings pages (Users, Notifications, Security/API tokens, SSO), and host CRUD (add / edit / delete). |
| Negative-path ACs for security gates | P2 | The scan kill-switch bug this session passed all 988 tests + the specter gate because the scan path simply had **no AC requiring it to honor the switch** — the suite tests specced behavior, so gaps *between* specs slip through. Generalize the pattern of `system-connection-profile/AC-07` (asserts "kill-switch off / key-only cred → no `sudo -S`") across the other security gates: every gate should have a spec'd AC + test for the **disallowed** path, not just the happy path. |

---

## How to Use This File

1. **Starting a session**: Read this file alongside `CLAUDE.md` and `SESSION_LOG.md`
2. **Picking work**: Default to the highest-priority "Active Work" + Packaging (P0) items, then the OpenWatch OS or OpenWatch+ planned items
3. **Completing work**: **Remove** the row from this file; record the PR in the commit message and `SESSION_LOG.md` (this file tracks only pending work)
4. **Discovering new work**: Add to the most appropriate section
5. **Ending a session**: Update statuses, remove completed rows, prepend `SESSION_LOG.md`, create a handoff file in `docs/handoff/` if the next session will be a different operator
