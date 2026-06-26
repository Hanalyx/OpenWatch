# BACKLOG.md — OpenWatch Prioritized Work Queue

> **Purpose**: Single source of truth for **pending** work in OpenWatch (repo root).
> Completed work is removed from this file; provenance lives in the commit history + `SESSION_LOG.md`.

**Last Updated**: 2026-06-25
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
| In-app notifications — **change-driven** | P1 | Partial (MVP shipped) | **MVP is live, not Planned:** a working bell + unread badge in `TopBar.tsx` bumped by `report.ready` over SSE (`useLiveEvents.ts` → `useNotificationStore`), session-scoped, with tests (`notification-bell.test.ts`). **Redesign (the real work):** the bell must surface **meaningful state changes**, not finished reports. Primary case: a rule that was passing is **now failing** (the write-on-change `transactions` log already records `state_changed`/`first_seen`); plus host unreachable, compliance band drop, fleet drift (the `alertrouter` already classifies `host_unreachable`/`host_recovered`/`drift_*` with severity + dedup), failed scans, failed remediation, exception approvals/expiry (RBAC-scoped to approvers), lockouts, license expiry. Architecture: an **in-app channel of `alertrouter`** + a small **transaction-log regression projector** → a durable per-user `notifications` table → `GET /api/v1/notifications` + unread + `:markRead` + drawer + SSE push. Grouped (one row per host/scan burst, not 30), severity-gated (badge counts unread high+), noise-excluded (no scheduler ticks / routine package churn / sub-threshold jitter). `report.ready` demoted to one `info` producer. Full design + taxonomy + phasing: [docs/engineering/notifications_design.md](docs/engineering/notifications_design.md). Slice 1 = durable feed + wire the existing alerts into it. |
| Reports — full build-out (snapshot-with-faces) | P2 | **Phase A shipped** | Design doc: **`docs/engineering/reports_design.md`** — a report is one immutable signed point-in-time **snapshot** with multiple rendered **faces**; format follows audience × cardinality so the 1000-page PDF is structurally impossible. **Phase A complete (PRs #631-#637, 2026-06-21):** the `executive` kind is now scoped (group/framework, A1), coverage-honest (staleness caveat that respects scope, A2), content-addressed on the renamed `report_snapshots` + `report_faces` model (A3a), with a bounded pure-Go **PDF face** + `GET /reports/{id}/export` (A3b) and a frontend Download control (A3b-2), **Ed25519-signed** with offline verification via `GET /reports/signing-key` (A4a) and a frontend **Signed badge + Verify** action (A4b). Production op: set `[reports].signing_key_file` for a durable signing key (dev uses an ephemeral per-boot key). **Remaining (Phases B-D, separate initiative):** B) fleet OSCAL SAR + CSV evidence extract, async (the scale-correct bulk path for auditors/GRC); C) scheduled + emailed + the in-app bell "ready" signal + Exception Register / Remediation Activity kinds; D) POA&M + Host Evidence Pack + Drift&Trend. The other prototype report kinds + the Templates/Scheduled tabs land here |
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

## Packaging / Deployment

| ID | Item | Priority | Status | Notes |
|----|------|----------|--------|-------|
| PKG-3 | Remediation broken on every packaged install — Kensa rollback store can't open under the hardened unit | **P1** | Open | **Symptom (prod rc.14):** boot WARN `kensa remediation wiring unavailable` with `error=kensa: compose remediation service: …`; scans work but every remediation/rollback returns `kensa: remediate path not wired` (`internal/kensa/executor.go:153`). **Root cause:** `packaging/common/openwatch.service` sets `ProtectSystem=strict` + `ReadWritePaths=/var/lib/openwatch /var/log/openwatch` but (a) sets **no `WorkingDirectory`** (systemd defaults it to read-only `/`) and (b) **never sets `OPENWATCH_KENSA_STORE_PATH`**. So `kensaStorePath()` (`cmd/openwatch/main.go:768`) falls back to `.kensa/remediation.db` -> `/.kensa/remediation.db`, and Kensa's `OpenSQLite` `MkdirAll` fails on the read-only root. Scans are unaffected because the scan path composes a store-less Kensa; only remediation needs the SQLite rollback-pre-state store (`pkgkensa.DefaultWithTransportFactory`, pure-Go `modernc.org/sqlite`). **Fix:** add to the unit `Environment=OPENWATCH_KENSA_STORE_PATH=/var/lib/openwatch/kensa/remediation.db` and `WorkingDirectory=/var/lib/openwatch` (both `serve` and any `worker` unit — `worker.go:209` wires identically). **Regression:** a release test asserting remediation wiring composes under the hardened unit so it can't silently break again. **Operator workaround (no new pkg):** `systemctl edit openwatch` -> `[Service]\nEnvironment=OPENWATCH_KENSA_STORE_PATH=/var/lib/openwatch/kensa/remediation.db` -> restart. Worth an rc.15 since it breaks all remediation on hardened packaged installs |

---

## Security / Auth

| ID | Item | Priority | Status | Notes |
|----|------|----------|--------|-------|
| AUTH-1 | Idle + Absolute session timeouts (`/settings/security` Authentication policy) are not effectively enforced for the browser | **P1** | In progress | **Symptom:** a user who walks away stays logged in far past the configured idle timeout; the absolute timeout never bites either. The real ceiling is the 7-day refresh token. Security/compliance gap (NIST 800-53 AC-11/AC-12 — the frameworks OpenWatch itself scans for). **Backend is correct in isolation:** `internal/identity/sessions.go` `VerifySession` rejects on idle/absolute expiry and uses the configured windows. **Three compounding causes defeat it:** (1) the SPA polls many endpoints every 15-60s (ScansPage 15s, ScanningPage 30s, HostDetailPage 60s, ActivityPage 15s) + a persistent SSE stream; every authenticated request slides `expires_at = now + idle` (`sessions.go:188`), so "idle" tracks HTTP traffic, not user activity, and the window never elapses. (2) the cookie-refresh path (`internal/server/auth_handlers.go:269` `PostAuthRefreshCookie`) validates only the 7-day refresh token and mints a **fresh** session with new idle AND new absolute windows (`IssueSession` line 304) on the API client's transparent 401 retry (`frontend/src/api/client.ts:142`), masking expiry and resetting the absolute cap. (3) there is **no client-side user-activity idle timer** in the frontend — no mousemove/keydown tracking, no proactive logout/redirect. **Fix (layered):** (a) client-side idle timer keyed to real user input, reads `session_idle_timeout_seconds` from `/api/v1/auth-policy`, on inactivity calls logout (revoke session+refresh) + redirect `/login` [slice 1, in progress]; (b) enforce the absolute ceiling in refresh-cookie — carry the original login's absolute deadline in the refresh token; refuse to refresh past it; (c) defense-in-depth: only slide the server idle window on user-initiated requests (e.g. an `X-User-Activity` header), so server-side idle is real even if the client timer is bypassed |

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
| DOC-2 | `~539` approximate rule-count bounds not updated to `~538` after Kensa v0.6.0 | P3 | Open | The factual rule counts moved 539->538 with Kensa v0.6.0 (rc.14), but the explicitly-approximate `~539` bounds that justify the unpaginated host-compliance lens were left as-is in `internal/server/host_compliance_lens_handler.go`, `api/openapi.yaml` (+ generated `openapi_embed.yaml` / `frontend/src/api/schema.d.ts`), and specs `host-compliance` / `host-compliance-tab`. Cosmetic only (the `~` already disclaims precision and the bounded->no-pagination claim is unaffected by ±1); updating the openapi source requires `make generate-api` to re-sync the two generated copies |
| DOC-3 | Operator-guide truthfulness + style remediation (2026-06-25 audit) | P2 | **Done** | A full audit of `docs/guides/*.md` vs code found defects clustering in API-surface sections, RBAC specifics, and stale versions. **Pass 1 (#680):** UPGRADE_PROCEDURE `--config`-after-subcommand x3; COMPLIANCE_CONTROLS invented `analyst` role + "three-tier role model" + fabricated rate-limit numbers; API_GUIDE false "not yet in the API" section; `rc.13`->`rc.14` sweep. **Pass 2 (#682, all code-verified):** SCANNING_AND_COMPLIANCE appendix dead `/api/v1/compliance/{posture,drift,alerts,audit/*}` paths replaced with real endpoints (paths + query params checked vs `openapi_embed.yaml`); USER_ROLES matrix now 67 rows = full registry (added token:*/system:auth_policy_*), `remediation:execute/rollback` corrected to free-core+`ops_lead`-held (only `audit:export` is license_gated), 19->20 categories, ops_lead prose; DATABASE_MIGRATIONS real `migrations applied — version N -> N` + 10-min timeout; HOSTS_AND_REMEDIATION 5-min `DefaultProbeInterval` + ICMP/SSH-banner/privilege layering (not 30s/SSH-auth); INSTALLATION kensa-rules `0.5.0`->`0.6.0` + create-admin password-echo caveat; LINUX_DISTRIBUTION_SUPPORT re-verified Kensa v0.6.0 = 538/538 rhel-family; Last Updated headers added to SECURITY_HARDENING + LINUX_DISTRIBUTION_SUPPORT. **Two backlog assumptions were themselves wrong and corrected during the pass:** (1) INSTALLATION's PostgreSQL dependency is **NOT phantom** — `packaging/rpm/openwatch.spec:37` really has `Requires: postgresql-server`, so the claim was kept; (2) LINUX_DISTRIBUTION_SUPPORT **did** carry the stale `v0.4.3`/`539` (the rest of the guides were already 538), now corrected to v0.6.0/538 via direct module count. **Deferred (separate cleanup):** blanket spaced-em-dash close-up across all guides (pre-existing, large mechanical diff); MONITORING date left at 2026-06-10 (no content review this pass — bumping unreviewed dates would be dishonest metadata). |

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
| `internal/transactionlog.TestApply_1000Rules_Under2Seconds` | P2 | **GATING flake** — missed the 2026-06-21 migration: still a HARD `if elapsed > 2*time.Second { t.Errorf }` (`writer_test.go:476`), so under `-race` + CI load it fails the build (took 2.54s on #676's gate 2026-06-25; passed on rerun). Fix: move AC-10's assertion to the non-gating `perftest.Budgetf()` with `internalrace.Multiplier()` like the other three perf tests, so a slow p99 emits a note instead of gating merges |

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
