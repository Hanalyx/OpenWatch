# BACKLOG.md — OpenWatch Go Prioritized Work Queue

> **Purpose**: Single source of truth for pending work in the **OpenWatch Go** rebuild (`app/`).
> Updated at the end of each AI session.

**Last Updated**: 2026-06-04
**Active Tree**: `app/` (Go backend + React/TypeScript frontend)
**Frozen Tree**: `backend/` (legacy Python/FastAPI — FROZEN as of 2026-06-04, see CLAUDE.md)

---

## Priority Legend

| Priority | Meaning |
|----------|---------|
| P0 | Blocker — must ship before next milestone |
| P1 | High — needed for parity with the Python release |
| P2 | Medium — improves quality, can defer |
| P3 | Low — nice to have |

---

## Recently Completed (2026-06-03 / 2026-06-04 session)

| Item | PR | Notes |
|------|----|-------|
| `sudo -S` password fallback wired into liveness privilege probe + discovery firewall queries | #469 | system-ssh-connectivity v1.2.0 C-09. Three call sites (collector, sshprivilege, discovery) share identical retry shape |
| SSH dialer fix — AuthBoth offers both PublicKeys AND Password | #470 | Latent bug from #469 rollout — handshake failed on AuthBoth before sudo-n ever ran. Affected 4 dev hosts (owas-rhl10/ub22/ub24/ub26) |
| `hosts.os_family` stores distro ID, not family rollup | #471 | system-host-discovery v1.3.0 AC-22. Migration 0022 backfills existing rows from `host_system_info.os_id`. Fixed "Ubuntu hosts show as Debian" badge bug |
| Server intelligence card — 2×3 snapshot tile grid | #472 | frontend-host-detail-intelligence-feed v2.0.0. Replaces event-feed v1.0.0 |
| TRUNCATE…CASCADE test hygiene | #474 | 6 integration test helpers silently discarded `TRUNCATE TABLE hosts` errors caused by Q1 FK additions (transactions, host_rule_state) |
| `CardServerIntel` cache-shape collision fix | #475 | New card shared a queryKey with the existing `intelligenceStateQuery` but expected a different value shape — silently rendered "Not collected yet" everywhere |
| Activity service wired into main + `host_id` filter crash fix | #477 | The service had `WithActivity` but no caller — `/api/v1/activity` returned 503. After wiring, host_id-filtered queries crashed with `invalid input syntax for type uuid: ""` (audit leg's `'' = $hostPH` predicate). system-activity AC-13 added |
| `host_monitoring_history` as 5th source leg + Recent activity card rewrite | #478 | system-activity v1.0.0 → v1.1.0. Card now consumes the unified `/activity?host_id=X` feed |
| Recent activity card polish — icons, "View all", 5-row slice, long-form date | #479 | Matches mockup. `View all` links to `/hosts/{id}?tab=activity` (tab is a `TabStub` today) |

---

## Active Work — Host Detail Overview Tab (~90% complete)

| Item | Priority | Status | Notes |
|------|----------|--------|-------|
| Top failed rules card | P1 | Stub | Returns hardcoded `EmptyState` because no scans have run on the dev fleet. Needs: query `host_rule_state` for `status='fail'`, sort by severity DESC + count DESC, slice to 5, link rule IDs to rule reference page |
| Compliance trend (last 30 days) card | P1 | Stub | Returns "Not enough data yet" empty state. Needs: posture-snapshot subsystem (BACKLOG). When transactions exist, can derive trend from `transactions` table via a daily aggregate query |
| Open exceptions count on Server intelligence tile #6 | P2 | Placeholder | Renders `—`. Needs: `/api/v1/compliance/exceptions?host_id=X` wire — exceptions service exists, just no card hook yet |
| Updates-pending count on Server intelligence tile #1 | P2 | Placeholder | Renders "No updates pending" always. Needs: collector to surface `available_updates` field on the snapshot (apt/dnf unattended-upgrades parsing) |

---

## Active Work — Host Detail Other Tabs

| Tab | Priority | Status | Notes |
|-----|----------|--------|-------|
| Compliance | P1 | Stub | TabStub placeholder. Needs: per-host compliance summary from `host_rule_state` |
| Packages | P1 | Partial | Reads `intelligenceStateQuery.data.packages` — works when collector has run. UI exists in `pages/host-detail/InventoryTabs.tsx` |
| Services | P1 | Partial | Same shape as Packages — reads `intelligenceStateQuery.data.services` |
| Users | P1 | Partial | Same shape — reads `intelligenceStateQuery.data.users` |
| Network | P1 | Wired | Renders `intelligenceStateQuery.data.network_interfaces` + `listening_ports` + firewall from `host_system_info` |
| Audit log | P2 | Stub | Needs host-scoped `audit_events` API hook |
| Activity | P1 | Stub | **Where "View all" lands today.** Needs full-feed renderer with cursor pagination + source/severity filters on the unified `/api/v1/activity?host_id=X` endpoint |
| Remediation | P2 | Stub | Kensa Phase 4 (K-2/K-3 done, K-4 risk-aware policies + K-5 snapshot retention pending) |
| Terminal | P3 | Stub | Browser-based SSH terminal. Web terminal lib + SSH-WS bridge needed |

---

## Activity Feed Follow-ups (from #478/#479)

| Item | Priority | Notes |
|------|----------|-------|
| Build out the Activity tab at `/hosts/{id}?tab=activity` | P1 | "View all" on the Recent activity card lands on a `TabStub` today. Tab should render the full feed (paginated, source/severity filters, time-range) |
| SSE auto-refresh of `host_activity` query key | P2 | `useLiveEvents.ts` invalidates `['host_intelligence_events', hostId]` + `['intelligence_state', hostId]` on `intelligence.event`. Should also invalidate `['host_activity', hostId]` on any of: `intelligence.event`, `monitoring.band.changed`, `alert.fired`, `scan.completed` |
| Filter NULL→online transitions on first-contact | P3 | Dev-fleet backend restarts wipe `previous_state` so every reboot writes a NULL→online row, dominating the feed. Real fleets won't see this pattern — defer until production reports it |

---

## OpenWatch OS Remaining Work

| Item | Priority | Status | Notes |
|------|----------|--------|-------|
| Adaptive Compliance Scheduler | P1 | Planned | Auto-scan with state-based intervals (max 48h). Depends on monitoring spec (complete) |
| Email alert notifications | P1 | Planned | SMTP/SES dispatcher. User preferences table (which alert types). RBAC-gated. The Q1 notification-channels work (Slack/email/webhook) is the foundation |
| In-app notifications | P1 | Planned | Bell icon with unread count, drawer, mark-as-read. Sources: alerts, scan completions, exception approvals, system events. RBAC-filtered. WebSocket or SSE delivery (the existing SSE bus can carry it) |
| Dashboard layout customization (drag/drop) | P2 | Planned | 3 tiers per spec AC-12: full (admins), limited (analysts), none (auditor). Preset structure ready, needs `@dnd-kit/core` + persistence |
| Remediation Phase 4 follow-ups | P3 | Mostly Complete | K-4 (risk-aware policies), K-5 (snapshot retention) |
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
| `PATCH /api/v1/credentials/{id}` — in-place credential update | P2 | Deferred | Frontend uses replace-on-save (`<ReplaceCredentialModal>` runs `POST → DELETE`). Real PATCH would close the orphan-credential failure mode |
| `POST /api/v1/bulk/hosts/analyze-csv` + `import-with-mapping` | P2 | Deferred | Today the wizard runs CSV analysis client-side and submits row-by-row — no atomic semantics, no "update existing", no row caps |
| Standalone SSH-key vault | P3 | Deferred | Today every credential owns its own key material; no first-class "SSH key" resource. Worth doing when rotation cadence forces N-credentials-share-1-key |
| Track B SSE: invalidate `['scans']` / `['transactions']` / `['groups']` query keys | P2 | Deferred | Depends on those pages landing. Wire alongside the pages, don't retrofit |
| Track B SSE: `Last-Event-ID` resume cursor | P3 | Deferred | Events published while disconnected are lost. Needs persistent event ring; defer until operators report missed transitions |
| Track B SSE: bus drop counter on a metrics endpoint | P3 | Deferred | `eventbus.Bus.Metrics()` exposes counters but nothing scrapes them. Plumb `/api/v1/system/eventbus/metrics` or merge into existing metrics endpoint |
| Specter `sync` ignores `settings.tests_glob` | P3 | Worked around | CI passes `--tests '**/*'`; upstream bug. Documented in `app/specter.yaml` |

---

## CI / Flakes

| Item | Priority | Notes |
|------|----------|-------|
| `internal/license.TestVerify_P99Latency` flake under `-race` | P3 | Tight <1ms p99 budget. Bump to 2ms, skip under `-race`, or pre-warm verifier |
| `internal/audit.TestEmitSync_Latency` flake | P3 | p99 latency assertion, sensitive to CI runner load. Hit on PR #477 — single rerun cleared |
| `internal/queue.TestEnqueue_LatencyP99` flake | P3 | Same shape — hit on PR #479, single rerun cleared. Trend: three p99 flakes in one session — consider widening all budgets or moving them to a perf-suite that doesn't gate merges |

---

## How to Use This File

1. **Starting a session**: Read this file alongside `CLAUDE.md` and `SESSION_LOG.md`
2. **Picking work**: Default to the highest-priority "Active Work" sections, then the OpenWatch OS or OpenWatch+ planned items
3. **Completing work**: Move the row out of "Active" into "Recently Completed", note the PR
4. **Discovering new work**: Add to the most appropriate section
5. **Ending a session**: Update statuses, prepend SESSION_LOG, create a handoff file in `docs/handoff/` if the next session will be a different operator
