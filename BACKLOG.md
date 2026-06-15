# BACKLOG.md — OpenWatch Go Prioritized Work Queue

> **Purpose**: Single source of truth for **pending** work in the OpenWatch Go rebuild (repo root).
> Completed work is removed from this file; provenance lives in the commit history + `SESSION_LOG.md`.

**Last Updated**: 2026-06-15
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

## Packaging / Install

| ID | Item | Priority | Status | Notes |
|----|------|----------|--------|-------|
| PKG-1 | RPM/DEB install does not provision identity keys — fresh install fails to boot | **P0** | Open | `systemctl enable --now openwatch.service` on a fresh rc7 RPM dies with `/etc/openwatch/keys/jwt_private.pem: no such file or directory`. Root cause: the app deliberately refuses to auto-generate signing keys in production (`cmd/openwatch/main.go:177-204` exits if `identity.jwt_private_key` / `credential_key_file` are missing — no ephemeral fallback), but neither the RPM `%post` (`packaging/rpm/openwatch.spec` — only `daemon-reload`) nor the DEB `postinst` creates `/etc/openwatch/keys/` or generates the keys. The shipped `openwatch.toml` has no `[identity]` section, so the `config.go:81-82` defaults apply: `/etc/openwatch/keys/jwt_private.pem` + `/etc/openwatch/keys/credential.key`. Fix: have `%post`/`postinst` idempotently (only if absent) create `/etc/openwatch/keys/` (0750 root:openwatch) and generate (a) RSA-2048 PEM JWT key (0640 root:openwatch) and (b) 32 raw-byte credential DEK (0600 openwatch:openwatch — `secretkey.LoadFromFile` rejects any group/other perm bits and any length != 32), same pattern as the demo TLS cert. Two keys, distinct rotation semantics: regenerating the credential DEK makes stored SSH creds + MFA secrets undecryptable, so generate-once + back-up; the JWT key only invalidates live sessions. Manual workaround documented for operators in the meantime |
| PKG-2 | Native package ships no Kensa rule corpus — scanning is dead out of the box | **P0** | Open | The Kensa *engine* is compiled into the binary (`github.com/Hanalyx/kensa v0.4.3` in `go.mod`, integration in `internal/kensa/`), but the ~508-rule YAML corpus is **not** bundled. `kensa.LoadRules` reads from disk at `DefaultPath = /usr/share/kensa/rules` (kensa `pkg/kensa/rules.go`); only `varsub/embedded/defaults.yml` (variable defaults) is `go:embed`ed, not the rules. `packaging/rpm/build-rpm.sh` copies only the binary + `openwatch.toml` + `openwatch.service`; `grep -i kensa packaging/` is empty. `cmd/openwatch/main.go:460-468` (C-16) states the design intent: production/air-gapped installs "rely on the signed kensa-rules package at the loader's default path" — but no such package is produced in this repo. Effect on a fresh install: server boots (rule loading is non-fatal — `main.go:473-496` warns and continues) but scans return no results, `/api/v1/rules` → 503, failed-rules titles fall back to bare rule ids, scan-variables surface disabled. `OPENWATCH_KENSA_RULES_DIR` is a dev-only override (warned loudly). Fix: produce + ship a `kensa-rules` package landing the corpus at `/usr/share/kensa/rules` (RPM `Requires:` / DEB `Depends:`), or vendor the corpus into the openwatch package. Blocks first-run usefulness |

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
| Remediation tab | P2 | Not started (scoping required) | Host-mutating fixes (apply + rollback). The last scan-plan piece; plan + the five decisions in `docs/engineering/scan_remaining_work.md` |
| Terminal tab | P3 | Stub | Browser-based SSH terminal. Web terminal lib + SSH-WS bridge needed |

---

## Activity Feed Follow-ups

| Item | Priority | Notes |
|------|----------|-------|
| SSE auto-refresh of `host_activity` query key | P2 | `useLiveEvents.ts` invalidates `['host_intelligence_events', hostId]` + `['intelligence_state', hostId]` on `intelligence.event`. Should also invalidate `['host_activity', hostId]` on any of: `intelligence.event`, `monitoring.band.changed`, `alert.fired`, `scan.completed` |
| Filter NULL→online transitions on first-contact | P3 | Dev-fleet backend restarts wipe `previous_state` so every reboot writes a NULL→online row, dominating the feed. Real fleets won't see this pattern — defer until production reports it |

---

## OpenWatch OS Remaining Work

| Item | Priority | Status | Notes |
|------|----------|--------|-------|
| Email alert notifications (dispatch on alert) | P1 | Partial | The notification **channel** layer (Slack/email/webhook CRUD + test) shipped. Remaining: dispatch fired alerts through channels by type + a user-preferences table (which alert types per user), RBAC-gated |
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

## CI / Flakes

| Item | Priority | Notes |
|------|----------|-------|
| `internal/license.TestVerify_P99Latency` flake under `-race` | P3 | Tight <1ms p99 budget. Bump to 2ms, skip under `-race`, or pre-warm verifier |
| `internal/audit.TestEmitSync_Latency` flake | P3 | p99 latency assertion, sensitive to CI runner load. Single rerun cleared |
| `internal/queue.TestEnqueue_LatencyP99` flake | P3 | Same shape — single rerun cleared. Trend: consider widening all p99 budgets or moving them to a perf-suite that doesn't gate merges |

---

## How to Use This File

1. **Starting a session**: Read this file alongside `CLAUDE.md` and `SESSION_LOG.md`
2. **Picking work**: Default to the highest-priority "Active Work" + Packaging (P0) items, then the OpenWatch OS or OpenWatch+ planned items
3. **Completing work**: **Remove** the row from this file; record the PR in the commit message and `SESSION_LOG.md` (this file tracks only pending work)
4. **Discovering new work**: Add to the most appropriate section
5. **Ending a session**: Update statuses, remove completed rows, prepend `SESSION_LOG.md`, create a handoff file in `docs/handoff/` if the next session will be a different operator
