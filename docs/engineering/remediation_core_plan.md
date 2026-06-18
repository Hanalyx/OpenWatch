# Remediation — OpenWatch Core (Free) Plan

> **Companion doc:** [`remediation_licensed_plan.md`](remediation_licensed_plan.md)
> covers the OpenWatch+ (paid) half. **Forward-looking remainder context:**
> [`scan_remaining_work.md`](scan_remaining_work.md) (Phase 7).
>
> **Status:** scoping / design. No remediation handler, service, or schema
> exists yet — only the registries (RBAC, license feature, audit codes) and the
> OpenAPI skeleton. This doc defines what ships **free, in the AGPLv3 core**.

---

## 1. Why a free/paid line exists here at all

OpenWatch Core is **AGPLv3 + Managed Service Exception** (`LICENSE`). The MSE
restricts *offering OpenWatch as a hosted service to third parties*; it does
**not** grant feature tiering. Feature tiering is a separate **open-core /
dual-licensing** decision layered on top of the AGPL base, enforced by the
license subsystem (`internal/license/`, `licensing/features.yaml`, signed
Ed25519 JWTs minted by `cmd/owlicgen`).

The product line is **"OpenWatch sees, plans, and governs remediation for
free; the act of mutating a host is OpenWatch+."** This doc is the *free* side
of that line. The paid side is the companion doc.

> **AGPL implication, stated plainly.** Any code that ships in this core tree is
> source you are obliged to publish (AGPLv3 §13) and that a user may legally
> modify, including deleting a runtime license check (§2). So an in-core 402
> gate is an *honor-system + friction* control, not DRM. That is an acceptable
> and common open-core posture for the manual-execution tier; the robustly
> gated capability (the auto-remediation engine) is treated differently in the
> companion doc. See Decision D-3 there.

---

## 2. The boundary (what is free)

| Capability | Free (this doc) | Licensed (companion) |
|---|---|---|
| View remediable findings, projected score lift | ✅ | |
| Request a remediation (`remediation:request`) | ✅ | |
| Approve / reject a request (`remediation:approve`) | ✅ | |
| View transaction history + signed evidence (`remediation:read`) | ✅ | |
| Configure the approvals policy (who approves, dual-approval) | ✅ | |
| **Dry-run a fix** (`remediation:execute`) | | ✅ `remediation_execution` |
| **Execute a fix on a host** (`remediation:execute`) | | ✅ `remediation_execution` |
| **Rollback** (`remediation:rollback`) | | ✅ `remediation_execution` |
| Bulk / fleet / auto-remediation policy engine | | ✅ (proposed `remediation_auto`) |

The free tier is a complete **see-and-govern** loop: an operator can discover
what is fixable, understand the projected compliance-score impact, request the
fix, route it through approval, and audit every fix that was applied. The one
thing it cannot do is pull the trigger on a host mutation — that is the paid
moment, and the upsell is honest because the whole workflow up to it is free.

This matches OpenWatch's "The Eye" visibility-first positioning and the risk
gradient ratified in `scan_remaining_work.md` (read-only is safe; host mutation
has blast radius).

---

## 3. What already exists (build on, do not re-create)

- **RBAC** (`auth/permissions.yaml` → `internal/auth/permissions.gen.go`):
  `remediation:read`, `:request`, `:approve` (free); `:execute`, `:rollback`
  (`license_gated: remediation_execution`, `dangerous: true`).
- **Audit codes** (`audit/events.yaml`): `remediation.requested`,
  `remediation.approved`, `remediation.executed`, `remediation.rolled_back`.
- **OpenAPI skeleton** (`api/remediation.yaml`, fidelity = skeleton): the full
  lifecycle `request → approve → dry-run → execute → rollback`, with read
  endpoints explicitly un-gated and act endpoints gated. Also
  `api/scans.yaml` → `POST /scans/{scan_id}:remediate` (create-from-findings).
- **Kensa** (`internal/kensa/`, kensa **v0.5.0**): `executor.go` wired for
  scans; `transport.go` implements `Run` (scan path), with `Put`/`Get` stubbed
  (`ErrTransportOpNotSupported`) pending a remediation payload-upload need. The
  Kensa transaction model is `Capture → Apply → Validate → Commit`, with
  automatic pre-state restore on validation failure.
- **License subsystem** (`internal/license/`): `EnforcePermission` /
  `EnforceFeature` / `RequireFeature`, 402-on-deny with rate-limited audit;
  free tier with no license file; SIGHUP reload.

**Does not exist:** any `remediations` migration (next number is **0037**), any
remediation handler/service, any frontend beyond the placeholder Remediation
tab (`HostDetailPage.tsx`, "deferred (BACKLOG)").

---

## 4. Architecture — what the core owns

The data model and state machine are built **in core** because both the free
governance path and the paid execution path read and write the same tables.
Only the *act* handlers carry the license check.

### 4.1 Schema (migration `0037_remediation.sql`)

- `remediation_requests` — one row per requested fix.
  `id`, `host_id`, `rule_id`, `scan_run_id` (provenance),
  `status` (`pending_approval | approved | rejected | dry_run_complete |
  executing | executed | rolled_back | failed`), `requester_id`,
  `approver_id`, `created_at`, `decided_at`, projected-lift snapshot
  (`projected_cis`, `projected_stig`, `projected_nist`), `mechanism`
  (kensa handler id), `reboot_required bool`, `transactional bool`.
- `remediation_transactions` — the Kensa per-rule transaction journal: `id`,
  `request_id`, `kensa_txn_id`, `phase_result` (`committed | rolled_back |
  skipped`), `pre_state` (captured), `evidence` (content-addressed, mirrors the
  `scan_results` store pattern), `applied_at`. This is the durable rollback
  point and the signed-evidence record (`kensa verify`).

State transitions only ever move forward except the `:rollback` path
(`executed → rolled_back`). The journal is append-only.

### 4.2 Service (`internal/remediation/`)

- `Request(...)`, `Approve(...)`, `Reject(...)` — free verbs; pure state
  transitions + audit, no host contact.
- `ProjectLift(...)` — read-only: compute the predicted CIS/STIG/NIST delta if a
  rule (or set) flips to pass, from the current `host_rule_state` + framework
  mappings. Powers the "Projected lift" UI. No mutation.
- The mutating methods (`DryRun`, `Execute`, `Rollback`) are **defined in core**
  but their handlers call `EnforceFeature(remediation_execution)` before
  touching a host (see companion doc). The Kensa apply/rollback plumbing
  (`transport.Put`/`Get` if a mechanism needs to push a payload) lands here.

### 4.3 API (core-owned, free endpoints)

From the existing `api/remediation.yaml` skeleton, promote to full fidelity the
un-gated endpoints:

- `GET  /api/v1/remediation/requests` (list, filter)
- `GET  /api/v1/remediation/requests/{id}` (+ `/steps`, `/audit`)
- `POST /api/v1/remediation/requests` (`remediation:request`)
- `POST /api/v1/remediation/requests/{id}:approve` (`remediation:approve`)
- `POST /api/v1/remediation/requests/{id}:reject`
- `POST /api/v1/scans/{scan_id}:remediate` (create requests from findings)

---

## 5. Frontend (free surfaces)

- **Compliance tab → Top failed rules** (`HostDetailPage`): each failed rule
  gets a **"Request remediation"** affordance (prototype shows "Remediate"; the
  free action is *request*, which routes to approval). Shows the per-rule
  projected lift.
- **Remediation tab** (read surfaces only in the free build): the "How each fix
  runs · Capture → Apply → Validate → Commit" explainer, the
  `committed/rolled_back/skipped` legend, the **Recent transactions** table with
  signed-evidence verification, and per-request status. The **Remediate /
  Rollback buttons render as upsell** (disabled with an "OpenWatch+" affordance)
  when the license lacks `remediation_execution`. The frontend does not gate
  today (backend-only enforcement); this adds the first license-aware UI.
- **Projected lift** display is free everywhere it appears (planning is free;
  applying is paid).

---

## 6. Specs to author (SDD)

- `system-remediation` — the request/approve state machine, schema invariants,
  audit emission, the free/paid verb split as a constraint.
- `api-remediation` — promote `api/remediation.yaml` from skeleton; ACs for the
  free endpoints + the 402 contract on the act endpoints.
- `frontend-remediation-tab` — the read surfaces + the request affordance + the
  license-upsell rendering.

Register in `specter.yaml`; annotate tests with `// @spec` + `// @ac`.

---

## 7. Sequencing

1. Migration `0037` + `internal/remediation` service (state machine + projection,
   no host contact). Backend-first, the same layering used for exceptions.
2. Free API endpoints (`request`/`approve`/`reject`/list/get) + audit wiring.
3. Frontend: request affordance on the Compliance tab + read surfaces on the
   Remediation tab + license-upsell rendering of the act buttons.
4. Hand off the **act** verbs (`dry-run`/`execute`/`rollback`) to the companion
   doc's Tier A, which reuses this schema and service.

This is the GA **beta** remediation slice's free half. Execution is beta-in-GA
per `scan_remaining_work.md`; the free governance loop can ship first and stand
on its own.

---

## 8. Open decisions (carried from the design discussion)

- **D-1 (line placement).** Keep "any host mutation = paid" (current in-tree
  encoding, recommended), or carve out free *manual single-host single-rule*
  execution? Keeping it is cleaner and is what the registry already encodes;
  the cost is a possible "approve, then paywall at execute" funnel feel,
  mitigated by honest upsell copy. **Recommend: keep.**
- **D-2 / D-3** are about the paid tiers and the enforcement model — see the
  companion doc.
