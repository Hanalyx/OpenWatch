# Remediation — OpenWatch+ (Licensed) Plan

> **Companion doc:** [`remediation_core_plan.md`](remediation_core_plan.md)
> covers the free AGPLv3 half (see-and-govern). This doc covers the **paid**
> capabilities: the act of mutating a host, and the fleet automation on top.
>
> **Status:** scoping / design. Builds on the same schema + `internal/remediation`
> service defined in the core doc; adds the license-gated act path and a
> second feature for the automation engine.
>
> **Ratified (2026-06-18):** **auto-remediation is an OpenWatch+ (licensed)
> feature.** Tier B below is paid; it is not part of the free AGPL core. The
> remaining open points are the *granularity* (own key vs. shared) and *SKU
> level* of that gate (D-2) and *where the code lives* (D-3).

---

## 1. The two paid tiers

The prototype shows two distinct paid surfaces with very different value and
risk. They should be **two feature keys**, not one (Decision D-2).

| Tier | Feature key | Capability | Prototype surface |
|---|---|---|---|
| **A — Apply** | `remediation_execution` *(exists)* | Dry-run, execute, and rollback a fix on a **single host**, operator-driven, one rule (or one request) at a time. | Host Detail → Compliance "Remediate", Remediation tab per-txn **Rollback** |
| **B — Automate** | `remediation_auto` *(proposed, new)* | Fleet/bulk remediation, remediation **groups**, and the **auto-remediation policy engine**: per-severity auto-fix/approve/off, scope-by-group, canary-first, max-changes-per-run, circuit breaker, scheduled playbooks. | Scans → **Configuration** (auto-remediation), Host Detail "Remediate all · groups" |

Tier A is "let me fix this one thing and prove it." Tier B is "keep the fleet
compliant without me clicking" — the most powerful and most dangerous surface,
and where the commercial value concentrates.

---

## 2. Tier A — `remediation_execution` (the act of applying)

### 2.1 What it is

The three act verbs already gated in `auth/permissions.yaml`:
`remediation:execute` (dry-run + execute) and `remediation:rollback`, both
`license_gated: remediation_execution`, `dangerous: true`. The skeleton
`api/remediation.yaml` already marks `:dry-run`, `:execute`, `:rollback` as
requiring the feature.

### 2.2 Where the code lives — Decision D-3

Tier A is built **in the core tree** (`internal/remediation`), gated at the
handler by `EnforceFeature(remediation_execution)`. This is an *honor-system +
friction* gate: under AGPLv3 the execute code is publishable source a user
could recompile without the check. **That is an accepted posture for Tier A**
because:

- The manual single-host primitive (apply one Kensa transaction, capture
  pre-state, rollback) is small and intrinsic to the remediation engine the
  free governance loop already references.
- The license here is about legitimacy, support, and audit, not DRM.

The robust open-core treatment is reserved for Tier B (§3.3), where it is worth
the architectural cost.

### 2.3 Execution model (first slice)

Per-rule, per-host, **approval-gated**, **snapshot + rollback** — exactly the
`scan_remaining_work.md` first slice. Flow:

1. `:dry-run` — Kensa `Capture → Apply → Validate` with no `Commit`; returns the
   would-be transaction + projected lift. Free users see the *plan* (read), paid
   users can *run* the dry-run.
2. `:execute` — full `Capture → Apply → Validate → Commit`; writes the
   `remediation_transactions` journal row with signed evidence; re-scan the
   rule to confirm state flip; emit `remediation.executed`.
3. `:rollback` — restore from the captured pre-state; emit
   `remediation.rolled_back`.

### 2.4 Kensa work

- Wire `kensa.Remediate()` (available in v0.5.0) through `internal/kensa`.
- Implement transport `Put`/`Get` **only if** a mechanism needs to push a helper
  payload (`transport.go` currently returns `ErrTransportOpNotSupported`). The
  scan path proves `Run` is enough for command-based checks; many handlers
  (`config_set`, `service_enabled`, `sysctl_set`) are command-only.

### 2.5 API + audit

Promote the act endpoints in `api/remediation.yaml` to full fidelity; they
already carry `x-required-feature: remediation_execution` and 402 responses.
Audit codes `remediation.executed` (with `dry_run` flag, steps succeeded/failed)
and `remediation.rolled_back` already exist.

---

## 3. Tier B — `remediation_auto` (the automation engine)

### 3.1 What it is (the prototype's Scans → Configuration screen)

- **Policy by severity** — High/Med/Low each: auto-fix · require-approval · off.
- **Scope & guardrails** — auto-remediate only in named groups
  (e.g. "Development only"); **canary-first** (one host, validate, then the
  rest); **max changes per run**; **circuit breaker** (pause all auto-remediation
  if rollbacks exceed N).
- **Bulk / groups** — "Remediate all High & Med · N rules"; themed
  **remediation groups** ("Harden SSH", "Enable firewall", "Install auditd")
  each showing the multi-framework lift.
- **Scheduled / cadence playbooks** — auto-remediation on the adaptive schedule.

### 3.2 Hard dependency — Kensa rule ordering (carries `scan_remaining_work.md` D-4)

Bulk and grouped remediation need rule **ordering / grouping** metadata
(`depends_on` / `conflicts` / `supersedes`). Kensa's `LoadRules` deliberately
does **not** expose this today. Tier B's groups and "remediate all" are
**blocked on a Kensa-team ratification**, not an OpenWatch-only build. Per-rule
manual (Tier A) has no such dependency, which is one more reason Tier A ships
first.

### 3.3 Where the code lives — Decision D-3 (the robust seam)

Tier B is the right place to spend the open-core architecture cost. Recommended:
build the **auto-remediation policy engine as a separate licensed module**
loaded through the existing plugin interface (ORSA), **not** in the AGPL core.
Rationale:

- It is the flagship paid capability and the most defensible to truly gate.
- It is the highest blast-radius surface (unattended fleet mutation); keeping it
  behind a real boundary is also a safety win, not only a licensing one.
- A module that is physically absent without a license is an *enforceable* cap,
  unlike the in-core honor-system gate acceptable for Tier A.

The core exposes the Tier-A primitive (apply one rule, rollback) as the
interface; the Tier-B module orchestrates it (policy evaluation, fleet fan-out,
canary, circuit breaker, scheduling).

### 3.4 Feature registry change

Add to `licensing/features.yaml`:

```yaml
  - id: remediation_auto
    tier: openwatch_plus        # or `enterprise` if it should be a higher SKU — D-2
    description: Policy-driven and fleet/bulk auto-remediation (canary, circuit
      breaker, scheduled playbooks, remediation groups)
    introduced: "<next release>"
```

Then `go generate ./internal/license/...`, reference it from the auto-remediation
routes' `x-required-feature`, and (if a new perm is warranted) a
`remediation:auto` permission gated on it. CI (`scripts/validate-features.go`)
enforces that every gated reference resolves to a registered feature.

### 3.5 New surfaces

- **API:** an auto-remediation policy resource (`GET/PUT
  /api/v1/remediation/policy`), bulk/group execute endpoints, all gated on
  `remediation_auto`.
- **Frontend:** the Scans → Configuration auto-remediation panel and the Host
  Detail "Remediate all / groups" cards, rendered as upsell when unlicensed.
- **Audit:** likely new codes for policy changes and auto-runs
  (`remediation.policy.changed`, `remediation.auto.run`) — register before use.

---

## 4. Specs to author (SDD)

- `system-remediation-policy` — the policy data model, severity routing,
  guardrails (canary, max-changes, circuit breaker), and the Tier-B module
  boundary.
- `api-remediation` (extend) — the gated act endpoints (Tier A) and the policy /
  bulk endpoints (Tier B), 402 contracts.
- `frontend-scan-remediation-config` — the Scans Configuration auto-remediation
  surface + upsell rendering.

---

## 5. Sequencing

1. **Tier A first**, on the core schema/service: wire `kensa.Remediate`,
   build `:dry-run`/`:execute`/`:rollback` gated by `remediation_execution`,
   per-rule manual + approval + rollback. Ship as GA **beta**.
2. Prove Tier A on a real host (the test fleet) before any automation.
3. **Tier B second**, after (a) Kensa ratifies rule ordering (§3.2) and (b) the
   `remediation_auto` feature + plugin module boundary are agreed. Build the
   policy engine in the licensed module; start with bulk/manual groups, then
   the auto/scheduled posture last (riskiest).

---

## 6. Open decisions

- **D-1 (line placement).** Recommended: keep "any host mutation = paid"
  (Tier A gates all of dry-run/execute/rollback). See core doc §8.
- **D-2 (one tier or two).** *Auto-remediation is licensed — ratified
  2026-06-18.* Still to confirm: give it its **own key** `remediation_auto`
  (recommended, so it can be priced/tiered independently of single-host apply)
  vs. folding it under the existing `remediation_execution`; and whether that key
  is `openwatch_plus` or a higher `enterprise` SKU.
- **D-3 (enforcement model / code location).** Recommended graduated answer:
  Tier A **in-core, honor-system gate** (pragmatic, small primitive); Tier B as
  a **separate licensed plugin module** (robustly enforceable, safety boundary).
  This is the most consequential fork — it sets where the auto-remediation
  engine gets built.
- **D-4 (Kensa ordering).** Bulk/grouped remediation requires a Kensa-team
  ratification of rule ordering before it can be built. Tracks
  `scan_remaining_work.md` decision #4.
