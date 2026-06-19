# Remediation Approval Governance (ADR)

> **Status:** Accepted 2026-06-19. Implementation pending (the conditional-approval
> path is not yet built; today every remediation request goes through
> request → approve → execute).
> **Authority:** This document is the decision record for *when* a remediation
> requires human approval. The role/permission matrix that backs it is
> [remediation_exception_governance.md](remediation_exception_governance.md);
> the permission source of truth is `auth/permissions.yaml`.
> **Audience:** Anyone implementing or specing the remediation lifecycle, and
> anyone scoping the OpenWatch+ licensed remediation track.

---

## Context

Remediation is open-core. The boundary, decided separately, is:

- **Free core:** per-rule **manual** remediation — an operator fixes one finding
  on one host, and can roll it back.
- **OpenWatch+ (licensed):** **bulk and automated** remediation — apply many
  rules / fleet-wide, and policy-driven auto-remediation. Gated at the handler
  via `license.EnforceFeature(remediation_execution)`.

The shipped lifecycle is a single state machine with a human approval gate:

```
Request → pending_approval → (Approve) → approved → (MarkExecuting) → executing → executed → rolled_back
                  │                                                                  (failed, dry_run_complete are side branches)
                  └── (Reject) → rejected
```

Approval enforces **separation of duties**: the reviewer must differ from the
requester. This is hard-coded with no bypass (`internal/remediation/service.go`,
`if requestedBy == reviewedBy { return ErrSelfReview }`) and the execute handler
refuses anything not in `approved` state
(`internal/server/remediation_handlers.go`, 409 `only an approved request can be
executed`).

**The problem this ADR resolves:** that gate makes the product unusable for a
single operator. A lone administrator can request but can never approve their
own request (409 `self_review`, even as `admin`), so they never reach Fix. The
same applies to compliance exceptions. Requiring approval here also buys *no*
separation of duties — the requester and the approver would be the same human.

## Decision

**Keep the governance machinery; make the human approval step *conditional* on
the remediation track ("A-keep").**

- **Free-core, single-rule manual remediation does not require a separate human
  approval.** A free-core request reaches an executable state directly (auto-approved
  on creation, or a `ready` state the execute handler also accepts). The operator
  clicks **Fix**; there is no `pending_approval` interstitial.
- **The licensed bulk / auto-remediation track keeps the full request → approve →
  execute flow with the self-review separation-of-duties guard.** This is where an
  approval gate carries real risk-management value (many rules, fleet-wide, or
  unattended), and where multiple roles realistically exist.

We do **not** delete the governance code. It is exactly the machinery the
licensed track needs.

## Consequences

**Stays, unchanged:**

- The `remediation_requests` + `remediation_transactions` tables (migration 0037)
  — every request and its transactions are still recorded for audit, history, and
  rollback, approval or not.
- The execution half of the state machine (`executing → executed → rolled_back →
  failed`, `dry_run_complete`), `MarkExecuting`, `RecordExecution`, the
  `RemediationWorker`, the execute/rollback handlers, the
  `remediation:execute` / `remediation:rollback` permissions, and the frontend
  Fix/rollback UI.

**Stays, but becomes conditional — reserved for the licensed track:**

- `Request` / `Approve` / `Reject`, the self-review guard, the
  `pending_approval` / `approved` / `rejected` states, and the
  `remediation:request` / `remediation:approve` permissions.

**Changes (small, surgical):**

1. A free-core single-rule request reaches an executable state without a human
   approval transition.
2. UI: the Fix button is live immediately for free-core (no pending-approval step).
3. Specs/tests: the `api-remediation` ACs that assert "must be approved before
   execute" split into free-core (no approval) vs. licensed (approval + self-review).
   The self-review test stays, retargeted to the licensed path.

**Accepted trade-off:** until the bulk/auto track ships, the approve/reject/
self-review code is present-but-dormant (exercised only by its tests). We accept
carrying it rather than deleting working, tested code and rebuilding it later.

## Alternatives considered

- **Single-operator mode (config flag relaxing self-review).** Viable, but adds a
  config surface and an "I approved my own request" audit nuance. The conditional
  split achieves the same outcome for the free tier without a flag.
- **Require a second approver account.** Rejected as the *only* answer: it is poor
  UX and, since the same human clicks both, delivers no real separation of duties.
- **A-defer (strip governance now, rebuild for the licensed track).** Rejected:
  throws away working, tested, just-merged code to rebuild the same machinery later.

## References

- Role/permission matrix + self-review rule:
  [remediation_exception_governance.md](remediation_exception_governance.md)
- Permission source of truth: `auth/permissions.yaml`
- RBAC registry: [rbac_registry.md](rbac_registry.md)
- Lifecycle code: `internal/remediation/`, `internal/server/remediation_handlers.go`
- Spec: `specs/api/remediation.spec.yaml`
