# Remediation & Exception Governance — Role Matrix

> **Status:** Current as of 2026-06-19.
> **Authority:** `auth/permissions.yaml` is the source of truth for who can do
> what (codegen produces `internal/auth/permissions.gen.go` / `roles.gen.go`).
> This document is a human-readable view of it; if the two disagree, the YAML
> wins and this doc is stale.
> **Audience:** Operators deciding how to assign roles, and engineers working on
> the remediation / exception lifecycles.

This is the answer to "which role can **request**, **approve/reject**, and
**execute** remediation and exceptions." Two governed lifecycles share the same
separation-of-duties rule.

---

## Built-in roles (least → most privilege)

`viewer` → `auditor` → `ops_lead` → `security_admin` → `admin`

`admin` holds the `*` wildcard (every permission). Custom roles may be created
and are validated against the permission registry.

## Remediation

| Action | permission | viewer | auditor | ops_lead | security_admin | admin |
|--------|------------|:------:|:-------:|:--------:|:--------------:|:-----:|
| View requests/history | `remediation:read` | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Request** | `remediation:request` | | | ✓ | ✓ | ✓ |
| **Approve / Reject** | `remediation:approve` | | | | ✓ | ✓ |
| Execute (Fix) | `remediation:execute` | | | ✓ | ✓ | ✓ |
| Rollback | `remediation:rollback` | | | ✓ | ✓ | ✓ |

Note the deliberate asymmetry: **`ops_lead` can request and execute remediation
but cannot approve it** — approval needs `security_admin` or `admin`.

`remediation:execute` and `remediation:rollback` are **free core** (single-rule
manual). Bulk and automated remediation is the licensed track, gated separately
at the handler via `license.EnforceFeature(remediation_execution)` — not via a
permission.

## Exceptions

| Action | permission | viewer | auditor | ops_lead | security_admin | admin |
|--------|------------|:------:|:-------:|:--------:|:--------------:|:-----:|
| View | `exception:read` | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Request** | `exception:request` | | ✓ | ✓ | ✓ | ✓ |
| Comment | `exception:comment` | | ✓ | ✓ | ✓ | ✓ |
| **Approve** | `exception:approve` | | ✓ | | ✓ | ✓ |
| Revoke | `exception:revoke` | | | | ✓ | ✓ |

Note the asymmetry mirrors remediation in reverse: **`auditor` can approve
exceptions but not remediation**, and **`ops_lead` can request exceptions but not
approve them**.

## Separation of duties (self-review rule)

For **both** lifecycles, the reviewer must differ from the requester. Approving
or rejecting your own request is refused with **409 `self_review`** — and there
is **no bypass**: not for `admin`, and there is no config flag.

- Remediation: `internal/remediation/service.go` (`ErrSelfReview`)
- Exceptions: `internal/exception/service.go`

**One-operator note:** because of this rule, a single-operator workspace cannot
complete the request → approve flow today. The resolution for the free tier is
[Remediation Approval Governance (ADR)](remediation_governance_adr.md): free-core
single-rule remediation will not require a separate approval; the approval gate
(with self-review) is reserved for the licensed bulk/auto track. Until that lands,
two distinct users are required to approve any remediation/exception.

## On `approver_roles` policies

The policies-as-data framework registers an `approvals` policy *type*
(`internal/policy/types.go`), but **no `approvals` policy is currently
configured**, and no code reads `approver_roles`. The enforced approval gate
today is purely the `remediation:approve` / `exception:approve` **permission**
above. If an `approvals` policy is ever added, its `approver_roles` must be a
subset of the roles that hold the corresponding `*:approve` permission, or the
policy can name a role that cannot actually approve.

## References

- Source of truth: `auth/permissions.yaml`
- RBAC registry: [rbac_registry.md](rbac_registry.md)
- Decision record: [remediation_governance_adr.md](remediation_governance_adr.md)
- Operator guide: [../guides/HOSTS_AND_REMEDIATION.md](../guides/HOSTS_AND_REMEDIATION.md)
