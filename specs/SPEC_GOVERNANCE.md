# Spec Governance Rules

> How behavioral specs are created, changed, approved, and maintained.

---

## Ownership

Every spec file has an `owner` field identifying the team or individual responsible.
The owner is the approver for changes to that spec.

| Owner Value | Meaning |
|-------------|---------|
| `engineering` | Core engineering team (default for most specs) |
| `security` | Security team (auth, encryption, SSH specs) |
| `{name}` | Named individual (for highly specialized specs) |

The owner reviews and approves all PRs that modify their spec.

---

## Spec Lifecycle

```
draft  -->  review  -->  active  -->  deprecated
  ^           |
  |           v
  +-- (revisions)
```

| Status | Meaning | Rules |
|--------|---------|-------|
| `draft` | Spec created but not yet complete or reviewed | ACs may change freely |
| `review` | Spec content complete, awaiting approval | ACs frozen pending review |
| `active` | Approved and enforced; tests exist | ACs can only be changed via versioned update |
| `deprecated` | Superseded or no longer applicable | Must include `deprecated_by` field if replaced |

---

## Change Process

1. **Spec changes require a pull request** with code review
2. **Spec diff comes first** logically in the PR (spec change, then test change, then code change)
3. **Spec and code changes may coexist** in one PR; the spec update must be reviewable independently
4. **Every behavioral change** to an Active spec requires a version bump (`version` field, semver)
5. **Non-behavioral changes** (typos, formatting, clarifications that don't alter ACs) do not require a version bump

---

## Approval Gates

Acceptance criteria marked with `[APPROVAL GATE]` require explicit human sign-off
in the PR description before implementation begins. These are used for:

- SSH operations on remote hosts
- Credential handling (encryption, decryption, storage)
- Audit-facing data (compliance scores, posture reports)
- Destructive operations (remediation, rollback)
- Authentication and authorization changes

**Format in PR description:**

```markdown
## Approval Gates

- [x] AC-7: SSH credential decryption requires ADMIN role — approved by @owner
- [x] AC-12: Remediation rollback restores previous state — approved by @owner
```

Implementation MUST NOT proceed on gated ACs until sign-off is recorded.

---

## Versioning

- Specs use the `version` field with semver (e.g., `"1.0"`, `"1.1"`, `"2.0"`)
- The spec version is independent of the codebase version
- **Increment minor** for additive changes (new ACs, new constraints)
- **Increment major** for breaking changes (removed ACs, changed behavior)
- Active specs MUST include a `changelog` entry when the version changes:

```yaml
changelog:
  - version: "1.1"
    date: "2026-03-15"
    changes:
      - "Add AC-16: Rate limiting on scan start endpoint"
```

---

## Immutability Rules

Once a spec reaches `active` status:

1. **ACs cannot be silently removed** — removal requires a version bump and migration note
2. **AC IDs are stable** — once assigned, an AC-N ID is never reused for different behavior
3. **Constraints using RFC 2119 keywords** (MUST, MUST NOT, SHOULD, MAY) are binding
4. **Breaking changes** require a new major version with clear migration guidance

---

## Tiered Approach

Not all modules need full specs. Use the appropriate tier:

| Tier | When to Use | Deliverable |
|------|-------------|-------------|
| **Tier 1** | Safety-critical, security-critical, accuracy-critical modules | Full `.spec.yaml` with ACs, constraints, state machines |
| **Tier 2** | Standard business logic (CRUD, queries) | Enriched Pydantic docstrings with behavioral notes |
| **Tier 3** | Utilities, helpers, formatters | Type system + unit tests only |

**Tier evaluation criteria:**
- Would a bug cause security exposure? → Tier 1
- Would a bug cause incorrect audit data? → Tier 1
- Would a bug cause data loss or corruption? → Tier 1
- Would a bug cause user-facing errors? → Tier 2
- Would a bug cause developer inconvenience? → Tier 3

---

## Test Traceability Convention

### Test File Header

```python
# Spec: specs/pipelines/scan-execution.spec.yaml
```

### Per-Test AC Annotation

```python
@pytest.mark.integration
async def test_start_scan_duplicate_prevention(client, auth_headers):
    """AC-5: Duplicate scan request for host with active scan -> 409."""
```

### Gap Comments (for untested ACs)

```python
# AC-8: SSH connection failure handling -- NOT YET TESTED
# AC-15: Scan timeout handling -- NOT YET TESTED
```

### Coverage Requirement

- **Active specs**: every AC must have at least one test (enforced by CI)
- **Draft/review specs**: informational coverage reporting only
- Coverage is checked by `scripts/check-spec-coverage.py`

---

## Quarterly Review

Every quarter (or every major version), review:

1. Are Active specs still accurate? (spot-check 2-3 against code)
2. Are Draft specs ready for promotion? (move to review/active)
3. Are there new modules that should be specced? (evaluate against tiers)
4. Is the spec-to-test coverage at 100% for Active specs?
5. Should any specs be deprecated?

---

## Ongoing Maintenance Process

### New Feature Workflow

When adding a feature covered by an existing Active spec:

1. **Check the spec first** — does the feature fit the current ACs?
2. If yes: implement the feature, ensure AC coverage stays at 100%
3. If no: open a spec change (add a new AC), get owner approval, then implement
4. Update `spec.version` and `changelog` section in the YAML

### Bug Fix Workflow

When fixing a bug in spec-covered code:

1. **Determine if the bug was a spec violation** (spec says X, code did Y)
   - If yes: fix code to match spec; no spec change needed
   - If no: fix code; evaluate whether spec needs a new AC to prevent regression
2. Reference the spec AC in the fix commit message: `fix(auth): AC-5 lockout counter not reset on success`

### Version Bump Rules

| Change Type | Version Bump | Approval |
|-------------|-------------|----------|
| New AC added | minor (1.0 → 1.1) | Owner |
| AC constraint tightened | minor | Owner |
| AC removed or relaxed | major (1.x → 2.0) | Owner + review |
| Typo / clarification only | patch (1.0 → 1.0.1) | Owner |

### Deprecation Convention

To deprecate a spec:

1. Set `status: deprecated` in the YAML header
2. Add a `deprecated_by` field pointing to the replacement spec (if any)
3. Keep the spec file; do NOT delete it (preserves history)
4. Remove tests only after the deprecated spec's module is removed from code
5. Update `SPEC_REGISTRY.md` to mark the entry as deprecated

### CI Enforcement (Active Specs)

The `spec-checks` CI job runs on every PR and push:

| Check | Mode | Script |
|-------|------|--------|
| Schema validation | Mandatory (blocks merge) | `scripts/validate-specs.py` |
| AC coverage (Active only) | Mandatory (blocks merge) | `scripts/check-spec-coverage.py --enforce-active` |
| Spec-code drift warning | Advisory (never blocks) | `scripts/check-spec-changes.py` |

To add a new spec to CI enforcement: promote it to `status: active` in the YAML.
The `--enforce-active` flag automatically picks up all Active specs.
