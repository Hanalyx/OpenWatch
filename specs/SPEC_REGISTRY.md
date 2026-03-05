# OpenWatch Spec Registry

> Master index of all behavioral specifications. Specs use YAML format (`.spec.yaml`).
> The spec is the SSOT. If spec and code disagree, the spec wins (once approved by a human).

---

## Governance

Spec governance rules are defined in [SPEC_GOVERNANCE.md](SPEC_GOVERNANCE.md).

Key rules:
- Spec changes require PR review; spec diff comes first logically
- Active specs cannot have ACs silently removed (version bump required)
- `[APPROVAL GATE]` ACs require human sign-off before implementation
- See governance doc for full lifecycle, tiered approach, and quarterly review process

## Validation

All `.spec.yaml` files are validated against `specs/spec-schema.json` by `scripts/validate-specs.py`.

Required fields: `spec`, `version`, `status`, `owner`, `summary`

Status values: `draft` | `review` | `active` | `deprecated`

## Traceability

Test files reference specs via annotations:
- File header: `# Spec: specs/pipelines/scan-execution.spec.yaml`
- Per-test: `"""AC-5: Duplicate scan -> 409 SCAN_IN_PROGRESS."""`
- Gaps: `# AC-8: SSH connection failure handling -- NOT YET TESTED`

Coverage is checked by `scripts/check-spec-coverage.py`.

---

## System Specs

| Spec | File | Tests | Phase | Status |
|------|------|-------|-------|--------|
| Architecture | system/architecture.spec.yaml | — | — | Draft |
| Documentation | system/documentation.spec.yaml | — | — | Draft |
| Authentication | system/authentication.spec.yaml | TBD | 4 | Draft |
| Authorization | system/authorization.spec.yaml | TBD | 4 | Draft |
| Encryption | system/encryption.spec.yaml | TBD | 4 | Draft |
| Error Model | system/error-model.spec.yaml | TBD | 5 | Draft |
| Security Controls | system/security-controls.spec.yaml | TBD | 4 | Draft |
| Environment | system/environment.spec.yaml | — | — | Draft |
| SSH Security | system/ssh-security.spec.yaml | TBD | 2 | Draft |

## Pipeline Specs

| Spec | File | Tests | Phase | Status |
|------|------|-------|-------|--------|
| Scan Execution | pipelines/scan-execution.spec.yaml | backend/tests/unit/services/engine/test_scan_pipeline.py | 1 | Draft |
| Remediation Lifecycle | pipelines/remediation-lifecycle.spec.yaml | TBD | 2 | Draft |
| Drift Detection | pipelines/drift-detection.spec.yaml | TBD | 1 | Draft |

## Service Specs

| Spec | File | Tests | Phase | Status |
|------|------|-------|-------|--------|
| Temporal Compliance | services/compliance/temporal-compliance.spec.yaml | TBD | 3 | Draft |
| Exception Governance | services/compliance/exception-governance.spec.yaml | TBD | 3 | Draft |
| Alert Thresholds | services/compliance/alert-thresholds.spec.yaml | TBD | 3 | Draft |
| Drift Analysis | services/compliance/drift-analysis.spec.yaml | TBD | 3 | Draft |
| Kensa Scan | services/engine/kensa-scan.spec.yaml | backend/tests/unit/services/engine/test_kensa_scan.py | 1 | Draft |
| Scan Orchestration | services/engine/scan-orchestration.spec.yaml | backend/tests/unit/services/engine/test_scan_orchestration.py | 1 | Draft |
| Remediation Execution | services/remediation/remediation-execution.spec.yaml | TBD | 2 | Draft |
| Risk Classification | services/remediation/risk-classification.spec.yaml | TBD | 2 | Draft |
| MFA | services/auth/mfa.spec.yaml | TBD | 4 | Draft |
| SSH Connection | services/ssh/ssh-connection.spec.yaml | TBD | 2 | Draft |

## API Route Specs

| Spec | File | Tests | Phase | Status |
|------|------|-------|-------|--------|
| Start Kensa Scan | api/scans/start-kensa-scan.spec.yaml | TBD | 5 | Draft |
| Scan Results | api/scans/scan-results.spec.yaml | TBD | 5 | Draft |
| Posture Query | api/compliance/posture-query.spec.yaml | TBD | 5 | Draft |
| Drift Query | api/compliance/drift-query.spec.yaml | TBD | 5 | Draft |
| Exception CRUD | api/compliance/exception-crud.spec.yaml | TBD | 5 | Draft |
| Start Remediation | api/remediation/start-remediation.spec.yaml | TBD | 5 | Draft |
| Rollback | api/remediation/rollback.spec.yaml | TBD | 5 | Draft |
| Login | api/auth/login.spec.yaml | TBD | 5 | Draft |
| MFA Verify | api/auth/mfa-verify.spec.yaml | TBD | 5 | Draft |

## Plugin Specs

| Spec | File | Tests | Phase | Status |
|------|------|-------|-------|--------|
| ORSA v2.0 | plugins/orsa-v2.spec.yaml | backend/tests/unit/plugins/test_orsa_interface.py | 1 | Draft |

## Release Workflow Specs

| Spec | File | Tests | Phase | Status |
|------|------|-------|-------|--------|
| Changelog | release/changelog.spec.yaml | packaging/tests/test_version_consistency.sh | 0 | Active |
| Cleanup Operations | release/cleanup-operations.spec.yaml | packaging/tests/test_cleanup_conventions.sh | 0 | Active |
| Commit Conventions | release/commit-conventions.spec.yaml | packaging/tests/test_commit_conventions.sh | 0 | Active |
| Package Build | release/package-build.spec.yaml | packaging/tests/test_package_build.sh | 0 | Active |

## Coverage Summary

| Category | Total Specs | Active | Draft | Deprecated |
|----------|-------------|--------|-------|------------|
| System | 9 | 0 | 9 | 0 |
| Pipelines | 3 | 0 | 3 | 0 |
| Services | 10 | 0 | 10 | 0 |
| API | 9 | 0 | 9 | 0 |
| Plugins | 1 | 0 | 1 | 0 |
| Release | 4 | 4 | 0 | 0 |
| **Total** | **36** | **4** | **32** | **0** |

## Cross-Module Dependencies

- scan-execution.spec &rarr; kensa-scan.spec (Kensa invocation)
- scan-execution.spec &rarr; temporal-compliance.spec (snapshot creation)
- remediation-lifecycle.spec &rarr; risk-classification.spec (approval gates)
- drift-analysis.spec &rarr; alert-thresholds.spec (alert generation)

## Activation Schedule

Specs are activated through phased SDD migration (see `internal/sdd/plans/`):

| Phase | Focus | Specs |
|-------|-------|-------|
| 0 | Foundation and Governance | (infrastructure only) |
| 1 | Scan Pipeline | scan-execution, kensa-scan, scan-orchestration, drift-detection, orsa-v2 |
| 2 | Remediation | remediation-lifecycle, remediation-execution, risk-classification, ssh-security, ssh-connection |
| 3 | Temporal Compliance | temporal-compliance, exception-governance, alert-thresholds, drift-analysis |
| 4 | Auth and RBAC | authentication, authorization, encryption, security-controls, mfa |
| 5 | API Contracts | 9 API route specs + error-model |
| 6 | Registry Maintenance | CI enforcement, documentation updates |
