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
| Authentication | system/authentication.spec.yaml | tests/backend/unit/services/auth/test_authentication.py | 4 | Active |
| Authorization | system/authorization.spec.yaml | tests/backend/unit/services/auth/test_authorization.py | 4 | Active |
| Encryption | system/encryption.spec.yaml | tests/backend/unit/services/auth/test_encryption.py | 4 | Active |
| Error Model | system/error-model.spec.yaml | tests/backend/unit/api/test_error_model.py | 5 | Active |
| Security Controls | system/security-controls.spec.yaml | tests/backend/unit/services/auth/test_security_controls.py | 4 | Active |
| Environment | system/environment.spec.yaml | — | — | Draft |
| SSH Security | system/ssh-security.spec.yaml | tests/backend/unit/services/ssh/test_ssh_security.py | 2 | Active |

## Pipeline Specs

| Spec | File | Tests | Phase | Status |
|------|------|-------|-------|--------|
| Scan Execution | pipelines/scan-execution.spec.yaml | tests/backend/unit/services/engine/test_scan_pipeline.py, test_concurrent_scan_guard.py | 1 | Draft |
| Remediation Lifecycle | pipelines/remediation-lifecycle.spec.yaml | tests/backend/unit/pipelines/test_remediation_lifecycle.py | 2 | Active |
| Drift Detection | pipelines/drift-detection.spec.yaml | tests/backend/unit/services/engine/test_drift_detection.py | 1 | Active |

## Service Specs

| Spec | File | Tests | Phase | Status |
|------|------|-------|-------|--------|
| Temporal Compliance | services/compliance/temporal-compliance.spec.yaml | tests/backend/unit/services/compliance/test_temporal_compliance.py | 3 | Active |
| Exception Governance | services/compliance/exception-governance.spec.yaml | tests/backend/unit/services/compliance/test_exception_governance.py | 3 | Active |
| Alert Thresholds | services/compliance/alert-thresholds.spec.yaml | tests/backend/unit/services/compliance/test_alert_thresholds.py | 3 | Active |
| Drift Analysis | services/compliance/drift-analysis.spec.yaml | tests/backend/unit/services/compliance/test_drift_analysis.py | 3 | Active |
| Kensa Scan | services/engine/kensa-scan.spec.yaml | tests/backend/unit/services/engine/test_kensa_scan.py | 1 | Active |
| Scan Orchestration | services/engine/scan-orchestration.spec.yaml | tests/backend/unit/services/engine/test_scan_orchestration.py | 1 | Active |
| Remediation Execution | services/remediation/remediation-execution.spec.yaml | tests/backend/unit/services/compliance/test_remediation_execution.py | 2 | Active |
| Risk Classification | services/remediation/risk-classification.spec.yaml | tests/backend/unit/services/compliance/test_risk_classification.py | 2 | Active |
| MFA | services/auth/mfa.spec.yaml | tests/backend/unit/services/auth/test_mfa.py | 4 | Active |
| SSH Connection | services/ssh/ssh-connection.spec.yaml | tests/backend/unit/services/ssh/test_ssh_connection.py | 2 | Active |
| Host Monitoring | services/monitoring/host-monitoring.spec.yaml | tests/backend/unit/services/monitoring/test_host_monitoring.py | 7 | Active |

## API Route Specs

| Spec | File | Tests | Phase | Status |
|------|------|-------|-------|--------|
| Start Kensa Scan | api/scans/start-kensa-scan.spec.yaml | tests/backend/unit/api/test_scan_api.py | 5 | Active |
| Scan Results | api/scans/scan-results.spec.yaml | tests/backend/unit/api/test_scan_api.py | 5 | Active |
| Posture Query | api/compliance/posture-query.spec.yaml | tests/backend/unit/api/test_compliance_api.py | 5 | Active |
| Drift Query | api/compliance/drift-query.spec.yaml | tests/backend/unit/api/test_compliance_api.py | 5 | Active |
| Exception CRUD | api/compliance/exception-crud.spec.yaml | tests/backend/unit/api/test_compliance_api.py | 5 | Active |
| Start Remediation | api/remediation/start-remediation.spec.yaml | tests/backend/unit/api/test_remediation_api.py | 5 | Active |
| Rollback | api/remediation/rollback.spec.yaml | tests/backend/unit/api/test_remediation_api.py | 5 | Active |
| Login | api/auth/login.spec.yaml | tests/backend/unit/api/test_auth_api.py | 5 | Active |
| MFA Verify | api/auth/mfa-verify.spec.yaml | tests/backend/unit/api/test_auth_api.py | 5 | Active |

## Frontend Specs

| Spec | File | Tests | Phase | Status |
|------|------|-------|-------|--------|
| State Management | frontend/state-management.spec.yaml | tests/frontend/store/state-management.spec.test.ts | 8 | Active |

## Plugin Specs

| Spec | File | Tests | Phase | Status |
|------|------|-------|-------|--------|
| ORSA v2.0 | plugins/orsa-v2.spec.yaml | tests/backend/unit/plugins/test_orsa_interface.py | 1 | Active |

## Release Workflow Specs

| Spec | File | Tests | Phase | Status |
|------|------|-------|-------|--------|
| Changelog | release/changelog.spec.yaml | tests/packaging/test_version_consistency.sh | 0 | Active |
| Cleanup Operations | release/cleanup-operations.spec.yaml | tests/packaging/test_cleanup_conventions.sh | 0 | Active |
| Commit Conventions | release/commit-conventions.spec.yaml | tests/packaging/test_commit_conventions.sh | 0 | Active |
| Package Build | release/package-build.spec.yaml | tests/packaging/test_package_build.sh | 0 | Active |

## Coverage Summary

| Category | Total Specs | Active | Draft | Deprecated |
|----------|-------------|--------|-------|------------|
| System | 9 | 6 | 3 | 0 |
| Pipelines | 3 | 2 | 1 | 0 |
| Services | 11 | 11 | 0 | 0 |
| API | 9 | 9 | 0 | 0 |
| Plugins | 1 | 1 | 0 | 0 |
| Release | 4 | 4 | 0 | 0 |
| Frontend | 1 | 1 | 0 | 0 |
| **Total** | **38** | **34** | **4** | **0** |

## Cross-Module Dependencies

- scan-execution.spec &rarr; kensa-scan.spec (Kensa invocation)
- scan-execution.spec &rarr; temporal-compliance.spec (snapshot creation)
- remediation-lifecycle.spec &rarr; risk-classification.spec (approval gates)
- drift-analysis.spec &rarr; alert-thresholds.spec (alert generation)
- drift-detection.spec &rarr; alert-thresholds.spec (CONFIGURATION_DRIFT, MASS_DRIFT alerts)
- host-monitoring.spec &rarr; kensa-scan.spec (ONLINE state gates scan eligibility)
- host-monitoring.spec &rarr; alert-thresholds.spec (HOST_UNREACHABLE, state transition alerts)

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
| 7 | Monitoring | host-monitoring (Tier 1: scan eligibility, compliance implications) |
| 8 | Frontend Architecture | state-management (Zustand Phase 1: auth + notifications migrated) |
