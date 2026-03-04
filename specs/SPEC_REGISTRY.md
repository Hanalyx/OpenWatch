# OpenWatch Spec Registry

> Master index of all behavioral specifications. Specs use YAML format (`.spec.yaml`).
> The spec is the SSOT. If spec and code disagree, the spec wins (once approved by a human).

---

## System Specs

| Spec | File | Tests | Phase | Status |
|------|------|-------|-------|--------|
| Architecture | system/architecture.spec.yaml | — | 1 | Pending |
| Authentication | system/authentication.spec.yaml | TBD | 4 | Pending |
| Authorization | system/authorization.spec.yaml | TBD | 4 | Pending |
| Encryption | system/encryption.spec.yaml | TBD | 4 | Pending |
| Error Model | system/error-model.spec.yaml | TBD | 5 | Pending |
| Security Controls | system/security-controls.spec.yaml | TBD | 4 | Pending |
| Environment | system/environment.spec.yaml | — | 6 | Pending |
| SSH Security | system/ssh-security.spec.yaml | TBD | 2 | Pending |

## Pipeline Specs

| Spec | File | Tests | Phase | Status |
|------|------|-------|-------|--------|
| Scan Execution | pipelines/scan-execution.spec.yaml | TBD | 1 | Pending |
| Remediation Lifecycle | pipelines/remediation-lifecycle.spec.yaml | TBD | 2 | Pending |
| Drift Detection | pipelines/drift-detection.spec.yaml | TBD | 1 | Pending |

## Service Specs

| Spec | File | Tests | Phase | Status |
|------|------|-------|-------|--------|
| Temporal Compliance | services/compliance/temporal-compliance.spec.yaml | TBD | 3 | Pending |
| Exception Governance | services/compliance/exception-governance.spec.yaml | TBD | 3 | Pending |
| Alert Thresholds | services/compliance/alert-thresholds.spec.yaml | TBD | 3 | Pending |
| Drift Analysis | services/compliance/drift-analysis.spec.yaml | TBD | 3 | Pending |
| Kensa Scan | services/engine/kensa-scan.spec.yaml | TBD | 1 | Pending |
| Scan Orchestration | services/engine/scan-orchestration.spec.yaml | TBD | 1 | Pending |
| Remediation Execution | services/remediation/remediation-execution.spec.yaml | TBD | 2 | Pending |
| Risk Classification | services/remediation/risk-classification.spec.yaml | TBD | 2 | Pending |
| MFA | services/auth/mfa.spec.yaml | TBD | 4 | Pending |
| SSH Connection | services/ssh/ssh-connection.spec.yaml | TBD | 2 | Pending |

## API Route Specs

| Spec | File | Tests | Phase | Status |
|------|------|-------|-------|--------|
| Start Kensa Scan | api/scans/start-kensa-scan.spec.yaml | TBD | 5 | Pending |
| Scan Results | api/scans/scan-results.spec.yaml | TBD | 5 | Pending |
| Posture Query | api/compliance/posture-query.spec.yaml | TBD | 5 | Pending |
| Drift Query | api/compliance/drift-query.spec.yaml | TBD | 5 | Pending |
| Exception CRUD | api/compliance/exception-crud.spec.yaml | TBD | 5 | Pending |
| Start Remediation | api/remediation/start-remediation.spec.yaml | TBD | 5 | Pending |
| Rollback | api/remediation/rollback.spec.yaml | TBD | 5 | Pending |
| Login | api/auth/login.spec.yaml | TBD | 5 | Pending |
| MFA Verify | api/auth/mfa-verify.spec.yaml | TBD | 5 | Pending |

## Plugin Specs

| Spec | File | Tests | Phase | Status |
|------|------|-------|-------|--------|
| ORSA v2.0 | plugins/orsa-v2.spec.yaml | TBD | 1 | Pending |

## Release Workflow Specs

| Spec | File | Tests | Phase | Status |
|------|------|-------|-------|--------|
| Changelog | release/changelog.spec.yaml | packaging/tests/test_version_consistency.sh | 1 | Active |
| Package Build | release/package-build.spec.yaml | packaging/tests/test_package_build.sh | 1 | Active |

## Cross-Module Dependencies

- scan-execution.spec &rarr; kensa-scan.spec (Kensa invocation)
- scan-execution.spec &rarr; temporal-compliance.spec (snapshot creation)
- remediation-lifecycle.spec &rarr; risk-classification.spec (approval gates)
- drift-analysis.spec &rarr; alert-thresholds.spec (alert generation)
