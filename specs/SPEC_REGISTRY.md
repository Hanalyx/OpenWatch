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

## System Specs (10 Active)

| Spec | File | Tests | Phase | Status |
|------|------|-------|-------|--------|
| Architecture | system/architecture.spec.yaml | tests/backend/unit/system/test_architecture_spec.py | 8 | Active |
| Documentation | system/documentation.spec.yaml | tests/backend/unit/system/test_documentation_spec.py | 8 | Active |
| Integration Testing | system/integration-testing.spec.yaml | tests/backend/integration/test_*.py (20 files) | 9 | Active |
| Authentication | system/authentication.spec.yaml | tests/backend/unit/services/auth/test_authentication.py | 4 | Active |
| Authorization | system/authorization.spec.yaml | tests/backend/unit/services/auth/test_authorization.py | 4 | Active |
| Encryption | system/encryption.spec.yaml | tests/backend/unit/services/auth/test_encryption.py | 4 | Active |
| Error Model | system/error-model.spec.yaml | tests/backend/unit/api/test_error_model.py | 5 | Active |
| Security Controls | system/security-controls.spec.yaml | tests/backend/unit/services/auth/test_security_controls.py | 4 | Active |
| Environment | system/environment.spec.yaml | tests/backend/unit/system/test_environment_spec.py | 9 | Active |
| SSH Security | system/ssh-security.spec.yaml | tests/backend/unit/services/ssh/test_ssh_security.py | 2 | Active |

## Pipeline Specs (3 Active)

| Spec | File | Tests | Phase | Status |
|------|------|-------|-------|--------|
| Scan Execution | pipelines/scan-execution.spec.yaml | tests/backend/unit/pipelines/test_scan_execution.py | 1 | Active |
| Remediation Lifecycle | pipelines/remediation-lifecycle.spec.yaml | tests/backend/unit/pipelines/test_remediation_lifecycle.py | 2 | Active |
| Drift Detection | pipelines/drift-detection.spec.yaml | tests/backend/unit/services/engine/test_drift_detection.py | 1 | Active |

## Service Specs (22 Active)

| Spec | File | Tests | Phase | Status |
|------|------|-------|-------|--------|
| Temporal Compliance | services/compliance/temporal-compliance.spec.yaml | tests/backend/unit/services/compliance/test_temporal_compliance.py | 3 | Active |
| Exception Governance | services/compliance/exception-governance.spec.yaml | tests/backend/unit/services/compliance/test_exception_governance.py | 3 | Active |
| Alert Thresholds | services/compliance/alert-thresholds.spec.yaml | tests/backend/unit/services/compliance/test_alert_thresholds.py | 3 | Active |
| Drift Analysis | services/compliance/drift-analysis.spec.yaml | tests/backend/unit/services/compliance/test_drift_analysis.py | 3 | Active |
| Audit Query | services/compliance/audit-query.spec.yaml | tests/backend/unit/services/compliance/test_audit_query_spec.py | 9 | Active |
| Compliance Scheduler | services/compliance/compliance-scheduler.spec.yaml | tests/backend/unit/services/compliance/test_compliance_scheduler_spec.py | 9 | Active |
| Kensa Scan | services/engine/kensa-scan.spec.yaml | tests/backend/unit/services/engine/test_kensa_scan.py | 1 | Active |
| Scan Orchestration | services/engine/scan-orchestration.spec.yaml | tests/backend/unit/services/engine/test_scan_orchestration.py | 1 | Active |
| Remediation Execution | services/remediation/remediation-execution.spec.yaml | tests/backend/unit/services/compliance/test_remediation_execution.py | 2 | Active |
| Risk Classification | services/remediation/risk-classification.spec.yaml | tests/backend/unit/services/compliance/test_risk_classification.py | 2 | Active |
| MFA | services/auth/mfa.spec.yaml | tests/backend/unit/services/auth/test_mfa.py | 4 | Active |
| SSH Connection | services/ssh/ssh-connection.spec.yaml | tests/backend/unit/services/ssh/test_ssh_connection.py | 2 | Active |
| Host Monitoring | services/monitoring/host-monitoring.spec.yaml | tests/backend/unit/services/monitoring/test_host_monitoring.py | 7 | Active |
| Input Validation | services/validation/input-validation.spec.yaml | tests/backend/unit/services/validation/test_input_validation_spec.py | 9 | Active |
| Audit Logging | services/infrastructure/audit-logging.spec.yaml | tests/backend/unit/services/infrastructure/test_audit_logging_spec.py | 9 | Active |
| License Service | services/licensing/license-service.spec.yaml | tests/backend/unit/services/licensing/test_license_service_spec.py | 9 | Active |
| Compliance Scoring | services/owca/compliance-scoring.spec.yaml | tests/backend/unit/services/owca/test_compliance_scoring_spec.py | 9 | Active |
| Framework Mapping | services/framework/framework-mapping.spec.yaml | tests/backend/unit/services/framework/test_framework_mapping_spec.py | 9 | Active |
| Host Discovery | services/discovery/host-discovery.spec.yaml | tests/backend/unit/services/discovery/test_host_discovery_spec.py | 9 | Active |
| Rule Reference | services/rules/rule-reference.spec.yaml | tests/backend/unit/services/rules/test_rule_reference_spec.py | 9 | Active |
| Server Intelligence | services/system-info/server-intelligence.spec.yaml | tests/backend/unit/services/system_info/test_server_intelligence_spec.py | 9 | Active |

## API Route Specs (22 Active)

| Spec | File | Tests | Phase | Status |
|------|------|-------|-------|--------|
| Start Kensa Scan | api/scans/start-kensa-scan.spec.yaml | tests/backend/unit/api/test_scan_api.py | 5 | Active |
| Scan Results | api/scans/scan-results.spec.yaml | tests/backend/unit/api/test_scan_api.py | 5 | Active |
| Scan CRUD | api/scans/scan-crud.spec.yaml | tests/backend/unit/api/test_scan_crud_spec.py | 9 | Active |
| Scan Reports | api/scans/scan-reports.spec.yaml | tests/backend/unit/api/test_scan_reports_spec.py | 9 | Active |
| Posture Query | api/compliance/posture-query.spec.yaml | tests/backend/unit/api/test_compliance_api.py | 5 | Active |
| Drift Query | api/compliance/drift-query.spec.yaml | tests/backend/unit/api/test_compliance_api.py | 5 | Active |
| Exception CRUD | api/compliance/exception-crud.spec.yaml | tests/backend/unit/api/test_compliance_api.py | 5 | Active |
| Alerts CRUD | api/compliance/alerts-crud.spec.yaml | tests/backend/unit/api/test_alerts_crud_spec.py | 9 | Active |
| Audit Queries | api/compliance/audit-queries.spec.yaml | tests/backend/unit/api/test_audit_queries_spec.py | 9 | Active |
| Scheduler | api/compliance/scheduler.spec.yaml | tests/backend/unit/api/test_scheduler_spec.py | 9 | Active |
| Start Remediation | api/remediation/start-remediation.spec.yaml | tests/backend/unit/api/test_remediation_api.py | 5 | Active |
| Rollback | api/remediation/rollback.spec.yaml | tests/backend/unit/api/test_remediation_api.py | 5 | Active |
| Login | api/auth/login.spec.yaml | tests/backend/unit/api/test_auth_api.py | 5 | Active |
| MFA Verify | api/auth/mfa-verify.spec.yaml | tests/backend/unit/api/test_auth_api.py | 5 | Active |
| API Keys | api/auth/api-keys.spec.yaml | tests/backend/unit/api/test_api_keys_spec.py | 9 | Active |
| Test Connection | api/hosts/test-connection.spec.yaml | tests/backend/unit/api/test_host_api.py | 9 | Active |
| Host CRUD | api/hosts/host-crud.spec.yaml | tests/backend/unit/api/test_host_crud_spec.py | 9 | Active |
| Host Intelligence | api/hosts/host-intelligence.spec.yaml | tests/backend/unit/api/test_host_intelligence_spec.py | 9 | Active |
| Users CRUD | api/admin/users-crud.spec.yaml | tests/backend/unit/api/test_users_crud_spec.py | 9 | Active |
| Security Config | api/admin/security-config.spec.yaml | tests/backend/unit/api/test_security_config_spec.py | 9 | Active |
| Credentials | api/admin/credentials.spec.yaml | tests/backend/unit/api/test_credentials_spec.py | 9 | Active |
| Audit Events | api/admin/audit-events.spec.yaml | tests/backend/unit/api/test_audit_events_spec.py | 9 | Active |
| Host Groups CRUD | api/host-groups/host-groups-crud.spec.yaml | tests/backend/unit/api/test_host_groups_spec.py | 9 | Active |
| SSH Settings | api/ssh/ssh-settings.spec.yaml | tests/backend/unit/api/test_ssh_settings_spec.py | 9 | Active |
| Rule Reference | api/rules/rule-reference.spec.yaml | tests/backend/unit/api/test_rule_reference_spec.py | 9 | Active |
| ORSA Routes | api/integrations/orsa-routes.spec.yaml | tests/backend/unit/api/test_orsa_routes_spec.py | 9 | Active |
| Webhooks | api/integrations/webhooks.spec.yaml | tests/backend/unit/api/test_webhooks_spec.py | 9 | Active |
| System Health | api/system/system-health.spec.yaml | tests/backend/unit/api/test_system_health_spec.py | 9 | Active |

## Frontend Specs (13 Active)

| Spec | File | Tests | Phase | Status |
|------|------|-------|-------|--------|
| State Management | frontend/state-management.spec.yaml | tests/frontend/store/state-management.spec.test.ts | 8 | Active |
| Auth Flow | frontend/auth-flow.spec.yaml | tests/frontend/auth/auth-flow.spec.test.ts | 8 | Active |
| Scan Workflow | frontend/scan-workflow.spec.yaml | tests/frontend/scans/scan-workflow.spec.test.ts | 8 | Active |
| Host Detail Behavior | frontend/host-detail-behavior.spec.yaml | tests/frontend/hosts/host-detail.spec.test.ts | 8 | Active |
| Add Host Form | frontend/add-host-form.spec.yaml | tests/frontend/hosts/add-host-form.spec.test.ts | 9 | Active |
| Role Dashboards | frontend/role-dashboards.spec.yaml | tests/frontend/dashboard/role-dashboards.spec.test.ts | 9 | Active |
| Settings Page | frontend/settings-page.spec.yaml | tests/frontend/settings/settings-page.spec.test.ts | 9 | Active |
| Users Management | frontend/users-management.spec.yaml | tests/frontend/users/users-management.spec.test.ts | 9 | Active |
| Audit Query Builder | frontend/audit-query-builder.spec.yaml | tests/frontend/audit/audit-query-builder.spec.test.ts | 9 | Active |
| Compliance Posture | frontend/compliance-posture.spec.yaml | tests/frontend/compliance/compliance-posture.spec.test.ts | 9 | Active |
| Rule Reference | frontend/rule-reference.spec.yaml | tests/frontend/content/rule-reference.spec.test.ts | 9 | Active |
| Compliance Groups | frontend/compliance-groups.spec.yaml | tests/frontend/host-groups/compliance-groups.spec.test.ts | 9 | Active |
| Scans List | frontend/scans-list.spec.yaml | tests/frontend/scans/scans-list.spec.test.ts | 9 | Active |

## Plugin Specs (1 Active)

| Spec | File | Tests | Phase | Status |
|------|------|-------|-------|--------|
| ORSA v2.0 | plugins/orsa-v2.spec.yaml | tests/backend/unit/plugins/test_orsa_interface.py | 1 | Active |

## Release Workflow Specs (4 Active)

| Spec | File | Tests | Phase | Status |
|------|------|-------|-------|--------|
| Changelog | release/changelog.spec.yaml | tests/packaging/test_version_consistency.sh | 0 | Active |
| Cleanup Operations | release/cleanup-operations.spec.yaml | tests/packaging/test_cleanup_conventions.sh | 0 | Active |
| Commit Conventions | release/commit-conventions.spec.yaml | tests/packaging/test_commit_conventions.sh | 0 | Active |
| Package Build | release/package-build.spec.yaml | tests/packaging/test_package_build.sh | 0 | Active |

---

## Coverage Summary

| Category | Total Specs | Active | Draft | Deprecated |
|----------|-------------|--------|-------|------------|
| System | 10 | 10 | 0 | 0 |
| Pipelines | 3 | 3 | 0 | 0 |
| Services | 22 | 22 | 0 | 0 |
| API | 28 | 28 | 0 | 0 |
| Plugins | 1 | 1 | 0 | 0 |
| Release | 4 | 4 | 0 | 0 |
| Frontend | 13 | 13 | 0 | 0 |
| **Total** | **80** | **80** | **0** | **0** |

**Total ACs: 682 (100% covered by tests)**

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
| 0 | Foundation and Governance | (infrastructure only — release specs) |
| 1 | Scan Pipeline | scan-execution, kensa-scan, scan-orchestration, drift-detection, orsa-v2 |
| 2 | Remediation | remediation-lifecycle, remediation-execution, risk-classification, ssh-security, ssh-connection |
| 3 | Temporal Compliance | temporal-compliance, exception-governance, alert-thresholds, drift-analysis |
| 4 | Auth and RBAC | authentication, authorization, encryption, security-controls, mfa |
| 5 | API Contracts | 9 API route specs + error-model |
| 6 | Registry Maintenance | CI enforcement, documentation updates |
| 7 | Monitoring | host-monitoring (Tier 1: scan eligibility, compliance implications) |
| 8 | Frontend Architecture | state-management v2.0, auth-flow, scan-workflow, host-detail-behavior, architecture, documentation |
| 9 | Coverage Push | 36 new specs (API, service, frontend) + environment promotion, 17 integration test files |
