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

## System Specs (10 Active, 3 Draft)

| Spec | File | Tests | Phase | Status |
|------|------|-------|-------|--------|
| Transaction Log | system/transaction-log.spec.yaml | tests/backend/unit/system/test_transaction_log_spec.py | Q1 | Draft |
| Host Rule State | system/host-rule-state.spec.yaml | tests/backend/unit/system/test_host_rule_state_spec.py | Q1 | Draft |
| Job Queue | system/job-queue.spec.yaml | tests/backend/unit/system/test_job_queue_spec.py | Q1-D | Draft |
| Architecture | system/architecture.spec.yaml | tests/backend/unit/system/test_architecture_spec.py | 8 | Active |
| Documentation | system/documentation.spec.yaml | tests/backend/unit/system/test_documentation_spec.py | 8 | Active |
| Integration Testing | system/integration-testing.spec.yaml | tests/backend/integration/test_*.py (40 files) | 9 | Active |
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

## Service Specs (21 Active, 8 Draft)

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
| Host Liveness | services/monitoring/host-liveness.spec.yaml | tests/backend/unit/services/monitoring/test_host_liveness_spec.py | Q1 | Draft |
| Notification Channels | services/infrastructure/notification-channels.spec.yaml | tests/backend/unit/services/infrastructure/test_notification_channels_spec.py | Q1 | Draft |
| SSO Federation | services/auth/sso-federation.spec.yaml | tests/backend/unit/services/auth/test_sso_federation_spec.py | Q1 | Draft |
| Evidence Signing | services/signing/evidence-signing.spec.yaml | tests/backend/unit/services/signing/test_evidence_signing_spec.py | Q2 | Draft |
| Jira Sync | services/infrastructure/jira-sync.spec.yaml | tests/backend/unit/services/infrastructure/test_jira_sync_spec.py | Q2 | Draft |
| Baseline Management | services/compliance/baseline-management.spec.yaml | tests/backend/unit/services/compliance/test_baseline_management_spec.py | Q2 | Draft |
| Alert Routing | services/compliance/alert-routing.spec.yaml | tests/backend/unit/services/compliance/test_alert_routing_spec.py | Q2 | Draft |
| Retention Policy | services/compliance/retention-policy.spec.yaml | tests/backend/unit/services/compliance/test_retention_policy_spec.py | Q2 | Draft |

## API Route Specs (28 Active)

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

## Frontend Specs (13 Active, 3 Draft)

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
| Exception Workflow | frontend/exception-workflow.spec.yaml | tests/frontend/compliance/exception-workflow.spec.test.ts | Q2 | Draft |
| Scheduled Scans | frontend/scheduled-scans.spec.yaml | tests/frontend/scans/scheduled-scans.spec.test.ts | Q2 | Draft |
| Host Audit Timeline | frontend/host-audit-timeline.spec.yaml | tests/frontend/hosts/host-audit-timeline.spec.test.ts | Q2 | Draft |

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
| System | 13 | 10 | 3 | 0 |
| Pipelines | 3 | 3 | 0 | 0 |
| Services | 29 | 21 | 8 | 0 |
| API | 28 | 28 | 0 | 0 |
| Plugins | 1 | 1 | 0 | 0 |
| Release | 4 | 4 | 0 | 0 |
| Frontend | 16 | 13 | 3 | 0 |
| **Total** | **94** | **80** | **14** | **0** |

**Active ACs: 762 (100% covered by tests) + 50 Q2 draft ACs (specs created, code pending)**

### Q1 Draft Specs

| Spec | Workstream | ACs | Status | Notes |
|------|------------|-----|--------|-------|
| transaction-log | A (Eye) | 17 | Code landed | Write-on-change v0.2, Celery removed |
| host-rule-state | A (Eye) | 8 | Code landed | Scalable state table |
| host-liveness | B (Heartbeat) | 10 | Code landed | 5-min TCP ping |
| notification-channels | C (Control Plane) | 13 | Code landed | Slack + email + webhook |
| sso-federation | C (Control Plane) | 16 | Code landed | Security scan clean |
| job-queue | D (Infrastructure) | 14 | Code landed | Celery + Redis removed, replaced by pg-based queue |

| Spec | Workstream | ACs | Unskipped | Still Skipped | Blocker |
|------|------------|-----|-----------|---------------|---------|
| transaction-log | A (Eye) | 17 | 11 | 6 | ORM model (not used), remediation write path, benchmarks |
| host-rule-state | A (Eye) | 8 | 0 | 8 | Write-on-change model for scalable state tracking |
| host-liveness | B (Heartbeat) | 10 | 4 | 6 | State machine behavioral tests (need DB) |
| notification-channels | C (Control Plane) | 13 | 4 | 9 | Route imports, behavioral tests (need DB + deps) |
| sso-federation | C (Control Plane) | 16 | 5 | 11 | Route imports, integration flows (need IdP + deps) |
| job-queue | D (Infrastructure) | 14 | 0 | 14 | Planned — code not yet implemented |

### Q2 Draft Specs (created 2026-04-13, code pending)

| Spec | Workstream | ACs | Notes |
|------|------------|-----|-------|
| evidence-signing | F (Eye) | 8 | Ed25519, key rotation, verification |
| jira-sync | G (Control Plane) | 8 | Bidirectional Jira integration |
| baseline-management | I (Heartbeat) | 5 | Reset/promote/rolling baseline |
| alert-routing | I (Heartbeat) | 6 | Per-severity routing, PagerDuty |
| retention-policy | I (Heartbeat) | 6 | TTL, signed archives |
| exception-workflow (FE) | G (Control Plane) | 7 | Exception list/form/approval UI |
| scheduled-scans (FE) | G (Control Plane) | 5 | Scheduler config/preview UI |
| host-audit-timeline (FE) | F (Eye) | 5 | Per-host timeline tab |

### Updated Active Specs in Q1

| Spec | Change | New Version |
|------|--------|-------------|
| compliance-scheduler | AC-7: auto-baseline on first scan | 1.1 |
| alert-thresholds | AC-11: notification dispatch wiring | 1.1 |

## Cross-Module Dependencies

- scan-execution.spec &rarr; kensa-scan.spec (Kensa invocation)
- scan-execution.spec &rarr; temporal-compliance.spec (snapshot creation)
- remediation-lifecycle.spec &rarr; risk-classification.spec (approval gates)
- drift-analysis.spec &rarr; alert-thresholds.spec (alert generation)
- drift-detection.spec &rarr; alert-thresholds.spec (CONFIGURATION_DRIFT, MASS_DRIFT alerts)
- host-monitoring.spec &rarr; kensa-scan.spec (ONLINE state gates scan eligibility)
- host-monitoring.spec &rarr; alert-thresholds.spec (HOST_UNREACHABLE, state transition alerts)
- host-rule-state.spec &rarr; transaction-log.spec (transactions only on state changes)
- job-queue.spec &rarr; transaction-log.spec (job queue writes transactions on task completion)
- notification-channels.spec &rarr; alert-thresholds.spec (alerts dispatched via notification channels)
- sso-federation.spec &rarr; authentication.spec (SSO extends the authentication flow)
- host-liveness.spec &rarr; alert-thresholds.spec (HOST_UNREACHABLE alert type)
- host-liveness.spec &rarr; host-monitoring.spec (host state enum)
- host-liveness.spec &rarr; notification-channels.spec (HOST_UNREACHABLE alerts dispatched)
- sso-federation.spec &rarr; audit-logging.spec (SSO login events logged)
- notification-channels.spec &rarr; audit-logging.spec (dispatch results logged)

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
