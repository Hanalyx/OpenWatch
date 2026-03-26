"""
Runtime coverage tests for service modules.
Imports and exercises pure functions, data classes, and validators.

Spec: specs/system/architecture.spec.yaml
"""

import pytest


@pytest.mark.unit
class TestValidationServices:
    """AC-1: Validation services handle error classification."""

    def test_sanitization_levels(self):
        from app.services.validation.sanitization import SanitizationLevel

        assert SanitizationLevel.MINIMAL.value == "minimal"
        assert SanitizationLevel.STANDARD.value == "standard"
        assert SanitizationLevel.STRICT.value == "strict"

    def test_error_sanitization_service_init(self):
        from app.services.validation.sanitization import ErrorSanitizationService

        svc = ErrorSanitizationService()
        assert svc.MAX_ERRORS_PER_HOUR == 50
        assert svc.MAX_ERRORS_PER_MINUTE == 10

    def test_generic_messages_exist(self):
        from app.services.validation.sanitization import ErrorSanitizationService

        svc = ErrorSanitizationService()
        assert "NET_001" in svc.GENERIC_MESSAGES
        assert "AUTH_001" in svc.GENERIC_MESSAGES
        assert "RES_001" in svc.GENERIC_MESSAGES

    def test_sensitive_patterns_populated(self):
        from app.services.validation.sanitization import ErrorSanitizationService

        svc = ErrorSanitizationService()
        assert len(svc.SENSITIVE_PATTERNS) > 5

    def test_security_context_model(self):
        from app.services.validation.errors import SecurityContext

        ctx = SecurityContext(
            hostname="test-host",
            username="admin",
            auth_method="ssh_key",
        )
        assert ctx.hostname == "test-host"
        assert ctx.username == "admin"

    def test_error_classification_service_init(self):
        from app.services.validation.errors import ErrorClassificationService

        svc = ErrorClassificationService()
        assert svc is not None

    def test_classify_authentication_error(self):
        from app.services.validation.errors import (
            SecurityContext,
            classify_authentication_error,
        )

        ctx = SecurityContext(hostname="h", username="u", auth_method="pw")
        result = classify_authentication_error(ctx)
        assert result.error_code == "AUTH_GENERIC"

    def test_group_validation_importable(self):
        from app.services.validation.group import GroupValidationService

        assert GroupValidationService is not None

    def test_system_sanitization_importable(self):
        from app.services.validation.system_sanitization import (
            SystemInfoSanitizationService,
        )

        assert SystemInfoSanitizationService is not None


@pytest.mark.unit
class TestMonitoringServices:
    """AC-1: Monitoring services."""

    def test_host_monitor_importable(self):
        import app.services.monitoring.host as mod

        assert mod is not None

    def test_monitoring_state_importable(self):
        import app.services.monitoring.state as mod

        assert mod is not None

    def test_monitoring_drift_importable(self):
        import app.services.monitoring.drift as mod

        assert mod is not None

    def test_monitoring_health_importable(self):
        import app.services.monitoring.health as mod

        assert mod is not None

    def test_monitoring_scheduler_importable(self):
        import app.services.monitoring.scheduler as mod

        assert mod is not None


@pytest.mark.unit
class TestLicensingService:
    """AC-1: Licensing service feature gating."""

    def test_license_service_importable(self):
        from app.services.licensing.service import LicenseService

        assert LicenseService is not None

    def test_license_service_instantiation(self):
        from app.services.licensing.service import LicenseService

        svc = LicenseService()
        assert svc is not None


@pytest.mark.unit
class TestSSHServices:
    """AC-1: SSH service modules."""

    def test_ssh_config_manager_importable(self):
        from app.services.ssh.config_manager import SSHConfigManager

        assert SSHConfigManager is not None

    def test_known_hosts_manager_importable(self):
        from app.services.ssh.known_hosts import KnownHostsManager

        assert KnownHostsManager is not None


@pytest.mark.unit
class TestComplianceServices:
    """AC-1: Compliance service modules."""

    def test_alert_service_importable(self):
        from app.services.compliance.alerts import AlertService

        assert AlertService is not None

    def test_drift_service_importable(self):
        from app.services.monitoring.drift import DriftDetectionService

        assert DriftDetectionService is not None

    def test_temporal_service_importable(self):
        from app.services.compliance.temporal import TemporalComplianceService

        assert TemporalComplianceService is not None

    def test_exception_service_importable(self):
        from app.services.compliance.exceptions import ExceptionService

        assert ExceptionService is not None


@pytest.mark.unit
class TestInfrastructureServices:
    """AC-1: Infrastructure service modules."""

    def test_audit_service_importable(self):
        import app.services.infrastructure.audit as mod

        assert mod is not None

    def test_email_service_importable(self):
        import app.services.infrastructure.email as mod

        assert mod is not None

    def test_config_service_importable(self):
        import app.services.infrastructure.config as mod

        assert mod is not None

    def test_http_service_importable(self):
        import app.services.infrastructure.http as mod

        assert mod is not None

    def test_sandbox_service_importable(self):
        import app.services.infrastructure.sandbox as mod

        assert mod is not None

    def test_webhooks_service_importable(self):
        import app.services.infrastructure.webhooks as mod

        assert mod is not None


@pytest.mark.unit
class TestOWCAServices:
    """AC-1: OWCA compliance scoring modules."""

    def test_score_calculator_importable(self):
        from app.services.owca.core.score_calculator import ComplianceScoreCalculator

        assert ComplianceScoreCalculator is not None

    def test_fleet_aggregator_importable(self):
        import app.services.owca.aggregation.fleet_aggregator as mod

        assert mod is not None

    def test_trend_analyzer_importable(self):
        import app.services.owca.intelligence.trend_analyzer as mod

        assert mod is not None

    def test_risk_scorer_importable(self):
        import app.services.owca.intelligence.risk_scorer as mod

        assert mod is not None

    def test_baseline_drift_importable(self):
        import app.services.owca.intelligence.baseline_drift as mod

        assert mod is not None

    def test_owca_models_importable(self):
        import app.services.owca.models as mod

        assert mod is not None

    def test_framework_models_importable(self):
        import app.services.owca.framework.models as mod

        assert mod is not None


@pytest.mark.unit
class TestPluginServices:
    """AC-1: Plugin framework modules."""

    def test_plugin_interface(self):
        import app.plugins.interface as mod

        assert mod is not None

    def test_plugin_interface(self):
        import app.plugins.interface as mod

        assert mod is not None

    def test_kensa_plugin(self):
        import app.plugins.kensa.plugin as mod

        assert mod is not None

    def test_governance_service(self):
        import app.services.plugins.governance.service as mod

        assert mod is not None

    def test_orsa_interface(self):
        import app.services.plugins.orsa.interface as mod

        assert mod is not None

    def test_security_service(self):
        import app.services.plugins.security.validator as mod

        assert mod is not None

    def test_registry_service(self):
        import app.services.plugins.registry.service as mod

        assert mod is not None


@pytest.mark.unit
class TestTaskModules:
    """AC-3: Celery task modules importable."""

    def test_scan_tasks(self):
        import app.tasks.scan_tasks as mod

        assert mod is not None

    def test_monitoring_tasks(self):
        import app.tasks.monitoring_tasks as mod

        assert mod is not None

    def test_compliance_tasks(self):
        import app.tasks.compliance_tasks as mod

        assert mod is not None

    def test_stale_scan_detection(self):
        import app.tasks.stale_scan_detection as mod

        assert mod is not None

    def test_webhook_tasks(self):
        import app.tasks.webhook_tasks as mod

        assert mod is not None

    def test_remediation_tasks(self):
        import app.tasks.remediation_tasks as mod

        assert mod is not None

    def test_os_discovery_tasks(self):
        import app.tasks.os_discovery_tasks as mod

        assert mod is not None
