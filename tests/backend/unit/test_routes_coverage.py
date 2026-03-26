"""
Runtime coverage tests for route modules.
Imports route modules to exercise module-level code (schemas, decorators, router setup).

Spec: specs/system/architecture.spec.yaml
"""

import pytest


@pytest.mark.unit
class TestHostRoutes:
    """AC-5: Host routes registered and importable."""

    def test_hosts_crud(self):
        import app.routes.hosts.crud as mod

        assert hasattr(mod, "router")

    def test_hosts_discovery(self):
        import app.routes.hosts.discovery as mod

        assert hasattr(mod, "router")

    def test_hosts_monitoring(self):
        import app.routes.hosts.monitoring as mod

        assert hasattr(mod, "router")

    def test_hosts_intelligence(self):
        import app.routes.hosts.intelligence as mod

        assert hasattr(mod, "router")

    def test_hosts_baselines(self):
        import app.routes.hosts.baselines as mod

        assert hasattr(mod, "router")


@pytest.mark.unit
class TestScanRoutes:
    """AC-5: Scan routes registered and importable."""

    def test_scans_crud(self):
        import app.routes.scans.crud as mod

        assert hasattr(mod, "router")

    def test_scans_kensa(self):
        import app.routes.scans.kensa as mod

        assert hasattr(mod, "router")

    def test_scans_compliance(self):
        import app.routes.scans.compliance as mod

        assert hasattr(mod, "router")

    def test_scans_reports(self):
        import app.routes.scans.reports as mod

        assert hasattr(mod, "router")

    def test_scans_validation(self):
        import app.routes.scans.validation as mod

        assert hasattr(mod, "router")


@pytest.mark.unit
class TestAdminRoutes:
    """AC-5: Admin routes registered and importable."""

    def test_admin_users(self):
        import app.routes.admin.users as mod

        assert hasattr(mod, "router")

    def test_admin_audit(self):
        import app.routes.admin.audit as mod

        assert hasattr(mod, "router")

    def test_admin_security(self):
        import app.routes.admin.security as mod

        assert hasattr(mod, "router")

    def test_admin_credentials(self):
        import app.routes.admin.credentials as mod

        assert hasattr(mod, "router")

    def test_admin_authorization(self):
        import app.routes.admin.authorization as mod

        assert hasattr(mod, "router")


@pytest.mark.unit
class TestComplianceRoutes:
    """AC-5: Compliance routes registered and importable."""

    def test_compliance_posture(self):
        import app.routes.compliance.posture as mod

        assert hasattr(mod, "router")

    def test_compliance_drift(self):
        import app.routes.compliance.drift as mod

        assert hasattr(mod, "router")

    def test_compliance_exceptions(self):
        import app.routes.compliance.exceptions as mod

        assert hasattr(mod, "router")

    def test_compliance_alerts(self):
        import app.routes.compliance.alerts as mod

        assert hasattr(mod, "router")

    def test_compliance_audit(self):
        import app.routes.compliance.audit as mod

        assert hasattr(mod, "router")

    def test_compliance_scheduler(self):
        import app.routes.compliance.scheduler as mod

        assert hasattr(mod, "router")

    def test_compliance_remediation(self):
        import app.routes.compliance.remediation as mod

        assert hasattr(mod, "router")


@pytest.mark.unit
class TestSystemRoutes:
    """AC-5: System routes registered and importable."""

    def test_system_health(self):
        import app.routes.system.health as mod

        assert hasattr(mod, "router")

    def test_system_settings(self):
        import app.routes.system.settings as mod

        assert hasattr(mod, "router")

    def test_system_version(self):
        import app.routes.system.version as mod

        assert hasattr(mod, "router")

    def test_system_capabilities(self):
        import app.routes.system.capabilities as mod

        assert hasattr(mod, "router")


@pytest.mark.unit
class TestIntegrationRoutes:
    """AC-5: Integration routes registered and importable."""

    def test_integrations_orsa(self):
        import app.routes.integrations.orsa as mod

        assert hasattr(mod, "router")

    def test_integrations_webhooks(self):
        import app.routes.integrations.webhooks as mod

        assert hasattr(mod, "router")

    def test_integrations_metrics(self):
        import app.routes.integrations.metrics as mod

        assert hasattr(mod, "router")

    def test_integrations_orsa(self):
        import app.routes.integrations.orsa as mod

        assert hasattr(mod, "router")


@pytest.mark.unit
class TestSSHRoutes:
    """AC-5: SSH routes registered and importable."""

    def test_ssh_settings(self):
        import app.routes.ssh.settings as mod

        assert hasattr(mod, "router")

    def test_ssh_debug(self):
        import app.routes.ssh.debug as mod

        assert hasattr(mod, "router")


@pytest.mark.unit
class TestHostGroupRoutes:
    """AC-5: Host group routes registered and importable."""

    def test_host_groups_crud(self):
        import app.routes.host_groups.crud as mod

        assert hasattr(mod, "router")

    def test_host_groups_scans(self):
        import app.routes.host_groups.scans as mod

        assert hasattr(mod, "router")


@pytest.mark.unit
class TestRuleRoutes:
    """AC-5: Rule routes registered and importable."""

    def test_rules_reference(self):
        import app.routes.rules.reference as mod

        assert hasattr(mod, "router")


@pytest.mark.unit
class TestAuthRoutes:
    """AC-5: Auth routes registered and importable."""

    def test_auth_login(self):
        import app.routes.auth.login as mod

        assert hasattr(mod, "router")

    def test_auth_mfa(self):
        import app.routes.auth.mfa as mod

        assert hasattr(mod, "router")

    def test_auth_api_keys(self):
        import app.routes.auth.api_keys as mod

        assert hasattr(mod, "router")


@pytest.mark.unit
class TestRemediationRoutes:
    """AC-5: Remediation routes registered and importable."""

    def test_remediation_provider(self):
        import app.routes.remediation.provider as mod

        assert hasattr(mod, "router")

    def test_remediation_fixes(self):
        import app.routes.remediation.fixes as mod

        assert hasattr(mod, "router")
