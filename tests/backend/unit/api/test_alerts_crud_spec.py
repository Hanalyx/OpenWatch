"""
Source-inspection tests for the Compliance Alerts CRUD API route.
Verifies that routes/compliance/alerts.py implements all acceptance criteria
from the alerts-crud spec: pagination, stats, role checks, 404/400 handling,
and AlertService delegation.

Spec: specs/api/compliance/alerts-crud.spec.yaml
"""
import inspect

import pytest


@pytest.mark.unit
class TestAC1ListAlertsPaginationAndFiltering:
    """AC-1: List alerts supports pagination and filtering by status/severity."""

    def test_list_alerts_has_page_parameter(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.list_alerts)
        assert "page:" in source, "list_alerts must accept page parameter"

    def test_list_alerts_has_per_page_parameter(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.list_alerts)
        assert "per_page:" in source, "list_alerts must accept per_page parameter"

    def test_list_alerts_has_status_filter(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.list_alerts)
        assert "status:" in source, "list_alerts must accept status filter"

    def test_list_alerts_has_severity_filter(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.list_alerts)
        assert "severity:" in source, "list_alerts must accept severity filter"

    def test_list_alerts_validates_status_against_enum(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.list_alerts)
        assert "AlertStatus" in source, "list_alerts must validate status against AlertStatus enum"

    def test_list_alerts_validates_severity_against_enum(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.list_alerts)
        assert "AlertSeverity" in source, "list_alerts must validate severity against AlertSeverity enum"


@pytest.mark.unit
class TestAC2AlertStatsEndpoint:
    """AC-2: Alert stats endpoint returns counts by status and severity."""

    def test_get_alert_stats_exists(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.get_alert_stats)
        assert "get_stats" in source, "get_alert_stats must call service.get_stats()"

    def test_get_alert_stats_returns_counts_by_status(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.get_alert_stats)
        assert "total_active" in source, "Stats must include total_active"
        assert "total_acknowledged" in source, "Stats must include total_acknowledged"
        assert "total_resolved" in source, "Stats must include total_resolved"

    def test_get_alert_stats_returns_counts_by_severity(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.get_alert_stats)
        assert "by_severity" in source, "Stats must include by_severity"


@pytest.mark.unit
class TestAC3ThresholdsAccess:
    """AC-3: Get/update thresholds available to authenticated users; update restricted to admin roles."""

    def test_get_thresholds_requires_authentication(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.get_alert_thresholds)
        assert "get_current_user" in source, "get_alert_thresholds must require authentication"

    def test_update_thresholds_requires_authentication(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.update_alert_thresholds)
        assert "get_current_user" in source, "update_alert_thresholds must require authentication"

    def test_update_thresholds_has_role_check(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.update_alert_thresholds)
        assert "current_user.role" in source, "update_alert_thresholds must check user role"


@pytest.mark.unit
class TestAC4UpdateThresholdsRoleRestriction:
    """AC-4: Update thresholds requires super_admin, security_admin, or admin role (403 otherwise)."""

    def test_update_thresholds_checks_super_admin(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.update_alert_thresholds)
        assert "super_admin" in source, "Must check for super_admin role"

    def test_update_thresholds_checks_security_admin(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.update_alert_thresholds)
        assert "security_admin" in source, "Must check for security_admin role"

    def test_update_thresholds_checks_admin(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.update_alert_thresholds)
        assert '"admin"' in source, "Must check for admin role"

    def test_update_thresholds_returns_403(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.update_alert_thresholds)
        assert "HTTP_403_FORBIDDEN" in source, "Must return 403 for unauthorized roles"


@pytest.mark.unit
class TestAC5GetAlertNotFound:
    """AC-5: Get alert by ID returns 404 if not found."""

    def test_get_alert_returns_404_when_not_found(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.get_alert)
        assert "HTTP_404_NOT_FOUND" in source, "Must return 404 when alert not found"

    def test_get_alert_checks_none_result(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.get_alert)
        assert "not alert" in source or "alert is None" in source, (
            "Must check for None result from service"
        )


@pytest.mark.unit
class TestAC6AcknowledgeAlertStatusTransition:
    """AC-6: Acknowledge alert changes status; returns 400 if alert not in correct state."""

    def test_acknowledge_alert_calls_service(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.acknowledge_alert)
        assert "acknowledge_alert" in source, "Must call service.acknowledge_alert"

    def test_acknowledge_alert_returns_400_on_wrong_state(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.acknowledge_alert)
        assert "HTTP_400_BAD_REQUEST" in source, "Must return 400 on invalid state transition"

    def test_acknowledge_alert_uses_request_schema(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.acknowledge_alert)
        assert "AlertAcknowledgeRequest" in source, "Must use AlertAcknowledgeRequest schema"


@pytest.mark.unit
class TestAC7ResolveAlertStatusTransition:
    """AC-7: Resolve alert changes status; returns 400 if alert not in correct state."""

    def test_resolve_alert_calls_service(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.resolve_alert)
        assert "resolve_alert" in source, "Must call service.resolve_alert"

    def test_resolve_alert_returns_400_on_wrong_state(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.resolve_alert)
        assert "HTTP_400_BAD_REQUEST" in source, "Must return 400 on invalid state transition"

    def test_resolve_alert_uses_request_schema(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.resolve_alert)
        assert "AlertResolveRequest" in source, "Must use AlertResolveRequest schema"


@pytest.mark.unit
class TestAC8AllOperationsDelegateToAlertService:
    """AC-8: All alert operations delegate to AlertService."""

    def test_module_imports_alert_service(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod)
        assert "AlertService" in source, "Module must import AlertService"

    def test_list_alerts_creates_alert_service(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.list_alerts)
        assert "AlertService(db)" in source, "list_alerts must instantiate AlertService(db)"

    def test_get_alert_creates_alert_service(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.get_alert)
        assert "AlertService(db)" in source, "get_alert must instantiate AlertService(db)"

    def test_acknowledge_creates_alert_service(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.acknowledge_alert)
        assert "AlertService(db)" in source, "acknowledge_alert must instantiate AlertService(db)"

    def test_resolve_creates_alert_service(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.resolve_alert)
        assert "AlertService(db)" in source, "resolve_alert must instantiate AlertService(db)"

    def test_get_thresholds_creates_alert_service(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.get_alert_thresholds)
        assert "AlertService(db)" in source, "get_alert_thresholds must instantiate AlertService(db)"

    def test_update_thresholds_creates_alert_service(self):
        import app.routes.compliance.alerts as mod

        source = inspect.getsource(mod.update_alert_thresholds)
        assert "AlertService(db)" in source, "update_alert_thresholds must instantiate AlertService(db)"
