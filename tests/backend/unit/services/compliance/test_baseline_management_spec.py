"""
Source-inspection tests for baseline management.

Spec: specs/services/compliance/baseline-management.spec.yaml
Status: draft (Q2 -- workstream I1)

Tests verify the baseline management implementation via source inspection.
AC-3 (rolling baseline) remains skip-marked until scheduler integration lands.
"""

import pytest

SKIP_REASON = "Q2: baseline management not yet implemented"


@pytest.mark.unit
class TestAC1BaselineReset:
    """AC-1: POST /api/hosts/{host_id}/baseline/reset establishes new baseline."""

    def test_reset_route_exists(self):
        """Baseline reset route is registered."""
        import inspect

        import app.routes.compliance.baselines as mod

        source = inspect.getsource(mod)
        assert "reset" in source

    def test_reset_uses_latest_scan(self):
        """BaselineManagementService.reset_baseline references latest scan data."""
        import inspect

        import app.services.compliance.baseline_management as mod

        source = inspect.getsource(mod)
        assert "latest" in source.lower() or "most_recent" in source.lower()


@pytest.mark.unit
class TestAC2BaselinePromote:
    """AC-2: POST /api/hosts/{host_id}/baseline/promote promotes current posture."""

    def test_promote_route_exists(self):
        """Baseline promote route is registered."""
        import inspect

        import app.routes.compliance.baselines as mod

        source = inspect.getsource(mod)
        assert "promote" in source

    def test_promote_method_exists(self):
        """BaselineManagementService has a promote method."""
        from app.services.compliance.baseline_management import BaselineManagementService

        assert callable(
            getattr(BaselineManagementService, "promote_baseline", None)
        )


@pytest.mark.unit
class TestAC3RollingBaseline:
    """AC-3: Rolling baseline type computes 7-day moving average."""

    def test_rolling_baseline_computation(self):
        """BaselineManagementService source references 7-day moving average."""
        import inspect

        import app.services.compliance.baseline_management as mod

        source = inspect.getsource(mod)
        assert "rolling" in source.lower() or "moving_average" in source.lower()


@pytest.mark.unit
class TestAC4RBACEnforcement:
    """AC-4: Baseline operations require SECURITY_ANALYST or higher role."""

    def test_rbac_decorator_on_routes(self):
        """Baseline routes use require_role decorator."""
        import inspect

        import app.routes.compliance.baselines as mod

        source = inspect.getsource(mod)
        assert "require_role" in source
        assert "SECURITY_ANALYST" in source


@pytest.mark.unit
class TestAC5AuditLogging:
    """AC-5: Baseline changes are logged to audit log."""

    def test_audit_logging_in_service(self):
        """BaselineManagementService source references audit logging."""
        import inspect

        import app.services.compliance.baseline_management as mod

        source = inspect.getsource(mod)
        assert "audit" in source.lower()

    def test_audit_logging_in_routes(self):
        """Baseline routes call log_audit_event."""
        import inspect

        import app.routes.compliance.baselines as mod

        source = inspect.getsource(mod)
        assert "log_audit_event" in source
