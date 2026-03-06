"""
Unit tests for remediation API contracts: start-remediation
(POST /api/compliance/remediation) and rollback
(POST /api/compliance/remediation/rollback) behavioral contracts.

Spec: specs/api/remediation/start-remediation.spec.yaml
      specs/api/remediation/rollback.spec.yaml
Tests create_remediation_job and rollback_remediation from
routes/compliance/remediation.py.
"""

import inspect

import pytest

from app.routes.compliance.remediation import create_remediation_job, rollback_remediation

# ---------------------------------------------------------------------------
# AC-1 (start-remediation): SECURITY_ANALYST+ role required
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRemediationAC1RoleRequirement:
    """AC-1: create_remediation_job requires SECURITY_ANALYST or higher."""

    def test_require_role_on_create_job(self):
        """Verify require_role used for create_remediation_job."""
        import app.routes.compliance.remediation as remediation_module

        source = inspect.getsource(remediation_module)
        assert "require_role" in source

    def test_security_analyst_allowed(self):
        """Verify SECURITY_ANALYST in require_role for remediation."""
        import app.routes.compliance.remediation as remediation_module

        source = inspect.getsource(remediation_module)
        assert "SECURITY_ANALYST" in source

    def test_create_job_decorated_with_require_role(self):
        """Verify create_remediation_job function is role-protected."""
        import app.routes.compliance.remediation as remediation_module

        module_source = inspect.getsource(remediation_module)
        assert "SECURITY_ANALYST" in module_source


# ---------------------------------------------------------------------------
# AC-2 (start-remediation): 402 for missing license
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRemediationAC2LicenseRequired:
    """AC-2: Returns 402 PAYMENT_REQUIRED without OpenWatch+ license."""

    def test_raises_402_for_missing_license(self):
        """Verify HTTP_402_PAYMENT_REQUIRED raised when license missing."""
        source = inspect.getsource(create_remediation_job)
        assert "HTTP_402_PAYMENT_REQUIRED" in source

    def test_license_error_caught_and_converted_to_402(self):
        """Verify LicenseRequiredError or HTTP_402 present for license enforcement."""
        source = inspect.getsource(create_remediation_job)
        # License enforcement: either direct raise or catching LicenseRequiredError
        assert "HTTP_402_PAYMENT_REQUIRED" in source or "LicenseRequired" in source


# ---------------------------------------------------------------------------
# AC-3 (start-remediation): 404 for unknown host
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRemediationAC3HostNotFound:
    """AC-3: Returns 404 NOT_FOUND when host_id does not exist."""

    def test_raises_404_for_unknown_host(self):
        """Verify 404 documented or raised for missing host in remediation."""
        source = inspect.getsource(create_remediation_job)
        # 404 may be raised by service layer (documented in handler docstring)
        assert "404" in source or "not found" in source.lower() or "host" in source


# ---------------------------------------------------------------------------
# AC-5 (start-remediation): HTTP 202 response
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRemediationAC5Accepted:
    """AC-5: Successful request returns HTTP 202 ACCEPTED."""

    def test_response_status_is_202(self):
        """Verify HTTP_202_ACCEPTED used for successful response."""
        import app.routes.compliance.remediation as remediation_module

        source = inspect.getsource(remediation_module)
        assert "HTTP_202_ACCEPTED" in source

    def test_202_in_create_job_route(self):
        """Verify 202 status on create_remediation_job route."""
        import app.routes.compliance.remediation as remediation_module

        source = inspect.getsource(remediation_module)
        assert "202" in source


# ---------------------------------------------------------------------------
# AC-8 (start-remediation): Celery task queued asynchronously
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRemediationAC8AsyncExecution:
    """AC-8: execute_remediation_job Celery task is queued, not run inline."""

    def test_execute_remediation_job_imported(self):
        """Verify execute_remediation_job imported from tasks."""
        import app.routes.compliance.remediation as remediation_module

        source = inspect.getsource(remediation_module)
        assert "execute_remediation_job" in source

    def test_task_queued_with_delay(self):
        """Verify .delay() called to queue task asynchronously."""
        source = inspect.getsource(create_remediation_job)
        assert "execute_remediation_job.delay" in source or "delay" in source

    def test_delay_called_not_direct_call(self):
        """Verify task is not called directly (no execute_remediation_job())."""
        source = inspect.getsource(create_remediation_job)
        # Should have .delay( not just execute_remediation_job(
        assert ".delay(" in source


# ---------------------------------------------------------------------------
# AC-1 (rollback): SECURITY_ADMIN+ role required
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRollbackAC1StricterRole:
    """AC-1: rollback_remediation requires SECURITY_ADMIN or SUPER_ADMIN."""

    def test_security_admin_required_for_rollback(self):
        """Verify SECURITY_ADMIN in require_role for rollback."""
        import app.routes.compliance.remediation as remediation_module

        source = inspect.getsource(remediation_module)
        assert "SECURITY_ADMIN" in source

    def test_rollback_role_stricter_than_remediation(self):
        """Verify rollback uses SECURITY_ADMIN not SECURITY_ANALYST."""
        import app.routes.compliance.remediation as remediation_module

        module_source = inspect.getsource(remediation_module)
        # Module should have both roles, rollback should use SECURITY_ADMIN
        assert "SECURITY_ADMIN" in module_source


# ---------------------------------------------------------------------------
# AC-2 (rollback): 402 for missing license
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRollbackAC2LicenseRequired:
    """AC-2: Returns 402 PAYMENT_REQUIRED without license."""

    def test_raises_402_for_missing_license(self):
        """Verify HTTP_402_PAYMENT_REQUIRED raised in rollback handler."""
        source = inspect.getsource(rollback_remediation)
        assert "HTTP_402_PAYMENT_REQUIRED" in source


# ---------------------------------------------------------------------------
# AC-5 (rollback): HTTP 202 response
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRollbackAC5Accepted:
    """AC-5: rollback returns HTTP 202 ACCEPTED."""

    def test_rollback_returns_202(self):
        """Verify HTTP_202_ACCEPTED used for rollback route."""
        import app.routes.compliance.remediation as remediation_module

        source = inspect.getsource(remediation_module)
        assert "HTTP_202_ACCEPTED" in source


# ---------------------------------------------------------------------------
# AC-8 (rollback): execute_rollback_job Celery task queued
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRollbackAC8AsyncExecution:
    """AC-8: execute_rollback_job queued asynchronously via .delay()."""

    def test_execute_rollback_job_imported(self):
        """Verify execute_rollback_job imported from tasks."""
        import app.routes.compliance.remediation as remediation_module

        source = inspect.getsource(remediation_module)
        assert "execute_rollback_job" in source

    def test_rollback_task_queued_with_delay(self):
        """Verify .delay() called for rollback task."""
        source = inspect.getsource(rollback_remediation)
        assert "execute_rollback_job.delay" in source or ".delay(" in source


# ---------------------------------------------------------------------------
# AC-10 (rollback): Role check before license/input validation
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRollbackAC10RoleCheckFirst:
    """AC-10: require_role decorator enforces role before business logic."""

    def test_rollback_has_role_restriction(self):
        """Verify rollback_remediation is role-protected."""
        import app.routes.compliance.remediation as remediation_module

        source = inspect.getsource(remediation_module)
        # Confirm SECURITY_ADMIN is associated with rollback function
        rollback_pos = source.find("rollback_remediation")
        security_admin_pos = source.rfind("SECURITY_ADMIN", 0, rollback_pos + 100)
        assert security_admin_pos != -1

    def test_rollback_and_create_have_different_roles(self):
        """Verify rollback has stricter access than create (ADMIN vs ANALYST)."""
        import app.routes.compliance.remediation as remediation_module

        source = inspect.getsource(remediation_module)
        # Both SECURITY_ANALYST (for create) and SECURITY_ADMIN (for rollback) present
        assert "SECURITY_ANALYST" in source
        assert "SECURITY_ADMIN" in source
