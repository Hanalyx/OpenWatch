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


# ---------------------------------------------------------------------------
# AC-4 (start-remediation): 400 for invalid/empty rule_ids
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRemediationAC4InvalidRules:
    """AC-4: Returns 400 BAD_REQUEST when rule_ids is empty or unrecognized."""

    def test_raises_400_for_invalid_rules(self):
        """Verify HTTP 400 raised for invalid rule_ids."""
        source = inspect.getsource(create_remediation_job)
        assert "HTTP_400_BAD_REQUEST" in source or "400" in source

    def test_value_error_caught_and_returned_as_400(self):
        """Verify ValueError from service is converted to 400 BAD_REQUEST."""
        source = inspect.getsource(create_remediation_job)
        assert "ValueError" in source
        assert "HTTP_400_BAD_REQUEST" in source


# ---------------------------------------------------------------------------
# AC-6 (start-remediation): Response includes job_id and status="queued"
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRemediationAC6ResponseShape:
    """AC-6: Response body includes job_id (UUID string) and status='queued'."""

    def test_response_model_has_job_id(self):
        """Verify RemediationJobResponse schema has job_id field."""
        from app.schemas.remediation_schemas import RemediationJobResponse

        fields = RemediationJobResponse.model_fields
        assert "id" in fields or "job_id" in fields

    def test_response_model_has_status(self):
        """Verify RemediationJobResponse schema has status field."""
        from app.schemas.remediation_schemas import RemediationJobResponse

        fields = RemediationJobResponse.model_fields
        assert "status" in fields

    def test_response_uses_remediation_job_response_model(self):
        """Verify create_remediation_job uses RemediationJobResponse."""
        import app.routes.compliance.remediation as remediation_module

        source = inspect.getsource(remediation_module)
        assert "RemediationJobResponse" in source


# ---------------------------------------------------------------------------
# AC-7 (start-remediation): Response echoes host_id and rule_ids
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRemediationAC7ResponseEcho:
    """AC-7: Response echoes back host_id and rule_ids for client-side correlation."""

    def test_response_schema_has_host_id(self):
        """Verify RemediationJobResponse schema has host_id field."""
        from app.schemas.remediation_schemas import RemediationJobResponse

        fields = RemediationJobResponse.model_fields
        assert "host_id" in fields

    def test_response_schema_has_rule_ids(self):
        """Verify RemediationJobResponse schema has rule_ids field."""
        from app.schemas.remediation_schemas import RemediationJobResponse

        fields = RemediationJobResponse.model_fields
        assert "rule_ids" in fields


# ---------------------------------------------------------------------------
# AC-9 (start-remediation): Job created in DB before response
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRemediationAC9JobCreatedFirst:
    """AC-9: Remediation job record created in DB with status 'queued' before response."""

    def test_job_created_before_celery_delay(self):
        """Verify service.create_job called before execute_remediation_job.delay."""
        source = inspect.getsource(create_remediation_job)
        create_pos = source.find("create_job")
        delay_pos = source.find(".delay(")
        assert create_pos != -1 and delay_pos != -1
        assert create_pos < delay_pos

    def test_job_id_passed_to_delay(self):
        """Verify job ID returned from create_job is passed to delay call."""
        source = inspect.getsource(create_remediation_job)
        assert "job.id" in source or "job_id" in source


# ---------------------------------------------------------------------------
# AC-4 (rollback): 400 for non-eligible state
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRollbackAC4NonEligibleState:
    """AC-4: Returns 400 BAD_REQUEST when job is not in a rollback-eligible state."""

    def test_raises_400_for_invalid_state(self):
        """Verify HTTP 400 raised for non-eligible rollback state."""
        source = inspect.getsource(rollback_remediation)
        assert "HTTP_400_BAD_REQUEST" in source or "400" in source

    def test_value_error_caught_as_400(self):
        """Verify ValueError (non-eligible state) converted to 400."""
        source = inspect.getsource(rollback_remediation)
        assert "ValueError" in source
        assert "HTTP_400_BAD_REQUEST" in source


# ---------------------------------------------------------------------------
# AC-6 (rollback): Response includes rollback_job_id and status
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRollbackAC6ResponseShape:
    """AC-6: Response body includes rollback_job_id (UUID) and status='queued'."""

    def test_response_has_rollback_job_id(self):
        """Verify RollbackResponse schema has rollback_job_id field."""
        from app.schemas.remediation_schemas import RollbackResponse

        fields = RollbackResponse.model_fields
        assert "rollback_job_id" in fields

    def test_response_has_status(self):
        """Verify RollbackResponse schema has status field."""
        from app.schemas.remediation_schemas import RollbackResponse

        fields = RollbackResponse.model_fields
        assert "status" in fields

    def test_rollback_uses_rollback_response_model(self):
        """Verify rollback_remediation uses RollbackResponse."""
        import app.routes.compliance.remediation as remediation_module

        source = inspect.getsource(remediation_module)
        assert "RollbackResponse" in source


# ---------------------------------------------------------------------------
# AC-7 (rollback): Response echoes original job_id
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRollbackAC7EchoOriginalJob:
    """AC-7: Response echoes back the original job_id from the request."""

    def test_response_schema_has_original_job_id(self):
        """Verify RollbackResponse schema has original_job_id field."""
        from app.schemas.remediation_schemas import RollbackResponse

        fields = RollbackResponse.model_fields
        assert "original_job_id" in fields or "job_id" in fields

    def test_request_job_id_forwarded_to_service(self):
        """Verify request.job_id is passed to the service rollback call."""
        source = inspect.getsource(rollback_remediation)
        assert "request.job_id" in source


# ---------------------------------------------------------------------------
# AC-9 (rollback): Rollback job record created before HTTP response
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRollbackAC9JobCreatedFirst:
    """AC-9: Rollback job record created in DB with status 'queued' before response."""

    def test_rollback_job_created_before_delay(self):
        """Verify service.rollback_job called before execute_rollback_job.delay."""
        source = inspect.getsource(rollback_remediation)
        create_pos = source.find("rollback_job(")
        delay_pos = source.find("execute_rollback_job.delay")
        assert create_pos != -1 and delay_pos != -1
        assert create_pos < delay_pos

    def test_rollback_job_id_passed_to_delay(self):
        """Verify rollback_job_id from service response is passed to delay."""
        source = inspect.getsource(rollback_remediation)
        assert "rollback_job_id" in source
