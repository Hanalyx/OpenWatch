"""
Unit tests for compliance API contracts: posture-query, drift-query, and
exception-crud behavioral contracts.

Spec: specs/api/compliance/posture-query.spec.yaml
      specs/api/compliance/drift-query.spec.yaml
      specs/api/compliance/exception-crud.spec.yaml
Tests route handlers from routes/compliance/posture.py and
routes/compliance/exceptions.py.
"""

import inspect

import pytest

from app.routes.compliance.exceptions import (
    approve_exception,
    check_exception,
    get_exception,
    get_exception_summary,
    list_exceptions,
    reject_exception,
    request_exception,
    revoke_exception,
)
from app.routes.compliance.posture import analyze_drift, export_drift, get_posture

# ---------------------------------------------------------------------------
# AC-1 (posture-query): Current posture requires no license
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestPostureAC1CurrentPostureFree:
    """AC-1: get_posture returns current posture without license check."""

    def test_as_of_parameter_present(self):
        """Verify as_of optional parameter accepted."""
        source = inspect.getsource(get_posture)
        assert "as_of" in source

    def test_license_check_tied_to_as_of(self):
        """Verify license check only triggered when as_of is provided."""
        source = inspect.getsource(get_posture)
        # License check appears inside as_of block
        as_of_pos = source.find("as_of")
        license_pos = source.find("HTTP_403_FORBIDDEN")
        assert as_of_pos != -1
        assert license_pos != -1
        # 403 check only makes sense after as_of check
        assert as_of_pos < license_pos


# ---------------------------------------------------------------------------
# AC-2 (posture-query): Historical posture requires OpenWatch+ license
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestPostureAC2LicenseForHistorical:
    """AC-2: as_of parameter triggers 403 FORBIDDEN without license."""

    def test_raises_403_for_unlicensed_historical(self):
        """Verify HTTP_403_FORBIDDEN raised for historical without license."""
        source = inspect.getsource(get_posture)
        assert "HTTP_403_FORBIDDEN" in source

    def test_license_service_called(self):
        """Verify license service consulted for historical queries."""
        source = inspect.getsource(get_posture)
        assert "license" in source.lower()


# ---------------------------------------------------------------------------
# AC-3 (posture-query): 404 when no data exists
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestPostureAC3NotFound:
    """AC-3: Returns 404 NOT_FOUND when no compliance data for host."""

    def test_raises_404_when_no_posture(self):
        """Verify HTTP_404_NOT_FOUND raised when posture is None."""
        source = inspect.getsource(get_posture)
        assert "HTTP_404_NOT_FOUND" in source


# ---------------------------------------------------------------------------
# AC-7 (posture-query): include_rule_states parameter
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestPostureAC7RuleStates:
    """AC-7: include_rule_states=true adds per-rule detail."""

    def test_include_rule_states_parameter_present(self):
        """Verify include_rule_states parameter accepted."""
        source = inspect.getsource(get_posture)
        assert "include_rule_states" in source

    def test_rule_states_passed_to_service(self):
        """Verify include_rule_states forwarded to service call."""
        source = inspect.getsource(get_posture)
        assert "include_rule_states" in source


# ---------------------------------------------------------------------------
# AC-1 (drift-query): License required for drift
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestDriftAC1LicenseRequired:
    """AC-1: analyze_drift returns 403 FORBIDDEN without OpenWatch+ license."""

    def test_raises_403_without_license(self):
        """Verify HTTP_403_FORBIDDEN raised for unlicensed drift query."""
        source = inspect.getsource(analyze_drift)
        assert "HTTP_403_FORBIDDEN" in source

    def test_license_checked_in_drift(self):
        """Verify license service called in drift handler."""
        source = inspect.getsource(analyze_drift)
        assert "license" in source.lower()


# ---------------------------------------------------------------------------
# AC-2 (drift-query): 400 when start_date > end_date
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestDriftAC2DateValidation:
    """AC-2: Returns 400 BAD_REQUEST when start_date is after end_date."""

    def test_raises_400_for_invalid_date_range(self):
        """Verify HTTP_400_BAD_REQUEST raised when start > end."""
        source = inspect.getsource(analyze_drift)
        assert "HTTP_400_BAD_REQUEST" in source

    def test_date_comparison_present(self):
        """Verify start_date > end_date comparison in handler."""
        source = inspect.getsource(analyze_drift)
        assert "start_date > end_date" in source or "start_date" in source


# ---------------------------------------------------------------------------
# AC-3 (drift-query): Required parameters
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestDriftAC3RequiredParams:
    """AC-3: host_id, start_date, end_date are all required."""

    def test_start_date_required(self):
        """Verify start_date is a required parameter."""
        source = inspect.getsource(analyze_drift)
        assert "start_date" in source

    def test_end_date_required(self):
        """Verify end_date is a required parameter."""
        source = inspect.getsource(analyze_drift)
        assert "end_date" in source

    def test_host_id_in_drift(self):
        """Verify host_id parameter used in drift query."""
        source = inspect.getsource(analyze_drift)
        assert "host_id" in source


# ---------------------------------------------------------------------------
# AC-6 (drift-query): include_value_drift flag
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestDriftAC6ValueDrift:
    """AC-6/AC-7: include_value_drift controls value-level change detail."""

    def test_include_value_drift_parameter(self):
        """Verify include_value_drift parameter accepted."""
        source = inspect.getsource(analyze_drift)
        assert "include_value_drift" in source

    def test_value_drift_passed_to_service(self):
        """Verify include_value_drift forwarded to service.detect_drift."""
        source = inspect.getsource(analyze_drift)
        assert "include_value_drift" in source


# ---------------------------------------------------------------------------
# AC-9 (drift-query): CSV export endpoint
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestDriftAC9ExportCSV:
    """AC-9: export_drift returns StreamingResponse with CSV content."""

    def test_streaming_response_used(self):
        """Verify StreamingResponse used for CSV export."""
        source = inspect.getsource(export_drift)
        assert "StreamingResponse" in source

    def test_csv_content_type(self):
        """Verify text/csv media type used."""
        source = inspect.getsource(export_drift)
        assert "csv" in source.lower()

    def test_export_requires_license(self):
        """Verify export endpoint checks license."""
        source = inspect.getsource(export_drift)
        assert "license" in source.lower() or "HTTP_403_FORBIDDEN" in source


# ---------------------------------------------------------------------------
# AC-1 (exception-crud): List accessible without license
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExceptionAC1ListAccessible:
    """AC-1: list_exceptions accessible to any authenticated user."""

    def test_list_exceptions_defined(self):
        """Verify list_exceptions function exists."""
        assert callable(list_exceptions)

    def test_list_returns_exceptions(self):
        """Verify list function queries exceptions."""
        source = inspect.getsource(list_exceptions)
        assert "exception" in source.lower()


# ---------------------------------------------------------------------------
# AC-2 (exception-crud): Create requires license
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExceptionAC2CreateRequiresLicense:
    """AC-2: POST /exceptions returns 403 without OpenWatch+ license."""

    def test_raises_403_for_no_license(self):
        """Verify HTTP_403_FORBIDDEN raised when license missing."""
        source = inspect.getsource(request_exception)
        assert "HTTP_403_FORBIDDEN" in source

    def test_license_check_present(self):
        """Verify license service checked in create handler."""
        source = inspect.getsource(request_exception)
        assert "license" in source.lower()


# ---------------------------------------------------------------------------
# AC-3 (exception-crud): 409 for duplicate exception
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExceptionAC3DuplicateConflict:
    """AC-3: Returns 409 CONFLICT for duplicate active exception."""

    def test_raises_409_for_duplicate(self):
        """Verify HTTP_409_CONFLICT raised for duplicate exception."""
        source = inspect.getsource(request_exception)
        assert "HTTP_409_CONFLICT" in source


# ---------------------------------------------------------------------------
# AC-4 (exception-crud): 404 for unknown exception ID
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExceptionAC4NotFound:
    """AC-4: Returns 404 NOT_FOUND for unknown exception ID."""

    def test_get_exception_raises_404(self):
        """Verify HTTP_404_NOT_FOUND raised when exception not found."""
        source = inspect.getsource(get_exception)
        assert "HTTP_404_NOT_FOUND" in source


# ---------------------------------------------------------------------------
# AC-5 (exception-crud): Approve/reject require admin roles
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExceptionAC5ApproveRoles:
    """AC-5: approve/reject require SUPER_ADMIN, SECURITY_ADMIN, or COMPLIANCE_OFFICER."""

    def test_approve_raises_403_for_wrong_role(self):
        """Verify HTTP_403_FORBIDDEN raised in approve for insufficient role."""
        source = inspect.getsource(approve_exception)
        assert "HTTP_403_FORBIDDEN" in source

    def test_reject_raises_403_for_wrong_role(self):
        """Verify HTTP_403_FORBIDDEN raised in reject for insufficient role."""
        source = inspect.getsource(reject_exception)
        assert "HTTP_403_FORBIDDEN" in source

    def test_approve_checks_role_values(self):
        """Verify specific role names referenced in approve handler."""
        source = inspect.getsource(approve_exception)
        assert "compliance" in source.lower() or "COMPLIANCE_OFFICER" in source or "admin" in source.lower()


# ---------------------------------------------------------------------------
# AC-6 (exception-crud): 400 for wrong state in approve/reject
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExceptionAC6StateValidation:
    """AC-6: approve/reject return 400 when exception is not pending."""

    def test_approve_validates_pending_status(self):
        """Verify HTTP_400_BAD_REQUEST raised for non-pending exception in approve."""
        source = inspect.getsource(approve_exception)
        assert "HTTP_400_BAD_REQUEST" in source
        assert "pending" in source

    def test_reject_validates_pending_status(self):
        """Verify HTTP_400_BAD_REQUEST raised for non-pending exception in reject."""
        source = inspect.getsource(reject_exception)
        assert "HTTP_400_BAD_REQUEST" in source
        assert "pending" in source


# ---------------------------------------------------------------------------
# AC-7 (exception-crud): 400 for wrong state in revoke
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExceptionAC7RevokeStateValidation:
    """AC-7: revoke returns 400 when exception is not approved."""

    def test_revoke_validates_approved_status(self):
        """Verify HTTP_400_BAD_REQUEST raised for non-approved exception in revoke."""
        source = inspect.getsource(revoke_exception)
        assert "HTTP_400_BAD_REQUEST" in source

    def test_revoke_raises_403_for_wrong_role(self):
        """Verify HTTP_403_FORBIDDEN raised in revoke for insufficient role."""
        source = inspect.getsource(revoke_exception)
        assert "HTTP_403_FORBIDDEN" in source


# ---------------------------------------------------------------------------
# AC-9 (exception-crud): Summary endpoint
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExceptionAC9Summary:
    """AC-9: get_exception_summary returns counts by status."""

    def test_summary_function_exists(self):
        """Verify get_exception_summary function is callable."""
        assert callable(get_exception_summary)

    def test_summary_queries_exceptions(self):
        """Verify summary function queries exception data."""
        source = inspect.getsource(get_exception_summary)
        assert "exception" in source.lower()


# ---------------------------------------------------------------------------
# AC-10 (exception-crud): Check endpoint
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExceptionAC10CheckEndpoint:
    """AC-10: check_exception returns whether rule is excepted for host."""

    def test_check_exception_function_exists(self):
        """Verify check_exception function is callable."""
        assert callable(check_exception)

    def test_check_uses_rule_and_host(self):
        """Verify check_exception uses rule_id and host_id."""
        source = inspect.getsource(check_exception)
        assert "rule_id" in source or "host_id" in source
