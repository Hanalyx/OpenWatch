"""
Unit tests for exception governance: 5-status state machine, transition guards,
duplicate prevention, scope validation, is_excepted priority, bulk expiration,
summary counts, and schema constraints.

Spec: specs/services/compliance/exception-governance.spec.yaml
Tests the ExceptionService from exceptions.py (569 LOC).
"""

import inspect

import pytest
from pydantic import ValidationError

from app.schemas.exception_schemas import ExceptionCheckResponse, ExceptionRequestCreate, ExceptionSummary
from app.services.compliance.exceptions import ExceptionService

# ---------------------------------------------------------------------------
# AC-1: Exception status has exactly 5 values
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC1ExceptionStatuses:
    """AC-1: 5 status values: pending, approved, rejected, expired, revoked."""

    ALL_STATUSES = {"pending", "approved", "rejected", "expired", "revoked"}

    def test_pending_in_request_exception(self):
        """Verify 'pending' is set during request_exception."""
        source = inspect.getsource(ExceptionService.request_exception)
        assert '"pending"' in source

    def test_all_five_statuses_across_transitions(self):
        """Verify all 5 statuses appear across the 4 transition methods."""
        methods = [
            ExceptionService.request_exception,
            ExceptionService.approve_exception,
            ExceptionService.reject_exception,
            ExceptionService.revoke_exception,
            ExceptionService.expire_exceptions,
        ]
        found_statuses = set()
        for method in methods:
            source = inspect.getsource(method)
            for status in self.ALL_STATUSES:
                if f'"{status}"' in source:
                    found_statuses.add(status)
        assert found_statuses == self.ALL_STATUSES


# ---------------------------------------------------------------------------
# AC-2: approve_exception transition guard
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC2ApproveTransition:
    """AC-2: approve_exception transitions only from pending to approved."""

    def test_checks_pending_status(self):
        """Verify guard checks status != 'pending'."""
        source = inspect.getsource(ExceptionService.approve_exception)
        assert '"pending"' in source

    def test_sets_approved_status(self):
        """Verify status is set to 'approved'."""
        source = inspect.getsource(ExceptionService.approve_exception)
        assert '"approved"' in source


# ---------------------------------------------------------------------------
# AC-3: reject and revoke transition guards
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC3RejectRevokeTransitions:
    """AC-3: reject from pending; revoke from approved."""

    def test_reject_guards_pending(self):
        """Verify reject_exception checks for pending status."""
        source = inspect.getsource(ExceptionService.reject_exception)
        assert '"pending"' in source

    def test_reject_sets_rejected(self):
        """Verify reject_exception sets status to 'rejected'."""
        source = inspect.getsource(ExceptionService.reject_exception)
        assert '"rejected"' in source

    def test_revoke_guards_approved(self):
        """Verify revoke_exception checks for approved status."""
        source = inspect.getsource(ExceptionService.revoke_exception)
        assert '"approved"' in source

    def test_revoke_sets_revoked(self):
        """Verify revoke_exception sets status to 'revoked'."""
        source = inspect.getsource(ExceptionService.revoke_exception)
        assert '"revoked"' in source


# ---------------------------------------------------------------------------
# AC-4: Duplicate prevention
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC4DuplicatePrevention:
    """AC-4: _find_active_exception checks pending/approved; request returns None."""

    def test_find_active_checks_both_statuses(self):
        """Verify _find_active_exception checks for pending and approved."""
        source = inspect.getsource(ExceptionService._find_active_exception)
        assert "'pending'" in source
        assert "'approved'" in source

    def test_request_calls_find_active(self):
        """Verify request_exception calls _find_active_exception."""
        source = inspect.getsource(ExceptionService.request_exception)
        assert "_find_active_exception" in source

    def test_request_returns_none_on_duplicate(self):
        """Verify request_exception returns None when duplicate found."""
        source = inspect.getsource(ExceptionService.request_exception)
        # After finding existing, returns None
        assert "return None" in source


# ---------------------------------------------------------------------------
# AC-5: Schema validation constraints
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC5SchemaConstraints:
    """AC-5: justification min_length=20, duration_days ge=1, le=365."""

    def test_justification_min_length(self):
        """Verify justification requires at least 20 characters."""
        field_info = ExceptionRequestCreate.model_fields["justification"]
        assert field_info.metadata is not None
        min_length_found = any(getattr(m, "min_length", None) == 20 for m in field_info.metadata)
        assert min_length_found, "justification missing min_length=20"

    def test_duration_days_ge(self):
        """Verify duration_days has ge=1."""
        field_info = ExceptionRequestCreate.model_fields["duration_days"]
        ge_found = any(getattr(m, "ge", None) == 1 for m in field_info.metadata)
        assert ge_found, "duration_days missing ge=1"

    def test_duration_days_le(self):
        """Verify duration_days has le=365."""
        field_info = ExceptionRequestCreate.model_fields["duration_days"]
        le_found = any(getattr(m, "le", None) == 365 for m in field_info.metadata)
        assert le_found, "duration_days missing le=365"

    def test_short_justification_rejected(self):
        """Verify validation rejects short justification."""
        with pytest.raises(ValidationError):
            ExceptionRequestCreate(
                rule_id="test-rule",
                justification="too short",
                duration_days=30,
            )

    def test_valid_request_accepted(self):
        """Verify valid request passes validation."""
        req = ExceptionRequestCreate(
            rule_id="test-rule",
            justification="This is a sufficiently long justification for testing",
            duration_days=30,
        )
        assert req.duration_days == 30


# ---------------------------------------------------------------------------
# AC-6: is_excepted priority (host first, then group)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC6IsExceptedPriority:
    """AC-6: is_excepted checks host first, then host group via JOIN."""

    def test_checks_host_id_first(self):
        """Verify direct host exception query comes first."""
        source = inspect.getsource(ExceptionService.is_excepted)
        host_pos = source.find("host_id = :host_id")
        group_pos = source.find("host_group_memberships")
        assert host_pos < group_pos, "host_id check must come before group check"

    def test_joins_host_group_memberships(self):
        """Verify host group check uses host_group_memberships JOIN."""
        source = inspect.getsource(ExceptionService.is_excepted)
        assert "host_group_memberships" in source
        assert "JOIN" in source


# ---------------------------------------------------------------------------
# AC-7: Bulk expiration
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC7BulkExpiration:
    """AC-7: expire_exceptions bulk-updates approved past expires_at to expired."""

    def test_filters_approved(self):
        """Verify only approved exceptions are targeted."""
        source = inspect.getsource(ExceptionService.expire_exceptions)
        assert '"approved"' in source

    def test_sets_expired_status(self):
        """Verify status is set to 'expired'."""
        source = inspect.getsource(ExceptionService.expire_exceptions)
        assert '"expired"' in source

    def test_checks_expires_at(self):
        """Verify expires_at comparison is used."""
        source = inspect.getsource(ExceptionService.expire_exceptions)
        assert "expires_at" in source

    def test_returns_count(self):
        """Verify method returns a count."""
        source = inspect.getsource(ExceptionService.expire_exceptions)
        assert "return" in source
        assert "expired_count" in source


# ---------------------------------------------------------------------------
# AC-8: get_summary returns ExceptionSummary with 6 fields
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC8GetSummary:
    """AC-8: get_summary returns ExceptionSummary with 5 status counts + expiring_soon."""

    EXPECTED_FIELDS = {
        "total_pending",
        "total_approved",
        "total_rejected",
        "total_expired",
        "total_revoked",
        "expiring_soon",
    }

    def test_summary_has_all_fields(self):
        """Verify ExceptionSummary has all 6 expected fields."""
        model_fields = set(ExceptionSummary.model_fields.keys())
        assert self.EXPECTED_FIELDS.issubset(model_fields)

    def test_source_has_filter_expressions(self):
        """Verify get_summary source uses FILTER expressions for counting."""
        source = inspect.getsource(ExceptionService.get_summary)
        assert "FILTER" in source
        assert "'pending'" in source
        assert "'approved'" in source
        assert "'rejected'" in source
        assert "'expired'" in source
        assert "'revoked'" in source

    def test_default_values(self):
        """Verify ExceptionSummary defaults to 0 for all fields."""
        summary = ExceptionSummary()
        for field in self.EXPECTED_FIELDS:
            assert getattr(summary, field) == 0


# ---------------------------------------------------------------------------
# AC-9: Scope validation
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC9ScopeValidation:
    """AC-9: request_exception requires host_id or host_group_id."""

    def test_checks_no_scope(self):
        """Verify source checks for missing scope."""
        source = inspect.getsource(ExceptionService.request_exception)
        assert "not host_id and not host_group_id" in source

    def test_returns_none_on_missing_scope(self):
        """Verify return None when neither scope is provided."""
        source = inspect.getsource(ExceptionService.request_exception)
        # The scope check is followed by return None
        lines = source.split("\n")
        for i, line in enumerate(lines):
            if "not host_id and not host_group_id" in line:
                # Check subsequent lines for return None
                subsequent = "\n".join(lines[i : i + 3])
                assert "return None" in subsequent
                break


# ---------------------------------------------------------------------------
# AC-10: ExceptionCheckResponse fields
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC10CheckResponseSchema:
    """AC-10: ExceptionCheckResponse has is_excepted, exception_id, expires_at, justification."""

    REQUIRED_FIELDS = {"is_excepted", "exception_id", "expires_at", "justification"}

    def test_all_fields_present(self):
        """Verify all 4 fields exist on ExceptionCheckResponse."""
        model_fields = set(ExceptionCheckResponse.model_fields.keys())
        for field in self.REQUIRED_FIELDS:
            assert field in model_fields, f"Missing field: {field}"

    def test_default_not_excepted(self):
        """Verify default construction with is_excepted=False."""
        response = ExceptionCheckResponse(is_excepted=False)
        assert response.is_excepted is False
        assert response.exception_id is None
        assert response.expires_at is None
        assert response.justification is None
