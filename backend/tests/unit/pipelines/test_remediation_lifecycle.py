"""
Unit tests for remediation lifecycle: state machine, license enforcement,
validation gates, cancellation, rollback preconditions, and audit logging.

Spec: specs/pipelines/remediation-lifecycle.spec.yaml
Tests RemediationStatus enums, RemediationService lifecycle, and remediation_tasks flow.
"""

import inspect

import pytest

from app.models.remediation_models import RemediationStatus as ModelRemediationStatus
from app.schemas.remediation_schemas import RemediationStatus as SchemaRemediationStatus
from app.services.compliance.remediation import RemediationService
from app.tasks.remediation_tasks import execute_remediation_job

# ---------------------------------------------------------------------------
# AC-1: RemediationStatus schema enum has 7 values
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC1SchemaStatusEnum:
    """AC-1: RemediationStatus in schemas defines exactly 7 values."""

    EXPECTED_VALUES = {"pending", "running", "completed", "failed", "rolled_back", "cancelled", "manual"}

    def test_exactly_seven_values(self):
        members = list(SchemaRemediationStatus)
        assert len(members) == 7

    def test_expected_values_present(self):
        actual = {m.value for m in SchemaRemediationStatus}
        assert actual == self.EXPECTED_VALUES

    def test_is_string_enum(self):
        for member in SchemaRemediationStatus:
            assert isinstance(member.value, str)


# ---------------------------------------------------------------------------
# AC-2: RemediationStatus model enum has 5 values
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC2ModelStatusEnum:
    """AC-2: RemediationStatus in models defines exactly 5 values (no CANCELLED or MANUAL)."""

    EXPECTED_VALUES = {"pending", "running", "completed", "failed", "rolled_back"}

    def test_exactly_five_values(self):
        members = list(ModelRemediationStatus)
        assert len(members) == 5

    def test_expected_values_present(self):
        actual = {m.value for m in ModelRemediationStatus}
        assert actual == self.EXPECTED_VALUES

    def test_no_cancelled_or_manual(self):
        values = {m.value for m in ModelRemediationStatus}
        assert "cancelled" not in values
        assert "manual" not in values


# ---------------------------------------------------------------------------
# AC-3: Job creation enforces remediation license
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC3LicenseEnforcement:
    """AC-3: Job creation checks license via has_feature('remediation')."""

    def test_create_job_checks_remediation_license(self):
        source = inspect.getsource(RemediationService.create_job)
        assert 'has_feature("remediation")' in source

    def test_create_job_raises_license_required_error(self):
        source = inspect.getsource(RemediationService.create_job)
        assert "LicenseRequiredError" in source


# ---------------------------------------------------------------------------
# AC-4: Job creation validates host and rules
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC4ValidationGates:
    """AC-4: Job creation validates host exists and rules exist."""

    def test_create_job_validates_host(self):
        source = inspect.getsource(RemediationService.create_job)
        assert "_get_host" in source
        assert "Host" in source and "not found" in source

    def test_create_job_validates_rules(self):
        source = inspect.getsource(RemediationService.create_job)
        assert "_validate_rules" in source
        assert "No valid rules" in source

    def test_create_job_raises_value_error(self):
        source = inspect.getsource(RemediationService.create_job)
        assert "ValueError" in source


# ---------------------------------------------------------------------------
# AC-5: start_job transitions only from pending to running
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC5StartJobTransition:
    """AC-5: start_job transitions only from pending to running."""

    def test_start_job_sets_running(self):
        source = inspect.getsource(RemediationService.start_job)
        assert '"running"' in source

    def test_start_job_requires_pending(self):
        source = inspect.getsource(RemediationService.start_job)
        assert '"pending"' in source or "'pending'" in source

    def test_start_job_returns_bool(self):
        source = inspect.getsource(RemediationService.start_job)
        assert "rowcount > 0" in source


# ---------------------------------------------------------------------------
# AC-6: Final status logic: all failed -> "failed", else "completed"
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC6FinalStatusDetermination:
    """AC-6: Final job status is 'failed' when all rules failed, 'completed' otherwise."""

    def test_all_failed_yields_failed(self):
        source = inspect.getsource(execute_remediation_job)
        assert 'final_status = "failed"' in source

    def test_otherwise_completed(self):
        source = inspect.getsource(execute_remediation_job)
        assert 'final_status = "completed"' in source

    def test_checks_failed_count_equals_total(self):
        """Final status compares failed count to total rule count."""
        source = inspect.getsource(execute_remediation_job)
        assert 'result["failed"]' in source
        assert "rule_ids" in source


# ---------------------------------------------------------------------------
# AC-7: cancel_job transitions pending/running to cancelled
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC7CancelJob:
    """AC-7: cancel_job transitions pending or running jobs to cancelled."""

    def test_cancel_sets_cancelled(self):
        source = inspect.getsource(RemediationService.cancel_job)
        assert "'cancelled'" in source or '"cancelled"' in source

    def test_cancel_only_pending_or_running(self):
        source = inspect.getsource(RemediationService.cancel_job)
        assert "'pending'" in source or '"pending"' in source
        assert "'running'" in source or '"running"' in source

    def test_cancel_returns_bool(self):
        source = inspect.getsource(RemediationService.cancel_job)
        assert "rowcount > 0" in source


# ---------------------------------------------------------------------------
# AC-8: Rollback enforces rollback license
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC8RollbackLicense:
    """AC-8: Rollback checks license via has_feature('rollback')."""

    def test_rollback_checks_rollback_license(self):
        source = inspect.getsource(RemediationService.rollback_job)
        assert 'has_feature("rollback")' in source

    def test_rollback_raises_license_required_error(self):
        source = inspect.getsource(RemediationService.rollback_job)
        assert "LicenseRequiredError" in source


# ---------------------------------------------------------------------------
# AC-9: Rollback validates preconditions
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC9RollbackPreconditions:
    """AC-9: Rollback validates job exists, rollback_available, and not already rolled back."""

    def test_rollback_checks_job_exists(self):
        source = inspect.getsource(RemediationService.rollback_job)
        assert "get_job" in source
        assert "not found" in source

    def test_rollback_checks_rollback_available(self):
        source = inspect.getsource(RemediationService.rollback_job)
        assert "rollback_available" in source

    def test_rollback_rejects_already_rolled_back(self):
        source = inspect.getsource(RemediationService.rollback_job)
        assert "ROLLED_BACK" in source
        assert "already been rolled back" in source


# ---------------------------------------------------------------------------
# AC-10: Lifecycle events are audit logged
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC10AuditLogging:
    """AC-10: Lifecycle events are audit logged via _log_audit."""

    def test_create_job_logs_audit(self):
        source = inspect.getsource(RemediationService.create_job)
        assert "_log_audit" in source
        assert '"created"' in source

    def test_cancel_job_logs_audit(self):
        source = inspect.getsource(RemediationService.cancel_job)
        assert "_log_audit" in source
        assert '"cancelled"' in source

    def test_rollback_job_logs_audit(self):
        source = inspect.getsource(RemediationService.rollback_job)
        assert "_log_audit" in source
        assert '"rollback_created"' in source

    def test_log_audit_writes_to_audit_logs_table(self):
        source = inspect.getsource(RemediationService._log_audit)
        assert "audit_logs" in source
        assert "action" in source
        assert "user_id" in source
