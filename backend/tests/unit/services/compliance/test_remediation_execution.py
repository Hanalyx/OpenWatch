"""
Unit tests for remediation execution: Celery task configuration, shared SSH
session, rule loading, status determination, pre-state capture, step storage,
rollback reconstruction, progress tracking, and idempotent design.

Spec: specs/services/remediation/remediation-execution.spec.yaml
Tests remediation_tasks.py execution mechanics and RemediationService tracking.
"""

import inspect

import pytest

from app.services.compliance.remediation import RemediationService
from app.tasks.remediation_tasks import (
    _execute_rule_remediation,
    _execute_rule_rollback,
    _load_and_resolve_rules,
    _run_remediation,
    _run_rollback,
    execute_remediation_job,
    execute_rollback_job,
)

# ---------------------------------------------------------------------------
# AC-1: execute_remediation_job Celery task config
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC1RemediationTaskConfig:
    """AC-1: execute_remediation_job is Celery shared_task with max_retries=3, delay=60."""

    def test_is_celery_task(self):
        assert hasattr(execute_remediation_job, "delay")
        assert hasattr(execute_remediation_job, "apply_async")

    def test_max_retries_3(self):
        assert execute_remediation_job.max_retries == 3

    def test_default_retry_delay_60(self):
        assert execute_remediation_job.default_retry_delay == 60

    def test_task_name(self):
        assert execute_remediation_job.name == "app.tasks.execute_remediation"


# ---------------------------------------------------------------------------
# AC-2: execute_rollback_job Celery task config
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC2RollbackTaskConfig:
    """AC-2: execute_rollback_job is Celery shared_task with max_retries=2, delay=30."""

    def test_is_celery_task(self):
        assert hasattr(execute_rollback_job, "delay")
        assert hasattr(execute_rollback_job, "apply_async")

    def test_max_retries_2(self):
        assert execute_rollback_job.max_retries == 2

    def test_default_retry_delay_30(self):
        assert execute_rollback_job.default_retry_delay == 30

    def test_task_name(self):
        assert execute_rollback_job.name == "app.tasks.execute_rollback"


# ---------------------------------------------------------------------------
# AC-3: Single SSH session per host
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC3SharedSSHSession:
    """AC-3: Execution uses a single SSH session per host via KensaSessionFactory."""

    def test_run_remediation_uses_factory(self):
        source = inspect.getsource(_run_remediation)
        assert "KensaSessionFactory" in source

    def test_run_remediation_uses_context_manager(self):
        """Session created via async context manager (single session for all rules)."""
        source = inspect.getsource(_run_remediation)
        assert "async with factory.create_session" in source

    def test_run_rollback_uses_shared_session(self):
        source = inspect.getsource(_run_rollback)
        assert "async with factory.create_session" in source


# ---------------------------------------------------------------------------
# AC-4: Rules loaded and variable-resolved before execution
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC4RuleLoadingAndResolution:
    """AC-4: Rules loaded via _load_and_resolve_rules before execution."""

    def test_load_and_resolve_calls_load_rules(self):
        source = inspect.getsource(_load_and_resolve_rules)
        assert "load_rules" in source

    def test_load_and_resolve_calls_load_config(self):
        source = inspect.getsource(_load_and_resolve_rules)
        assert "load_config" in source

    def test_load_and_resolve_calls_resolve_variables(self):
        source = inspect.getsource(_load_and_resolve_rules)
        assert "resolve_variables" in source

    def test_run_remediation_builds_rule_map(self):
        """Rules indexed by ID for O(1) lookup during execution."""
        source = inspect.getsource(_run_remediation)
        assert "rule_map" in source
        assert "_load_and_resolve_rules" in source or "rules_path" in source


# ---------------------------------------------------------------------------
# AC-5: Rule status determined by step outcomes
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC5RuleStatusDetermination:
    """AC-5: Rule status: any_failed->'failed', any_manual->'manual', else 'completed'."""

    def test_any_failed_yields_failed(self):
        source = inspect.getsource(_execute_rule_remediation)
        assert "any_failed" in source
        assert 'rule_status = "failed"' in source

    def test_any_manual_yields_manual(self):
        source = inspect.getsource(_execute_rule_remediation)
        assert "any_manual" in source
        assert 'rule_status = "manual"' in source

    def test_remediated_or_dry_run_yields_completed(self):
        source = inspect.getsource(_execute_rule_remediation)
        assert "result.remediated" in source
        assert "dry_run" in source
        assert 'rule_status = "completed"' in source

    def test_manual_check_uses_mechanism(self):
        """Manual steps identified by mechanism == 'manual'."""
        source = inspect.getsource(_execute_rule_remediation)
        assert 'mechanism == "manual"' in source or "mechanism ==" in source


# ---------------------------------------------------------------------------
# AC-6: Pre-state captured for rollback
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC6PreStateCapture:
    """AC-6: Pre-state captured when step.pre_state.capturable is True."""

    def test_checks_pre_state_capturable(self):
        source = inspect.getsource(_execute_rule_remediation)
        assert "pre_state" in source
        assert "capturable" in source

    def test_pre_state_stores_step_data(self):
        """Pre-state dict includes step_index, mechanism, data, capturable."""
        source = inspect.getsource(_execute_rule_remediation)
        assert '"step_index"' in source
        assert '"mechanism"' in source
        assert '"data"' in source
        assert '"capturable"' in source

    def test_rollback_available_flag(self):
        """has_rollback set when capturable pre-state exists."""
        source = inspect.getsource(_execute_rule_remediation)
        assert "has_rollback" in source


# ---------------------------------------------------------------------------
# AC-7: Step results stored with required fields
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC7StepResultStorage:
    """AC-7: Step results stored via add_step_result with required fields."""

    def test_add_step_result_called(self):
        source = inspect.getsource(_execute_rule_remediation)
        assert "add_step_result" in source

    def test_add_step_result_has_required_params(self):
        """add_step_result accepts mechanism, success, detail, pre_state_data, verified, risk_level."""
        sig = inspect.signature(RemediationService.add_step_result)
        param_names = set(sig.parameters.keys())
        required = {"mechanism", "success", "detail", "pre_state_data", "verified", "risk_level"}
        assert required.issubset(param_names), f"Missing params: {required - param_names}"

    def test_step_result_includes_verify_detail(self):
        sig = inspect.signature(RemediationService.add_step_result)
        assert "verify_detail" in sig.parameters

    def test_step_result_includes_pre_state_capturable(self):
        sig = inspect.signature(RemediationService.add_step_result)
        assert "pre_state_capturable" in sig.parameters


# ---------------------------------------------------------------------------
# AC-8: Rollback reconstructs RemediationStepRecord from pre-state
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC8RollbackReconstruction:
    """AC-8: Rollback reconstructs RemediationStepRecord from stored pre-state."""

    def test_imports_remediation_step_record(self):
        source = inspect.getsource(_execute_rule_rollback)
        assert "RemediationStepRecord" in source

    def test_imports_rollback_from_stored(self):
        source = inspect.getsource(_execute_rule_rollback)
        assert "rollback_from_stored" in source

    def test_reconstructs_step_records(self):
        """Step records built from pre_state['steps'] list."""
        source = inspect.getsource(_execute_rule_rollback)
        assert 'pre_state.get("steps"' in source
        assert "RemediationStepRecord(" in source

    def test_calls_rollback_from_stored(self):
        source = inspect.getsource(_execute_rule_rollback)
        assert "rollback_from_stored(ssh, step_records)" in source


# ---------------------------------------------------------------------------
# AC-9: Progress updated after each rule
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC9ProgressTracking:
    """AC-9: Progress updated after each rule via update_job_progress."""

    def test_remediation_updates_progress(self):
        source = inspect.getsource(_run_remediation)
        assert "update_job_progress" in source

    def test_rollback_updates_progress(self):
        source = inspect.getsource(_run_rollback)
        assert "update_job_progress" in source

    def test_progress_tracks_three_counters(self):
        """update_job_progress accepts completed, failed, skipped."""
        sig = inspect.signature(RemediationService.update_job_progress)
        param_names = set(sig.parameters.keys())
        assert {"completed", "failed", "skipped"}.issubset(param_names)


# ---------------------------------------------------------------------------
# AC-10: Idempotent: passed=True yields "completed"
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC10IdempotentDesign:
    """AC-10: Already-passing rules (passed=True, remediated=False) return 'completed'."""

    def test_checks_passed_attribute(self):
        source = inspect.getsource(_execute_rule_remediation)
        assert "passed" in source

    def test_passed_yields_completed(self):
        """When result.passed is True, rule_status is 'completed'."""
        source = inspect.getsource(_execute_rule_remediation)
        assert 'getattr(result, "passed", False)' in source
        # After this check, rule_status = "completed" (may be after multi-line comment)
        lines = source.split("\n")
        for i, line in enumerate(lines):
            if "passed" in line and "getattr" in line:
                for j in range(i + 1, min(i + 10, len(lines))):
                    if 'rule_status = "completed"' in lines[j]:
                        return
        pytest.fail("passed=True should lead to rule_status='completed'")

    def test_idempotent_comment_present(self):
        """Source documents the idempotent check-before-fix pattern."""
        source = inspect.getsource(_execute_rule_remediation)
        assert "idempotent" in source.lower()
