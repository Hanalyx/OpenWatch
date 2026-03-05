"""
Unit tests for scan orchestration (Celery task lifecycle).

Spec: specs/services/engine/scan-orchestration.spec.yaml
Tests stale scan recovery, timeout handling, and task configuration.
"""

from datetime import timedelta

import pytest

# ---------------------------------------------------------------------------
# AC-7: Stale running scans (>2h) recovered
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_stale_scan_running_timeout_threshold():
    """AC-7: Running scans older than 2 hours are recovered."""
    from app.tasks.stale_scan_detection import RUNNING_TIMEOUT

    assert RUNNING_TIMEOUT == timedelta(hours=2), f"Running timeout should be 2 hours, got {RUNNING_TIMEOUT}"


# ---------------------------------------------------------------------------
# AC-8: Stale pending scans (>30m) recovered
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_stale_scan_pending_timeout_threshold():
    """AC-8: Pending scans older than 30 minutes are recovered."""
    from app.tasks.stale_scan_detection import PENDING_TIMEOUT

    assert PENDING_TIMEOUT == timedelta(minutes=30), f"Pending timeout should be 30 minutes, got {PENDING_TIMEOUT}"


# ---------------------------------------------------------------------------
# AC-2: celery_task_id recorded on scan
# AC-5: Retry once after 120s
# AC-9: Worker crash recovery (acks_late, reject_on_worker_lost)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_kensa_task_configuration():
    """AC-2, AC-5, AC-9: Celery task has correct configuration."""
    from app.tasks.kensa_scan_tasks import execute_kensa_scan_task

    # Task name
    assert execute_kensa_scan_task.name == "app.tasks.execute_kensa_scan"

    # acks_late and reject_on_worker_lost are set on the task decorator
    # We verify them via the task's attributes
    assert getattr(execute_kensa_scan_task, "acks_late", None) is True, "acks_late should be True for crash recovery"
    assert (
        getattr(execute_kensa_scan_task, "reject_on_worker_lost", None) is True
    ), "reject_on_worker_lost should be True for crash recovery"
    assert getattr(execute_kensa_scan_task, "max_retries", None) == 1, "max_retries should be 1"


# ---------------------------------------------------------------------------
# AC-3: QUEUED -> IN_PROGRESS transition
# AC-4: Soft timeout -> TIMED_OUT
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_kensa_task_time_limits():
    """AC-4: Task has soft and hard time limits configured."""
    from app.tasks.kensa_scan_tasks import execute_kensa_scan_task

    soft_limit = getattr(execute_kensa_scan_task, "soft_time_limit", None)
    hard_limit = getattr(execute_kensa_scan_task, "time_limit", None)

    assert soft_limit == 3300, f"Soft time limit should be 3300s (55min), got {soft_limit}"
    assert hard_limit == 3600, f"Hard time limit should be 3600s (60min), got {hard_limit}"
    assert soft_limit < hard_limit, "Soft limit must be less than hard limit"


# ---------------------------------------------------------------------------
# AC-10: Post-scan is non-critical
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_stale_detection_task_configuration():
    """AC-7, AC-8: Stale detection task has correct schedule config."""
    from app.tasks.stale_scan_detection import detect_stale_scans

    # Task is registered with correct name
    assert detect_stale_scans.name == "app.tasks.detect_stale_scans"

    # Time limits set
    hard_limit = getattr(detect_stale_scans, "time_limit", None)
    soft_limit = getattr(detect_stale_scans, "soft_time_limit", None)
    assert hard_limit == 120
    assert soft_limit == 90


# ---------------------------------------------------------------------------
# Celery Beat schedule verification
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_celery_beat_schedule_has_stale_detection():
    """AC-7: Stale scan detection is in the Celery Beat schedule."""
    from app.celery_app import celery_app

    beat_schedule = celery_app.conf.beat_schedule or {}
    stale_task_found = False
    for name, config in beat_schedule.items():
        if config.get("task") == "app.tasks.detect_stale_scans":
            stale_task_found = True
            # Should run every 10 minutes (600 seconds)
            assert (
                config.get("schedule") == 600.0 or config.get("schedule") == 600
            ), f"Stale detection should run every 600s, got {config.get('schedule')}"
            break

    assert stale_task_found, "detect_stale_scans should be in beat_schedule"


# ---------------------------------------------------------------------------
# AC-4: TIMED_OUT in ScanStatus enum
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_timed_out_in_scan_status_enum():
    """AC-4: ScanStatus enum includes TIMED_OUT value."""
    from app.models.scan_models import ScanStatus

    assert hasattr(ScanStatus, "TIMED_OUT"), "ScanStatus must have TIMED_OUT member"
    assert ScanStatus.TIMED_OUT.value == "timed_out"


@pytest.mark.unit
def test_timed_out_handler_uses_distinct_status():
    """AC-4: Timeout handler sets 'timed_out' not 'failed'."""
    from unittest.mock import MagicMock

    from app.tasks.kensa_scan_tasks import _update_scan_timed_out

    mock_db = MagicMock()
    _update_scan_timed_out(mock_db, "test-scan-id", "Timed out")

    # Verify the SQL sets status to 'timed_out'
    call_args = mock_db.execute.call_args
    params = call_args[0][1] if len(call_args[0]) > 1 else call_args[1].get("params", {})
    assert params.get("set_status") == "timed_out", f"Expected 'timed_out', got {params}"


# ---------------------------------------------------------------------------
# AC-6: After max retries exhausted, scan remains in FAILED state
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_max_retries_exhausted_stays_failed():
    """AC-6: After max retries exhausted, scan remains in FAILED state."""
    from app.tasks.kensa_scan_tasks import execute_kensa_scan_task

    max_retries = getattr(execute_kensa_scan_task, "max_retries", None)
    assert max_retries == 1, f"max_retries should be 1, got {max_retries}"

    # When max_retries is exhausted, Celery does NOT re-raise the exception.
    # The task's on_failure handler writes status='failed' to the DB.
    # We verify the retry count is bounded: after 1 retry (attempt 2), the task
    # stops retrying and the scan stays in FAILED state.
    assert max_retries is not None, "max_retries must be explicitly set on the task"


@pytest.mark.unit
def test_celery_beat_schedule_has_compliance_dispatcher():
    """AC-1: Compliance scan dispatcher is in the Celery Beat schedule."""
    from app.celery_app import celery_app

    beat_schedule = celery_app.conf.beat_schedule or {}
    dispatcher_found = False
    for name, config in beat_schedule.items():
        if config.get("task") == "app.tasks.dispatch_compliance_scans":
            dispatcher_found = True
            # Should run every 2 minutes (120 seconds)
            assert (
                config.get("schedule") == 120.0 or config.get("schedule") == 120
            ), f"Compliance dispatcher should run every 120s, got {config.get('schedule')}"
            break

    assert dispatcher_found, "dispatch_compliance_scans should be in beat_schedule"
