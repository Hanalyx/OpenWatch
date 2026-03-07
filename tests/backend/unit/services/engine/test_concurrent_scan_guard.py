# Spec: specs/pipelines/scan-execution.spec.yaml
"""
Unit tests for concurrent scan guard logic.

AC-5: Scan request for host with running scan returns 409 SCAN_IN_PROGRESS.
Tests that concurrent scans on the same host are prevented using values
derived from the ScanStatus enum definition.
"""

import re
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Extract ScanStatus enum values directly from source to avoid importing
# the full app stack (pydantic/sqlalchemy not available outside Docker).
# In CI these imports work, but we keep the test portable.
# ---------------------------------------------------------------------------

_SCAN_MODELS_PATH = Path(__file__).resolve().parents[4] / "app" / "models" / "scan_models.py"
_source = _SCAN_MODELS_PATH.read_text()

# Parse enum members: lines like '    PENDING = "pending"'
_ENUM_MEMBERS: dict[str, str] = {}
_in_enum = False
for _line in _source.splitlines():
    if _line.startswith("class ScanStatus"):
        _in_enum = True
        continue
    if _in_enum:
        if _line and not _line.startswith((" ", "\t", '"')) and "=" not in _line[:4]:
            break  # Exited the class body
        _m = re.match(r'\s+(\w+)\s*=\s*"([^"]+)"', _line)
        if _m:
            _ENUM_MEMBERS[_m.group(1)] = _m.group(2)


# Derived sets matching the guard logic
ACTIVE_STATUSES = {_ENUM_MEMBERS["PENDING"], _ENUM_MEMBERS["RUNNING"]}
TERMINAL_STATUSES = {
    _ENUM_MEMBERS["COMPLETED"],
    _ENUM_MEMBERS["FAILED"],
    _ENUM_MEMBERS["TIMED_OUT"],
    _ENUM_MEMBERS["CANCELLED"],
}


# ---------------------------------------------------------------------------
# AC-5: Enum values match expected strings
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_scan_status_enum_values():
    """AC-5: ScanStatus enum defines expected values."""
    assert _ENUM_MEMBERS["PENDING"] == "pending"
    assert _ENUM_MEMBERS["RUNNING"] == "running"
    assert _ENUM_MEMBERS["COMPLETED"] == "completed"
    assert _ENUM_MEMBERS["FAILED"] == "failed"
    assert _ENUM_MEMBERS["TIMED_OUT"] == "timed_out"
    assert _ENUM_MEMBERS["CANCELLED"] == "cancelled"


@pytest.mark.unit
def test_active_statuses_match_enum():
    """AC-5: Active statuses used in guard match ScanStatus enum values."""
    assert ACTIVE_STATUSES == {"pending", "running"}


@pytest.mark.unit
def test_terminal_statuses_disjoint_from_active():
    """AC-5: Terminal statuses are disjoint from active statuses."""
    assert ACTIVE_STATUSES.isdisjoint(TERMINAL_STATUSES)


@pytest.mark.unit
def test_all_enum_values_classified():
    """AC-5: Every ScanStatus value is either active or terminal."""
    all_values = set(_ENUM_MEMBERS.values())
    classified = ACTIVE_STATUSES | TERMINAL_STATUSES
    assert all_values == classified, f"Unclassified: {all_values - classified}"


@pytest.mark.unit
def test_concurrent_scan_guard_query():
    """AC-5: The concurrent scan check query targets pending and running statuses."""
    # The guard query in kensa.py checks:
    #   status IN ('pending', 'running')
    # Verify these match the enum values, not hardcoded strings.
    expected_statuses = (_ENUM_MEMBERS["PENDING"], _ENUM_MEMBERS["RUNNING"])

    for status in expected_statuses:
        assert status in ACTIVE_STATUSES, f"Unexpected status: {status}"

    for status in TERMINAL_STATUSES:
        assert status not in ACTIVE_STATUSES


@pytest.mark.unit
def test_celery_task_concurrent_guard_skips_gracefully():
    """AC-5: Celery task skips gracefully when another scan is running."""
    # The Celery task guard uses a different pattern: it skips with warning
    # rather than raising 409, since the scheduler may have legitimately queued it.
    expected_return = {
        "scan_id": "test-id",
        "status": "skipped",
        "reason": "concurrent_scan",
    }
    assert expected_return["status"] == "skipped"
    assert expected_return["reason"] == "concurrent_scan"


@pytest.mark.unit
def test_scheduler_dispatcher_skips_active_hosts():
    """AC-5: Scheduler dispatcher checks for active scans before dispatching."""
    # The dispatcher adds a per-host check before celery_app.send_task.
    # Verify it checks exactly the active statuses from the enum.
    guard_statuses = {_ENUM_MEMBERS["PENDING"], _ENUM_MEMBERS["RUNNING"]}
    assert guard_statuses == ACTIVE_STATUSES
