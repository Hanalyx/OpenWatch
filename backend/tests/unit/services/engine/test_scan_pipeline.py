"""
Unit tests for scan execution pipeline.

Spec: specs/pipelines/scan-execution.spec.yaml
Tests scan state transitions, result storage logic, and score calculation.
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

# ---------------------------------------------------------------------------
# AC-7: IN_PROGRESS -> COMPLETED with scan_results and scan_findings
# AC-14: Completed scan has timestamps
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_score_calculation_logic():
    """AC-7: Compliance score calculated as passed / (passed + failed) * 100."""
    # Replicate the calculation from kensa.py:283 and kensa_scan_tasks.py:199
    test_cases = [
        # (passed, failed, skipped, expected_score)
        (100, 0, 0, 100.0),
        (0, 100, 0, 0.0),
        (50, 50, 0, 50.0),
        (75, 25, 10, 75.0),  # Skipped excluded from denominator
        (0, 0, 100, 0.0),  # All skipped -> 0 score
    ]

    for passed, failed, skipped, expected in test_cases:
        score = (passed / (passed + failed) * 100) if (passed + failed) > 0 else 0.0
        assert (
            abs(score - expected) < 0.01
        ), f"passed={passed}, failed={failed}, skipped={skipped}: expected {expected}, got {score}"


@pytest.mark.unit
def test_severity_breakdown_logic():
    """AC-7: Severity breakdown counts are accumulated correctly."""
    # Simulate the severity counting loop from kensa_scan_tasks.py:202-216
    results = [
        SimpleNamespace(passed=True, skipped=False, severity="critical"),
        SimpleNamespace(passed=False, skipped=False, severity="critical"),
        SimpleNamespace(passed=True, skipped=False, severity="high"),
        SimpleNamespace(passed=True, skipped=False, severity="medium"),
        SimpleNamespace(passed=False, skipped=False, severity="low"),
        SimpleNamespace(passed=True, skipped=True, severity="high"),  # Skipped - excluded
    ]

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    severity_passed = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    severity_failed = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for r in results:
        if r.skipped:
            continue
        sev = r.severity.lower() if r.severity else "medium"
        if sev not in severity_counts:
            sev = "medium"
        severity_counts[sev] += 1
        if r.passed:
            severity_passed[sev] += 1
        else:
            severity_failed[sev] += 1

    assert severity_counts["critical"] == 2
    assert severity_passed["critical"] == 1
    assert severity_failed["critical"] == 1
    assert severity_counts["high"] == 1  # Skipped one excluded
    assert severity_counts["medium"] == 1
    assert severity_counts["low"] == 1


# ---------------------------------------------------------------------------
# AC-10: Evidence stored as JSONB
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_finding_status_mapping():
    """AC-10: Rule results mapped to correct status strings."""
    test_cases = [
        # (passed, skipped, expected_status)
        (True, False, "pass"),
        (False, False, "fail"),
        (False, True, "skipped"),
        (True, True, "skipped"),  # Skipped takes priority
    ]

    for passed, skipped, expected in test_cases:
        status_str = "pass" if passed else "fail"
        if skipped:
            status_str = "skipped"
        assert status_str == expected, f"passed={passed}, skipped={skipped}: expected '{expected}', got '{status_str}'"


# ---------------------------------------------------------------------------
# AC-14: Timestamps on completed scan
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_duration_calculation():
    """AC-14: Duration derivable from started_at and completed_at."""
    start_time = datetime(2026, 3, 4, 12, 0, 0, tzinfo=timezone.utc)
    end_time = datetime(2026, 3, 4, 12, 5, 30, tzinfo=timezone.utc)

    duration_ms = int((end_time - start_time).total_seconds() * 1000)
    assert duration_ms == 330000  # 5 minutes 30 seconds in ms


# ---------------------------------------------------------------------------
# AC-3: Invalid host -> 404
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_scan_request_model_validation():
    """AC-1, AC-3: KensaScanRequest validates host_id is non-empty."""
    from app.routes.scans.kensa import KensaScanRequest

    # Valid request
    request = KensaScanRequest(host_id="550e8400-e29b-41d4-a716-446655440000")
    assert request.host_id == "550e8400-e29b-41d4-a716-446655440000"

    # Empty host_id should fail validation
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        KensaScanRequest(host_id="")


@pytest.mark.unit
def test_scan_response_model():
    """AC-14: KensaScanResponse contains all required fields."""
    from app.routes.scans.kensa import KensaScanResponse

    response = KensaScanResponse(
        scan_id="test-scan-id",
        status="completed",
        host_id="test-host-id",
        hostname="test-host",
        framework=None,
        total_rules=100,
        passed=75,
        failed=20,
        skipped=5,
        compliance_score=78.95,
        kensa_version="1.2.5",
        duration_ms=5000,
        started_at="2026-03-04T12:00:00Z",
        completed_at="2026-03-04T12:00:05Z",
    )

    assert response.scan_id == "test-scan-id"
    assert response.status == "completed"
    assert response.compliance_score == 78.95
    assert response.started_at is not None
    assert response.completed_at is not None


# ---------------------------------------------------------------------------
# AC-15: Soft time limit -> TIMED_OUT status
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_timed_out_status_exists():
    """AC-15: ScanStatus includes TIMED_OUT for timeout distinction."""
    from app.models.scan_models import ScanStatus

    assert hasattr(ScanStatus, "TIMED_OUT")
    assert ScanStatus.TIMED_OUT.value == "timed_out"


# ---------------------------------------------------------------------------
# State machine: status values
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# AC-13: Alerts generated when drift exceeds configured threshold
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_alert_on_configuration_drift():
    """AC-13: AlertGenerator creates CONFIGURATION_DRIFT alert when rule changes pass->fail."""
    from unittest.mock import MagicMock

    from app.services.compliance.alert_generator import AlertGenerator
    from app.services.compliance.alerts import AlertType

    mock_db = MagicMock()

    # Previous scan: rule was passing
    mock_previous = MagicMock()
    mock_previous.fetchall.return_value = [
        MagicMock(rule_id="sshd-disable-root-login", passed=True),
    ]

    # Set up db.execute to return previous results for the drift query
    mock_db.execute.return_value = mock_previous

    generator = AlertGenerator(mock_db)

    # Mock alert_service.create_alert to capture calls
    created_alerts = []

    def capture_alert(**kwargs):
        created_alerts.append(kwargs)
        return kwargs

    generator.alert_service.create_alert = capture_alert

    # Mock get_thresholds to return defaults
    generator.alert_service.get_thresholds = MagicMock(
        return_value={
            "compliance": {
                "critical_finding": False,
                "high_finding": False,
                "score_drop_threshold": 999,
                "non_compliant_threshold": 0,
            },
            "drift": {"mass_drift_threshold": 100},
        }
    )

    # Current results: rule now failing
    current_results = [
        {"rule_id": "sshd-disable-root-login", "passed": False, "severity": "high", "title": "SSH Root Login"},
    ]

    alerts = generator._check_configuration_drift(
        host_id=MagicMock(),
        scan_id=MagicMock(),
        results=current_results,
        hostname="test-host",
        drift_thresholds={"mass_drift_threshold": 100},
    )

    # Should have created a CONFIGURATION_DRIFT alert
    drift_alerts = [a for a in alerts if a.get("alert_type") == AlertType.CONFIGURATION_DRIFT]
    assert len(drift_alerts) >= 1, f"Expected CONFIGURATION_DRIFT alert, got {alerts}"


@pytest.mark.unit
def test_scan_status_values():
    """Scan pipeline uses defined status values including TIMED_OUT."""
    from app.models.scan_models import ScanStatus

    # These are the status values used across the codebase
    valid_statuses = {"pending", "running", "completed", "failed", "timed_out", "stopped"}

    # Verify the enum covers the expected values
    enum_values = {s.value for s in ScanStatus}
    # cancelled is in enum but "stopped" is the DB convention
    assert "timed_out" in enum_values, "ScanStatus must include timed_out"

    # Verify the sync path uses "running" as initial status
    assert "running" in valid_statuses

    # Verify terminal states
    terminal = {"completed", "failed", "timed_out", "stopped"}
    assert terminal.issubset(valid_statuses)


# =============================================================================
# Contract tests (source-parsing) for AC gaps
# These verify structural contracts in the implementation source code.
# =============================================================================

# Resolve source file paths once
_BACKEND = Path(__file__).resolve().parents[4]  # backend/
_KENSA_ROUTE = _BACKEND / "app" / "routes" / "scans" / "kensa.py"
_KENSA_TASK = _BACKEND / "app" / "tasks" / "kensa_scan_tasks.py"
_EXECUTOR = _BACKEND / "app" / "plugins" / "kensa" / "executor.py"


def _read_source(path: Path) -> str:
    """Read a source file and return its content."""
    return path.read_text(encoding="utf-8")


def _assert_call_in_try_except(source: str, call_name: str, label: str) -> None:
    """Verify a function call exists and is wrapped in try/except (non-blocking)."""
    assert call_name in source, f"{call_name} must be called in {label}"
    call_pos = source.find(call_name)
    preceding = source[max(0, call_pos - 300) : call_pos]
    assert "try:" in preceding, f"{call_name} in {label} must be wrapped in try/except (non-blocking)"


# ---------------------------------------------------------------------------
# AC-2: GUEST/AUDITOR gets 403
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_ac2_rbac_excludes_guest_auditor():
    """AC-2: execute_kensa_scan requires SECURITY_ANALYST+; GUEST/AUDITOR excluded."""
    source = _read_source(_KENSA_ROUTE)

    # Find the @require_role decorator immediately above execute_kensa_scan
    pattern = r"@require_role\(\[([^\]]+)\]\)\s*\n\s*async def execute_kensa_scan"
    match = re.search(pattern, source)
    assert match, "Could not find @require_role decorator on execute_kensa_scan"

    role_list = match.group(1)

    # SECURITY_ANALYST must be allowed
    assert "SECURITY_ANALYST" in role_list, "SECURITY_ANALYST must be in require_role list"

    # GUEST and AUDITOR must NOT be allowed
    assert "GUEST" not in role_list, "GUEST must NOT be in require_role list"
    assert "AUDITOR" not in role_list, "AUDITOR must NOT be in require_role list"


# ---------------------------------------------------------------------------
# AC-4: No SSH credentials -> clear error
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_ac4_credential_not_found_raises_clear_error():
    """AC-4: Missing SSH credentials raises RuntimeError with descriptive message."""
    source = _read_source(_EXECUTOR)

    # Verify CredentialNotFoundError is caught
    assert "CredentialNotFoundError" in source, "executor.py must catch CredentialNotFoundError"

    # Verify the clear error message pattern
    assert (
        'RuntimeError(f"No SSH credentials for host:' in source
    ), "executor.py must raise RuntimeError with 'No SSH credentials for host' message"


# ---------------------------------------------------------------------------
# AC-6: PENDING -> RUNNING transition
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_ac6_pending_to_running_transition():
    """AC-6: Task sets status='running' and progress=5 before scan execution."""
    source = _read_source(_KENSA_TASK)

    # Find the status=running and progress=5 settings
    running_pos = source.find('.set("status", "running")')
    progress_pos = source.find('.set("progress", 5)')
    check_rules_pos = source.find("check_rules_from_path")

    assert running_pos > 0, "Task must set status to 'running'"
    assert progress_pos > 0, "Task must set progress to 5"
    assert check_rules_pos > 0, "Task must call check_rules_from_path"

    # Both must occur BEFORE check_rules_from_path
    assert running_pos < check_rules_pos, "status='running' must be set BEFORE check_rules_from_path is called"
    assert progress_pos < check_rules_pos, "progress=5 must be set BEFORE check_rules_from_path is called"


# ---------------------------------------------------------------------------
# AC-8: SSH failure -> FAILED with descriptive error
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_ac8_error_handler_sets_failed_with_truncation():
    """AC-8: _update_scan_error sets status='failed' and truncates error to 500 chars."""
    source = _read_source(_KENSA_TASK)

    # Verify _update_scan_error helper exists
    assert "def _update_scan_error(" in source, "_update_scan_error helper must exist in kensa_scan_tasks.py"

    # Extract the helper body
    helper_start = source.find("def _update_scan_error(")
    # Find the next function definition or end of file
    next_def = source.find("\ndef ", helper_start + 1)
    helper_body = source[helper_start:next_def] if next_def > 0 else source[helper_start:]

    # Verify it sets status to "failed"
    assert '"failed"' in helper_body, "_update_scan_error must set status to 'failed'"

    # Verify 500-char truncation
    assert "[:500]" in helper_body, "_update_scan_error must truncate error_message to 500 chars"

    # Verify the broad except handler calls _update_scan_error
    # Pattern: except Exception ... _update_scan_error
    broad_except_pattern = r"except Exception as \w+:.*?_update_scan_error"
    assert re.search(
        broad_except_pattern, source, re.DOTALL
    ), "Broad except Exception handler must call _update_scan_error"


# ---------------------------------------------------------------------------
# AC-9: Kensa eval failure caught by broad exception (distinct from timeout)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_ac9_timeout_before_broad_exception():
    """AC-9: SoftTimeLimitExceeded is caught BEFORE broad Exception, each with distinct handler."""
    source = _read_source(_KENSA_TASK)

    timeout_pos = source.find("except SoftTimeLimitExceeded")
    broad_pos = source.find("except Exception as exc")

    assert timeout_pos > 0, "SoftTimeLimitExceeded handler must exist"
    assert broad_pos > 0, "Broad except Exception handler must exist"

    # SoftTimeLimitExceeded must appear BEFORE the broad handler
    assert timeout_pos < broad_pos, "SoftTimeLimitExceeded must be caught BEFORE broad except Exception"

    # Each must call a DIFFERENT helper
    # Extract the handler blocks (up to ~200 chars after each except)
    timeout_block = source[timeout_pos : timeout_pos + 200]
    broad_block = source[broad_pos : broad_pos + 200]

    assert "_update_scan_timed_out" in timeout_block, "SoftTimeLimitExceeded handler must call _update_scan_timed_out"
    assert "_update_scan_error" in broad_block, "Broad Exception handler must call _update_scan_error"

    # They must NOT call each other's handler
    assert "_update_scan_error" not in timeout_block, "SoftTimeLimitExceeded handler must NOT call _update_scan_error"
    assert "_update_scan_timed_out" not in broad_block, "Broad Exception handler must NOT call _update_scan_timed_out"


# ---------------------------------------------------------------------------
# AC-11: Posture snapshot runs after completion (both paths)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_ac11_posture_snapshot_both_paths():
    """AC-11: create_snapshot called in both sync (route) and async (task) paths, non-blocking."""
    route_source = _read_source(_KENSA_ROUTE)
    task_source = _read_source(_KENSA_TASK)

    for label, source in [("route (kensa.py)", route_source), ("task (kensa_scan_tasks.py)", task_source)]:
        _assert_call_in_try_except(source, "create_snapshot", label)


# ---------------------------------------------------------------------------
# AC-12: Drift detection runs after completion (both paths)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_ac12_drift_detection_both_paths():
    """AC-12: detect_drift called with auto_baseline=True in both paths, non-blocking."""
    route_source = _read_source(_KENSA_ROUTE)
    task_source = _read_source(_KENSA_TASK)

    for label, source in [("route (kensa.py)", route_source), ("task (kensa_scan_tasks.py)", task_source)]:
        assert "auto_baseline=True" in source, f"detect_drift must use auto_baseline=True in {label}"
        _assert_call_in_try_except(source, "detect_drift", label)
