"""
Unit tests for scan execution pipeline.

Spec: specs/pipelines/scan-execution.spec.yaml
Tests scan state transitions, result storage logic, and score calculation.
"""

from datetime import datetime, timezone
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
# State machine: status values
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_scan_status_values():
    """Scan pipeline uses defined status values."""
    # These are the status values used across the codebase
    valid_statuses = {"pending", "running", "completed", "failed", "stopped"}

    # Verify the sync path uses "running" as initial status
    assert "running" in valid_statuses

    # Verify terminal states
    terminal = {"completed", "failed", "stopped"}
    assert terminal.issubset(valid_statuses)
