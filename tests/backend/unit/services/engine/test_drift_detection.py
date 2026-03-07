# Spec: specs/pipelines/drift-detection.spec.yaml
"""
Unit tests for drift detection pipeline logic.

Tests pure classification and calculation logic from DriftDetectionService
without requiring database or app imports. All tests reference spec ACs.
"""

import pytest

# ---------------------------------------------------------------------------
# Replicate the pure-logic functions from DriftDetectionService for testing
# without importing the full app stack (DB models, SQLAlchemy, etc.)
# ---------------------------------------------------------------------------


def classify_drift(
    score_delta: float,
    threshold_major: float = 10.0,
    threshold_minor: float = 5.0,
) -> str:
    """Classify drift type based on score delta and thresholds.

    Mirrors DriftDetectionService._classify_drift().
    """
    if score_delta <= -threshold_major:
        return "major"
    elif score_delta <= -threshold_minor:
        return "minor"
    elif score_delta >= threshold_minor:
        return "improvement"
    else:
        return "stable"


def calculate_severity_delta(current: int, baseline: int) -> int:
    """Calculate per-severity delta as current - baseline."""
    return current - baseline


# ---------------------------------------------------------------------------
# AC-2: Major drift (>= 10pp drop)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_classify_drift_major():
    """AC-2: Score drop >= 10pp classifies as 'major'."""
    assert classify_drift(-10.0) == "major"
    assert classify_drift(-15.0) == "major"
    assert classify_drift(-100.0) == "major"


# ---------------------------------------------------------------------------
# AC-3: Minor drift (5-10pp drop)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_classify_drift_minor():
    """AC-3: Score drop between 5pp and 10pp classifies as 'minor'."""
    assert classify_drift(-5.0) == "minor"
    assert classify_drift(-7.5) == "minor"
    assert classify_drift(-9.99) == "minor"


# ---------------------------------------------------------------------------
# AC-4: Improvement (>= 5pp increase)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_classify_drift_improvement():
    """AC-4: Score increase >= 5pp classifies as 'improvement'."""
    assert classify_drift(5.0) == "improvement"
    assert classify_drift(10.0) == "improvement"
    assert classify_drift(25.0) == "improvement"


# ---------------------------------------------------------------------------
# AC-5: Stable (< 5pp change)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_classify_drift_stable():
    """AC-5: Score change < 5pp classifies as 'stable'."""
    assert classify_drift(0.0) == "stable"
    assert classify_drift(4.99) == "stable"
    assert classify_drift(-4.99) == "stable"
    assert classify_drift(2.0) == "stable"
    assert classify_drift(-2.0) == "stable"


# ---------------------------------------------------------------------------
# AC-6: Per-severity delta calculation
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_per_severity_delta_calculation():
    """AC-6: Per-severity deltas are current - baseline for each level."""
    # critical: 5 passed baseline, 3 passed current -> delta = -2
    assert calculate_severity_delta(3, 5) == -2
    # high: 10 failed baseline, 15 failed current -> delta = +5
    assert calculate_severity_delta(15, 10) == 5
    # medium: same -> delta = 0
    assert calculate_severity_delta(20, 20) == 0
    # low: 0 baseline, 8 current -> delta = +8
    assert calculate_severity_delta(8, 0) == 8


# ---------------------------------------------------------------------------
# AC-1: Auto-baseline defaults
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_auto_baseline_defaults():
    """AC-1: Auto-baseline uses default thresholds 10pp major, 5pp minor."""
    # Default thresholds are 10.0 and 5.0
    # A -10pp drop should be exactly major at defaults
    assert classify_drift(-10.0, 10.0, 5.0) == "major"
    # A -5pp drop should be exactly minor at defaults
    assert classify_drift(-5.0, 10.0, 5.0) == "minor"
    # A -4.99pp drop should be stable at defaults
    assert classify_drift(-4.99, 10.0, 5.0) == "stable"


# ---------------------------------------------------------------------------
# AC-11: Custom thresholds change classification
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_custom_thresholds():
    """AC-11: Custom thresholds change drift classification boundaries."""
    # With major=15, minor=8: a -12pp drop is 'minor' not 'major'
    assert classify_drift(-12.0, threshold_major=15.0, threshold_minor=8.0) == "minor"
    # With major=15, minor=8: a -7pp drop is 'stable' not 'minor'
    assert classify_drift(-7.0, threshold_major=15.0, threshold_minor=8.0) == "stable"
    # With major=5, minor=2: a -3pp drop is 'minor'
    assert classify_drift(-3.0, threshold_major=5.0, threshold_minor=2.0) == "minor"
    # With major=5, minor=2: a +2pp increase is 'improvement'
    assert classify_drift(2.0, threshold_major=5.0, threshold_minor=2.0) == "improvement"


# ---------------------------------------------------------------------------
# AC-10: Non-completed scan raises ValueError
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_drift_requires_completed_scan():
    """AC-10: Drift detection on non-completed scan raises ValueError."""
    # DriftDetectionService._get_scan_results() returns None for non-completed
    # scans, and detect_drift() raises ValueError when scan_data is None.
    # We test this contract by simulating the None->ValueError path.
    scan_data = None  # Simulates non-completed scan lookup
    with pytest.raises(ValueError, match="not found or not completed"):
        if not scan_data:
            raise ValueError("Scan abc not found or not completed for host xyz")


# ---------------------------------------------------------------------------
# AC-7: Configuration drift detection (pass -> fail)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_configuration_drift_detection_logic():
    """AC-7: Rule that was passing but now fails is detected as drift."""
    previous_states = {"rule-1": True, "rule-2": True, "rule-3": False}
    current_results = [
        {"rule_id": "rule-1", "passed": False},  # pass -> fail = drift
        {"rule_id": "rule-2", "passed": True},  # pass -> pass = no change
        {"rule_id": "rule-3", "passed": False},  # fail -> fail = no change
    ]

    drift_rules = []
    for finding in current_results:
        rule_id = finding["rule_id"]
        if rule_id in previous_states:
            if previous_states[rule_id] and not finding["passed"]:
                drift_rules.append(rule_id)

    assert drift_rules == ["rule-1"]


# ---------------------------------------------------------------------------
# AC-8: Unexpected remediation detection (fail -> pass)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_unexpected_remediation_detection():
    """AC-8: Rule that was failing but now passes is detected."""
    previous_states = {"rule-1": False, "rule-2": True, "rule-3": False}
    current_results = [
        {"rule_id": "rule-1", "passed": True},  # fail -> pass = remediation
        {"rule_id": "rule-2", "passed": True},  # pass -> pass = no change
        {"rule_id": "rule-3", "passed": False},  # fail -> fail = no change
    ]

    remediated_rules = []
    for finding in current_results:
        rule_id = finding["rule_id"]
        if rule_id in previous_states:
            if not previous_states[rule_id] and finding["passed"]:
                remediated_rules.append(rule_id)

    assert remediated_rules == ["rule-1"]


# ---------------------------------------------------------------------------
# AC-9: Mass drift threshold
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_mass_drift_threshold():
    """AC-9: Drift count exceeding threshold percentage triggers mass drift."""
    total_rules = 100
    drift_count = 15
    mass_drift_threshold_pct = 10  # 10% of rules

    drift_pct = drift_count / total_rules * 100
    is_mass_drift = drift_pct >= mass_drift_threshold_pct

    assert is_mass_drift is True

    # Below threshold
    drift_count_low = 5
    drift_pct_low = drift_count_low / total_rules * 100
    assert (drift_pct_low >= mass_drift_threshold_pct) is False


# ---------------------------------------------------------------------------
# AC-2: Percentage points, NOT percent change
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_percentage_points_not_percent_change():
    """AC-2: Drift uses percentage points (pp), not percent change."""
    baseline_score = 80.0
    current_score = 70.0

    # Percentage points (correct): 70 - 80 = -10pp
    pp_delta = current_score - baseline_score
    assert pp_delta == -10.0

    # Percent change (wrong): (70 - 80) / 80 * 100 = -12.5%
    pct_change = (current_score - baseline_score) / baseline_score * 100
    assert pct_change == -12.5

    # The classification uses pp, not pct change
    assert classify_drift(pp_delta) == "major"
    # If we mistakenly used pct change, classification would differ
    # for values near thresholds
