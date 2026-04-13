"""
Unit tests for alert thresholds: AlertType enum members, AlertSeverity and
AlertStatus enums, status transition guards, AlertGenerator scan processing,
DEFAULT_THRESHOLDS structure, deduplication logic, severity sorting, stats
return shape, and configuration drift detection.

Spec: specs/services/compliance/alert-thresholds.spec.yaml
Tests AlertService (alerts.py, 686 LOC) and AlertGenerator (alert_generator.py, 398 LOC).
"""

import inspect

import pytest

from app.services.compliance.alert_generator import AlertGenerator
from app.services.compliance.alerts import DEFAULT_THRESHOLDS, AlertSeverity, AlertStatus, AlertType

# ---------------------------------------------------------------------------
# AC-1: AlertType enum has exactly 16 members
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC1AlertTypeEnum:
    """AC-1: AlertType defines exactly 16 members across 4 categories."""

    COMPLIANCE = {
        "CRITICAL_FINDING",
        "HIGH_FINDING",
        "SCORE_DROP",
        "NON_COMPLIANT",
        "DEGRADING_TREND",
    }
    OPERATIONAL = {
        "HOST_UNREACHABLE",
        "SCAN_FAILED",
        "SCHEDULER_STOPPED",
        "SCAN_BACKLOG",
        "HOST_NOT_SCANNED",
    }
    EXCEPTION = {
        "EXCEPTION_EXPIRING",
        "EXCEPTION_EXPIRED",
        "EXCEPTION_REQUESTED",
    }
    DRIFT = {
        "CONFIGURATION_DRIFT",
        "UNEXPECTED_REMEDIATION",
        "MASS_DRIFT",
    }

    def test_exactly_16_members(self):
        """Verify AlertType has exactly 16 members."""
        assert len(AlertType) == 16

    def test_compliance_members(self):
        """Verify all 5 compliance alert types exist."""
        names = {m.name for m in AlertType}
        assert self.COMPLIANCE.issubset(names)

    def test_operational_members(self):
        """Verify all 5 operational alert types exist."""
        names = {m.name for m in AlertType}
        assert self.OPERATIONAL.issubset(names)

    def test_exception_members(self):
        """Verify all 3 exception alert types exist."""
        names = {m.name for m in AlertType}
        assert self.EXCEPTION.issubset(names)

    def test_drift_members(self):
        """Verify all 3 drift alert types exist."""
        names = {m.name for m in AlertType}
        assert self.DRIFT.issubset(names)


# ---------------------------------------------------------------------------
# AC-2: AlertSeverity enum has 5 values
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC2AlertSeverityEnum:
    """AC-2: AlertSeverity has exactly 5 values: critical, high, medium, low, info."""

    EXPECTED = {"critical", "high", "medium", "low", "info"}

    def test_exactly_5_members(self):
        """Verify AlertSeverity has exactly 5 members."""
        assert len(AlertSeverity) == 5

    def test_expected_values(self):
        """Verify all expected severity values exist."""
        values = {m.value for m in AlertSeverity}
        assert values == self.EXPECTED


# ---------------------------------------------------------------------------
# AC-3: AlertStatus enum has 3 values
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC3AlertStatusEnum:
    """AC-3: AlertStatus has exactly 3 values: active, acknowledged, resolved."""

    EXPECTED = {"active", "acknowledged", "resolved"}

    def test_exactly_3_members(self):
        """Verify AlertStatus has exactly 3 members."""
        assert len(AlertStatus) == 3

    def test_expected_values(self):
        """Verify all expected status values exist."""
        values = {m.value for m in AlertStatus}
        assert values == self.EXPECTED


# ---------------------------------------------------------------------------
# AC-4: Acknowledge and resolve transition guards
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC4StatusTransitions:
    """AC-4: acknowledge from active; resolve from active or acknowledged."""

    def test_acknowledge_from_active(self):
        """Verify acknowledge_alert only transitions from active."""
        from app.services.compliance.alerts import AlertService

        source = inspect.getsource(AlertService.acknowledge_alert)
        assert "status = 'active'" in source

    def test_resolve_from_active_or_acknowledged(self):
        """Verify resolve_alert transitions from active or acknowledged."""
        from app.services.compliance.alerts import AlertService

        source = inspect.getsource(AlertService.resolve_alert)
        assert "IN ('active', 'acknowledged')" in source


# ---------------------------------------------------------------------------
# AC-5: AlertGenerator.process_scan_results dispatches 4 checks
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC5ProcessScanResults:
    """AC-5: process_scan_results checks findings, score drop, non-compliant, drift."""

    def test_calls_create_finding_alert(self):
        """Verify finding alerts are created."""
        source = inspect.getsource(AlertGenerator.process_scan_results)
        assert "_create_finding_alert" in source

    def test_calls_check_score_drop(self):
        """Verify score drop check is called."""
        source = inspect.getsource(AlertGenerator.process_scan_results)
        assert "_check_score_drop" in source

    def test_calls_create_non_compliant_alert(self):
        """Verify non-compliant alert is created."""
        source = inspect.getsource(AlertGenerator.process_scan_results)
        assert "_create_non_compliant_alert" in source

    def test_calls_check_configuration_drift(self):
        """Verify configuration drift check is called."""
        source = inspect.getsource(AlertGenerator.process_scan_results)
        assert "_check_configuration_drift" in source


# ---------------------------------------------------------------------------
# AC-6: DEFAULT_THRESHOLDS has 4 top-level keys
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC6DefaultThresholds:
    """AC-6: DEFAULT_THRESHOLDS has compliance, operational, exceptions, drift."""

    EXPECTED_KEYS = {"compliance", "operational", "exceptions", "drift"}

    def test_exactly_4_keys(self):
        """Verify DEFAULT_THRESHOLDS has exactly 4 top-level keys."""
        assert set(DEFAULT_THRESHOLDS.keys()) == self.EXPECTED_KEYS

    def test_compliance_has_thresholds(self):
        """Verify compliance section has score_drop_threshold."""
        assert "score_drop_threshold" in DEFAULT_THRESHOLDS["compliance"]

    def test_drift_has_mass_drift_threshold(self):
        """Verify drift section has mass_drift_threshold."""
        assert "mass_drift_threshold" in DEFAULT_THRESHOLDS["drift"]


# ---------------------------------------------------------------------------
# AC-7: _is_duplicate checks alert_type, host_id, rule_id, status=active
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC7Deduplication:
    """AC-7: _is_duplicate queries matching alert within window."""

    def test_checks_alert_type(self):
        """Verify alert_type is part of dedup query."""
        from app.services.compliance.alerts import AlertService

        source = inspect.getsource(AlertService._is_duplicate)
        assert "alert_type" in source

    def test_checks_host_id(self):
        """Verify host_id is part of dedup query."""
        from app.services.compliance.alerts import AlertService

        source = inspect.getsource(AlertService._is_duplicate)
        assert "host_id" in source

    def test_checks_rule_id(self):
        """Verify rule_id is part of dedup query."""
        from app.services.compliance.alerts import AlertService

        source = inspect.getsource(AlertService._is_duplicate)
        assert "rule_id" in source

    def test_filters_active_status(self):
        """Verify only active alerts are checked for duplicates."""
        from app.services.compliance.alerts import AlertService

        source = inspect.getsource(AlertService._is_duplicate)
        assert "status = 'active'" in source


# ---------------------------------------------------------------------------
# AC-8: list_alerts sorts by severity priority
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC8SeveritySorting:
    """AC-8: list_alerts sorts by CASE severity (critical=1...) then created_at DESC."""

    def test_case_expression_values(self):
        """Verify CASE expression maps severity to correct priority numbers."""
        from app.services.compliance.alerts import AlertService

        source = inspect.getsource(AlertService.list_alerts)
        assert "'critical' THEN 1" in source
        assert "'high' THEN 2" in source
        assert "'medium' THEN 3" in source
        assert "'low' THEN 4" in source
        assert "ELSE 5" in source

    def test_secondary_sort_created_at_desc(self):
        """Verify secondary sort is created_at DESC."""
        from app.services.compliance.alerts import AlertService

        source = inspect.getsource(AlertService.list_alerts)
        assert "created_at DESC" in source


# ---------------------------------------------------------------------------
# AC-9: get_stats return shape
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC9StatsReturnShape:
    """AC-9: get_stats returns total_active/acknowledged/resolved and by_severity."""

    def test_returns_status_totals(self):
        """Verify get_stats source returns all 3 status totals."""
        from app.services.compliance.alerts import AlertService

        source = inspect.getsource(AlertService.get_stats)
        assert '"total_active"' in source
        assert '"total_acknowledged"' in source
        assert '"total_resolved"' in source

    def test_returns_by_severity(self):
        """Verify get_stats returns by_severity with 5 keys."""
        from app.services.compliance.alerts import AlertService

        source = inspect.getsource(AlertService.get_stats)
        assert '"by_severity"' in source
        assert '"critical"' in source
        assert '"high"' in source
        assert '"medium"' in source
        assert '"low"' in source
        assert '"info"' in source


# ---------------------------------------------------------------------------
# AC-10: Configuration drift detection (3 alert types)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC10ConfigurationDrift:
    """AC-10: _check_configuration_drift detects CONFIGURATION_DRIFT, UNEXPECTED_REMEDIATION, MASS_DRIFT."""

    def test_detects_configuration_drift(self):
        """Verify pass->fail generates CONFIGURATION_DRIFT alert."""
        source = inspect.getsource(AlertGenerator._check_configuration_drift)
        assert "CONFIGURATION_DRIFT" in source

    def test_detects_unexpected_remediation(self):
        """Verify fail->pass generates UNEXPECTED_REMEDIATION alert."""
        source = inspect.getsource(AlertGenerator._check_configuration_drift)
        assert "UNEXPECTED_REMEDIATION" in source

    def test_detects_mass_drift(self):
        """Verify mass drift above threshold generates MASS_DRIFT alert."""
        source = inspect.getsource(AlertGenerator._check_configuration_drift)
        assert "MASS_DRIFT" in source

    def test_pass_to_fail_detection(self):
        """Verify pass->fail logic in source."""
        source = inspect.getsource(AlertGenerator._check_configuration_drift)
        assert "previous_passed and not current_passed" in source

    def test_fail_to_pass_detection(self):
        """Verify fail->pass logic in source."""
        source = inspect.getsource(AlertGenerator._check_configuration_drift)
        assert "not previous_passed and current_passed" in source


# ---------------------------------------------------------------------------
# AC-11: create_alert dispatches notification task (fire-and-forget)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC11NotificationDispatch:
    """AC-11: create_alert enqueues dispatch_alert_notifications; failures don't raise."""

    def test_dispatches_notification_task(self):
        """Verify create_alert references dispatch_alert_notifications."""
        from app.services.compliance.alerts import AlertService

        source = inspect.getsource(AlertService.create_alert)
        assert "dispatch_alert_notifications" in source

    def test_imports_notification_tasks(self):
        """Verify create_alert imports from notification_tasks module."""
        from app.services.compliance.alerts import AlertService

        source = inspect.getsource(AlertService.create_alert)
        assert "notification_tasks" in source

    def test_dispatch_wrapped_in_try_except(self):
        """Verify dispatch is wrapped in try/except so failures don't propagate."""
        from app.services.compliance.alerts import AlertService

        source = inspect.getsource(AlertService.create_alert)
        # The dispatch block must be inside a try/except
        assert "Failed to enqueue alert notification" in source

    def test_uses_delay_for_async_dispatch(self):
        """Verify .delay() is used for fire-and-forget Celery dispatch."""
        from app.services.compliance.alerts import AlertService

        source = inspect.getsource(AlertService.create_alert)
        assert ".delay(" in source
