"""
Source-inspection tests for the ComplianceSchedulerService.
Verifies that services/compliance/compliance_scheduler.py implements all
acceptance criteria from the compliance-scheduler spec: config intervals,
host due queries, maintenance mode, adaptive intervals, concurrent scan
limits, and host_schedule table usage.

Spec: specs/services/compliance/compliance-scheduler.spec.yaml
"""
import inspect

import pytest


@pytest.mark.unit
class TestAC1SchedulerConfigIntervals:
    """AC-1: Scheduler config includes interval settings per compliance state."""

    def test_default_config_has_compliant_interval(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService._get_default_config)
        assert '"compliant"' in source, "Default config must include compliant interval"

    def test_default_config_has_critical_interval(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService._get_default_config)
        assert '"critical"' in source, "Default config must include critical interval"

    def test_default_config_has_mostly_compliant_interval(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService._get_default_config)
        assert '"mostly_compliant"' in source, "Default config must include mostly_compliant interval"

    def test_default_config_has_partial_interval(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService._get_default_config)
        assert '"partial"' in source, "Default config must include partial interval"

    def test_default_config_has_low_interval(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService._get_default_config)
        assert '"low"' in source, "Default config must include low interval"

    def test_default_config_has_unknown_interval(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService._get_default_config)
        assert '"unknown"' in source, "Default config must include unknown interval"

    def test_default_config_has_maintenance_interval(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService._get_default_config)
        assert '"maintenance"' in source, "Default config must include maintenance interval"

    def test_get_config_reads_from_database(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService.get_config)
        assert "compliance_scheduler_config" in source, "Must read from compliance_scheduler_config table"


@pytest.mark.unit
class TestAC2HostsDueForScan:
    """AC-2: get_hosts_due_for_scan returns hosts where next_scheduled_scan is past."""

    def test_hosts_due_checks_next_scheduled_scan(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService.get_hosts_due_for_scan)
        assert "next_scheduled_scan" in source, "Must query next_scheduled_scan"

    def test_hosts_due_filters_active_hosts(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService.get_hosts_due_for_scan)
        assert "is_active = true" in source, "Must filter for active hosts"

    def test_hosts_due_filters_maintenance_mode(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService.get_hosts_due_for_scan)
        assert "maintenance_mode" in source, "Must filter out hosts in maintenance mode"

    def test_hosts_due_orders_by_priority(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService.get_hosts_due_for_scan)
        assert "scan_priority" in source, "Must order by scan_priority"
        assert "DESC" in source, "Priority must be ordered DESC (higher first)"

    def test_hosts_due_returns_empty_when_disabled(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService.get_hosts_due_for_scan)
        assert 'config["enabled"]' in source, "Must check if scheduler is enabled"
        assert "return []" in source, "Must return empty list when disabled"

    def test_hosts_due_compares_with_now(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService.get_hosts_due_for_scan)
        assert ":now" in source, "Must compare next_scheduled_scan with current time"


@pytest.mark.unit
class TestAC3MaintenanceMode:
    """AC-3: set_maintenance_mode updates maintenance_mode and maintenance_until."""

    def test_set_maintenance_mode_updates_fields(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService.set_maintenance_mode)
        assert "maintenance_mode" in source, "Must update maintenance_mode field"
        assert "maintenance_until" in source, "Must update maintenance_until field"

    def test_set_maintenance_mode_uses_host_schedule_table(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService.set_maintenance_mode)
        assert "host_schedule" in source, "Must operate on host_schedule table"

    def test_set_maintenance_mode_accepts_enabled_param(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService.set_maintenance_mode)
        assert "enabled" in source, "Must accept enabled parameter"

    def test_set_host_maintenance_mode_is_alias(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService.set_host_maintenance_mode)
        assert "set_maintenance_mode" in source, "set_host_maintenance_mode must delegate to set_maintenance_mode"


@pytest.mark.unit
class TestAC4AdaptiveIntervalCalculation:
    """AC-4: Interval adapts based on compliance score."""

    def test_critical_state_for_low_score(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService.get_compliance_state_from_score)
        assert "critical" in source, "Must map low scores to critical state"

    def test_compliant_state_for_100_score(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService.get_compliance_state_from_score)
        assert "score >= 100" in source, "Must check for score >= 100 for compliant"

    def test_mostly_compliant_state(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService.get_compliance_state_from_score)
        assert "score >= 80" in source, "Must check for score >= 80 for mostly_compliant"

    def test_partial_state(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService.get_compliance_state_from_score)
        assert "score >= 50" in source, "Must check for score >= 50 for partial"

    def test_low_state(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService.get_compliance_state_from_score)
        assert "score >= 20" in source, "Must check for score >= 20 for low"

    def test_critical_on_critical_findings(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService.get_compliance_state_from_score)
        assert "has_critical" in source, "Must check has_critical parameter"

    def test_unknown_for_none_score(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService.get_compliance_state_from_score)
        assert "score is None" in source, "Must return unknown for None score"
        assert '"unknown"' in source, "Must return 'unknown' string"

    def test_default_intervals_match_spec(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService._get_default_config)
        assert "1440" in source, "Compliant default must be 1440 minutes (24h)"
        assert "720" in source, "Mostly compliant default must be 720 minutes (12h)"
        assert "360" in source, "Partial default must be 360 minutes (6h)"
        assert "120" in source, "Low default must be 120 minutes (2h)"
        assert ": 60" in source or '"critical": 60' in source, "Critical default must be 60 minutes (1h)"


@pytest.mark.unit
class TestAC5MaxConcurrentScans:
    """AC-5: Max concurrent scans is configurable (default range 1-20)."""

    def test_default_config_has_max_concurrent_scans(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService._get_default_config)
        assert "max_concurrent_scans" in source, "Default config must include max_concurrent_scans"

    def test_update_config_supports_max_concurrent_scans(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService.update_config)
        assert "max_concurrent_scans" in source, "update_config must support max_concurrent_scans"

    def test_hosts_due_respects_limit(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService.get_hosts_due_for_scan)
        assert "max_concurrent_scans" in source, "Must use max_concurrent_scans as default limit"
        assert "LIMIT" in source, "Must apply LIMIT to query"


@pytest.mark.unit
class TestAC6HostScheduleTable:
    """AC-6: Scheduler operates on host_schedule table."""

    def test_hosts_due_queries_host_schedule(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService.get_hosts_due_for_scan)
        assert "host_schedule" in source, "Must query host_schedule table"

    def test_update_schedule_writes_host_schedule(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService.update_host_schedule)
        assert "host_schedule" in source, "Must write to host_schedule table"

    def test_host_schedule_stores_next_scan(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService.update_host_schedule)
        assert "next_scheduled_scan" in source, "Must store next_scheduled_scan"

    def test_host_schedule_stores_maintenance_mode(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService.set_maintenance_mode)
        assert "maintenance_mode" in source, "Must store maintenance_mode"

    def test_host_schedule_stores_priority(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService.update_host_schedule)
        assert "scan_priority" in source, "Must store scan_priority"

    def test_host_schedule_stores_consecutive_failures(self):
        from app.services.compliance.compliance_scheduler import ComplianceSchedulerService

        source = inspect.getsource(ComplianceSchedulerService.record_scan_failure)
        assert "consecutive_scan_failures" in source, "Must track consecutive_scan_failures"
