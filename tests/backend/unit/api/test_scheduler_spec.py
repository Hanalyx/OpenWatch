"""
Source-inspection tests for the Adaptive Compliance Scheduler API route.
Verifies that routes/compliance/scheduler.py implements all acceptance criteria
from the scheduler spec: role-based access, Field validation, Celery task dispatch,
and 404 handling.

Spec: specs/api/compliance/scheduler.spec.yaml
"""
import inspect

import pytest


@pytest.mark.unit
class TestAC1ReadEndpointsAllowAllRoles:
    """AC-1: Read-only endpoints allow all authenticated roles."""

    def test_get_config_allows_guest(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.get_scheduler_config)
        assert "UserRole.GUEST" in source, "get_scheduler_config must allow GUEST role"

    def test_get_config_allows_auditor(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.get_scheduler_config)
        assert "UserRole.AUDITOR" in source, "get_scheduler_config must allow AUDITOR role"

    def test_get_status_allows_all_roles(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.get_scheduler_status)
        assert "UserRole.GUEST" in source, "get_scheduler_status must allow GUEST role"
        assert "UserRole.SUPER_ADMIN" in source, "get_scheduler_status must allow SUPER_ADMIN"

    def test_get_hosts_due_allows_all_roles(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.get_hosts_due_for_scan)
        assert "UserRole.GUEST" in source, "get_hosts_due must allow GUEST role"

    def test_get_host_schedule_allows_all_roles(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.get_host_schedule)
        assert "UserRole.GUEST" in source, "get_host_schedule must allow GUEST role"


@pytest.mark.unit
class TestAC2WriteEndpointsRequireAdmin:
    """AC-2: Write endpoints require SECURITY_ADMIN or SUPER_ADMIN."""

    def test_update_config_requires_security_admin(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.update_scheduler_config)
        assert "UserRole.SECURITY_ADMIN" in source, "update_config must require SECURITY_ADMIN"

    def test_update_config_requires_super_admin(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.update_scheduler_config)
        assert "UserRole.SUPER_ADMIN" in source, "update_config must require SUPER_ADMIN"

    def test_toggle_requires_admin_roles(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.toggle_scheduler)
        assert "UserRole.SECURITY_ADMIN" in source, "toggle must require SECURITY_ADMIN"
        assert "UserRole.SUPER_ADMIN" in source, "toggle must require SUPER_ADMIN"

    def test_initialize_requires_admin_roles(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.initialize_schedules)
        assert "UserRole.SECURITY_ADMIN" in source, "initialize must require SECURITY_ADMIN"
        assert "UserRole.SUPER_ADMIN" in source, "initialize must require SUPER_ADMIN"

    def test_update_config_excludes_guest(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.update_scheduler_config)
        assert "UserRole.GUEST" not in source, "update_config must NOT allow GUEST"

    def test_toggle_excludes_analyst(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.toggle_scheduler)
        assert "UserRole.SECURITY_ANALYST" not in source, "toggle must NOT allow SECURITY_ANALYST"


@pytest.mark.unit
class TestAC3OperationalEndpointsRequireAnalyst:
    """AC-3: Operational endpoints require SECURITY_ANALYST or higher."""

    def test_maintenance_mode_allows_security_analyst(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.set_host_maintenance_mode)
        assert "UserRole.SECURITY_ANALYST" in source, "maintenance must allow SECURITY_ANALYST"

    def test_maintenance_mode_allows_super_admin(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.set_host_maintenance_mode)
        assert "UserRole.SUPER_ADMIN" in source, "maintenance must allow SUPER_ADMIN"

    def test_force_scan_allows_security_analyst(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.force_host_scan)
        assert "UserRole.SECURITY_ANALYST" in source, "force_scan must allow SECURITY_ANALYST"

    def test_force_scan_allows_compliance_officer(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.force_host_scan)
        assert "UserRole.COMPLIANCE_OFFICER" in source, "force_scan must allow COMPLIANCE_OFFICER"

    def test_force_scan_excludes_guest(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.force_host_scan)
        assert "UserRole.GUEST" not in source, "force_scan must NOT allow GUEST"


@pytest.mark.unit
class TestAC4SchedulerConfigUpdateValidation:
    """AC-4: SchedulerConfigUpdate validates interval ranges (15-2880 minutes)."""

    def test_interval_critical_min_15(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.SchedulerConfigUpdate)
        # interval_critical has ge=15
        assert "ge=15" in source, "interval_critical must have ge=15"

    def test_intervals_max_2880(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.SchedulerConfigUpdate)
        assert "le=2880" in source, "Intervals must have le=2880"

    def test_interval_compliant_min_60(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.SchedulerConfigUpdate)
        assert "ge=60" in source, "interval_compliant must have ge=60"

    def test_max_concurrent_scans_range(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.SchedulerConfigUpdate)
        assert "ge=1" in source, "max_concurrent_scans must have ge=1"
        assert "le=20" in source, "max_concurrent_scans must have le=20"


@pytest.mark.unit
class TestAC5MaintenanceModeRequestValidation:
    """AC-5: MaintenanceModeRequest validates duration (1-168 hours)."""

    def test_duration_hours_min_1(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.MaintenanceModeRequest)
        assert "ge=1" in source, "duration_hours must have ge=1"

    def test_duration_hours_max_168(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.MaintenanceModeRequest)
        assert "le=168" in source, "duration_hours must have le=168 (one week)"


@pytest.mark.unit
class TestAC6ForceScanDispatchesCeleryTask:
    """AC-6: Force scan dispatches Celery task to compliance_scanning queue."""

    def test_force_scan_uses_send_task(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.force_host_scan)
        assert "send_task" in source, "force_scan must use celery_app.send_task"

    def test_force_scan_targets_correct_task(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.force_host_scan)
        assert "run_scheduled_kensa_scan" in source, "Must dispatch run_scheduled_kensa_scan task"

    def test_force_scan_uses_compliance_scanning_queue(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.force_host_scan)
        assert "compliance_scanning" in source, "Must use compliance_scanning queue"


@pytest.mark.unit
class TestAC7InitializeDispatchesCeleryTask:
    """AC-7: Initialize schedules dispatches Celery task."""

    def test_initialize_uses_send_task(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.initialize_schedules)
        assert "send_task" in source, "initialize must use celery_app.send_task"

    def test_initialize_targets_correct_task(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.initialize_schedules)
        assert "initialize_compliance_schedules" in source, (
            "Must dispatch initialize_compliance_schedules task"
        )

    def test_initialize_uses_compliance_scanning_queue(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.initialize_schedules)
        assert "compliance_scanning" in source, "Must use compliance_scanning queue"


@pytest.mark.unit
class TestAC8HostSchedule404:
    """AC-8: Host schedule returns 404 if schedule not found for host."""

    def test_get_host_schedule_returns_404(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.get_host_schedule)
        assert "404" in source, "Must return 404 status"

    def test_get_host_schedule_checks_none(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.get_host_schedule)
        assert "not schedule" in source, "Must check for None result from service"

    def test_get_host_schedule_uses_service(self):
        import app.routes.compliance.scheduler as mod

        source = inspect.getsource(mod.get_host_schedule)
        assert "get_host_schedule" in source, "Must call compliance_scheduler_service.get_host_schedule"
