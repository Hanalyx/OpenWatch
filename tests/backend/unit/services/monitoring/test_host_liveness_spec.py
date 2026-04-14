"""
Source-inspection tests for host liveness monitoring.

Spec: specs/services/monitoring/host-liveness.spec.yaml
Status: draft (Q1 -- promotion to active scheduled for week 12)
"""

import pytest

SKIP_REASON = "Q1: host liveness not yet implemented"


@pytest.mark.unit
class TestAC1HostLivenessTable:
    """AC-1: host_liveness table exists with required columns."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_model_defined(self):
        from app.models.host_liveness import HostLiveness  # noqa: F401

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_required_columns(self):
        from app.models.host_liveness import HostLiveness

        required = {
            "host_id", "last_ping_at", "last_response_ms",
            "reachability_status", "consecutive_failures", "last_state_change_at",
        }
        actual = {c.name for c in HostLiveness.__table__.columns}
        assert required.issubset(actual)


@pytest.mark.unit
class TestAC2PingMechanics:
    """AC-2: ping_host opens TCP connection with 5s timeout, no command execution."""

    def test_ping_host_uses_tcp_socket(self):
        import inspect

        import app.services.monitoring.liveness as mod

        source = inspect.getsource(mod)
        assert "socket" in source or "asyncio.open_connection" in source
        assert "timeout=5" in source or "timeout = 5" in source
        # MUST NOT execute SSH commands
        assert "exec_command" not in source


@pytest.mark.unit
class TestAC3FiveMinutePingTask:
    """AC-3: ping_all_managed_hosts scheduled every 5 minutes."""

    def test_celery_task_exists(self):
        from app.tasks.liveness_tasks import ping_all_managed_hosts  # noqa: F401

    def test_celery_beat_schedule(self):
        from app.celery_app import celery_app

        schedule = celery_app.conf.beat_schedule
        assert any(
            "ping_all_managed_hosts" in str(v.get("task", ""))
            for v in schedule.values()
        )


@pytest.mark.unit
class TestAC4UnreachableAfterTwoFailures:
    """AC-4: transitions to unreachable after 2 consecutive failed pings."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_two_failures_triggers_unreachable(self):
        pass  # exercises LivenessService.ping_host state machine


@pytest.mark.unit
class TestAC5ReachableOnFirstSuccess:
    """AC-5: transitions to reachable on first successful ping."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_single_success_triggers_reachable(self):
        pass


@pytest.mark.unit
class TestAC6HostUnreachableAlert:
    """AC-6: reachable->unreachable triggers HOST_UNREACHABLE alert."""

    def test_unreachable_transition_creates_alert(self):
        import inspect

        import app.services.monitoring.liveness as mod

        source = inspect.getsource(mod)
        assert "HOST_UNREACHABLE" in source
        assert "AlertService" in source or "create_alert" in source


@pytest.mark.unit
class TestAC7HostRecoveredAlert:
    """AC-7: unreachable->reachable triggers HOST_RECOVERED alert."""

    def test_recovered_transition_creates_alert(self):
        import inspect

        import app.services.monitoring.liveness as mod

        source = inspect.getsource(mod)
        assert "HOST_RECOVERED" in source


@pytest.mark.unit
class TestAC8MaintenanceModeSkipped:
    """AC-8: hosts in maintenance mode are skipped by the ping task."""

    def test_maintenance_hosts_skipped(self):
        import inspect

        import app.tasks.liveness_tasks as mod

        source = inspect.getsource(mod)
        assert "maintenance_mode" in source


@pytest.mark.unit
class TestAC9SchedulerSkipsUnreachable:
    """AC-9: compliance_scheduler skips unreachable hosts."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_scheduler_filters_unreachable(self):
        import inspect

        import app.services.compliance.compliance_scheduler as mod

        source = inspect.getsource(mod)
        assert "reachability_status" in source or "host_liveness" in source


@pytest.mark.unit
class TestAC10FleetHealthSourcesFromLiveness:
    """AC-10: fleet health summary reads reachable counts from host_liveness."""

    @pytest.mark.skip(reason=SKIP_REASON)
    def test_fleet_health_summary_endpoint(self):
        import inspect

        # Endpoint location TBD; check common paths
        try:
            import app.routes.fleet.health as mod
        except ImportError:
            import app.routes.hosts.health as mod

        source = inspect.getsource(mod)
        assert "host_liveness" in source
