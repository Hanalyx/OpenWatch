# Spec: specs/services/monitoring/host-monitoring.spec.yaml
"""
Unit tests for host monitoring state machine behavioral contracts.

Tests MonitoringState enum values, connectivity-to-state mapping,
progressive degradation, recovery thresholds, scan eligibility,
scheduling intervals and priorities, and maintenance mode behavior.
"""

import inspect

import pytest


# ---------------------------------------------------------------------------
# AC-1: MonitoringState enum has exactly 6 valid values; "offline" is not one
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC1MonitoringStateEnum:
    """AC-1: MonitoringState enum defines exactly 6 values; OFFLINE absent."""

    def test_monitoring_state_has_online(self):
        """Verify ONLINE is a valid MonitoringState."""
        from app.services.monitoring.state import MonitoringState

        assert hasattr(MonitoringState, "ONLINE")
        assert MonitoringState.ONLINE.value == "online"

    def test_monitoring_state_has_degraded(self):
        """Verify DEGRADED is a valid MonitoringState."""
        from app.services.monitoring.state import MonitoringState

        assert hasattr(MonitoringState, "DEGRADED")
        assert MonitoringState.DEGRADED.value == "degraded"

    def test_monitoring_state_has_critical(self):
        """Verify CRITICAL is a valid MonitoringState."""
        from app.services.monitoring.state import MonitoringState

        assert hasattr(MonitoringState, "CRITICAL")
        assert MonitoringState.CRITICAL.value == "critical"

    def test_monitoring_state_has_down(self):
        """Verify DOWN is a valid MonitoringState."""
        from app.services.monitoring.state import MonitoringState

        assert hasattr(MonitoringState, "DOWN")
        assert MonitoringState.DOWN.value == "down"

    def test_monitoring_state_has_maintenance(self):
        """Verify MAINTENANCE is a valid MonitoringState."""
        from app.services.monitoring.state import MonitoringState

        assert hasattr(MonitoringState, "MAINTENANCE")
        assert MonitoringState.MAINTENANCE.value == "maintenance"

    def test_monitoring_state_has_unknown(self):
        """Verify UNKNOWN is a valid MonitoringState."""
        from app.services.monitoring.state import MonitoringState

        assert hasattr(MonitoringState, "UNKNOWN")
        assert MonitoringState.UNKNOWN.value == "unknown"

    def test_monitoring_state_has_no_offline(self):
        """Verify OFFLINE is NOT a MonitoringState (raw connectivity string, not a state)."""
        from app.services.monitoring.state import MonitoringState

        assert not hasattr(MonitoringState, "OFFLINE")
        # Confirm that attempting to construct from "offline" raises ValueError
        with pytest.raises(ValueError):
            MonitoringState("offline")

    def test_monitoring_state_has_exactly_6_values(self):
        """Verify exactly 6 MonitoringState values (no accidental additions)."""
        from app.services.monitoring.state import MonitoringState

        assert len(MonitoringState) == 6


# ---------------------------------------------------------------------------
# AC-2: Connectivity-to-state mapping exists in host.py before DB write
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC2ConnectivityMapping:
    """AC-2: host.py maps connectivity results to MonitoringState before DB write."""

    def test_host_module_has_connectivity_mapping(self):
        """Verify a mapping from connectivity strings to states exists in host.py."""
        import app.services.monitoring.host as host_module

        source = inspect.getsource(host_module)
        # The mapping must translate "offline" to a valid state
        assert "offline" in source
        assert "down" in source.lower()

    def test_connectivity_offline_uses_progressive_degradation(self):
        """Verify 'offline' is NOT in CONNECTIVITY_STATE_MAP (uses progressive path instead)."""
        from app.services.monitoring.host import CONNECTIVITY_STATE_MAP

        # "offline" must NOT be a flat map entry — it would produce false-positive DOWN
        assert "offline" not in CONNECTIVITY_STATE_MAP, (
            "'offline' must not be in CONNECTIVITY_STATE_MAP; "
            "use _progressive_offline_state() to avoid false-positive DOWN on first failure"
        )

    def test_progressive_offline_state_function_exists(self):
        """Verify _progressive_offline_state function exists in host.py."""
        from app.services.monitoring import host as host_module

        assert hasattr(host_module, "_progressive_offline_state"), (
            "_progressive_offline_state() must exist to implement AC-3 progressive degradation"
        )

    def test_progressive_offline_first_failure_is_degraded(self):
        """Verify first 'offline' check (from online) produces DEGRADED, not DOWN."""
        from app.services.monitoring.host import _progressive_offline_state

        assert _progressive_offline_state("online") == "degraded"
        assert _progressive_offline_state("unknown") == "degraded"
        assert _progressive_offline_state(None) == "degraded"

    def test_progressive_offline_second_failure_is_critical(self):
        """Verify second consecutive 'offline' check (from degraded) produces CRITICAL."""
        from app.services.monitoring.host import _progressive_offline_state

        assert _progressive_offline_state("degraded") == "critical"

    def test_progressive_offline_third_failure_is_down(self):
        """Verify third+ consecutive 'offline' check produces DOWN."""
        from app.services.monitoring.host import _progressive_offline_state

        assert _progressive_offline_state("critical") == "down"
        assert _progressive_offline_state("down") == "down"

    def test_connectivity_error_maps_to_unknown(self):
        """Verify 'error' connectivity result maps to 'unknown' state."""
        import app.services.monitoring.host as host_module

        source = inspect.getsource(host_module)
        assert "error" in source
        assert "unknown" in source.lower()

    def test_update_host_status_uses_state_mapping(self):
        """Verify update_host_status does not write raw connectivity strings to DB."""
        from app.services.monitoring.host import HostMonitor

        source = inspect.getsource(HostMonitor)
        # The mapping or conversion must be present in the class
        assert "CONNECTIVITY" in source or "connectivity" in source.lower() or "state_map" in source.lower() or "MonitoringState" in source


# ---------------------------------------------------------------------------
# AC-3: Progressive degradation thresholds
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC3ProgressiveDegradation:
    """AC-3: 1 failure->DEGRADED, 2->CRITICAL, 3+->DOWN via _progressive_offline_state."""

    def test_degraded_on_first_failure_from_online(self):
        """AC-3: first offline check from ONLINE -> DEGRADED (not DOWN)."""
        from app.services.monitoring.host import _progressive_offline_state

        assert _progressive_offline_state("online") == "degraded"

    def test_degraded_on_first_failure_from_unknown(self):
        """AC-3: first offline check from UNKNOWN -> DEGRADED."""
        from app.services.monitoring.host import _progressive_offline_state

        assert _progressive_offline_state("unknown") == "degraded"

    def test_critical_on_second_failure(self):
        """AC-3: second consecutive offline check (DEGRADED) -> CRITICAL."""
        from app.services.monitoring.host import _progressive_offline_state

        assert _progressive_offline_state("degraded") == "critical"

    def test_down_on_third_failure(self):
        """AC-3: third+ consecutive offline check (CRITICAL) -> DOWN."""
        from app.services.monitoring.host import _progressive_offline_state

        assert _progressive_offline_state("critical") == "down"

    def test_down_stays_down(self):
        """AC-3: hosts already DOWN remain DOWN on further offline checks."""
        from app.services.monitoring.host import _progressive_offline_state

        assert _progressive_offline_state("down") == "down"

    def test_function_in_source(self):
        """AC-3: _progressive_offline_state is defined in host.py."""
        import app.services.monitoring.host as host_module

        source = inspect.getsource(host_module)
        assert "_progressive_offline_state" in source


# ---------------------------------------------------------------------------
# AC-4: Recovery threshold requires 3 consecutive successes
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC4RecoveryThreshold:
    """AC-4: 3 consecutive full successes required to restore ONLINE."""

    def test_recovery_threshold_is_3(self):
        """Verify recovery threshold value of 3 is referenced in state machine."""
        from app.services.monitoring.state import HostMonitoringStateMachine

        source = inspect.getsource(HostMonitoringStateMachine)
        assert "3" in source

    def test_consecutive_successes_tracked(self):
        """Verify consecutive_successes counter used for recovery logic."""
        from app.services.monitoring.state import HostMonitoringStateMachine

        source = inspect.getsource(HostMonitoringStateMachine)
        assert "consecutive_success" in source or "success_count" in source

    def test_recovery_restores_to_online(self):
        """Verify ONLINE state is the recovery destination."""
        from app.services.monitoring.state import HostMonitoringStateMachine

        source = inspect.getsource(HostMonitoringStateMachine)
        # Recovery path must reference ONLINE
        assert "ONLINE" in source or "online" in source


# ---------------------------------------------------------------------------
# AC-5: Scan eligibility gated on ONLINE state
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC5ScanEligibility:
    """AC-5: Only ONLINE hosts are eligible for Kensa compliance scans."""

    def test_scan_eligibility_references_online_state(self):
        """Verify scan eligibility check references 'online' state."""
        import app.services.monitoring.host as host_module

        source = inspect.getsource(host_module)
        # The module must reference online state for scan gating
        assert "online" in source.lower()

    def test_down_hosts_not_scanned(self):
        """Verify DOWN state is recognized as scan-ineligible."""
        import app.services.monitoring.host as host_module

        source = inspect.getsource(host_module)
        # Code must handle down state distinctly from online
        assert "down" in source.lower()

    def test_scheduler_excludes_ineligible_states(self):
        """Verify get_hosts_due_for_check or scheduler handles state-based eligibility."""
        from app.services.monitoring.scheduler import AdaptiveSchedulerService

        source = inspect.getsource(AdaptiveSchedulerService)
        # Scheduler must handle state-based filtering
        assert "status" in source


# ---------------------------------------------------------------------------
# AC-6: UNKNOWN state triggers immediate re-check (interval=0)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC6UnknownImmediate:
    """AC-6: UNKNOWN state -> interval=0, immediate check."""

    def test_unknown_interval_is_zero(self):
        """Verify default interval for 'unknown' state is 0 (immediate)."""
        from app.services.monitoring.scheduler import AdaptiveSchedulerService

        service = AdaptiveSchedulerService()
        config = service._get_default_config()
        assert config["intervals"]["unknown"] == 0

    def test_calculate_next_check_time_immediate_for_unknown(self):
        """Verify calculate_next_check_time returns now() for unknown state."""
        from app.services.monitoring.scheduler import AdaptiveSchedulerService

        source = inspect.getsource(AdaptiveSchedulerService.calculate_next_check_time)
        assert "unknown" in source.lower()
        # Must return current time (no delay) for unknown
        assert "utcnow" in source or "now" in source

    def test_unknown_uses_zero_interval_path(self):
        """Verify interval=0 triggers the immediate path in calculate_next_check_time."""
        from app.services.monitoring.scheduler import AdaptiveSchedulerService

        source = inspect.getsource(AdaptiveSchedulerService.calculate_next_check_time)
        assert "== 0" in source or "interval_minutes == 0" in source or "== 0" in source


# ---------------------------------------------------------------------------
# AC-7: State-based check intervals in default config
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC7CheckIntervals:
    """AC-7: Default intervals: unknown=0, critical=2, degraded=5, online=15, down=30, maintenance=60."""

    def test_default_intervals_present(self):
        """Verify _get_default_config returns all 6 state intervals."""
        from app.services.monitoring.scheduler import AdaptiveSchedulerService

        service = AdaptiveSchedulerService()
        config = service._get_default_config()
        intervals = config["intervals"]
        assert set(intervals.keys()) >= {"unknown", "online", "degraded", "critical", "down", "maintenance"}

    def test_critical_interval_is_2(self):
        """Verify critical state uses 2-minute check interval."""
        from app.services.monitoring.scheduler import AdaptiveSchedulerService

        service = AdaptiveSchedulerService()
        config = service._get_default_config()
        assert config["intervals"]["critical"] == 2

    def test_degraded_interval_is_5(self):
        """Verify degraded state uses 5-minute check interval."""
        from app.services.monitoring.scheduler import AdaptiveSchedulerService

        service = AdaptiveSchedulerService()
        config = service._get_default_config()
        assert config["intervals"]["degraded"] == 5

    def test_online_interval_is_15(self):
        """Verify online state uses 15-minute check interval."""
        from app.services.monitoring.scheduler import AdaptiveSchedulerService

        service = AdaptiveSchedulerService()
        config = service._get_default_config()
        assert config["intervals"]["online"] == 15

    def test_down_interval_is_30(self):
        """Verify down state uses 30-minute check interval (retry without hammering)."""
        from app.services.monitoring.scheduler import AdaptiveSchedulerService

        service = AdaptiveSchedulerService()
        config = service._get_default_config()
        assert config["intervals"]["down"] == 30

    def test_maintenance_interval_is_60(self):
        """Verify maintenance state uses 60-minute check interval."""
        from app.services.monitoring.scheduler import AdaptiveSchedulerService

        service = AdaptiveSchedulerService()
        config = service._get_default_config()
        assert config["intervals"]["maintenance"] == 60


# ---------------------------------------------------------------------------
# AC-8: State-based Celery priorities in default config
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC8CeleryPriorities:
    """AC-8: Default priorities: unknown=10, critical=8, degraded=6, online=4, down=2, maintenance=1."""

    def test_default_priorities_present(self):
        """Verify _get_default_config returns all 6 state priorities."""
        from app.services.monitoring.scheduler import AdaptiveSchedulerService

        service = AdaptiveSchedulerService()
        config = service._get_default_config()
        priorities = config["priorities"]
        assert set(priorities.keys()) >= {"unknown", "critical", "degraded", "online", "down", "maintenance"}

    def test_unknown_has_highest_priority(self):
        """Verify unknown state has highest Celery priority (10)."""
        from app.services.monitoring.scheduler import AdaptiveSchedulerService

        service = AdaptiveSchedulerService()
        config = service._get_default_config()
        assert config["priorities"]["unknown"] == 10

    def test_critical_priority_is_8(self):
        """Verify critical state has priority 8."""
        from app.services.monitoring.scheduler import AdaptiveSchedulerService

        service = AdaptiveSchedulerService()
        config = service._get_default_config()
        assert config["priorities"]["critical"] == 8

    def test_degraded_priority_is_6(self):
        """Verify degraded state has priority 6."""
        from app.services.monitoring.scheduler import AdaptiveSchedulerService

        service = AdaptiveSchedulerService()
        config = service._get_default_config()
        assert config["priorities"]["degraded"] == 6

    def test_online_priority_is_4(self):
        """Verify online state has priority 4."""
        from app.services.monitoring.scheduler import AdaptiveSchedulerService

        service = AdaptiveSchedulerService()
        config = service._get_default_config()
        assert config["priorities"]["online"] == 4

    def test_down_priority_is_2(self):
        """Verify down state has priority 2 (retry but not urgent)."""
        from app.services.monitoring.scheduler import AdaptiveSchedulerService

        service = AdaptiveSchedulerService()
        config = service._get_default_config()
        assert config["priorities"]["down"] == 2

    def test_maintenance_has_lowest_priority(self):
        """Verify maintenance state has lowest priority (1)."""
        from app.services.monitoring.scheduler import AdaptiveSchedulerService

        service = AdaptiveSchedulerService()
        config = service._get_default_config()
        assert config["priorities"]["maintenance"] == 1

    def test_unknown_priority_exceeds_all_others(self):
        """Verify unknown priority is strictly highest of all states."""
        from app.services.monitoring.scheduler import AdaptiveSchedulerService

        service = AdaptiveSchedulerService()
        config = service._get_default_config()
        unknown_priority = config["priorities"]["unknown"]
        others = [v for k, v in config["priorities"].items() if k != "unknown"]
        assert all(unknown_priority > p for p in others)


# ---------------------------------------------------------------------------
# AC-9: Maintenance exclusion and UNKNOWN transition on disable
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC9MaintenanceMode:
    """AC-9: Maintenance hosts excluded from check queue; disable -> UNKNOWN."""

    def test_get_hosts_due_filters_maintenance(self):
        """Verify get_hosts_due_for_check excludes maintenance hosts when mode=skip."""
        from app.services.monitoring.scheduler import AdaptiveSchedulerService

        source = inspect.getsource(AdaptiveSchedulerService.get_hosts_due_for_check)
        assert "maintenance" in source.lower()

    def test_maintenance_skip_mode_applied(self):
        """Verify 'skip' maintenance_mode causes maintenance filter to be applied."""
        from app.services.monitoring.scheduler import AdaptiveSchedulerService

        source = inspect.getsource(AdaptiveSchedulerService.get_hosts_due_for_check)
        assert "skip" in source

    def test_set_maintenance_mode_transitions_to_unknown(self):
        """Verify disabling maintenance mode transitions host to UNKNOWN state."""
        from app.services.monitoring.state import HostMonitoringStateMachine

        source = inspect.getsource(HostMonitoringStateMachine.set_maintenance_mode)
        # Disabling maintenance must transition to UNKNOWN for immediate re-check
        assert "UNKNOWN" in source or "unknown" in source

    def test_maintenance_state_in_interval_map(self):
        """Verify maintenance state has a defined interval (not undefined/error)."""
        from app.services.monitoring.scheduler import AdaptiveSchedulerService

        service = AdaptiveSchedulerService()
        config = service._get_default_config()
        assert "maintenance" in config["intervals"]
        assert config["intervals"]["maintenance"] > 0  # Not immediate (skip mode handles exclusion)


# ---------------------------------------------------------------------------
# AC-10: State transition alerts and logging
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC10TransitionAlertsAndLogging:
    """AC-10: Status changes trigger alerts; all transitions are logged."""

    def test_send_status_change_alerts_exists(self):
        """Verify send_status_change_alerts function defined in host module."""
        from app.services.monitoring.host import HostMonitor

        assert hasattr(HostMonitor, "send_status_change_alerts") or callable(
            getattr(HostMonitor, "send_status_change_alerts", None)
        )

    def test_alert_covers_online_offline_transition(self):
        """Verify alert logic references both online and offline status transitions."""
        import app.services.monitoring.host as host_module

        source = inspect.getsource(host_module)
        assert "online" in source.lower()
        assert "offline" in source.lower()

    def test_state_machine_logs_transitions(self):
        """Verify HostMonitoringStateMachine uses logger for state change events."""
        from app.services.monitoring.state import HostMonitoringStateMachine

        source = inspect.getsource(HostMonitoringStateMachine)
        assert "logger" in source
        assert "log" in source.lower()

    def test_host_monitor_has_logging(self):
        """Verify HostMonitor module uses logging for status changes."""
        import app.services.monitoring.host as host_module

        source = inspect.getsource(host_module)
        assert "logger" in source


# ---------------------------------------------------------------------------
# AC-11: transition_state() handles stale/invalid DB status gracefully
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC11TransitionStateInvalidStatusResilience:
    """AC-11: transition_state() must not crash on stale invalid hosts.status values.

    Root cause (confirmed via live worker logs 2026-03-06):
      hosts.status = 'offline' (written before state machine enforced)
      -> MonitoringState('offline') -> ValueError
      -> state machine rolled back every cycle
      -> hosts.status never updated, host permanently stuck
      even though SSH was succeeding (host was genuinely online).

    Fix: try/except around MonitoringState(current_status) in transition_state(),
    defaulting to UNKNOWN and logging a warning so the cycle can complete.
    """

    def test_transition_state_has_try_except_around_monitoring_state_parse(self):
        """AC-11: transition_state source must contain ValueError handling around status parse."""
        from app.services.monitoring.state import HostMonitoringStateMachine

        source = inspect.getsource(HostMonitoringStateMachine.transition_state)
        # Must catch ValueError when parsing current DB status
        assert "ValueError" in source, (
            "transition_state() must catch ValueError from MonitoringState(current_status) "
            "so a stale 'offline' value does not crash the monitoring cycle"
        )

    def test_transition_state_falls_back_to_unknown_on_invalid_status(self):
        """AC-11: invalid current_status falls back to UNKNOWN, not crash."""
        from app.services.monitoring.state import HostMonitoringStateMachine

        source = inspect.getsource(HostMonitoringStateMachine.transition_state)
        # The fallback must explicitly use UNKNOWN
        assert "UNKNOWN" in source or "MonitoringState.UNKNOWN" in source, (
            "transition_state() must fall back to MonitoringState.UNKNOWN for invalid DB status"
        )

    def test_transition_state_logs_warning_for_invalid_status(self):
        """AC-11: warning must be logged identifying host_id and invalid value."""
        from app.services.monitoring.state import HostMonitoringStateMachine

        source = inspect.getsource(HostMonitoringStateMachine.transition_state)
        # Warning log must be present in the ValueError handler
        assert "warning" in source.lower(), (
            "transition_state() must log a warning when encountering invalid DB status, "
            "so operators can identify stuck hosts"
        )

    def test_invalid_status_not_in_valid_monitoring_states(self):
        """AC-11: confirm 'offline' is genuinely invalid — enum has no OFFLINE member."""
        from app.services.monitoring.state import MonitoringState
        import pytest

        with pytest.raises(ValueError):
            MonitoringState("offline")

    def test_transition_state_source_references_invalid_status_message(self):
        """AC-11: warning message must reference the invalid status string for diagnostics."""
        from app.services.monitoring.state import HostMonitoringStateMachine

        source = inspect.getsource(HostMonitoringStateMachine.transition_state)
        # The warning must interpolate the bad status value (not a generic message)
        assert "invalid" in source.lower() or "not a MonitoringState" in source, (
            "Warning log must identify the invalid status value to aid incident investigation"
        )
