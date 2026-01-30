"""
Host Monitoring State Machine
Implements adaptive monitoring with state-based check intervals
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class MonitoringState(Enum):
    """Host monitoring states with different check intervals

    Status values aligned with frontend and database:
    - online: Can ping AND ssh to host (fully operational)
    - degraded: Can ping and ssh, but no elevated privilege (permission issues)
    - critical: Can ping but can't ssh (partial connectivity)
    - down: No ping, no ssh (completely unavailable)
    - maintenance: Planned/manual maintenance mode
    - unknown: Host added but not yet checked
    """

    ONLINE = "online"  # 30 min interval - fully operational (ping + ssh + privilege)
    DEGRADED = "degraded"  # 5 min interval - permission issues (ping + ssh, no privilege)
    CRITICAL = "critical"  # 2 min interval - partial connectivity (ping only, no ssh)
    DOWN = "down"  # 30 min interval - completely unavailable (no ping, no ssh)
    MAINTENANCE = "maintenance"  # No checks - user-defined maintenance window
    UNKNOWN = "unknown"  # Initial state - not yet checked


@dataclass
class StateTransitionConfig:
    """Configuration for state transitions

    Multi-level monitoring thresholds:
    - Ping failures → down status (no connectivity)
    - SSH failures (when ping succeeds) → critical status (partial connectivity)
    - Privilege failures (when SSH succeeds) → degraded status (permission issues)
    """

    # Thresholds for state transitions
    ping_failures_to_down: int = 3  # 3 consecutive ping failures: any → down
    ssh_failures_to_critical: int = 2  # 2 consecutive SSH failures (ping OK): online/degraded → critical
    privilege_failures_to_degraded: int = 2  # 2 consecutive privilege failures (SSH OK): online → degraded

    # Recovery thresholds
    successes_to_online: int = 3  # 3 consecutive full successes: any → online
    successes_to_degraded: int = 1  # 1 SSH success (from critical/down) → degraded
    successes_to_critical: int = 1  # 1 ping success (from down) → critical

    # Check intervals (minutes)
    online_interval: int = 30  # Stable hosts checked every 30 minutes
    degraded_interval: int = 5  # Permission issues checked every 5 minutes
    critical_interval: int = 2  # Partial connectivity checked every 2 minutes
    down_interval: int = 30  # Down hosts checked every 30 minutes
    unknown_interval: int = 5  # New hosts checked every 5 minutes

    # Priority levels for Celery queue (1-10, higher = more urgent)
    online_priority: int = 3
    degraded_priority: int = 6
    critical_priority: int = 9
    down_priority: int = 4
    unknown_priority: int = 7  # New hosts have high priority for initial check


class HostMonitoringStateMachine:
    """Manages host monitoring state transitions and adaptive intervals"""

    def __init__(self, db: Session, config: Optional[StateTransitionConfig] = None):
        self.db = db

        # If no config provided, load from database
        if config is None:
            config = self._load_config_from_database()

        self.config = config

    def _load_config_from_database(self) -> StateTransitionConfig:
        """Load configuration from database host_monitoring_config table"""
        try:
            from .scheduler import adaptive_scheduler_service

            db_config = adaptive_scheduler_service.get_config(self.db)

            # Create StateTransitionConfig from database values
            return StateTransitionConfig(
                # Use database intervals
                online_interval=db_config["intervals"]["online"],
                degraded_interval=db_config["intervals"]["degraded"],
                critical_interval=db_config["intervals"]["critical"],
                down_interval=db_config["intervals"]["down"],
                unknown_interval=db_config["intervals"]["unknown"],
                # Use database priorities
                online_priority=db_config["priorities"]["online"],
                degraded_priority=db_config["priorities"]["degraded"],
                critical_priority=db_config["priorities"]["critical"],
                down_priority=db_config["priorities"]["down"],
                unknown_priority=db_config["priorities"]["unknown"],
            )
        except Exception as e:
            logger.warning(f"Failed to load config from database, using defaults: {e}")
            return StateTransitionConfig()

    def transition_state(
        self,
        host_id: str,
        ping_success: bool,
        ssh_success: bool = False,
        privilege_success: bool = False,
        response_time_ms: Optional[int] = None,
        error_message: Optional[str] = None,
        error_type: Optional[str] = None,
    ) -> Tuple[MonitoringState, int]:
        """
        Process multi-level check result and transition to new state if needed.

        Multi-level monitoring logic:
        - down: No ping, no ssh (completely unavailable)
        - critical: Can ping but can't ssh (partial connectivity)
        - degraded: Can ping and ssh, but no elevated privilege (permission issues)
        - online: Can ping AND ssh AND has privilege (fully operational)

        Args:
            host_id: UUID of the host
            ping_success: Whether ping check succeeded
            ssh_success: Whether SSH connection succeeded (only if ping succeeded)
            privilege_success: Whether privilege escalation succeeded (only if SSH succeeded)
            response_time_ms: Response time in milliseconds
            error_message: Error message if check failed
            error_type: Type of error (TIMEOUT, CONNECTION_REFUSED, SSH_AUTH_FAILED, etc.)

        Returns:
            Tuple of (new_state, next_check_interval_minutes)
        """
        try:
            # Get current host state with multi-level counters
            result = self.db.execute(
                text(
                    """
                SELECT status,
                       ping_consecutive_failures, ping_consecutive_successes,
                       ssh_consecutive_failures, ssh_consecutive_successes,
                       privilege_consecutive_failures, privilege_consecutive_successes
                FROM hosts
                WHERE id = :host_id
            """
                ),
                {"host_id": host_id},
            )

            row = result.fetchone()
            if not row:
                logger.error(f"Host {host_id} not found for state transition")
                return MonitoringState.UNKNOWN, self.config.unknown_interval

            current_status = row.status or "unknown"
            current_state = MonitoringState(current_status)

            # Current counters
            ping_failures = row.ping_consecutive_failures
            ping_successes = row.ping_consecutive_successes
            ssh_failures = row.ssh_consecutive_failures
            ssh_successes = row.ssh_consecutive_successes
            priv_failures = row.privilege_consecutive_failures
            priv_successes = row.privilege_consecutive_successes

            # Determine new state based on multi-level check results
            new_state, counters = self._calculate_new_state(
                current_state=current_state,
                ping_success=ping_success,
                ssh_success=ssh_success,
                privilege_success=privilege_success,
                ping_failures=ping_failures,
                ping_successes=ping_successes,
                ssh_failures=ssh_failures,
                ssh_successes=ssh_successes,
                priv_failures=priv_failures,
                priv_successes=priv_successes,
            )

            # Get check interval and priority for new state
            check_interval = self._get_check_interval(new_state)
            priority = self._get_priority(new_state)
            next_check_time = datetime.utcnow() + timedelta(minutes=check_interval)

            # Update host state in database
            state_changed = new_state.value != current_status
            self.db.execute(
                text(
                    """
                UPDATE hosts
                SET status = :status,
                    ping_consecutive_failures = :ping_failures,
                    ping_consecutive_successes = :ping_successes,
                    ssh_consecutive_failures = :ssh_failures,
                    ssh_consecutive_successes = :ssh_successes,
                    privilege_consecutive_failures = :priv_failures,
                    privilege_consecutive_successes = :priv_successes,
                    next_check_time = :next_check,
                    check_priority = :priority,
                    response_time_ms = :response_time,
                    last_check = :last_check,
                    last_state_change = CASE WHEN :state_changed THEN :last_check ELSE last_state_change END,
                    updated_at = :last_check
                WHERE id = :host_id
            """
                ),
                {
                    "host_id": host_id,
                    "status": new_state.value,
                    "ping_failures": counters["ping_failures"],
                    "ping_successes": counters["ping_successes"],
                    "ssh_failures": counters["ssh_failures"],
                    "ssh_successes": counters["ssh_successes"],
                    "priv_failures": counters["priv_failures"],
                    "priv_successes": counters["priv_successes"],
                    "next_check": next_check_time,
                    "priority": priority,
                    "response_time": response_time_ms,
                    "last_check": datetime.utcnow(),
                    "state_changed": state_changed,
                },
            )

            # Log to monitoring history
            overall_success = (
                ping_success and (ssh_success or not ping_success) and (privilege_success or not ssh_success)
            )
            self._log_history(
                host_id=host_id,
                check_time=datetime.utcnow(),
                monitoring_state=new_state.value,
                previous_state=current_state.value if state_changed else None,
                response_time_ms=response_time_ms,
                success=overall_success,
                error_message=error_message,
                error_type=error_type,
            )

            self.db.commit()

            if state_changed:
                logger.info(f"Host {host_id} state transition: {current_state.value} → {new_state.value}")

            return new_state, check_interval

        except Exception as e:
            logger.error(f"State transition failed for host {host_id}: {e}")
            self.db.rollback()
            return MonitoringState.UNKNOWN, self.config.unknown_interval

    def _calculate_new_state(
        self,
        current_state: MonitoringState,
        ping_success: bool,
        ssh_success: bool,
        privilege_success: bool,
        ping_failures: int,
        ping_successes: int,
        ssh_failures: int,
        ssh_successes: int,
        priv_failures: int,
        priv_successes: int,
    ) -> Tuple[MonitoringState, Dict]:
        """
        Calculate new state based on multi-level check results.

        Progressive state degradation model (matches UI):
        - 1 failure of ANY type → degraded
        - 2 consecutive failures → critical
        - 3 consecutive failures → down

        Counters track diagnostic details (which check failed) for troubleshooting,
        but state is determined by total consecutive failure count.

        Returns:
            Tuple of (new_state, counters_dict)
        """
        # Initialize new counters
        new_ping_failures = ping_failures
        new_ping_successes = ping_successes
        new_ssh_failures = ssh_failures
        new_ssh_successes = ssh_successes
        new_priv_failures = priv_failures
        new_priv_successes = priv_successes

        # Determine state based on check results
        # Track which specific check failed for diagnostics
        if not ping_success:
            # Ping failed - increment ping counter
            new_ping_failures += 1
            new_ping_successes = 0
            new_ssh_failures = 0
            new_ssh_successes = 0
            new_priv_failures = 0
            new_priv_successes = 0

        elif not ssh_success:
            # Ping succeeded but SSH failed - increment ssh counter
            new_ping_failures = 0
            new_ping_successes += 1
            new_ssh_failures += 1
            new_ssh_successes = 0
            new_priv_failures = 0
            new_priv_successes = 0

        elif not privilege_success:
            # SSH succeeded but privilege check failed - increment priv counter
            new_ping_failures = 0
            new_ping_successes += 1
            new_ssh_failures = 0
            new_ssh_successes += 1
            new_priv_failures += 1
            new_priv_successes = 0

        else:
            # All checks succeeded - reset all failure counters
            new_ping_failures = 0
            new_ping_successes += 1
            new_ssh_failures = 0
            new_ssh_successes += 1
            new_priv_failures = 0
            new_priv_successes += 1

        # Calculate total consecutive failures (sum of all failure types)
        total_failures = new_ping_failures + new_ssh_failures + new_priv_failures

        # Progressive state degradation based on total failure count
        if total_failures == 0:
            # All checks passed - transition to online after enough successes
            if (
                new_ping_successes >= self.config.successes_to_online
                and new_ssh_successes >= self.config.successes_to_online
                and new_priv_successes >= self.config.successes_to_online
            ):
                new_state = MonitoringState.ONLINE
            else:
                new_state = current_state  # Stay in current state until threshold
        elif total_failures == 1:
            # 1 failure → degraded
            new_state = MonitoringState.DEGRADED
        elif total_failures == 2:
            # 2 failures → critical
            new_state = MonitoringState.CRITICAL
        else:  # total_failures >= 3
            # 3+ failures → down
            new_state = MonitoringState.DOWN

        counters = {
            "ping_failures": new_ping_failures,
            "ping_successes": new_ping_successes,
            "ssh_failures": new_ssh_failures,
            "ssh_successes": new_ssh_successes,
            "priv_failures": new_priv_failures,
            "priv_successes": new_priv_successes,
        }

        return new_state, counters

    def _get_check_interval(self, state: MonitoringState) -> int:
        """Get check interval in minutes for a state"""
        intervals = {
            MonitoringState.ONLINE: self.config.online_interval,
            MonitoringState.DEGRADED: self.config.degraded_interval,
            MonitoringState.CRITICAL: self.config.critical_interval,
            MonitoringState.DOWN: self.config.down_interval,
            MonitoringState.UNKNOWN: self.config.unknown_interval,
            MonitoringState.MAINTENANCE: 0,  # No checks during maintenance
        }
        return intervals.get(state, self.config.online_interval)

    def _get_priority(self, state: MonitoringState) -> int:
        """Get Celery queue priority for a state"""
        priorities = {
            MonitoringState.ONLINE: self.config.online_priority,
            MonitoringState.DEGRADED: self.config.degraded_priority,
            MonitoringState.CRITICAL: self.config.critical_priority,
            MonitoringState.DOWN: self.config.down_priority,
            MonitoringState.UNKNOWN: self.config.unknown_priority,
            MonitoringState.MAINTENANCE: 1,  # Lowest priority
        }
        return priorities.get(state, self.config.online_priority)

    def _log_history(
        self,
        host_id: str,
        check_time: datetime,
        monitoring_state: str,
        previous_state: Optional[str],
        response_time_ms: Optional[int],
        success: bool,
        error_message: Optional[str],
        error_type: Optional[str],
    ):
        """Log monitoring check to history table"""
        try:
            self.db.execute(
                text(
                    """
                INSERT INTO host_monitoring_history
                (host_id, check_time, monitoring_state, previous_state, response_time_ms,
                 success, error_message, error_type)
                VALUES (:host_id, :check_time, :monitoring_state, :previous_state,
                        :response_time, :success, :error_message, :error_type)
            """
                ),
                {
                    "host_id": host_id,
                    "check_time": check_time,
                    "monitoring_state": monitoring_state,
                    "previous_state": previous_state,
                    "response_time": response_time_ms,
                    "success": success,
                    "error_message": error_message,
                    "error_type": error_type,
                },
            )
        except Exception as e:
            logger.warning(f"Failed to log monitoring history for {host_id}: {e}")

    def get_hosts_to_check(self, limit: int = 100) -> list:
        """
        Get hosts that need to be checked, ordered by priority and due time.

        Args:
            limit: Maximum number of hosts to return

        Returns:
            List of host dictionaries with id, hostname, ip_address, priority
        """
        try:
            result = self.db.execute(
                text(
                    """
                SELECT id, hostname, ip_address, check_priority, status
                FROM hosts
                WHERE is_active = true
                  AND status != 'maintenance'
                  AND (next_check_time IS NULL OR next_check_time <= CURRENT_TIMESTAMP)
                ORDER BY check_priority DESC, next_check_time ASC NULLS FIRST
                LIMIT :limit
            """
                ),
                {"limit": limit},
            )

            hosts = []
            for row in result:
                hosts.append(
                    {
                        "id": str(row.id),
                        "hostname": row.hostname,
                        "ip_address": row.ip_address,
                        "priority": row.check_priority,
                        "state": row.status,
                    }
                )

            return hosts

        except Exception as e:
            logger.error(f"Failed to get hosts to check: {e}")
            return []

    def set_maintenance_mode(self, host_id: str, enabled: bool):
        """Enable or disable maintenance mode for a host"""
        try:
            new_state = MonitoringState.MAINTENANCE.value if enabled else MonitoringState.UNKNOWN.value

            self.db.execute(
                text(
                    """
                UPDATE hosts
                SET status = :state,
                    ping_consecutive_failures = 0,
                    ping_consecutive_successes = 0,
                    ssh_consecutive_failures = 0,
                    ssh_consecutive_successes = 0,
                    privilege_consecutive_failures = 0,
                    privilege_consecutive_successes = 0,
                    last_state_change = CURRENT_TIMESTAMP
                WHERE id = :host_id
            """
                ),
                {"host_id": host_id, "state": new_state},
            )

            self.db.commit()
            logger.info(f"Host {host_id} maintenance mode: {'enabled' if enabled else 'disabled'}")

        except Exception as e:
            logger.error(f"Failed to set maintenance mode for {host_id}: {e}")
            self.db.rollback()
