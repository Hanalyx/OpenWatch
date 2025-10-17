"""
Host Monitoring State Machine
Implements adaptive monitoring with state-based check intervals
"""
import logging
from enum import Enum
from datetime import datetime, timedelta
from typing import Dict, Tuple, Optional
from dataclasses import dataclass
from sqlalchemy.orm import Session
from sqlalchemy import text

logger = logging.getLogger(__name__)


class MonitoringState(Enum):
    """Host monitoring states with different check intervals"""
    HEALTHY = "HEALTHY"          # 30 min interval - stable host
    DEGRADED = "DEGRADED"        # 5 min interval - showing issues
    CRITICAL = "CRITICAL"        # 2 min interval - repeated failures
    DOWN = "DOWN"                # 30 min interval - confirmed down
    MAINTENANCE = "MAINTENANCE"  # No checks - user-defined maintenance window


@dataclass
class StateTransitionConfig:
    """Configuration for state transitions"""
    # Thresholds
    failures_to_degraded: int = 1      # 1 failure: HEALTHY → DEGRADED
    failures_to_critical: int = 2      # 2 consecutive: DEGRADED → CRITICAL
    failures_to_down: int = 3          # 3 consecutive: CRITICAL → DOWN
    successes_to_healthy: int = 3      # 3 consecutive: any → HEALTHY
    successes_to_degraded: int = 1     # 1 success: CRITICAL/DOWN → DEGRADED

    # Check intervals (minutes)
    healthy_interval: int = 30
    degraded_interval: int = 5
    critical_interval: int = 2
    down_interval: int = 30

    # Priority levels for Celery queue (1-10, higher = more urgent)
    healthy_priority: int = 3
    degraded_priority: int = 6
    critical_priority: int = 9
    down_priority: int = 4


class HostMonitoringStateMachine:
    """Manages host monitoring state transitions and adaptive intervals"""

    def __init__(self, db: Session, config: Optional[StateTransitionConfig] = None):
        self.db = db
        self.config = config or StateTransitionConfig()

    def transition_state(self, host_id: str, check_success: bool,
                        response_time_ms: Optional[int] = None,
                        error_message: Optional[str] = None,
                        error_type: Optional[str] = None) -> Tuple[MonitoringState, int]:
        """
        Process check result and transition to new state if needed.

        Args:
            host_id: UUID of the host
            check_success: Whether the check succeeded
            response_time_ms: Response time in milliseconds
            error_message: Error message if check failed
            error_type: Type of error (TIMEOUT, CONNECTION_REFUSED, etc.)

        Returns:
            Tuple of (new_state, next_check_interval_minutes)
        """
        try:
            # Get current host state
            result = self.db.execute(text("""
                SELECT monitoring_state, consecutive_failures, consecutive_successes
                FROM hosts
                WHERE id = :host_id
            """), {"host_id": host_id})

            row = result.fetchone()
            if not row:
                logger.error(f"Host {host_id} not found for state transition")
                return MonitoringState.HEALTHY, self.config.healthy_interval

            current_state = MonitoringState(row.monitoring_state)
            consecutive_failures = row.consecutive_failures
            consecutive_successes = row.consecutive_successes

            # Calculate new state based on check result
            if check_success:
                new_state, new_failures, new_successes = self._handle_success(
                    current_state, consecutive_failures, consecutive_successes
                )
            else:
                new_state, new_failures, new_successes = self._handle_failure(
                    current_state, consecutive_failures, consecutive_successes
                )

            # Get check interval and priority for new state
            check_interval = self._get_check_interval(new_state)
            priority = self._get_priority(new_state)
            next_check_time = datetime.utcnow() + timedelta(minutes=check_interval)

            # Update host state in database
            state_changed = new_state != current_state
            self.db.execute(text("""
                UPDATE hosts
                SET monitoring_state = :state,
                    consecutive_failures = :failures,
                    consecutive_successes = :successes,
                    next_check_time = :next_check,
                    check_priority = :priority,
                    response_time_ms = :response_time,
                    last_check = :last_check,
                    last_state_change = CASE WHEN :state_changed THEN :last_check ELSE last_state_change END,
                    status = :status,
                    updated_at = :last_check
                WHERE id = :host_id
            """), {
                "host_id": host_id,
                "state": new_state.value,
                "failures": new_failures,
                "successes": new_successes,
                "next_check": next_check_time,
                "priority": priority,
                "response_time": response_time_ms,
                "last_check": datetime.utcnow(),
                "state_changed": state_changed,
                "status": "online" if check_success else "offline"
            })

            # Log to monitoring history
            self._log_history(
                host_id=host_id,
                check_time=datetime.utcnow(),
                monitoring_state=new_state.value,
                previous_state=current_state.value if state_changed else None,
                response_time_ms=response_time_ms,
                success=check_success,
                error_message=error_message,
                error_type=error_type
            )

            self.db.commit()

            if state_changed:
                logger.info(f"Host {host_id} state transition: {current_state.value} → {new_state.value}")

            return new_state, check_interval

        except Exception as e:
            logger.error(f"State transition failed for host {host_id}: {e}")
            self.db.rollback()
            return MonitoringState.HEALTHY, self.config.healthy_interval

    def _handle_success(self, current_state: MonitoringState,
                       consecutive_failures: int, consecutive_successes: int) -> Tuple[MonitoringState, int, int]:
        """Handle successful check and determine new state"""
        new_successes = consecutive_successes + 1
        new_failures = 0  # Reset failures on success

        # State transitions on success
        if new_successes >= self.config.successes_to_healthy:
            return MonitoringState.HEALTHY, new_failures, new_successes
        elif current_state in [MonitoringState.CRITICAL, MonitoringState.DOWN]:
            if new_successes >= self.config.successes_to_degraded:
                return MonitoringState.DEGRADED, new_failures, new_successes

        # Stay in current state
        return current_state, new_failures, new_successes

    def _handle_failure(self, current_state: MonitoringState,
                       consecutive_failures: int, consecutive_successes: int) -> Tuple[MonitoringState, int, int]:
        """Handle failed check and determine new state"""
        new_failures = consecutive_failures + 1
        new_successes = 0  # Reset successes on failure

        # State transitions on failure
        if current_state == MonitoringState.HEALTHY:
            if new_failures >= self.config.failures_to_degraded:
                return MonitoringState.DEGRADED, new_failures, new_successes
        elif current_state == MonitoringState.DEGRADED:
            if new_failures >= self.config.failures_to_critical:
                return MonitoringState.CRITICAL, new_failures, new_successes
        elif current_state == MonitoringState.CRITICAL:
            if new_failures >= self.config.failures_to_down:
                return MonitoringState.DOWN, new_failures, new_successes

        # Stay in current state
        return current_state, new_failures, new_successes

    def _get_check_interval(self, state: MonitoringState) -> int:
        """Get check interval in minutes for a state"""
        intervals = {
            MonitoringState.HEALTHY: self.config.healthy_interval,
            MonitoringState.DEGRADED: self.config.degraded_interval,
            MonitoringState.CRITICAL: self.config.critical_interval,
            MonitoringState.DOWN: self.config.down_interval,
            MonitoringState.MAINTENANCE: 0  # No checks during maintenance
        }
        return intervals.get(state, self.config.healthy_interval)

    def _get_priority(self, state: MonitoringState) -> int:
        """Get Celery queue priority for a state"""
        priorities = {
            MonitoringState.HEALTHY: self.config.healthy_priority,
            MonitoringState.DEGRADED: self.config.degraded_priority,
            MonitoringState.CRITICAL: self.config.critical_priority,
            MonitoringState.DOWN: self.config.down_priority,
            MonitoringState.MAINTENANCE: 1  # Lowest priority
        }
        return priorities.get(state, self.config.healthy_priority)

    def _log_history(self, host_id: str, check_time: datetime, monitoring_state: str,
                    previous_state: Optional[str], response_time_ms: Optional[int],
                    success: bool, error_message: Optional[str], error_type: Optional[str]):
        """Log monitoring check to history table"""
        try:
            self.db.execute(text("""
                INSERT INTO host_monitoring_history
                (host_id, check_time, monitoring_state, previous_state, response_time_ms,
                 success, error_message, error_type)
                VALUES (:host_id, :check_time, :monitoring_state, :previous_state,
                        :response_time, :success, :error_message, :error_type)
            """), {
                "host_id": host_id,
                "check_time": check_time,
                "monitoring_state": monitoring_state,
                "previous_state": previous_state,
                "response_time": response_time_ms,
                "success": success,
                "error_message": error_message,
                "error_type": error_type
            })
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
            result = self.db.execute(text("""
                SELECT id, hostname, ip_address, check_priority, monitoring_state
                FROM hosts
                WHERE is_active = true
                  AND monitoring_state != 'MAINTENANCE'
                  AND (next_check_time IS NULL OR next_check_time <= CURRENT_TIMESTAMP)
                ORDER BY check_priority DESC, next_check_time ASC NULLS FIRST
                LIMIT :limit
            """), {"limit": limit})

            hosts = []
            for row in result:
                hosts.append({
                    "id": str(row.id),
                    "hostname": row.hostname,
                    "ip_address": row.ip_address,
                    "priority": row.check_priority,
                    "state": row.monitoring_state
                })

            return hosts

        except Exception as e:
            logger.error(f"Failed to get hosts to check: {e}")
            return []

    def set_maintenance_mode(self, host_id: str, enabled: bool):
        """Enable or disable maintenance mode for a host"""
        try:
            new_state = MonitoringState.MAINTENANCE.value if enabled else MonitoringState.HEALTHY.value

            self.db.execute(text("""
                UPDATE hosts
                SET monitoring_state = :state,
                    consecutive_failures = 0,
                    consecutive_successes = 0,
                    last_state_change = CURRENT_TIMESTAMP
                WHERE id = :host_id
            """), {"host_id": host_id, "state": new_state})

            self.db.commit()
            logger.info(f"Host {host_id} maintenance mode: {'enabled' if enabled else 'disabled'}")

        except Exception as e:
            logger.error(f"Failed to set maintenance mode for {host_id}: {e}")
            self.db.rollback()
