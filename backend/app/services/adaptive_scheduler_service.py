"""
Adaptive Host Monitoring Scheduler Service

This service manages the configuration and execution of the adaptive Celery-based
host monitoring scheduler. It uses state-based check intervals to optimize resource
usage and enable rapid issue detection.

Architecture:
- Celery Beat schedules periodic dispatcher task
- Dispatcher queries hosts WHERE next_check_time <= NOW()
- Individual check tasks dispatched with state-based priority
- Results update host state and calculate next check time

State Transitions & Intervals:
- unknown (new hosts): immediate checks (priority 10)
- online (healthy): 15 min checks (priority 4)
- degraded (1 failure): 5 min checks (priority 6)
- critical (2 failures): 2 min checks (priority 8)
- down (3+ failures): 30 min checks (priority 2)
- maintenance: 60 min checks or skip (priority 1)
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import text

logger = logging.getLogger(__name__)


class AdaptiveSchedulerService:
    """Service for managing adaptive host monitoring scheduler configuration"""

    def __init__(self):
        self._config_cache: Optional[Dict] = None
        self._cache_timestamp: Optional[datetime] = None
        self._cache_ttl_seconds = 60  # Cache config for 1 minute

    def get_config(self, db: Session) -> Dict:
        """
        Get current scheduler configuration with caching.

        Returns:
            dict: Scheduler configuration with all intervals and settings
        """
        # Check cache validity
        if self._config_cache and self._cache_timestamp:
            cache_age = (datetime.utcnow() - self._cache_timestamp).total_seconds()
            if cache_age < self._cache_ttl_seconds:
                return self._config_cache

        try:
            result = db.execute(text("""
                SELECT
                    enabled,
                    interval_unknown,
                    interval_online,
                    interval_degraded,
                    interval_critical,
                    interval_down,
                    interval_maintenance,
                    maintenance_mode,
                    max_concurrent_checks,
                    check_timeout_seconds,
                    retry_on_failure,
                    priority_unknown,
                    priority_critical,
                    priority_degraded,
                    priority_online,
                    priority_down,
                    priority_maintenance
                FROM host_monitoring_config
                WHERE id = 1
            """))

            row = result.fetchone()
            if not row:
                # Return defaults if config doesn't exist
                return self._get_default_config()

            config = {
                'enabled': row.enabled,
                'intervals': {
                    'unknown': row.interval_unknown,
                    'online': row.interval_online,
                    'degraded': row.interval_degraded,
                    'critical': row.interval_critical,
                    'down': row.interval_down,
                    'maintenance': row.interval_maintenance,
                },
                'maintenance_mode': row.maintenance_mode,
                'max_concurrent_checks': row.max_concurrent_checks,
                'check_timeout_seconds': row.check_timeout_seconds,
                'retry_on_failure': row.retry_on_failure,
                'priorities': {
                    'unknown': row.priority_unknown,
                    'critical': row.priority_critical,
                    'degraded': row.priority_degraded,
                    'online': row.priority_online,
                    'down': row.priority_down,
                    'maintenance': row.priority_maintenance,
                }
            }

            # Update cache
            self._config_cache = config
            self._cache_timestamp = datetime.utcnow()

            return config

        except Exception as e:
            logger.error(f"Error loading scheduler config: {e}")
            return self._get_default_config()

    def update_config(
        self,
        db: Session,
        enabled: Optional[bool] = None,
        intervals: Optional[Dict[str, int]] = None,
        maintenance_mode: Optional[str] = None,
        max_concurrent_checks: Optional[int] = None,
        check_timeout_seconds: Optional[int] = None,
        retry_on_failure: Optional[bool] = None,
        user_id: Optional[int] = None
    ) -> Dict:
        """
        Update scheduler configuration.

        Args:
            db: Database session
            enabled: Enable/disable scheduler
            intervals: Dict of state intervals (e.g., {'online': 15, 'critical': 2})
            maintenance_mode: 'skip', 'passive', or 'reduced'
            max_concurrent_checks: Maximum concurrent check tasks
            check_timeout_seconds: Timeout for individual checks
            retry_on_failure: Whether to retry failed checks
            user_id: ID of user making the change

        Returns:
            dict: Updated configuration
        """
        try:
            updates = []
            params = {'updated_at': datetime.utcnow()}

            if enabled is not None:
                updates.append("enabled = :enabled")
                params['enabled'] = enabled

            if intervals:
                if 'unknown' in intervals:
                    updates.append("interval_unknown = :interval_unknown")
                    params['interval_unknown'] = intervals['unknown']
                if 'online' in intervals:
                    updates.append("interval_online = :interval_online")
                    params['interval_online'] = intervals['online']
                if 'degraded' in intervals:
                    updates.append("interval_degraded = :interval_degraded")
                    params['interval_degraded'] = intervals['degraded']
                if 'critical' in intervals:
                    updates.append("interval_critical = :interval_critical")
                    params['interval_critical'] = intervals['critical']
                if 'down' in intervals:
                    updates.append("interval_down = :interval_down")
                    params['interval_down'] = intervals['down']
                if 'maintenance' in intervals:
                    updates.append("interval_maintenance = :interval_maintenance")
                    params['interval_maintenance'] = intervals['maintenance']

            if maintenance_mode is not None:
                if maintenance_mode not in ['skip', 'passive', 'reduced']:
                    raise ValueError(f"Invalid maintenance_mode: {maintenance_mode}")
                updates.append("maintenance_mode = :maintenance_mode")
                params['maintenance_mode'] = maintenance_mode

            if max_concurrent_checks is not None:
                updates.append("max_concurrent_checks = :max_concurrent_checks")
                params['max_concurrent_checks'] = max_concurrent_checks

            if check_timeout_seconds is not None:
                updates.append("check_timeout_seconds = :check_timeout_seconds")
                params['check_timeout_seconds'] = check_timeout_seconds

            if retry_on_failure is not None:
                updates.append("retry_on_failure = :retry_on_failure")
                params['retry_on_failure'] = retry_on_failure

            if user_id is not None:
                updates.append("updated_by = :updated_by")
                params['updated_by'] = user_id

            if updates:
                updates.append("updated_at = :updated_at")
                query = f"UPDATE host_monitoring_config SET {', '.join(updates)} WHERE id = 1"
                db.execute(text(query), params)
                db.commit()

                # Invalidate cache
                self._config_cache = None
                self._cache_timestamp = None

                logger.info(f"Scheduler configuration updated by user {user_id}: {params}")

            return self.get_config(db)

        except Exception as e:
            logger.error(f"Error updating scheduler config: {e}")
            db.rollback()
            raise

    def get_interval_for_state(self, db: Session, state: str) -> int:
        """
        Get check interval (in minutes) for a given host state.

        Args:
            db: Database session
            state: Host state (online, degraded, critical, down, maintenance, unknown)

        Returns:
            int: Check interval in minutes
        """
        config = self.get_config(db)

        # Map status to interval key
        state_map = {
            'online': 'online',
            'degraded': 'degraded',
            'critical': 'critical',
            'down': 'down',
            'maintenance': 'maintenance',
            'unknown': 'unknown'
        }

        interval_key = state_map.get(state.lower(), 'online')
        return config['intervals'].get(interval_key, 15)

    def get_priority_for_state(self, db: Session, state: str) -> int:
        """
        Get Celery queue priority for a given host state.

        Args:
            db: Database session
            state: Host state (online, degraded, critical, down, maintenance, unknown)

        Returns:
            int: Priority (1-10, higher = more urgent)
        """
        config = self.get_config(db)

        state_map = {
            'online': 'online',
            'degraded': 'degraded',
            'critical': 'critical',
            'down': 'down',
            'maintenance': 'maintenance',
            'unknown': 'unknown'
        }

        priority_key = state_map.get(state.lower(), 'online')
        return config['priorities'].get(priority_key, 4)

    def calculate_next_check_time(self, db: Session, state: str) -> datetime:
        """
        Calculate next check time based on host state and configuration.

        Args:
            db: Database session
            state: Current host state

        Returns:
            datetime: Next check time
        """
        interval_minutes = self.get_interval_for_state(db, state)

        # Special handling for 'unknown' state - check immediately
        if state.lower() == 'unknown' or interval_minutes == 0:
            return datetime.utcnow()

        return datetime.utcnow() + timedelta(minutes=interval_minutes)

    def should_skip_maintenance_checks(self, db: Session) -> bool:
        """
        Check if maintenance hosts should skip monitoring checks.

        Returns:
            bool: True if maintenance checks should be skipped
        """
        config = self.get_config(db)
        return config['maintenance_mode'] == 'skip'

    def get_hosts_due_for_check(
        self,
        db: Session,
        limit: Optional[int] = None
    ) -> List[Dict]:
        """
        Get hosts that are due for monitoring checks.

        Args:
            db: Database session
            limit: Maximum number of hosts to return (uses max_concurrent_checks if None)

        Returns:
            List[dict]: Hosts due for checking, ordered by priority and next_check_time
        """
        config = self.get_config(db)

        if not config['enabled']:
            return []

        if limit is None:
            limit = config['max_concurrent_checks']

        try:
            # Build query based on maintenance mode
            maintenance_filter = ""
            if config['maintenance_mode'] == 'skip':
                maintenance_filter = "AND h.status != 'maintenance'"

            query = f"""
                SELECT
                    h.id,
                    h.hostname,
                    h.ip_address,
                    h.status,
                    h.next_check_time,
                    h.check_priority,
                    h.port,
                    h.username,
                    h.auth_method
                FROM hosts h
                WHERE h.is_active = true
                  AND (h.next_check_time IS NULL OR h.next_check_time <= :now)
                  {maintenance_filter}
                ORDER BY
                    h.check_priority DESC,  -- Higher priority first
                    h.next_check_time ASC   -- Older checks first
                LIMIT :limit
            """

            result = db.execute(
                text(query),
                {
                    'now': datetime.utcnow(),
                    'limit': limit
                }
            )

            hosts = []
            for row in result:
                hosts.append({
                    'id': str(row.id),
                    'hostname': row.hostname,
                    'ip_address': row.ip_address,
                    'status': row.status,
                    'next_check_time': row.next_check_time,
                    'check_priority': row.check_priority,
                    'port': row.port,
                    'username': row.username,
                    'auth_method': row.auth_method
                })

            return hosts

        except Exception as e:
            logger.error(f"Error getting hosts due for check: {e}")
            return []

    def get_scheduler_stats(self, db: Session) -> Dict:
        """
        Get real-time scheduler statistics.

        Returns:
            dict: Stats including hosts per state, overdue checks, etc.
        """
        try:
            # Get hosts by state
            state_result = db.execute(text("""
                SELECT status, COUNT(*) as count
                FROM hosts
                WHERE is_active = true
                GROUP BY status
            """))

            hosts_by_state = {row.status: row.count for row in state_result}

            # Get overdue hosts
            overdue_result = db.execute(text("""
                SELECT COUNT(*) as count
                FROM hosts
                WHERE is_active = true
                  AND next_check_time IS NOT NULL
                  AND next_check_time < :now
            """), {'now': datetime.utcnow()})

            overdue_count = overdue_result.fetchone().count

            # Get next check time
            next_check_result = db.execute(text("""
                SELECT MIN(next_check_time) as next_check
                FROM hosts
                WHERE is_active = true
                  AND next_check_time IS NOT NULL
            """))

            next_check_row = next_check_result.fetchone()
            next_check = next_check_row.next_check if next_check_row else None

            config = self.get_config(db)

            return {
                'enabled': config['enabled'],
                'hosts_by_state': hosts_by_state,
                'total_hosts': sum(hosts_by_state.values()),
                'overdue_checks': overdue_count,
                'next_check_time': next_check.isoformat() if next_check else None,
                'max_concurrent_checks': config['max_concurrent_checks'],
                'maintenance_mode': config['maintenance_mode']
            }

        except Exception as e:
            logger.error(f"Error getting scheduler stats: {e}")
            return {
                'enabled': False,
                'hosts_by_state': {},
                'total_hosts': 0,
                'overdue_checks': 0,
                'next_check_time': None
            }

    def _get_default_config(self) -> Dict:
        """Get default configuration when database config is unavailable"""
        return {
            'enabled': True,
            'intervals': {
                'unknown': 0,
                'online': 15,
                'degraded': 5,
                'critical': 2,
                'down': 30,
                'maintenance': 60,
            },
            'maintenance_mode': 'reduced',
            'max_concurrent_checks': 10,
            'check_timeout_seconds': 30,
            'retry_on_failure': True,
            'priorities': {
                'unknown': 10,
                'critical': 8,
                'degraded': 6,
                'online': 4,
                'down': 2,
                'maintenance': 1,
            }
        }


# Global service instance
adaptive_scheduler_service = AdaptiveSchedulerService()
