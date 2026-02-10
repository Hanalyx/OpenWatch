"""
Adaptive Compliance Scheduler Service

This service manages the configuration and execution of the adaptive Celery-based
compliance scanning scheduler. It uses compliance-state-based intervals to optimize
resource usage while ensuring continuous compliance visibility.

Architecture:
- Celery Beat schedules periodic dispatcher task (every 2 minutes)
- Dispatcher queries host_compliance_schedule WHERE next_scheduled_scan <= NOW()
- Individual Aegis scan tasks dispatched with state-based priority
- Results update compliance state and calculate next scan time (max 48 hours)

Compliance States & Intervals:
- unknown (new/never scanned): immediate scan (priority 10)
- compliant (100%): 24 hours (priority 3)
- mostly_compliant (80-99%): 12 hours (priority 4)
- partial (50-79%): 6 hours (priority 6)
- low (20-49%): 2 hours (priority 7)
- critical (<20% or critical findings): 1 hour (priority 9)
- maintenance: 48 hours or skip (priority 1)
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class ComplianceSchedulerService:
    """Service for managing adaptive compliance scanning scheduler"""

    def __init__(self) -> None:
        """Initialize compliance scheduler service with cache configuration."""
        self._config_cache: Optional[Dict[str, Any]] = None
        self._cache_timestamp: Optional[datetime] = None
        self._cache_ttl_seconds = 60  # Cache config for 1 minute

    def get_config(self, db: Session) -> Dict[str, Any]:
        """
        Get current scheduler configuration with caching.

        Returns:
            dict: Scheduler configuration with all intervals and settings
        """
        # Check cache validity
        if self._config_cache and self._cache_timestamp:
            cache_age = (datetime.now(timezone.utc) - self._cache_timestamp).total_seconds()
            if cache_age < self._cache_ttl_seconds:
                return self._config_cache

        try:
            result = db.execute(
                text(
                    """
                SELECT
                    enabled,
                    interval_compliant,
                    interval_mostly_compliant,
                    interval_partial,
                    interval_low,
                    interval_critical,
                    interval_unknown,
                    interval_maintenance,
                    max_interval_minutes,
                    priority_compliant,
                    priority_mostly_compliant,
                    priority_partial,
                    priority_low,
                    priority_critical,
                    priority_unknown,
                    priority_maintenance,
                    max_concurrent_scans,
                    scan_timeout_seconds
                FROM compliance_scheduler_config
                WHERE id = 1
            """
                )
            )

            row = result.fetchone()
            if not row:
                return self._get_default_config()

            config = {
                "enabled": row.enabled,
                "intervals": {
                    "compliant": row.interval_compliant,
                    "mostly_compliant": row.interval_mostly_compliant,
                    "partial": row.interval_partial,
                    "low": row.interval_low,
                    "critical": row.interval_critical,
                    "unknown": row.interval_unknown,
                    "maintenance": row.interval_maintenance,
                },
                "max_interval_minutes": row.max_interval_minutes,
                "priorities": {
                    "compliant": row.priority_compliant,
                    "mostly_compliant": row.priority_mostly_compliant,
                    "partial": row.priority_partial,
                    "low": row.priority_low,
                    "critical": row.priority_critical,
                    "unknown": row.priority_unknown,
                    "maintenance": row.priority_maintenance,
                },
                "max_concurrent_scans": row.max_concurrent_scans,
                "scan_timeout_seconds": row.scan_timeout_seconds,
            }

            # Update cache
            self._config_cache = config
            self._cache_timestamp = datetime.now(timezone.utc)

            return config

        except Exception as e:
            logger.error(f"Error loading compliance scheduler config: {e}")
            return self._get_default_config()

    def update_config(
        self,
        db: Session,
        enabled: Optional[bool] = None,
        intervals: Optional[Dict[str, int]] = None,
        max_concurrent_scans: Optional[int] = None,
        scan_timeout_seconds: Optional[int] = None,
        user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Update scheduler configuration.

        Args:
            db: Database session
            enabled: Enable/disable scheduler
            intervals: Dict of state intervals (e.g., {'compliant': 1440, 'critical': 60})
            max_concurrent_scans: Maximum concurrent scan tasks
            scan_timeout_seconds: Timeout for individual scans
            user_id: ID of user making the change

        Returns:
            dict: Updated configuration
        """
        try:
            updates = []
            params: Dict[str, Any] = {"updated_at": datetime.now(timezone.utc)}

            if enabled is not None:
                updates.append("enabled = :enabled")
                params["enabled"] = enabled

            if intervals:
                interval_fields = [
                    "compliant",
                    "mostly_compliant",
                    "partial",
                    "low",
                    "critical",
                    "unknown",
                    "maintenance",
                ]
                for field in interval_fields:
                    if field in intervals:
                        updates.append(f"interval_{field} = :interval_{field}")
                        params[f"interval_{field}"] = intervals[field]

            if max_concurrent_scans is not None:
                updates.append("max_concurrent_scans = :max_concurrent_scans")
                params["max_concurrent_scans"] = max_concurrent_scans

            if scan_timeout_seconds is not None:
                updates.append("scan_timeout_seconds = :scan_timeout_seconds")
                params["scan_timeout_seconds"] = scan_timeout_seconds

            if updates:
                updates.append("updated_at = :updated_at")
                query = f"UPDATE compliance_scheduler_config SET {', '.join(updates)} WHERE id = 1"
                db.execute(text(query), params)
                db.commit()

                # Invalidate cache
                self._config_cache = None
                self._cache_timestamp = None

                logger.info(f"Compliance scheduler config updated by user {user_id}")

            return self.get_config(db)

        except Exception as e:
            logger.error(f"Error updating compliance scheduler config: {e}")
            db.rollback()
            raise

    def get_compliance_state_from_score(self, score: Optional[float], has_critical: bool) -> str:
        """
        Determine compliance state from score and critical findings.

        Args:
            score: Compliance score (0-100) or None if never scanned
            has_critical: Whether host has critical findings

        Returns:
            str: Compliance state (compliant, mostly_compliant, partial, low, critical, unknown)
        """
        if score is None:
            return "unknown"

        if has_critical:
            return "critical"

        if score >= 100:
            return "compliant"
        elif score >= 80:
            return "mostly_compliant"
        elif score >= 50:
            return "partial"
        elif score >= 20:
            return "low"
        else:
            return "critical"

    def get_interval_for_state(self, db: Session, state: str) -> int:
        """
        Get scan interval (in minutes) for a given compliance state.

        Args:
            db: Database session
            state: Compliance state

        Returns:
            int: Scan interval in minutes (capped at max_interval_minutes)
        """
        config = self.get_config(db)
        interval = config["intervals"].get(state.lower(), 1440)

        # Enforce maximum interval (48 hours)
        max_interval = config["max_interval_minutes"]
        return min(interval, max_interval)

    def get_priority_for_state(self, db: Session, state: str) -> int:
        """
        Get Celery queue priority for a given compliance state.

        Args:
            db: Database session
            state: Compliance state

        Returns:
            int: Priority (1-10, higher = more urgent)
        """
        config = self.get_config(db)
        return config["priorities"].get(state.lower(), 5)

    def calculate_next_scan_time(self, db: Session, score: Optional[float], has_critical: bool) -> datetime:
        """
        Calculate next scan time based on compliance score and findings.

        Args:
            db: Database session
            score: Current compliance score
            has_critical: Whether host has critical findings

        Returns:
            datetime: Next scheduled scan time
        """
        state = self.get_compliance_state_from_score(score, has_critical)
        interval_minutes = self.get_interval_for_state(db, state)

        # Unknown state = immediate scan
        if state == "unknown" or interval_minutes == 0:
            return datetime.now(timezone.utc)

        return datetime.now(timezone.utc) + timedelta(minutes=interval_minutes)

    def get_hosts_due_for_scan(self, db: Session, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get hosts that are due for compliance scanning.

        Args:
            db: Database session
            limit: Maximum number of hosts to return

        Returns:
            List[dict]: Hosts due for scanning, ordered by priority and next_scheduled_scan
        """
        config = self.get_config(db)

        if not config["enabled"]:
            return []

        if limit is None:
            limit = config["max_concurrent_scans"]

        try:
            query = """
                SELECT
                    h.id as host_id,
                    h.hostname,
                    h.ip_address,
                    h.status as host_status,
                    hcs.compliance_score,
                    hcs.compliance_state,
                    hcs.has_critical_findings,
                    hcs.next_scheduled_scan,
                    hcs.scan_priority,
                    hcs.maintenance_mode,
                    hcs.last_scan_completed
                FROM hosts h
                LEFT JOIN host_compliance_schedule hcs ON h.id = hcs.host_id
                WHERE h.is_active = true
                  AND h.status != 'down'
                  AND (hcs.maintenance_mode IS NULL OR hcs.maintenance_mode = false)
                  AND (
                    hcs.next_scheduled_scan IS NULL
                    OR hcs.next_scheduled_scan <= :now
                  )
                ORDER BY
                    COALESCE(hcs.scan_priority, 10) DESC,
                    hcs.next_scheduled_scan ASC NULLS FIRST
                LIMIT :limit
            """

            result = db.execute(text(query), {"now": datetime.now(timezone.utc), "limit": limit})

            hosts = []
            for row in result:
                hosts.append(
                    {
                        "host_id": str(row.host_id),
                        "hostname": row.hostname,
                        "ip_address": row.ip_address,
                        "host_status": row.host_status,
                        "compliance_score": row.compliance_score,
                        "compliance_state": row.compliance_state or "unknown",
                        "has_critical_findings": row.has_critical_findings or False,
                        "next_scheduled_scan": row.next_scheduled_scan,
                        "scan_priority": row.scan_priority or 10,
                        "last_scan_completed": row.last_scan_completed,
                    }
                )

            return hosts

        except Exception as e:
            logger.error(f"Error getting hosts due for compliance scan: {e}")
            return []

    def update_host_schedule(
        self,
        db: Session,
        host_id: UUID,
        compliance_score: Optional[float],
        has_critical_findings: bool,
        pass_count: int,
        fail_count: int,
        scan_id: Optional[UUID] = None,
    ) -> None:
        """
        Update a host's compliance schedule after a scan completes.

        Args:
            db: Database session
            host_id: Host UUID
            compliance_score: New compliance score
            has_critical_findings: Whether scan found critical issues
            pass_count: Number of passing rules
            fail_count: Number of failing rules
            scan_id: ID of the completed scan
        """
        try:
            state = self.get_compliance_state_from_score(compliance_score, has_critical_findings)
            priority = self.get_priority_for_state(db, state)
            next_scan = self.calculate_next_scan_time(db, compliance_score, has_critical_findings)
            interval = self.get_interval_for_state(db, state)

            now = datetime.now(timezone.utc)

            # Upsert: insert or update
            query = """
                INSERT INTO host_compliance_schedule (
                    host_id, compliance_score, compliance_state,
                    has_critical_findings, pass_count, fail_count,
                    current_interval_minutes, next_scheduled_scan,
                    last_scan_completed, last_scan_id, scan_priority,
                    consecutive_scan_failures, updated_at
                ) VALUES (
                    :host_id, :score, :state,
                    :has_critical, :pass_count, :fail_count,
                    :interval, :next_scan,
                    :now, :scan_id, :priority,
                    0, :now
                )
                ON CONFLICT (host_id) DO UPDATE SET
                    compliance_score = :score,
                    compliance_state = :state,
                    has_critical_findings = :has_critical,
                    pass_count = :pass_count,
                    fail_count = :fail_count,
                    current_interval_minutes = :interval,
                    next_scheduled_scan = :next_scan,
                    last_scan_completed = :now,
                    last_scan_id = :scan_id,
                    scan_priority = :priority,
                    consecutive_scan_failures = 0,
                    updated_at = :now
            """

            db.execute(
                text(query),
                {
                    "host_id": str(host_id),
                    "score": compliance_score,
                    "state": state,
                    "has_critical": has_critical_findings,
                    "pass_count": pass_count,
                    "fail_count": fail_count,
                    "interval": interval,
                    "next_scan": next_scan,
                    "now": now,
                    "scan_id": str(scan_id) if scan_id else None,
                    "priority": priority,
                },
            )
            db.commit()

            logger.info(
                f"Updated compliance schedule for host {host_id}: "
                f"score={compliance_score}, state={state}, next_scan={next_scan}"
            )

        except Exception as e:
            logger.error(f"Error updating host compliance schedule: {e}")
            db.rollback()
            raise

    def record_scan_failure(self, db: Session, host_id: UUID, error: str) -> None:
        """
        Record a scan failure and update next scan time.

        Args:
            db: Database session
            host_id: Host UUID
            error: Error message
        """
        try:
            # Increment failure count and set retry time (5 minutes)
            query = """
                UPDATE host_compliance_schedule
                SET consecutive_scan_failures = consecutive_scan_failures + 1,
                    next_scheduled_scan = :next_scan,
                    updated_at = :now
                WHERE host_id = :host_id
            """

            db.execute(
                text(query),
                {
                    "host_id": str(host_id),
                    "next_scan": datetime.now(timezone.utc) + timedelta(minutes=5),
                    "now": datetime.now(timezone.utc),
                },
            )
            db.commit()

            logger.warning(f"Recorded scan failure for host {host_id}: {error}")

        except Exception as e:
            logger.error(f"Error recording scan failure: {e}")
            db.rollback()

    def initialize_host_schedule(self, db: Session, host_id: UUID) -> None:
        """
        Initialize compliance schedule for a new host (immediate scan).

        Args:
            db: Database session
            host_id: Host UUID
        """
        try:
            query = """
                INSERT INTO host_compliance_schedule (
                    host_id, compliance_state, scan_priority,
                    next_scheduled_scan, current_interval_minutes
                ) VALUES (
                    :host_id, 'unknown', 10,
                    :now, 0
                )
                ON CONFLICT (host_id) DO NOTHING
            """

            db.execute(
                text(query),
                {"host_id": str(host_id), "now": datetime.now(timezone.utc)},
            )
            db.commit()

            logger.info(f"Initialized compliance schedule for new host {host_id}")

        except Exception as e:
            logger.error(f"Error initializing host schedule: {e}")
            db.rollback()

    def set_maintenance_mode(
        self,
        db: Session,
        host_id: UUID,
        enabled: bool,
        until: Optional[datetime] = None,
    ) -> None:
        """
        Set maintenance mode for a host.

        Args:
            db: Database session
            host_id: Host UUID
            enabled: Enable or disable maintenance mode
            until: When maintenance mode should automatically end
        """
        try:
            query = """
                UPDATE host_compliance_schedule
                SET maintenance_mode = :enabled,
                    maintenance_until = :until,
                    updated_at = :now
                WHERE host_id = :host_id
            """

            db.execute(
                text(query),
                {
                    "host_id": str(host_id),
                    "enabled": enabled,
                    "until": until,
                    "now": datetime.now(timezone.utc),
                },
            )
            db.commit()

            logger.info(f"Set maintenance mode for host {host_id}: enabled={enabled}, until={until}")

        except Exception as e:
            logger.error(f"Error setting maintenance mode: {e}")
            db.rollback()
            raise

    def get_scheduler_stats(self, db: Session) -> Dict[str, Any]:
        """
        Get real-time scheduler statistics.

        Returns:
            dict: Stats including hosts per state, overdue scans, etc.
        """
        try:
            # Get hosts by compliance state
            state_result = db.execute(
                text(
                    """
                SELECT
                    COALESCE(hcs.compliance_state, 'unknown') as state,
                    COUNT(*) as count
                FROM hosts h
                LEFT JOIN host_compliance_schedule hcs ON h.id = hcs.host_id
                WHERE h.is_active = true
                GROUP BY hcs.compliance_state
            """
                )
            )

            hosts_by_state = {row.state: row.count for row in state_result}

            # Get overdue hosts
            overdue_result = db.execute(
                text(
                    """
                SELECT COUNT(*) as count
                FROM host_compliance_schedule hcs
                JOIN hosts h ON h.id = hcs.host_id
                WHERE h.is_active = true
                  AND hcs.maintenance_mode = false
                  AND hcs.next_scheduled_scan < :now
            """
                ),
                {"now": datetime.now(timezone.utc)},
            )

            overdue_count = overdue_result.fetchone().count

            # Get next scan time
            next_scan_result = db.execute(
                text(
                    """
                SELECT MIN(hcs.next_scheduled_scan) as next_scan
                FROM host_compliance_schedule hcs
                JOIN hosts h ON h.id = hcs.host_id
                WHERE h.is_active = true
                  AND hcs.maintenance_mode = false
                  AND hcs.next_scheduled_scan IS NOT NULL
            """
                )
            )

            next_scan_row = next_scan_result.fetchone()
            next_scan = next_scan_row.next_scan if next_scan_row else None

            # Get hosts in maintenance
            maintenance_result = db.execute(
                text(
                    """
                SELECT COUNT(*) as count
                FROM host_compliance_schedule
                WHERE maintenance_mode = true
            """
                )
            )

            maintenance_count = maintenance_result.fetchone().count

            config = self.get_config(db)

            return {
                "enabled": config["enabled"],
                "hosts_by_state": hosts_by_state,
                "total_hosts": sum(hosts_by_state.values()),
                "overdue_scans": overdue_count,
                "in_maintenance": maintenance_count,
                "next_scan_time": next_scan.isoformat() if next_scan else None,
                "max_concurrent_scans": config["max_concurrent_scans"],
                "max_interval_minutes": config["max_interval_minutes"],
            }

        except Exception as e:
            logger.error(f"Error getting scheduler stats: {e}")
            return {
                "enabled": False,
                "hosts_by_state": {},
                "total_hosts": 0,
                "overdue_scans": 0,
                "in_maintenance": 0,
                "next_scan_time": None,
            }

    def get_scheduler_status(self, db: Session) -> Dict[str, Any]:
        """
        Get current scheduler status including host counts and upcoming scans.

        Returns:
            dict: Status info for API response
        """
        try:
            stats = self.get_scheduler_stats(db)
            config = self.get_config(db)

            # Get next scheduled scans
            next_scans_result = db.execute(
                text(
                    """
                SELECT
                    h.id as host_id,
                    h.hostname,
                    hcs.compliance_state,
                    hcs.next_scheduled_scan
                FROM host_compliance_schedule hcs
                JOIN hosts h ON h.id = hcs.host_id
                WHERE h.is_active = true
                  AND hcs.maintenance_mode = false
                  AND hcs.next_scheduled_scan IS NOT NULL
                ORDER BY hcs.next_scheduled_scan ASC
                LIMIT 5
            """
                )
            )

            next_scans = [
                {
                    "host_id": str(row.host_id),
                    "hostname": row.hostname,
                    "compliance_state": row.compliance_state,
                    "scheduled_for": row.next_scheduled_scan.isoformat() if row.next_scheduled_scan else None,
                }
                for row in next_scans_result
            ]

            return {
                "enabled": config["enabled"],
                "total_hosts": stats["total_hosts"],
                "hosts_due": stats["overdue_scans"],
                "hosts_in_maintenance": stats["in_maintenance"],
                "by_compliance_state": stats["hosts_by_state"],
                "next_scheduled_scans": next_scans,
            }

        except Exception as e:
            logger.error(f"Error getting scheduler status: {e}")
            return {
                "enabled": False,
                "total_hosts": 0,
                "hosts_due": 0,
                "hosts_in_maintenance": 0,
                "by_compliance_state": {},
                "next_scheduled_scans": [],
            }

    def get_host_schedule(self, db: Session, host_id: UUID) -> Optional[Dict[str, Any]]:
        """
        Get compliance schedule details for a specific host.

        Args:
            db: Database session
            host_id: Host UUID

        Returns:
            dict: Schedule details or None if not found
        """
        try:
            result = db.execute(
                text(
                    """
                SELECT
                    h.id as host_id,
                    h.hostname,
                    hcs.compliance_score,
                    hcs.compliance_state,
                    hcs.has_critical_findings,
                    hcs.pass_count,
                    hcs.fail_count,
                    hcs.current_interval_minutes,
                    hcs.next_scheduled_scan,
                    hcs.last_scan_completed,
                    hcs.maintenance_mode,
                    hcs.maintenance_until,
                    hcs.scan_priority,
                    hcs.consecutive_scan_failures
                FROM hosts h
                LEFT JOIN host_compliance_schedule hcs ON h.id = hcs.host_id
                WHERE h.id = :host_id
            """
                ),
                {"host_id": str(host_id)},
            )

            row = result.fetchone()
            if not row:
                return None

            return {
                "host_id": str(row.host_id),
                "hostname": row.hostname,
                "compliance_score": row.compliance_score,
                "compliance_state": row.compliance_state or "unknown",
                "has_critical_findings": row.has_critical_findings or False,
                "pass_count": row.pass_count,
                "fail_count": row.fail_count,
                "current_interval_minutes": row.current_interval_minutes or 1440,
                "next_scheduled_scan": row.next_scheduled_scan,
                "last_scan_completed": row.last_scan_completed,
                "maintenance_mode": row.maintenance_mode or False,
                "maintenance_until": row.maintenance_until,
                "scan_priority": row.scan_priority or 5,
                "consecutive_scan_failures": row.consecutive_scan_failures or 0,
            }

        except Exception as e:
            logger.error(f"Error getting host schedule: {e}")
            return None

    def set_host_maintenance_mode(
        self,
        db: Session,
        host_id: UUID,
        enabled: bool,
        maintenance_until: Optional[datetime] = None,
    ) -> None:
        """
        Set maintenance mode for a host.

        Alias for set_maintenance_mode with different parameter name.

        Args:
            db: Database session
            host_id: Host UUID
            enabled: Enable or disable maintenance mode
            maintenance_until: When maintenance mode should automatically end
        """
        self.set_maintenance_mode(db, host_id, enabled, maintenance_until)

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration when database config is unavailable"""
        return {
            "enabled": True,
            "intervals": {
                "compliant": 1440,  # 24 hours
                "mostly_compliant": 720,  # 12 hours
                "partial": 360,  # 6 hours
                "low": 120,  # 2 hours
                "critical": 60,  # 1 hour
                "unknown": 0,  # Immediate
                "maintenance": 2880,  # 48 hours
            },
            "max_interval_minutes": 2880,  # 48 hours
            "priorities": {
                "compliant": 3,
                "mostly_compliant": 4,
                "partial": 6,
                "low": 7,
                "critical": 9,
                "unknown": 10,
                "maintenance": 1,
            },
            "max_concurrent_scans": 5,
            "scan_timeout_seconds": 600,
        }


# Global service instance
compliance_scheduler_service = ComplianceSchedulerService()
