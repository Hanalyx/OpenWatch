"""
Alert Service for OpenWatch Compliance Alerting

Provides alert management functionality:
- Creating alerts based on compliance events
- Listing, acknowledging, and resolving alerts
- Alert deduplication to prevent alert storms
- Alert statistics for dashboard

Part of OpenWatch OS Transformation - Alert Thresholds (doc 03).
"""

import logging
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Optional
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class AlertType(str, Enum):
    """Types of alerts that can be generated."""

    # Compliance alerts
    CRITICAL_FINDING = "critical_finding"
    HIGH_FINDING = "high_finding"
    SCORE_DROP = "score_drop"
    NON_COMPLIANT = "non_compliant"
    DEGRADING_TREND = "degrading_trend"

    # Operational alerts
    HOST_UNREACHABLE = "host_unreachable"
    SCAN_FAILED = "scan_failed"
    SCHEDULER_STOPPED = "scheduler_stopped"
    SCAN_BACKLOG = "scan_backlog"
    HOST_NOT_SCANNED = "host_not_scanned"

    # Exception alerts
    EXCEPTION_EXPIRING = "exception_expiring"
    EXCEPTION_EXPIRED = "exception_expired"
    EXCEPTION_REQUESTED = "exception_requested"

    # Drift alerts
    CONFIGURATION_DRIFT = "configuration_drift"
    UNEXPECTED_REMEDIATION = "unexpected_remediation"
    MASS_DRIFT = "mass_drift"


class AlertSeverity(str, Enum):
    """Alert severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, Enum):
    """Alert status values."""

    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


# Default alert thresholds
DEFAULT_THRESHOLDS = {
    "compliance": {
        "critical_finding": True,
        "high_finding": True,
        "medium_finding": False,
        "low_finding": False,
        "score_drop_threshold": 20,
        "score_drop_window_hours": 24,
        "non_compliant_threshold": 80,
        "degrading_trend_scans": 3,
    },
    "operational": {
        "unreachable_checks": 3,
        "max_scan_age_hours": 48,
        "scan_queue_threshold": 20,
        "scan_queue_age_minutes": 60,
    },
    "exceptions": {
        "expiry_warning_days": 7,
    },
    "drift": {
        "mass_drift_threshold": 10,
    },
}


class AlertService:
    """Service for managing compliance alerts."""

    def __init__(self, db: Session):
        """Initialize with database session."""
        self.db = db

    def create_alert(
        self,
        alert_type: AlertType,
        severity: AlertSeverity,
        title: str,
        message: Optional[str] = None,
        host_id: Optional[UUID] = None,
        host_group_id: Optional[int] = None,
        rule_id: Optional[str] = None,
        scan_id: Optional[UUID] = None,
        metadata: Optional[Dict[str, Any]] = None,
        dedupe_window_minutes: int = 60,
    ) -> Optional[Dict[str, Any]]:
        """
        Create a new alert with deduplication.

        Args:
            alert_type: Type of alert
            severity: Alert severity level
            title: Alert title
            message: Optional detailed message
            host_id: Optional host UUID
            host_group_id: Optional host group ID
            rule_id: Optional rule ID for finding alerts
            scan_id: Optional scan UUID
            metadata: Optional additional context
            dedupe_window_minutes: Window for deduplication (default 60 min)

        Returns:
            Created alert dict, or None if deduplicated
        """
        # Check for duplicate alert within window
        if self._is_duplicate(alert_type, host_id, rule_id, dedupe_window_minutes):
            logger.debug(f"Skipping duplicate alert: {alert_type} for host {host_id}, rule {rule_id}")
            return None

        # Insert alert
        insert_query = text(
            """
            INSERT INTO alerts (
                alert_type, severity, title, message,
                host_id, host_group_id, rule_id, scan_id,
                metadata, status
            ) VALUES (
                :alert_type, :severity, :title, :message,
                :host_id, :host_group_id, :rule_id, :scan_id,
                :metadata, 'active'
            )
            RETURNING id, created_at
            """
        )

        result = self.db.execute(
            insert_query,
            {
                "alert_type": alert_type.value,
                "severity": severity.value,
                "title": title,
                "message": message,
                "host_id": str(host_id) if host_id else None,
                "host_group_id": host_group_id,
                "rule_id": rule_id,
                "scan_id": str(scan_id) if scan_id else None,
                "metadata": metadata,
            },
        )
        row = result.fetchone()
        self.db.commit()

        logger.info(f"Created {severity.value} alert: {title} (type={alert_type.value}, host={host_id})")

        return {
            "id": str(row.id),
            "alert_type": alert_type.value,
            "severity": severity.value,
            "title": title,
            "message": message,
            "host_id": str(host_id) if host_id else None,
            "host_group_id": host_group_id,
            "rule_id": rule_id,
            "scan_id": str(scan_id) if scan_id else None,
            "status": "active",
            "created_at": row.created_at.isoformat(),
        }

    def _is_duplicate(
        self,
        alert_type: AlertType,
        host_id: Optional[UUID],
        rule_id: Optional[str],
        window_minutes: int,
    ) -> bool:
        """Check if a similar alert exists within the deduplication window."""
        query = text(
            """
            SELECT COUNT(*) FROM alerts
            WHERE alert_type = :alert_type
              AND status = 'active'
              AND created_at > :window_start
              AND (
                (:host_id IS NULL AND host_id IS NULL)
                OR host_id = :host_id
              )
              AND (
                (:rule_id IS NULL AND rule_id IS NULL)
                OR rule_id = :rule_id
              )
            """
        )

        window_start = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        result = self.db.execute(
            query,
            {
                "alert_type": alert_type.value,
                "host_id": str(host_id) if host_id else None,
                "rule_id": rule_id,
                "window_start": window_start,
            },
        )
        count = result.scalar()
        return count > 0

    def list_alerts(
        self,
        page: int = 1,
        per_page: int = 20,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        alert_type: Optional[str] = None,
        host_id: Optional[UUID] = None,
    ) -> Dict[str, Any]:
        """
        List alerts with filtering and pagination.

        Args:
            page: Page number (1-indexed)
            per_page: Items per page
            status: Filter by status
            severity: Filter by severity
            alert_type: Filter by type
            host_id: Filter by host

        Returns:
            Dictionary with alerts list and pagination info
        """
        # Calculate offset
        offset = (page - 1) * per_page

        # Build WHERE clause
        conditions = []
        params: Dict[str, Any] = {"limit": per_page, "offset": offset}

        if status:
            conditions.append("status = :status")
            params["status"] = status

        if severity:
            conditions.append("severity = :severity")
            params["severity"] = severity

        if alert_type:
            conditions.append("alert_type = :alert_type")
            params["alert_type"] = alert_type

        if host_id:
            conditions.append("host_id = :host_id")
            params["host_id"] = str(host_id)

        where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""

        # Get total count
        count_query = text(f"SELECT COUNT(*) FROM alerts {where_clause}")
        total = self.db.execute(count_query, params).scalar() or 0

        # Get alerts with host info
        query = text(
            f"""
            SELECT
                a.id, a.alert_type, a.severity, a.title, a.message,
                a.host_id, a.host_group_id, a.rule_id, a.scan_id,
                a.status, a.acknowledged_by, a.acknowledged_at,
                a.resolved_at, a.metadata, a.created_at,
                h.hostname
            FROM alerts a
            LEFT JOIN hosts h ON a.host_id = h.id
            {where_clause}
            ORDER BY
                CASE a.severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                a.created_at DESC
            LIMIT :limit OFFSET :offset
            """
        )

        result = self.db.execute(query, params)
        alerts = []
        for row in result.fetchall():
            alerts.append(
                {
                    "id": str(row.id),
                    "alert_type": row.alert_type,
                    "severity": row.severity,
                    "title": row.title,
                    "message": row.message,
                    "host_id": str(row.host_id) if row.host_id else None,
                    "hostname": row.hostname,
                    "host_group_id": row.host_group_id,
                    "rule_id": row.rule_id,
                    "scan_id": str(row.scan_id) if row.scan_id else None,
                    "status": row.status,
                    "acknowledged_by": row.acknowledged_by,
                    "acknowledged_at": (row.acknowledged_at.isoformat() if row.acknowledged_at else None),
                    "resolved_at": row.resolved_at.isoformat() if row.resolved_at else None,
                    "metadata": row.metadata,
                    "created_at": row.created_at.isoformat(),
                }
            )

        total_pages = (total + per_page - 1) // per_page if total > 0 else 1

        return {
            "items": alerts,
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
        }

    def get_alert(self, alert_id: UUID) -> Optional[Dict[str, Any]]:
        """Get a single alert by ID."""
        query = text(
            """
            SELECT
                a.id, a.alert_type, a.severity, a.title, a.message,
                a.host_id, a.host_group_id, a.rule_id, a.scan_id,
                a.status, a.acknowledged_by, a.acknowledged_at,
                a.resolved_at, a.metadata, a.created_at,
                h.hostname, u.username as acknowledged_by_username
            FROM alerts a
            LEFT JOIN hosts h ON a.host_id = h.id
            LEFT JOIN users u ON a.acknowledged_by = u.id
            WHERE a.id = :alert_id
            """
        )

        result = self.db.execute(query, {"alert_id": str(alert_id)})
        row = result.fetchone()

        if not row:
            return None

        return {
            "id": str(row.id),
            "alert_type": row.alert_type,
            "severity": row.severity,
            "title": row.title,
            "message": row.message,
            "host_id": str(row.host_id) if row.host_id else None,
            "hostname": row.hostname,
            "host_group_id": row.host_group_id,
            "rule_id": row.rule_id,
            "scan_id": str(row.scan_id) if row.scan_id else None,
            "status": row.status,
            "acknowledged_by": row.acknowledged_by,
            "acknowledged_by_username": row.acknowledged_by_username,
            "acknowledged_at": row.acknowledged_at.isoformat() if row.acknowledged_at else None,
            "resolved_at": row.resolved_at.isoformat() if row.resolved_at else None,
            "metadata": row.metadata,
            "created_at": row.created_at.isoformat(),
        }

    def acknowledge_alert(self, alert_id: UUID, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Acknowledge an alert.

        Args:
            alert_id: Alert UUID
            user_id: ID of user acknowledging

        Returns:
            Updated alert dict, or None if not found
        """
        query = text(
            """
            UPDATE alerts
            SET status = 'acknowledged',
                acknowledged_by = :user_id,
                acknowledged_at = :now
            WHERE id = :alert_id AND status = 'active'
            RETURNING id
            """
        )

        result = self.db.execute(
            query,
            {
                "alert_id": str(alert_id),
                "user_id": user_id,
                "now": datetime.now(timezone.utc),
            },
        )
        row = result.fetchone()
        self.db.commit()

        if not row:
            return None

        logger.info(f"Alert {alert_id} acknowledged by user {user_id}")
        return self.get_alert(alert_id)

    def resolve_alert(self, alert_id: UUID) -> Optional[Dict[str, Any]]:
        """
        Resolve an alert.

        Args:
            alert_id: Alert UUID

        Returns:
            Updated alert dict, or None if not found
        """
        query = text(
            """
            UPDATE alerts
            SET status = 'resolved',
                resolved_at = :now
            WHERE id = :alert_id AND status IN ('active', 'acknowledged')
            RETURNING id
            """
        )

        result = self.db.execute(
            query,
            {
                "alert_id": str(alert_id),
                "now": datetime.now(timezone.utc),
            },
        )
        row = result.fetchone()
        self.db.commit()

        if not row:
            return None

        logger.info(f"Alert {alert_id} resolved")
        return self.get_alert(alert_id)

    def get_stats(self) -> Dict[str, Any]:
        """
        Get alert statistics for dashboard.

        Returns:
            Dictionary with alert counts by status and severity
        """
        query = text(
            """
            SELECT
                COUNT(*) FILTER (WHERE status = 'active') as active_count,
                COUNT(*) FILTER (WHERE status = 'acknowledged') as acknowledged_count,
                COUNT(*) FILTER (WHERE status = 'resolved') as resolved_count,
                COUNT(*) FILTER (WHERE status = 'active' AND severity = 'critical') as critical_count,
                COUNT(*) FILTER (WHERE status = 'active' AND severity = 'high') as high_count,
                COUNT(*) FILTER (WHERE status = 'active' AND severity = 'medium') as medium_count,
                COUNT(*) FILTER (WHERE status = 'active' AND severity = 'low') as low_count,
                COUNT(*) FILTER (WHERE status = 'active' AND severity = 'info') as info_count
            FROM alerts
            """
        )

        result = self.db.execute(query)
        row = result.fetchone()

        # Get recent alerts (last 24h)
        recent_query = text(
            """
            SELECT
                a.id, a.alert_type, a.severity, a.title, a.host_id,
                a.created_at, h.hostname
            FROM alerts a
            LEFT JOIN hosts h ON a.host_id = h.id
            WHERE a.status = 'active'
              AND a.created_at > :since
            ORDER BY a.created_at DESC
            LIMIT 5
            """
        )

        recent_result = self.db.execute(
            recent_query,
            {"since": datetime.now(timezone.utc) - timedelta(hours=24)},
        )

        recent_alerts = []
        for r in recent_result.fetchall():
            recent_alerts.append(
                {
                    "id": str(r.id),
                    "alert_type": r.alert_type,
                    "severity": r.severity,
                    "title": r.title,
                    "hostname": r.hostname,
                    "created_at": r.created_at.isoformat(),
                }
            )

        # Get by_type counts
        type_query = text(
            """
            SELECT alert_type, COUNT(*) as count
            FROM alerts
            WHERE status = 'active'
            GROUP BY alert_type
            """
        )
        type_result = self.db.execute(type_query)
        by_type = {r.alert_type: r.count for r in type_result.fetchall()}

        # Get recent 24h count
        recent_count_query = text(
            """
            SELECT COUNT(*) FROM alerts WHERE created_at > :since
            """
        )
        recent_count = (
            self.db.execute(
                recent_count_query,
                {"since": datetime.now(timezone.utc) - timedelta(hours=24)},
            ).scalar()
            or 0
        )

        return {
            "total_active": row.active_count or 0,
            "total_acknowledged": row.acknowledged_count or 0,
            "total_resolved": row.resolved_count or 0,
            "by_severity": {
                "critical": row.critical_count or 0,
                "high": row.high_count or 0,
                "medium": row.medium_count or 0,
                "low": row.low_count or 0,
                "info": row.info_count or 0,
            },
            "by_type": by_type,
            "recent_24h": recent_count,
            "recent_alerts": recent_alerts,
        }

    def get_thresholds(self, host_id: Optional[UUID] = None, host_group_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Get alert thresholds, with optional host/group overrides.

        Args:
            host_id: Optional host UUID for host-specific settings
            host_group_id: Optional host group ID for group-specific settings

        Returns:
            Merged threshold settings (defaults + overrides)
        """
        # alert_settings table currently uses user-scoped schema
        # (user_id, alert_type) and has no settings, host_id, or
        # host_group_id columns. Host-scoped threshold overrides will be
        # added in a future migration. Return defaults for now.
        return DEFAULT_THRESHOLDS.copy()

    def _merge_settings(self, defaults: Dict[str, Any], overrides: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively merge override settings into defaults."""
        result = defaults.copy()
        for key, value in overrides.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_settings(result[key], value)
            else:
                result[key] = value
        return result

    def update_thresholds(
        self,
        settings: Dict[str, Any],
        host_id: Optional[UUID] = None,
        host_group_id: Optional[int] = None,
    ) -> None:
        """
        Update alert threshold settings.

        Creates or updates settings for global, host-specific, or group-specific scope.

        Args:
            settings: New settings to apply
            host_id: Optional host UUID for host-specific settings
            host_group_id: Optional host group ID for group-specific settings
        """
        import json

        if host_id:
            # Host-specific settings
            upsert_query = text(
                """
                INSERT INTO alert_settings (host_id, settings, updated_at)
                VALUES (:host_id, :settings, :now)
                ON CONFLICT (host_id) WHERE host_id IS NOT NULL
                DO UPDATE SET settings = :settings, updated_at = :now
                """
            )
            self.db.execute(
                upsert_query,
                {
                    "host_id": str(host_id),
                    "settings": json.dumps(settings),
                    "now": datetime.now(timezone.utc),
                },
            )
        elif host_group_id:
            # Host group-specific settings
            upsert_query = text(
                """
                INSERT INTO alert_settings (host_group_id, settings, updated_at)
                VALUES (:host_group_id, :settings, :now)
                ON CONFLICT (host_group_id) WHERE host_group_id IS NOT NULL
                DO UPDATE SET settings = :settings, updated_at = :now
                """
            )
            self.db.execute(
                upsert_query,
                {
                    "host_group_id": host_group_id,
                    "settings": json.dumps(settings),
                    "now": datetime.now(timezone.utc),
                },
            )
        else:
            # Global settings - use NULL for both host_id and host_group_id
            # Check if global settings exist
            check_query = text("SELECT id FROM alert_settings WHERE host_id IS NULL AND host_group_id IS NULL")
            result = self.db.execute(check_query)
            row = result.fetchone()

            if row:
                # Update existing global settings
                update_query = text(
                    """
                    UPDATE alert_settings
                    SET settings = :settings, updated_at = :now
                    WHERE host_id IS NULL AND host_group_id IS NULL
                    """
                )
                self.db.execute(
                    update_query,
                    {
                        "settings": json.dumps(settings),
                        "now": datetime.now(timezone.utc),
                    },
                )
            else:
                # Insert new global settings
                insert_query = text(
                    """
                    INSERT INTO alert_settings (settings, updated_at)
                    VALUES (:settings, :now)
                    """
                )
                self.db.execute(
                    insert_query,
                    {
                        "settings": json.dumps(settings),
                        "now": datetime.now(timezone.utc),
                    },
                )

        self.db.commit()
        logger.info(f"Updated alert thresholds (host={host_id}, group={host_group_id})")


# Convenience function to get service instance
def get_alert_service(db: Session) -> AlertService:
    """Get AlertService instance."""
    return AlertService(db)
