"""
Unified Alert Service

Centralized alert dispatching for all application alerts.
Integrates with existing AlertSettings table and webhook system.

Supported Alert Types:
    Monitoring: host_down, host_degraded, host_recovered
    Scan Events: scan_failed, scan_completed
    Compliance Drift: compliance_drift_major, compliance_drift_minor, compliance_improvement

Alert Channels:
    - Webhook (existing webhook system)
    - Database logging (AlertSettings table)
    - Application logging

This service replaces multiple scattered alert implementations with
a single, consistent alert dispatch mechanism.
"""

import logging
from datetime import datetime
from typing import Dict, Optional
from uuid import UUID

import requests
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..utils.query_builder import QueryBuilder

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("openwatch.audit")


class UnifiedAlertService:
    """
    Centralized service for dispatching all application alerts.

    Uses existing AlertSettings table for user preferences
    and webhook system for external notifications.
    """

    # Severity levels for different alert types
    ALERT_SEVERITIES = {
        "host_down": "high",
        "host_degraded": "medium",
        "host_recovered": "low",
        "scan_failed": "medium",
        "scan_completed": "low",
        "compliance_drift_major": "high",
        "compliance_drift_minor": "medium",
        "compliance_improvement": "low",
    }

    def dispatch_alert(
        self,
        db: Session,
        alert_type: str,
        host_id: UUID,
        details: Dict,
        user_id: Optional[UUID] = None,
    ) -> bool:
        """
        Dispatch alert through configured channels.

        Checks AlertSettings to see if alert is enabled, then dispatches
        via webhooks and logging as configured.

        Args:
            db: Database session
            alert_type: Type of alert (e.g., 'compliance_drift_major')
            host_id: Host UUID triggering the alert
            details: Alert-specific details (scores, deltas, error messages, etc.)
            user_id: Optional user ID if alert is user-specific

        Returns:
            True if alert dispatched successfully, False if disabled or error

        Raises:
            ValueError: If alert_type is invalid
        """
        # Validate alert type
        if alert_type not in self.ALERT_SEVERITIES:
            raise ValueError(
                f"Invalid alert_type: {alert_type}. "
                f"Valid types: {list(self.ALERT_SEVERITIES.keys())}"
            )

        # Check if alert is enabled
        if not self._is_alert_enabled(db, alert_type, user_id):
            logger.debug(f"Alert {alert_type} is disabled, skipping dispatch")
            return False

        severity = self.ALERT_SEVERITIES[alert_type]

        # Get host details for alert context
        host_info = self._get_host_info(db, host_id)
        if not host_info:
            logger.warning(f"Host {host_id} not found, cannot dispatch alert")
            return False

        # Build alert payload
        alert_payload = {
            "alert_type": alert_type,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat(),
            "host_id": str(host_id),
            "hostname": host_info["hostname"],
            "ip_address": host_info["ip_address"],
            "details": details,
        }

        # Log alert
        self._log_alert(alert_payload)

        # Dispatch to webhooks if enabled
        webhooks_dispatched = self._dispatch_to_webhooks(db, alert_payload)

        # Audit log
        audit_logger.info(
            f"ALERT_DISPATCHED - Type: {alert_type}, Host: {host_info['hostname']} "
            f"({host_id}), Severity: {severity}, Webhooks: {webhooks_dispatched}",
            extra={
                "event_type": "ALERT_DISPATCHED",
                "alert_type": alert_type,
                "severity": severity,
                "host_id": str(host_id),
                "hostname": host_info["hostname"],
                "webhooks_sent": webhooks_dispatched,
            },
        )

        return True

    def _is_alert_enabled(self, db: Session, alert_type: str, user_id: Optional[UUID]) -> bool:
        """
        Check if alert type is enabled in AlertSettings.

        Args:
            db: Database session
            alert_type: Alert type to check
            user_id: Optional user ID for user-specific settings

        Returns:
            True if alert is enabled, False otherwise
        """
        builder = QueryBuilder("alert_settings").select("id")

        # Filter by user if provided, otherwise check system-wide settings
        if user_id:
            builder.where("user_id = :user_id", user_id, "user_id")
        else:
            builder.where("user_id IS NULL")

        # Check if alert type is enabled
        builder.where(f"{alert_type}_enabled = :enabled", True, "enabled")

        query, params = builder.build()
        result = db.execute(text(query), params)

        return result.fetchone() is not None

    def _get_host_info(self, db: Session, host_id: UUID) -> Optional[Dict]:
        """
        Get basic host information for alert context.

        Args:
            db: Database session
            host_id: Host UUID

        Returns:
            Dict with hostname and ip_address, or None if not found
        """
        builder = (
            QueryBuilder("hosts")
            .select("hostname", "ip_address")
            .where("id = :host_id", host_id, "host_id")
        )

        query, params = builder.build()
        result = db.execute(text(query), params)
        row = result.fetchone()

        if not row:
            return None

        return {"hostname": row.hostname, "ip_address": row.ip_address}

    def _log_alert(self, alert_payload: Dict):
        """
        Log alert to application logger.

        Args:
            alert_payload: Complete alert payload
        """
        severity = alert_payload["severity"]
        alert_type = alert_payload["alert_type"]
        hostname = alert_payload["hostname"]
        details = alert_payload["details"]

        log_message = (
            f"ALERT [{severity.upper()}] - {alert_type} - Host: {hostname} - " f"Details: {details}"
        )

        if severity == "high":
            logger.error(log_message, extra=alert_payload)
        elif severity == "medium":
            logger.warning(log_message, extra=alert_payload)
        else:
            logger.info(log_message, extra=alert_payload)

    def _dispatch_to_webhooks(self, db: Session, alert_payload: Dict) -> int:
        """
        Dispatch alert to configured webhooks.

        Uses existing webhook system to send alerts to external systems.

        Args:
            db: Database session
            alert_payload: Complete alert payload

        Returns:
            Number of webhooks successfully dispatched
        """
        # Get enabled webhooks
        builder = (
            QueryBuilder("webhooks")
            .select("id", "url", "secret")
            .where("is_enabled = :enabled", True, "enabled")
            .where("event_type = :event_type", "alert", "event_type")
        )

        query, params = builder.build()
        result = db.execute(text(query), params)
        webhooks = [dict(row._mapping) for row in result]

        if not webhooks:
            logger.debug("No enabled webhooks found for alerts")
            return 0

        success_count = 0

        for webhook in webhooks:
            try:
                # Send webhook request
                response = requests.post(
                    webhook["url"],
                    json=alert_payload,
                    headers={
                        "Content-Type": "application/json",
                        "X-OpenWatch-Alert": alert_payload["alert_type"],
                        "X-OpenWatch-Severity": alert_payload["severity"],
                    },
                    timeout=10,
                )

                if response.status_code in [200, 201, 202, 204]:
                    success_count += 1
                    logger.debug(
                        f"Webhook {webhook['id']} dispatched successfully "
                        f"(status: {response.status_code})"
                    )
                else:
                    logger.warning(
                        f"Webhook {webhook['id']} returned non-success status: "
                        f"{response.status_code}"
                    )

            except requests.exceptions.RequestException as e:
                logger.error(
                    f"Failed to dispatch webhook {webhook['id']}: {str(e)}",
                    extra={"webhook_id": str(webhook["id"]), "error": str(e)},
                )

        return success_count

    def dispatch_compliance_drift_alert(
        self,
        db: Session,
        host_id: UUID,
        drift_type: str,
        baseline_score: float,
        current_score: float,
        score_delta: float,
        scan_id: UUID,
    ) -> bool:
        """
        Convenience method for dispatching compliance drift alerts.

        Args:
            db: Database session
            host_id: Host UUID
            drift_type: Drift type (major, minor, improvement, stable)
            baseline_score: Baseline compliance score
            current_score: Current compliance score
            score_delta: Score change in percentage points
            scan_id: Scan ID that triggered drift

        Returns:
            True if alert dispatched, False if disabled or error
        """
        # Map drift type to alert type
        alert_type_mapping = {
            "major": "compliance_drift_major",
            "minor": "compliance_drift_minor",
            "improvement": "compliance_improvement",
            "stable": None,  # No alert for stable
        }

        alert_type = alert_type_mapping.get(drift_type)
        if not alert_type:
            return False

        details = {
            "drift_type": drift_type,
            "baseline_score": baseline_score,
            "current_score": current_score,
            "score_delta": score_delta,
            "scan_id": str(scan_id),
            "message": (
                f"Compliance score changed by {score_delta:+.2f}pp "
                f"({baseline_score:.1f}% → {current_score:.1f}%)"
            ),
        }

        return self.dispatch_alert(db=db, alert_type=alert_type, host_id=host_id, details=details)

    def dispatch_monitoring_alert(
        self,
        db: Session,
        host_id: UUID,
        status: str,
        previous_status: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> bool:
        """
        Convenience method for dispatching host monitoring alerts.

        Args:
            db: Database session
            host_id: Host UUID
            status: Current host status (online, degraded, offline)
            previous_status: Previous host status
            error_message: Optional error message

        Returns:
            True if alert dispatched, False if disabled or error
        """
        # Map status to alert type
        alert_type_mapping = {
            "offline": "host_down",
            "degraded": "host_degraded",
            "online": "host_recovered",
        }

        alert_type = alert_type_mapping.get(status)
        if not alert_type:
            logger.warning(f"Unknown host status: {status}, cannot dispatch alert")
            return False

        details = {
            "status": status,
            "previous_status": previous_status,
            "message": f"Host status changed to {status}",
        }

        if error_message:
            details["error_message"] = error_message

        return self.dispatch_alert(db=db, alert_type=alert_type, host_id=host_id, details=details)
