"""
Alert Generator for Compliance Scans

Analyzes scan results and generates appropriate alerts based on configured thresholds.
Called after each compliance scan completes.

Part of OpenWatch OS Transformation - Alert Thresholds (doc 03).
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from .alerts import AlertService, AlertSeverity, AlertType

logger = logging.getLogger(__name__)


class AlertGenerator:
    """Generates alerts based on scan results and configured thresholds."""

    def __init__(self, db: Session):
        """Initialize with database session."""
        self.db = db
        self.alert_service = AlertService(db)

    def process_scan_results(
        self,
        host_id: UUID,
        scan_id: Optional[UUID],
        compliance_score: float,
        passed: int,
        failed: int,
        results: List[Dict[str, Any]],
        hostname: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Process scan results and generate alerts as needed.

        Args:
            host_id: Host UUID
            scan_id: Scan UUID (if available)
            compliance_score: Current compliance score (0-100)
            passed: Number of passed rules
            failed: Number of failed rules
            results: List of rule results from scan
            hostname: Optional hostname for alert messages

        Returns:
            List of created alerts
        """
        created_alerts = []
        thresholds = self.alert_service.get_thresholds(host_id=host_id)
        compliance_thresholds = thresholds.get("compliance", {})

        # Get host info if not provided
        if not hostname:
            result = self.db.execute(
                text("SELECT hostname FROM hosts WHERE id = :host_id"),
                {"host_id": str(host_id)},
            )
            row = result.fetchone()
            hostname = row.hostname if row else str(host_id)

        # Check for critical findings
        if compliance_thresholds.get("critical_finding", True):
            critical_findings = [r for r in results if not r.get("passed") and r.get("severity") == "critical"]
            for finding in critical_findings:
                alert = self._create_finding_alert(host_id, scan_id, finding, AlertSeverity.CRITICAL, hostname)
                if alert:
                    created_alerts.append(alert)

        # Check for high findings
        if compliance_thresholds.get("high_finding", True):
            high_findings = [r for r in results if not r.get("passed") and r.get("severity") == "high"]
            for finding in high_findings:
                alert = self._create_finding_alert(host_id, scan_id, finding, AlertSeverity.HIGH, hostname)
                if alert:
                    created_alerts.append(alert)

        # Check for medium findings (usually disabled by default)
        if compliance_thresholds.get("medium_finding", False):
            medium_findings = [r for r in results if not r.get("passed") and r.get("severity") == "medium"]
            for finding in medium_findings:
                alert = self._create_finding_alert(host_id, scan_id, finding, AlertSeverity.MEDIUM, hostname)
                if alert:
                    created_alerts.append(alert)

        # Check for score drop
        score_drop_threshold = compliance_thresholds.get("score_drop_threshold", 20)
        score_drop_window = compliance_thresholds.get("score_drop_window_hours", 24)
        score_drop_alert = self._check_score_drop(
            host_id, compliance_score, score_drop_threshold, score_drop_window, hostname
        )
        if score_drop_alert:
            created_alerts.append(score_drop_alert)

        # Check for non-compliant status
        non_compliant_threshold = compliance_thresholds.get("non_compliant_threshold", 80)
        if compliance_score < non_compliant_threshold:
            alert = self._create_non_compliant_alert(host_id, compliance_score, non_compliant_threshold, hostname)
            if alert:
                created_alerts.append(alert)

        # Check for configuration drift (rules that changed state)
        drift_alerts = self._check_configuration_drift(host_id, scan_id, results, hostname, thresholds.get("drift", {}))
        created_alerts.extend(drift_alerts)

        logger.info(
            f"Generated {len(created_alerts)} alerts for host {hostname} "
            f"(score={compliance_score}%, passed={passed}, failed={failed})"
        )

        return created_alerts

    def _create_finding_alert(
        self,
        host_id: UUID,
        scan_id: Optional[UUID],
        finding: Dict[str, Any],
        severity: AlertSeverity,
        hostname: str,
    ) -> Optional[Dict[str, Any]]:
        """Create an alert for a compliance finding."""
        rule_id = finding.get("rule_id", "unknown")
        title = finding.get("title", rule_id)

        alert_type = AlertType.CRITICAL_FINDING if severity == AlertSeverity.CRITICAL else AlertType.HIGH_FINDING

        return self.alert_service.create_alert(
            alert_type=alert_type,
            severity=severity,
            title=f"{severity.value.capitalize()} finding on {hostname}",
            message=f"Rule '{title}' failed on host {hostname}",
            host_id=host_id,
            scan_id=scan_id,
            rule_id=rule_id,
            metadata={
                "rule_title": title,
                "rule_severity": finding.get("severity"),
                "detail": finding.get("detail"),
            },
        )

    def _check_score_drop(
        self,
        host_id: UUID,
        current_score: float,
        threshold: int,
        window_hours: int,
        hostname: str,
    ) -> Optional[Dict[str, Any]]:
        """Check if compliance score dropped significantly."""
        # Get historical score from specified window
        query = text(
            """
            SELECT compliance_score
            FROM host_compliance_schedule
            WHERE host_id = :host_id
            """
        )
        result = self.db.execute(query, {"host_id": str(host_id)})
        row = result.fetchone()

        if not row or row.compliance_score is None:
            return None

        previous_score = row.compliance_score
        drop = previous_score - current_score

        if drop >= threshold:
            return self.alert_service.create_alert(
                alert_type=AlertType.SCORE_DROP,
                severity=AlertSeverity.HIGH,
                title=f"Compliance score dropped {drop:.0f}% on {hostname}",
                message=f"Score changed from {previous_score:.0f}% to {current_score:.0f}%",
                host_id=host_id,
                metadata={
                    "previous_score": previous_score,
                    "current_score": current_score,
                    "drop_percent": drop,
                },
            )

        return None

    def _create_non_compliant_alert(
        self,
        host_id: UUID,
        score: float,
        threshold: int,
        hostname: str,
    ) -> Optional[Dict[str, Any]]:
        """Create alert for host falling below compliance threshold."""
        return self.alert_service.create_alert(
            alert_type=AlertType.NON_COMPLIANT,
            severity=AlertSeverity.MEDIUM,
            title=f"Host {hostname} is non-compliant",
            message=f"Compliance score ({score:.0f}%) is below threshold ({threshold}%)",
            host_id=host_id,
            metadata={
                "compliance_score": score,
                "threshold": threshold,
            },
            # Longer dedup window for non-compliant alerts
            dedupe_window_minutes=1440,  # 24 hours
        )

    def _check_configuration_drift(
        self,
        host_id: UUID,
        scan_id: Optional[UUID],
        results: List[Dict[str, Any]],
        hostname: str,
        drift_thresholds: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Check for configuration drift compared to previous scan."""
        alerts = []

        # Get previous scan results for comparison
        query = text(
            """
            SELECT rule_id, passed
            FROM (
                SELECT
                    rule_id,
                    passed,
                    ROW_NUMBER() OVER (PARTITION BY rule_id ORDER BY created_at DESC) as rn
                FROM scan_findings
                WHERE host_id = :host_id
                  AND (:scan_id IS NULL OR scan_id != :scan_id)
            ) t
            WHERE rn = 1
            """
        )

        result = self.db.execute(
            query,
            {
                "host_id": str(host_id),
                "scan_id": str(scan_id) if scan_id else None,
            },
        )

        previous_states = {row.rule_id: row.passed for row in result.fetchall()}

        if not previous_states:
            # No previous scan to compare
            return alerts

        # Count drift
        drift_count = 0
        for finding in results:
            rule_id = finding.get("rule_id")
            current_passed = finding.get("passed", False)

            if rule_id in previous_states:
                previous_passed = previous_states[rule_id]

                if previous_passed and not current_passed:
                    # Rule was passing, now failing - configuration drift
                    drift_count += 1
                    alert = self.alert_service.create_alert(
                        alert_type=AlertType.CONFIGURATION_DRIFT,
                        severity=AlertSeverity.HIGH,
                        title=f"Configuration drift on {hostname}",
                        message=f"Rule '{finding.get('title', rule_id)}' was passing but now fails",
                        host_id=host_id,
                        scan_id=scan_id,
                        rule_id=rule_id,
                        metadata={
                            "rule_title": finding.get("title"),
                            "previous_state": "pass",
                            "current_state": "fail",
                        },
                    )
                    if alert:
                        alerts.append(alert)

                elif not previous_passed and current_passed:
                    # Rule was failing, now passing - unexpected remediation
                    alert = self.alert_service.create_alert(
                        alert_type=AlertType.UNEXPECTED_REMEDIATION,
                        severity=AlertSeverity.INFO,
                        title=f"Rule remediated on {hostname}",
                        message=f"Rule '{finding.get('title', rule_id)}' is now passing",
                        host_id=host_id,
                        scan_id=scan_id,
                        rule_id=rule_id,
                        metadata={
                            "rule_title": finding.get("title"),
                            "previous_state": "fail",
                            "current_state": "pass",
                        },
                    )
                    if alert:
                        alerts.append(alert)

        # Check for mass drift
        total_rules = len(results)
        mass_drift_threshold = drift_thresholds.get("mass_drift_threshold", 10)

        if total_rules > 0 and (drift_count / total_rules * 100) >= mass_drift_threshold:
            alert = self.alert_service.create_alert(
                alert_type=AlertType.MASS_DRIFT,
                severity=AlertSeverity.CRITICAL,
                title=f"Mass configuration drift on {hostname}",
                message=f"{drift_count} rules ({drift_count/total_rules*100:.0f}%) changed to failing state",
                host_id=host_id,
                scan_id=scan_id,
                metadata={
                    "drift_count": drift_count,
                    "total_rules": total_rules,
                    "drift_percent": drift_count / total_rules * 100,
                },
            )
            if alert:
                alerts.append(alert)

        return alerts

    def check_operational_alerts(self) -> List[Dict[str, Any]]:
        """
        Check for operational alerts (run periodically).

        Checks:
        - Hosts not scanned within max interval
        - Scan queue backlog

        Returns:
            List of created alerts
        """
        alerts = []
        thresholds = self.alert_service.get_thresholds()
        operational = thresholds.get("operational", {})

        # Check for hosts not scanned
        max_scan_age = operational.get("max_scan_age_hours", 48)
        alerts.extend(self._check_unscanned_hosts(max_scan_age))

        return alerts

    def _check_unscanned_hosts(self, max_hours: int) -> List[Dict[str, Any]]:
        """Check for hosts that haven't been scanned within max interval."""
        alerts = []

        query = text(
            """
            SELECT h.id, h.hostname, hcs.last_scan_completed
            FROM hosts h
            LEFT JOIN host_compliance_schedule hcs ON h.id = hcs.host_id
            WHERE h.is_active = true
              AND hcs.maintenance_mode = false
              AND (
                hcs.last_scan_completed IS NULL
                OR hcs.last_scan_completed < :threshold
              )
            """
        )

        threshold = datetime.now(timezone.utc) - timedelta(hours=max_hours)
        result = self.db.execute(query, {"threshold": threshold})

        for row in result.fetchall():
            alert = self.alert_service.create_alert(
                alert_type=AlertType.HOST_NOT_SCANNED,
                severity=AlertSeverity.MEDIUM,
                title=f"Host {row.hostname} not scanned",
                message=f"No compliance scan in over {max_hours} hours",
                host_id=row.id,
                metadata={
                    "last_scan": row.last_scan_completed.isoformat() if row.last_scan_completed else None,
                    "max_hours": max_hours,
                },
                dedupe_window_minutes=1440,  # Once per day
            )
            if alert:
                alerts.append(alert)

        return alerts


def get_alert_generator(db: Session) -> AlertGenerator:
    """Get AlertGenerator instance."""
    return AlertGenerator(db)
