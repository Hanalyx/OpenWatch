"""
OWCA Intelligence Layer - Baseline Drift Detection

Implements baseline drift detection per NIST SP 800-137 Continuous Monitoring.
Compares current compliance state against established baseline.
"""

import logging
from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from ....utils.query_builder import QueryBuilder

from ..core.score_calculator import ComplianceScoreCalculator
from ..models import BaselineDrift, DriftSeverity

logger = logging.getLogger(__name__)


class BaselineDriftDetector:
    """
    Baseline drift detection and analysis.

    Detects significant changes in compliance state compared to
    established baselines (per NIST SP 800-137).
    """

    # Drift thresholds (percentage points)
    THRESHOLD_CRITICAL = 10.0  # >10% decline
    THRESHOLD_HIGH = 5.0  # 5-10% decline
    THRESHOLD_MEDIUM = 2.0  # 2-5% decline

    def __init__(self, db: Session, score_calculator: ComplianceScoreCalculator):
        """
        Initialize baseline drift detector.

        Args:
            db: SQLAlchemy database session
            score_calculator: ComplianceScoreCalculator for current scores
        """
        self.db = db
        self.score_calculator = score_calculator

    async def detect_drift(self, host_id: UUID) -> Optional[BaselineDrift]:
        """
        Detect compliance drift from active baseline.

        Compares current compliance state against the host's active baseline.
        Calculates drift percentage and classifies severity.

        Args:
            host_id: UUID of the host to analyze

        Returns:
            BaselineDrift analysis or None if no active baseline exists

        Example:
            >>> detector = BaselineDriftDetector(db, score_calculator)
            >>> drift = await detector.detect_drift(host_id)
            >>> if drift and drift.drift_severity != DriftSeverity.NONE:
            ...     print(f"DRIFT DETECTED: {drift.drift_percentage}%")
        """
        # Get active baseline for host
        baseline_query = (
            QueryBuilder("baselines b")
            .select(
                "b.id",
                "b.baseline_score",
                "b.baseline_passed_rules",
                "b.baseline_failed_rules",
                "b.baseline_total_rules",
                "b.baseline_critical_passed",
                "b.baseline_critical_failed",
                "b.baseline_high_passed",
                "b.baseline_high_failed",
            )
            .where("b.host_id = :host_id", host_id, "host_id")
            .where("b.is_active = :is_active", True, "is_active")
        )

        query, params = baseline_query.build()
        baseline = self.db.execute(text(query), params).fetchone()

        if not baseline:
            logger.info(f"No active baseline found for host {host_id}")
            return None

        # Get current compliance score
        current_score_obj = await self.score_calculator.get_host_compliance_score(host_id)

        if not current_score_obj:
            logger.warning(f"No current compliance score for host {host_id}")
            return None

        # Calculate drift
        current_score = current_score_obj.overall_score
        baseline_score = float(baseline.baseline_score)
        drift_percentage = current_score - baseline_score

        # Classify drift severity
        drift_severity = self._classify_drift_severity(drift_percentage)

        # Calculate rule changes
        current_passed = current_score_obj.passed_rules
        current_failed = current_score_obj.failed_rules
        baseline_passed = baseline.baseline_passed_rules
        baseline_failed = baseline.baseline_failed_rules

        # Rules that changed status
        rules_changed = abs((current_passed - baseline_passed)) + abs((current_failed - baseline_failed))

        # Estimate newly failed and newly passed
        # (This is an approximation - exact tracking would require rule-level comparison)
        if current_passed > baseline_passed:
            newly_passed = current_passed - baseline_passed
            newly_failed = max(0, current_failed - baseline_failed)
        else:
            newly_passed = 0
            newly_failed = current_failed - baseline_failed

        # Critical and high regressions
        current_critical_failed = current_score_obj.severity_breakdown.critical_failed
        current_high_failed = current_score_obj.severity_breakdown.high_failed
        baseline_critical_failed = baseline.baseline_critical_failed or 0
        baseline_high_failed = baseline.baseline_high_failed or 0

        critical_regressions = max(0, current_critical_failed - baseline_critical_failed)
        high_regressions = max(0, current_high_failed - baseline_high_failed)

        # Build BaselineDrift model
        drift_analysis = BaselineDrift(
            host_id=host_id,
            baseline_id=baseline.id,
            current_score=current_score,
            baseline_score=baseline_score,
            drift_percentage=drift_percentage,
            drift_severity=drift_severity,
            rules_changed=rules_changed,
            newly_failed=newly_failed,
            newly_passed=newly_passed,
            critical_regressions=critical_regressions,
            high_regressions=high_regressions,
            detected_at=datetime.utcnow(),
        )

        logger.info(
            f"Baseline drift for host {host_id}: "
            f"{drift_percentage:+.2f}% ({drift_severity.value}), "
            f"{critical_regressions} critical regressions"
        )

        return drift_analysis

    def _classify_drift_severity(self, drift_percentage: float) -> DriftSeverity:
        """
        Classify drift severity based on percentage change.

        Negative drift (decline in compliance) is weighted more heavily.

        Args:
            drift_percentage: Drift in percentage points (can be positive or negative)

        Returns:
            DriftSeverity classification

        Example:
            >>> detector._classify_drift_severity(-12.5)
            DriftSeverity.CRITICAL
            >>> detector._classify_drift_severity(+3.0)
            DriftSeverity.NONE
        """
        # Negative drift (decline) - more serious
        if drift_percentage <= -self.THRESHOLD_CRITICAL:
            return DriftSeverity.CRITICAL
        elif drift_percentage <= -self.THRESHOLD_HIGH:
            return DriftSeverity.HIGH
        elif drift_percentage <= -self.THRESHOLD_MEDIUM:
            return DriftSeverity.MEDIUM
        # Positive drift (improvement) or minor negative - not concerning
        elif drift_percentage < self.THRESHOLD_MEDIUM:
            return DriftSeverity.LOW
        else:
            return DriftSeverity.NONE

    async def get_hosts_with_drift(self, min_severity: DriftSeverity = DriftSeverity.MEDIUM) -> list[BaselineDrift]:
        """
        Get all hosts with significant baseline drift.

        Args:
            min_severity: Minimum drift severity to include (default: MEDIUM)

        Returns:
            List of BaselineDrift objects for hosts with drift >= min_severity

        Example:
            >>> detector = BaselineDriftDetector(db, score_calculator)
            >>> drifted_hosts = await detector.get_hosts_with_drift(
            ...     min_severity=DriftSeverity.HIGH
            ... )
        """
        # Get all hosts with active baselines
        query = text(
            """
            SELECT DISTINCT b.host_id
            FROM baselines b
            WHERE b.is_active = true
            """
        )

        results = self.db.execute(query).fetchall()

        # Check each host for drift
        drifted_hosts = []
        for row in results:
            host_id = row.host_id
            drift = await self.detect_drift(host_id)

            if drift and self._meets_severity_threshold(drift.drift_severity, min_severity):
                drifted_hosts.append(drift)

        # Sort by severity (CRITICAL first) then by drift percentage (worst first)
        severity_order = {
            DriftSeverity.CRITICAL: 0,
            DriftSeverity.HIGH: 1,
            DriftSeverity.MEDIUM: 2,
            DriftSeverity.LOW: 3,
            DriftSeverity.NONE: 4,
        }

        drifted_hosts.sort(key=lambda d: (severity_order[d.drift_severity], d.drift_percentage))

        logger.info(f"Found {len(drifted_hosts)} hosts with drift >= {min_severity.value}")

        return drifted_hosts

    def _meets_severity_threshold(self, drift_severity: DriftSeverity, min_severity: DriftSeverity) -> bool:
        """
        Check if drift severity meets minimum threshold.

        Args:
            drift_severity: Actual drift severity
            min_severity: Minimum required severity

        Returns:
            True if drift_severity >= min_severity
        """
        severity_levels = {
            DriftSeverity.CRITICAL: 4,
            DriftSeverity.HIGH: 3,
            DriftSeverity.MEDIUM: 2,
            DriftSeverity.LOW: 1,
            DriftSeverity.NONE: 0,
        }

        return severity_levels[drift_severity] >= severity_levels[min_severity]

    async def should_alert(self, host_id: UUID) -> bool:
        """
        Determine if baseline drift warrants an alert.

        Alerts are triggered for:
        - CRITICAL or HIGH drift severity
        - Critical rule regressions (any amount)
        - High rule regressions (>5)

        Args:
            host_id: UUID of the host

        Returns:
            True if alert should be sent, False otherwise

        Example:
            >>> detector = BaselineDriftDetector(db, score_calculator)
            >>> if await detector.should_alert(host_id):
            ...     send_drift_alert(host_id)
        """
        drift = await self.detect_drift(host_id)

        if not drift:
            return False

        # Alert conditions
        critical_severity = drift.drift_severity in [
            DriftSeverity.CRITICAL,
            DriftSeverity.HIGH,
        ]
        has_critical_regressions = drift.critical_regressions > 0
        has_many_high_regressions = drift.high_regressions > 5

        should_alert = critical_severity or has_critical_regressions or has_many_high_regressions

        if should_alert:
            logger.warning(
                f"Alert threshold met for host {host_id}: "
                f"severity={drift.drift_severity.value}, "
                f"critical_regressions={drift.critical_regressions}, "
                f"high_regressions={drift.high_regressions}"
            )

        return should_alert
