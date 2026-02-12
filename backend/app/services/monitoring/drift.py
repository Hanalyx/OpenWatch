"""
Compliance Drift Detection Service

Automatically detects significant deviations from compliance baselines.
Implements NIST SP 800-137 Continuous Monitoring requirements for
configuration drift detection and alerting.

Drift Types:
    major: Score drop >= 10 percentage points
    minor: Score drop 5-10 percentage points
    improvement: Score increase >= 5 percentage points
    stable: Score change < 5 percentage points

Drift Calculation:
    Uses percentage points (absolute change), NOT percent change
    Example: 80% → 70% = 10pp (major drift), NOT 12.5% change

Auto-Baseline (Hybrid Approach):
    - First scan automatically creates baseline (no drift event)
    - Subsequent scans compare against baseline
    - Users can manually re-baseline via UI
    - Future: Auto-update on sustained improvement (configurable)
"""

import logging
from datetime import datetime
from typing import Dict, Optional, Tuple
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from ...database import ScanBaseline, ScanDriftEvent
from ...utils.query_builder import QueryBuilder

logger = logging.getLogger(__name__)


class DriftDetectionService:
    """
    Detects and records compliance drift events.

    Compares current scan results against active baseline to identify
    significant deviations in compliance posture.
    """

    def detect_drift(
        self, db: Session, host_id: UUID, scan_id: UUID, auto_baseline: bool = True
    ) -> Tuple[Optional[ScanDriftEvent], Optional[ScanBaseline]]:
        """
        Detect compliance drift for a completed scan.

        Compares scan results against active baseline and creates
        drift event if significant deviation detected.

        If no baseline exists and auto_baseline=True, automatically creates
        a baseline from this scan (Hybrid Auto-Baseline approach).

        Args:
            db: Database session
            host_id: Host UUID
            scan_id: Completed scan UUID
            auto_baseline: If True, auto-create baseline on first scan (default: True)

        Returns:
            Tuple of (ScanDriftEvent or None, ScanBaseline or None)
            - (None, new_baseline) if baseline was auto-created (first scan)
            - (drift_event, None) if drift was detected
            - (None, None) if stable (no significant drift)

        Raises:
            ValueError: If scan not found or not completed
        """
        # Get current scan results first (needed for both baseline creation and drift detection)
        scan_data = self._get_scan_results(db, scan_id, host_id)
        if not scan_data:
            raise ValueError(f"Scan {scan_id} not found or not completed for host {host_id}")

        # Get active baseline
        baseline = self._get_active_baseline(db, host_id)
        if not baseline:
            if auto_baseline:
                # Auto-create baseline from first scan
                new_baseline = self._create_auto_baseline(db, host_id, scan_id, scan_data)
                logger.info(
                    f"Auto-created baseline for host {host_id} from scan {scan_id}: "
                    f"{new_baseline.baseline_score:.1f}% compliance"
                )
                return (None, new_baseline)
            else:
                logger.info(f"No active baseline for host {host_id}, skipping drift detection")
                return (None, None)

        # Calculate drift metrics
        drift_metrics = self._calculate_drift_metrics(baseline, scan_data)

        # Determine drift type based on thresholds
        drift_type = self._classify_drift(
            drift_metrics["score_delta"],
            baseline.drift_threshold_major,
            baseline.drift_threshold_minor,
        )

        # Only create event if drift is significant (not stable)
        if drift_type == "stable":
            logger.info(
                f"Stable compliance for host {host_id}: "
                f"{drift_metrics['score_delta']:+.2f}pp change (within threshold)"
            )
            return (None, None)

        # Create drift event
        drift_event = ScanDriftEvent(
            host_id=host_id,
            scan_id=scan_id,
            baseline_id=baseline.id,
            drift_type=drift_type,
            drift_magnitude=abs(drift_metrics["score_delta"]),
            baseline_score=baseline.baseline_score,
            current_score=scan_data.score,
            score_delta=drift_metrics["score_delta"],
            critical_passed_delta=drift_metrics["critical_passed_delta"],
            critical_failed_delta=drift_metrics["critical_failed_delta"],
            high_passed_delta=drift_metrics["high_passed_delta"],
            high_failed_delta=drift_metrics["high_failed_delta"],
            medium_passed_delta=drift_metrics["medium_passed_delta"],
            medium_failed_delta=drift_metrics["medium_failed_delta"],
            low_passed_delta=drift_metrics["low_passed_delta"],
            low_failed_delta=drift_metrics["low_failed_delta"],
        )

        db.add(drift_event)
        db.commit()
        db.refresh(drift_event)

        logger.warning(
            f"Compliance drift detected for host {host_id}: "
            f"{drift_type.upper()} ({drift_metrics['score_delta']:+.2f}pp change, "
            f"{baseline.baseline_score:.1f}% → {scan_data.score:.1f}%)",
            extra={
                "host_id": str(host_id),
                "scan_id": str(scan_id),
                "drift_type": drift_type,
                "drift_magnitude": drift_metrics["score_delta"],
            },
        )

        return (drift_event, None)

    def _get_active_baseline(self, db: Session, host_id: UUID) -> Optional[ScanBaseline]:
        """
        Get active baseline for host.

        Args:
            db: Database session
            host_id: Host UUID

        Returns:
            Active baseline or None
        """
        builder = (
            QueryBuilder("scan_baselines")
            .select("id")
            .where("host_id = :host_id", host_id, "host_id")
            .where("is_active = :is_active", True, "is_active")
        )

        query, params = builder.build()
        result = db.execute(text(query), params)
        baseline_row = result.fetchone()

        if not baseline_row:
            return None

        baseline = db.query(ScanBaseline).filter(ScanBaseline.id == baseline_row.id).first()

        return baseline

    def _create_auto_baseline(self, db: Session, host_id: UUID, scan_id: UUID, scan_data) -> ScanBaseline:
        """
        Auto-create baseline from first scan (Hybrid Auto-Baseline approach).

        Creates a baseline with type 'auto' when no baseline exists for a host.
        This establishes the initial known state per NIST SP 800-137 requirements.

        Args:
            db: Database session
            host_id: Host UUID
            scan_id: Scan UUID that triggered baseline creation
            scan_data: Scan results row with compliance data

        Returns:
            Newly created ScanBaseline

        Note:
            - Sets baseline_type to 'auto' to distinguish from manual baselines
            - established_by is NULL for auto-created baselines
            - Default drift thresholds: major=10pp, minor=5pp
        """
        baseline = ScanBaseline(
            host_id=host_id,
            baseline_type="auto",
            established_at=datetime.utcnow(),
            established_by=None,  # Auto-created, no user
            baseline_score=scan_data.score,
            baseline_passed_rules=scan_data.passed_rules,
            baseline_failed_rules=scan_data.failed_rules,
            baseline_total_rules=scan_data.total_rules,
            baseline_critical_passed=scan_data.severity_critical_passed or 0,
            baseline_critical_failed=scan_data.severity_critical_failed or 0,
            baseline_high_passed=scan_data.severity_high_passed or 0,
            baseline_high_failed=scan_data.severity_high_failed or 0,
            baseline_medium_passed=scan_data.severity_medium_passed or 0,
            baseline_medium_failed=scan_data.severity_medium_failed or 0,
            baseline_low_passed=scan_data.severity_low_passed or 0,
            baseline_low_failed=scan_data.severity_low_failed or 0,
            drift_threshold_major=10.0,
            drift_threshold_minor=5.0,
            is_active=True,
        )

        db.add(baseline)
        db.commit()
        db.refresh(baseline)

        logger.info(
            f"Auto-baseline created for host {host_id}: "
            f"score={baseline.baseline_score:.1f}%, "
            f"passed={baseline.baseline_passed_rules}/{baseline.baseline_total_rules}",
            extra={
                "host_id": str(host_id),
                "scan_id": str(scan_id),
                "baseline_id": str(baseline.id),
                "baseline_type": "auto",
            },
        )

        return baseline

    def _get_scan_results(self, db: Session, scan_id: UUID, host_id: UUID) -> Optional:
        """
        Get scan results with per-severity data.

        Args:
            db: Database session
            scan_id: Scan UUID
            host_id: Host UUID

        Returns:
            Scan result row or None
        """
        builder = (
            QueryBuilder("scan_results sr")
            .select(
                "sr.score",
                "sr.passed_rules",
                "sr.failed_rules",
                "sr.total_rules",
                "sr.severity_critical_passed",
                "sr.severity_critical_failed",
                "sr.severity_high_passed",
                "sr.severity_high_failed",
                "sr.severity_medium_passed",
                "sr.severity_medium_failed",
                "sr.severity_low_passed",
                "sr.severity_low_failed",
            )
            .join("scans s", "s.id = sr.scan_id", "INNER")
            .where("s.id = :scan_id", scan_id, "scan_id")
            .where("s.host_id = :host_id", host_id, "host_id")
            .where("s.status = :status", "completed", "status")
        )

        query, params = builder.build()
        result = db.execute(text(query), params)
        return result.fetchone()

    def _calculate_drift_metrics(self, baseline: ScanBaseline, scan_data) -> Dict[str, float]:
        """
        Calculate drift metrics comparing baseline to current scan.

        Uses percentage points (absolute change), not percent change.
        Example: 80% → 70% = -10pp (not -12.5%)

        Args:
            baseline: Active baseline
            scan_data: Current scan result row

        Returns:
            Dict with score_delta and per-severity deltas
        """
        return {
            "score_delta": scan_data.score - baseline.baseline_score,
            "critical_passed_delta": ((scan_data.severity_critical_passed or 0) - baseline.baseline_critical_passed),
            "critical_failed_delta": ((scan_data.severity_critical_failed or 0) - baseline.baseline_critical_failed),
            "high_passed_delta": ((scan_data.severity_high_passed or 0) - baseline.baseline_high_passed),
            "high_failed_delta": ((scan_data.severity_high_failed or 0) - baseline.baseline_high_failed),
            "medium_passed_delta": ((scan_data.severity_medium_passed or 0) - baseline.baseline_medium_passed),
            "medium_failed_delta": ((scan_data.severity_medium_failed or 0) - baseline.baseline_medium_failed),
            "low_passed_delta": ((scan_data.severity_low_passed or 0) - baseline.baseline_low_passed),
            "low_failed_delta": ((scan_data.severity_low_failed or 0) - baseline.baseline_low_failed),
        }

    def _classify_drift(self, score_delta: float, threshold_major: float, threshold_minor: float) -> str:
        """
        Classify drift type based on score delta and thresholds.

        Drift types:
            major: Score drop >= threshold_major (default 10pp)
            minor: Score drop between threshold_minor and threshold_major (default 5-10pp)
            improvement: Score increase >= threshold_minor (default 5pp)
            stable: Score change < threshold_minor (default <5pp)

        Args:
            score_delta: Percentage point change (current - baseline)
            threshold_major: Major drift threshold in percentage points
            threshold_minor: Minor drift threshold in percentage points

        Returns:
            Drift type: 'major', 'minor', 'improvement', 'stable'
        """
        if score_delta <= -threshold_major:
            return "major"
        elif score_delta <= -threshold_minor:
            return "minor"
        elif score_delta >= threshold_minor:
            return "improvement"
        else:
            return "stable"

    def get_recent_drift_events(self, db: Session, host_id: UUID, limit: int = 10) -> list:
        """
        Get recent drift events for a host.

        Args:
            db: Database session
            host_id: Host UUID
            limit: Maximum number of events to return

        Returns:
            List of drift events ordered by most recent
        """
        builder = (
            QueryBuilder("scan_drift_events")
            .select(
                "id",
                "scan_id",
                "baseline_id",
                "drift_type",
                "drift_magnitude",
                "baseline_score",
                "current_score",
                "score_delta",
                "detected_at",
            )
            .where("host_id = :host_id", host_id, "host_id")
            .order_by("detected_at", "DESC")
            .limit(limit)
        )

        query, params = builder.build()
        result = db.execute(text(query), params)
        return [dict(row._mapping) for row in result]

    def get_drift_summary(self, db: Session, host_id: UUID) -> Dict:
        """
        Get drift summary statistics for a host.

        Args:
            db: Database session
            host_id: Host UUID

        Returns:
            Dict with drift counts by type and recent trend
        """
        builder = (
            QueryBuilder("scan_drift_events")
            .select("drift_type", "COUNT(*) as count")
            .where("host_id = :host_id", host_id, "host_id")
            .group_by("drift_type")
        )

        query, params = builder.build()
        result = db.execute(text(query), params)

        summary = {"major": 0, "minor": 0, "improvement": 0, "stable": 0, "total": 0}

        for row in result:
            summary[row.drift_type] = row.count
            summary["total"] += row.count

        return summary
