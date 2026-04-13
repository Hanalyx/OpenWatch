"""
Baseline Management Service

Provides explicit baseline reset, promote, and rolling baseline operations
for compliance posture management.

Auto-baseline on first scan is handled by DriftDetectionService._create_auto_baseline().
This service adds manual operations: reset (from latest scan), promote (from current
host_rule_state posture), and rolling baseline (7-day moving average).

Spec: specs/services/compliance/baseline-management.spec.yaml
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from ...database import ScanBaseline
from ...utils.mutation_builders import InsertBuilder, UpdateBuilder
from ...utils.query_builder import QueryBuilder

logger = logging.getLogger(__name__)

# Audit logger per security best practices
audit_logger = logging.getLogger("openwatch.audit")


class BaselineManagementService:
    """
    Manages compliance baselines for hosts.

    Supports three baseline types:
    - manual: Explicitly set by user from latest scan (reset)
    - promoted: Set from current host_rule_state posture (promote)
    - rolling_avg: Computed from 7-day moving average of scan scores
    """

    def reset_baseline(
        self,
        db: Session,
        host_id: UUID,
        user_id: int,
    ) -> ScanBaseline:
        """
        Establish new baseline from the most recent completed scan.

        Deactivates any existing active baseline and creates a new one
        using scan_results data from the latest completed scan.

        Args:
            db: Database session
            host_id: Host UUID
            user_id: ID of the user performing the reset

        Returns:
            Newly created ScanBaseline

        Raises:
            ValueError: If no completed scan exists for the host
        """
        # 1. Find most recent completed scan and its results
        scan_data = self._get_latest_scan_results(db, host_id)
        if not scan_data:
            raise ValueError(f"No completed scan found for host {host_id}")

        # 2. Deactivate current active baseline
        self._deactivate_current_baseline(db, host_id)

        # 3. Create new baseline from scan data
        baseline = self._create_baseline_from_scan(
            db, host_id, scan_data, baseline_type="manual", user_id=user_id
        )

        # 4. Audit log
        audit_logger.info(
            "BASELINE_RESET",
            extra={
                "user_id": user_id,
                "host_id": str(host_id),
                "baseline_id": str(baseline.id),
                "baseline_score": float(baseline.baseline_score),
                "action": "baseline_reset",
                "resource_type": "baseline",
                "resource_id": str(baseline.id),
            },
        )

        logger.info(
            f"Baseline reset for host {host_id} by user {user_id}: "
            f"score={baseline.baseline_score:.1f}%"
        )

        return baseline

    def promote_baseline(
        self,
        db: Session,
        host_id: UUID,
        user_id: int,
    ) -> ScanBaseline:
        """
        Promote current compliance posture to baseline.

        Uses aggregated host_rule_state data (current pass/fail counts per severity)
        to establish a new baseline. This is useful after a known legitimate change
        when the current posture should become the new reference point.

        Args:
            db: Database session
            host_id: Host UUID
            user_id: ID of the user performing the promotion

        Returns:
            Newly created ScanBaseline

        Raises:
            ValueError: If no host_rule_state data exists for the host
        """
        # 1. Aggregate current posture from host_rule_state
        posture = self._get_current_posture(db, host_id)
        if not posture:
            raise ValueError(f"No compliance state data found for host {host_id}")

        # 2. Deactivate current active baseline
        self._deactivate_current_baseline(db, host_id)

        # 3. Create new baseline from posture data
        now = datetime.now(timezone.utc)
        total = posture["total_rules"]
        passed = posture["passed_rules"]
        score = (passed / total * 100.0) if total > 0 else 0.0

        builder = (
            InsertBuilder("scan_baselines")
            .columns(
                "host_id",
                "baseline_type",
                "established_at",
                "established_by",
                "baseline_score",
                "baseline_passed_rules",
                "baseline_failed_rules",
                "baseline_total_rules",
                "baseline_critical_passed",
                "baseline_critical_failed",
                "baseline_high_passed",
                "baseline_high_failed",
                "baseline_medium_passed",
                "baseline_medium_failed",
                "baseline_low_passed",
                "baseline_low_failed",
                "drift_threshold_major",
                "drift_threshold_minor",
                "is_active",
            )
            .values(
                host_id,
                "promoted",
                now,
                user_id,
                score,
                passed,
                posture["failed_rules"],
                total,
                posture["critical_passed"],
                posture["critical_failed"],
                posture["high_passed"],
                posture["high_failed"],
                posture["medium_passed"],
                posture["medium_failed"],
                posture["low_passed"],
                posture["low_failed"],
                10.0,
                5.0,
                True,
            )
            .returning("id")
        )
        q, p = builder.build()
        row = db.execute(text(q), p).fetchone()
        db.commit()

        baseline = db.query(ScanBaseline).filter(ScanBaseline.id == row.id).first()

        # 4. Audit log
        audit_logger.info(
            "BASELINE_PROMOTED",
            extra={
                "user_id": user_id,
                "host_id": str(host_id),
                "baseline_id": str(baseline.id),
                "baseline_score": float(baseline.baseline_score),
                "action": "baseline_promote",
                "resource_type": "baseline",
                "resource_id": str(baseline.id),
            },
        )

        logger.info(
            f"Baseline promoted for host {host_id} by user {user_id}: "
            f"score={baseline.baseline_score:.1f}%"
        )

        return baseline

    def get_active_baseline(
        self,
        db: Session,
        host_id: UUID,
    ) -> Optional[ScanBaseline]:
        """
        Get the current active baseline for a host.

        Args:
            db: Database session
            host_id: Host UUID

        Returns:
            Active ScanBaseline or None
        """
        builder = (
            QueryBuilder("scan_baselines")
            .select("id")
            .where("host_id = :host_id", host_id, "host_id")
            .where("is_active = :is_active", True, "is_active")
        )
        query, params = builder.build()
        row = db.execute(text(query), params).fetchone()
        if not row:
            return None
        return db.query(ScanBaseline).filter(ScanBaseline.id == row.id).first()

    def compute_rolling_baseline(
        self,
        db: Session,
        host_id: UUID,
        user_id: Optional[int] = None,
        window_days: int = 7,
    ) -> Optional[ScanBaseline]:
        """
        Compute a rolling baseline from the 7-day moving average of scan results.

        Averages scan scores and per-severity counts over the last `window_days`
        days of completed scans to produce a smoothed baseline.

        Args:
            db: Database session
            host_id: Host UUID
            user_id: Optional user who triggered the computation
            window_days: Number of days for the moving average (default 7)

        Returns:
            Newly created ScanBaseline or None if insufficient data
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)

        builder = (
            QueryBuilder("scan_results sr")
            .select(
                "AVG(sr.score) as avg_score",
                "AVG(sr.passed_rules) as avg_passed",
                "AVG(sr.failed_rules) as avg_failed",
                "AVG(sr.total_rules) as avg_total",
                "AVG(COALESCE(sr.severity_critical_passed, 0)) as avg_crit_pass",
                "AVG(COALESCE(sr.severity_critical_failed, 0)) as avg_crit_fail",
                "AVG(COALESCE(sr.severity_high_passed, 0)) as avg_high_pass",
                "AVG(COALESCE(sr.severity_high_failed, 0)) as avg_high_fail",
                "AVG(COALESCE(sr.severity_medium_passed, 0)) as avg_med_pass",
                "AVG(COALESCE(sr.severity_medium_failed, 0)) as avg_med_fail",
                "AVG(COALESCE(sr.severity_low_passed, 0)) as avg_low_pass",
                "AVG(COALESCE(sr.severity_low_failed, 0)) as avg_low_fail",
                "COUNT(*) as scan_count",
            )
            .join("scans s", "s.id = sr.scan_id", "INNER")
            .where("s.host_id = :host_id", host_id, "host_id")
            .where("s.status = :status", "completed", "status")
            .where("s.started_at >= :cutoff", cutoff, "cutoff")
        )
        q, p = builder.build()
        row = db.execute(text(q), p).fetchone()

        if not row or row.scan_count == 0:
            return None

        self._deactivate_current_baseline(db, host_id)

        now = datetime.now(timezone.utc)
        ins = (
            InsertBuilder("scan_baselines")
            .columns(
                "host_id",
                "baseline_type",
                "established_at",
                "established_by",
                "baseline_score",
                "baseline_passed_rules",
                "baseline_failed_rules",
                "baseline_total_rules",
                "baseline_critical_passed",
                "baseline_critical_failed",
                "baseline_high_passed",
                "baseline_high_failed",
                "baseline_medium_passed",
                "baseline_medium_failed",
                "baseline_low_passed",
                "baseline_low_failed",
                "drift_threshold_major",
                "drift_threshold_minor",
                "is_active",
            )
            .values(
                host_id,
                "rolling_avg",
                now,
                user_id,
                float(row.avg_score),
                int(round(row.avg_passed)),
                int(round(row.avg_failed)),
                int(round(row.avg_total)),
                int(round(row.avg_crit_pass)),
                int(round(row.avg_crit_fail)),
                int(round(row.avg_high_pass)),
                int(round(row.avg_high_fail)),
                int(round(row.avg_med_pass)),
                int(round(row.avg_med_fail)),
                int(round(row.avg_low_pass)),
                int(round(row.avg_low_fail)),
                10.0,
                5.0,
                True,
            )
            .returning("id")
        )
        iq, ip = ins.build()
        new_row = db.execute(text(iq), ip).fetchone()
        db.commit()

        baseline = db.query(ScanBaseline).filter(ScanBaseline.id == new_row.id).first()

        audit_logger.info(
            "BASELINE_ROLLING_COMPUTED",
            extra={
                "host_id": str(host_id),
                "baseline_id": str(baseline.id),
                "baseline_score": float(baseline.baseline_score),
                "window_days": window_days,
                "scan_count": int(row.scan_count),
                "action": "baseline_rolling",
                "resource_type": "baseline",
            },
        )

        logger.info(
            f"Rolling baseline computed for host {host_id}: "
            f"score={baseline.baseline_score:.1f}% "
            f"(moving_average over {row.scan_count} scans in {window_days} days)"
        )

        return baseline

    # -------------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------------

    def _get_latest_scan_results(self, db: Session, host_id: UUID) -> Any:
        """Get results from the most recent completed scan for a host."""
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
            .where("s.host_id = :host_id", host_id, "host_id")
            .where("s.status = :status", "completed", "status")
            .order_by("s.completed_at", "DESC")
            .paginate(1, 1)
        )
        query, params = builder.build()
        return db.execute(text(query), params).fetchone()

    def _deactivate_current_baseline(self, db: Session, host_id: UUID) -> None:
        """Deactivate any active baseline for the host."""
        now = datetime.now(timezone.utc)
        builder = (
            UpdateBuilder("scan_baselines")
            .set("is_active", False)
            .set("superseded_at", now)
            .where("host_id = :host_id", host_id, "host_id")
            .where("is_active = :is_active", True, "is_active")
        )
        q, p = builder.build()
        db.execute(text(q), p)

    def _create_baseline_from_scan(
        self,
        db: Session,
        host_id: UUID,
        scan_data: Any,
        baseline_type: str,
        user_id: int,
    ) -> ScanBaseline:
        """Create a new baseline from scan result data."""
        now = datetime.now(timezone.utc)
        builder = (
            InsertBuilder("scan_baselines")
            .columns(
                "host_id",
                "baseline_type",
                "established_at",
                "established_by",
                "baseline_score",
                "baseline_passed_rules",
                "baseline_failed_rules",
                "baseline_total_rules",
                "baseline_critical_passed",
                "baseline_critical_failed",
                "baseline_high_passed",
                "baseline_high_failed",
                "baseline_medium_passed",
                "baseline_medium_failed",
                "baseline_low_passed",
                "baseline_low_failed",
                "drift_threshold_major",
                "drift_threshold_minor",
                "is_active",
            )
            .values(
                host_id,
                baseline_type,
                now,
                user_id,
                scan_data.score,
                scan_data.passed_rules,
                scan_data.failed_rules,
                scan_data.total_rules,
                scan_data.severity_critical_passed or 0,
                scan_data.severity_critical_failed or 0,
                scan_data.severity_high_passed or 0,
                scan_data.severity_high_failed or 0,
                scan_data.severity_medium_passed or 0,
                scan_data.severity_medium_failed or 0,
                scan_data.severity_low_passed or 0,
                scan_data.severity_low_failed or 0,
                10.0,
                5.0,
                True,
            )
            .returning("id")
        )
        q, p = builder.build()
        row = db.execute(text(q), p).fetchone()
        db.commit()

        return db.query(ScanBaseline).filter(ScanBaseline.id == row.id).first()

    def _get_current_posture(self, db: Session, host_id: UUID) -> Optional[Dict[str, int]]:
        """Aggregate current posture from host_rule_state."""
        query = text("""
            SELECT
                COUNT(*) AS total_rules,
                COUNT(*) FILTER (WHERE current_status = 'pass') AS passed_rules,
                COUNT(*) FILTER (WHERE current_status = 'fail') AS failed_rules,
                COUNT(*) FILTER (WHERE severity = 'critical' AND current_status = 'pass')
                    AS critical_passed,
                COUNT(*) FILTER (WHERE severity = 'critical' AND current_status = 'fail')
                    AS critical_failed,
                COUNT(*) FILTER (WHERE severity = 'high' AND current_status = 'pass')
                    AS high_passed,
                COUNT(*) FILTER (WHERE severity = 'high' AND current_status = 'fail')
                    AS high_failed,
                COUNT(*) FILTER (WHERE severity = 'medium' AND current_status = 'pass')
                    AS medium_passed,
                COUNT(*) FILTER (WHERE severity = 'medium' AND current_status = 'fail')
                    AS medium_failed,
                COUNT(*) FILTER (WHERE severity = 'low' AND current_status = 'pass')
                    AS low_passed,
                COUNT(*) FILTER (WHERE severity = 'low' AND current_status = 'fail')
                    AS low_failed
            FROM host_rule_state
            WHERE host_id = :host_id
        """)
        row = db.execute(query, {"host_id": str(host_id)}).fetchone()
        if not row or row.total_rules == 0:
            return None

        return {
            "total_rules": row.total_rules,
            "passed_rules": row.passed_rules,
            "failed_rules": row.failed_rules,
            "critical_passed": row.critical_passed,
            "critical_failed": row.critical_failed,
            "high_passed": row.high_passed,
            "high_failed": row.high_failed,
            "medium_passed": row.medium_passed,
            "medium_failed": row.medium_failed,
            "low_passed": row.low_passed,
            "low_failed": row.low_failed,
        }
