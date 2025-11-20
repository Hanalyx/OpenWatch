"""
Baseline Management Service

Handles compliance baseline establishment, retrieval, and management.
NIST SP 800-137 Continuous Monitoring requires establishing known-good
baselines to detect configuration drift and compliance changes.
"""

import logging
from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from ..database import ScanBaseline
from ..utils.query_builder import QueryBuilder

logger = logging.getLogger(__name__)


class BaselineService:
    """
    Manages compliance baseline establishment and retrieval.

    Baselines represent known-good compliance state for drift detection.
    Each host can have only one active baseline at a time.
    """

    def establish_baseline(
        self,
        db: Session,
        host_id: UUID,
        scan_id: UUID,
        baseline_type: str = "manual",
        established_by: Optional[UUID] = None,
    ) -> ScanBaseline:
        """
        Establish compliance baseline for a host.

        Supersedes any existing active baseline for the host.
        Uses per-severity pass/fail data for accurate tracking.

        Args:
            db: Database session
            host_id: Target host UUID
            scan_id: Reference scan to use as baseline
            baseline_type: 'initial', 'manual', or 'rolling_avg'
            established_by: User ID who established baseline (NULL for auto)

        Returns:
            Created baseline record

        Raises:
            ValueError: If scan not completed or host invalid
            DatabaseError: If baseline creation fails
        """
        # Fetch scan results with per-severity data
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
        scan_data = result.fetchone()

        if not scan_data:
            raise ValueError(f"Scan {scan_id} not found or not completed for host {host_id}")

        # Deactivate existing baseline (if any)
        existing_baseline = self.get_active_baseline(db, host_id)
        if existing_baseline:
            existing_baseline.is_active = False
            existing_baseline.superseded_at = datetime.utcnow()
            # superseded_by will be set after new baseline created

        # Convert score from string "64.82%" to float 64.82
        score_value = scan_data.score
        if isinstance(score_value, str):
            score_value = float(score_value.rstrip("%"))

        # Create new baseline with per-severity data
        baseline = ScanBaseline(
            host_id=host_id,
            baseline_type=baseline_type,
            established_by=established_by,
            baseline_score=score_value,
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
            is_active=True,
        )

        db.add(baseline)
        db.flush()  # Get baseline.id before updating superseded_by

        if existing_baseline:
            existing_baseline.superseded_by = baseline.id

        db.commit()
        db.refresh(baseline)

        logger.info(f"Established {baseline_type} baseline for host {host_id} " f"(score: {baseline.baseline_score}%)")

        return baseline

    def get_active_baseline(
        self,
        db: Session,
        host_id: UUID,
    ) -> Optional[ScanBaseline]:
        """
        Get active baseline for a host.

        Args:
            db: Database session
            host_id: Target host UUID

        Returns:
            Active baseline or None if no baseline established
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

        # Fetch full ORM object
        baseline = db.query(ScanBaseline).filter(ScanBaseline.id == baseline_row.id).first()

        return baseline

    def reset_baseline(
        self,
        db: Session,
        host_id: UUID,
    ) -> bool:
        """
        Reset baseline for a host (mark as inactive).

        Args:
            db: Database session
            host_id: Target host UUID

        Returns:
            True if baseline was reset, False if no active baseline
        """
        builder = (
            QueryBuilder("scan_baselines")
            .update(
                {
                    "is_active": False,
                    "superseded_at": datetime.utcnow(),
                }
            )
            .where("host_id = :host_id", host_id, "host_id")
            .where("is_active = :is_active", True, "is_active")
        )

        query, params = builder.build()
        result = db.execute(text(query), params)
        db.commit()

        if result.rowcount > 0:
            logger.info(f"Reset baseline for host {host_id}")
            return True

        return False
