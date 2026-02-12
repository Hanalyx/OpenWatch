"""
OWCA Intelligence Layer - Trend Analysis

Analyzes compliance trends over time to identify patterns and improvement/decline rates.
Provides historical compliance data for dashboard visualizations and reporting.

Unified Data Source:
    This analyzer now reads from posture_snapshots as the primary source for historical
    compliance data, with fallback to live scans for hosts without snapshots.
    This unifies OWCA's intelligence layer with Temporal Compliance.

Security: All database queries use QueryBuilder for SQL injection protection.
"""

import logging
from datetime import datetime, timedelta
from typing import List, Optional
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from ..core.score_calculator import ComplianceScoreCalculator
from ..models import TrendData, TrendDataPoint, TrendDirection

logger = logging.getLogger(__name__)


class TrendAnalyzer:
    """
    Compliance trend analysis over time.

    Analyzes historical scan results to identify:
    - Overall trend direction (improving, declining, stable)
    - Rate of improvement or decline (percentage points per day)
    - Historical data points for visualization
    - Compliance patterns and trajectories
    """

    # Trend classification thresholds (percentage points per day)
    THRESHOLD_IMPROVING = 0.1  # >0.1% improvement per day
    THRESHOLD_DECLINING = -0.1  # <-0.1% decline per day
    # Between thresholds = stable

    def __init__(self, db: Session, score_calculator: ComplianceScoreCalculator):
        """
        Initialize trend analyzer.

        Args:
            db: SQLAlchemy database session
            score_calculator: ComplianceScoreCalculator for score calculations
        """
        self.db = db
        self.score_calculator = score_calculator

    async def analyze_trend(
        self,
        entity_id: UUID,
        entity_type: str = "host",
        days: int = 30,
    ) -> Optional[TrendData]:
        """
        Analyze compliance trend over specified time period.

        Queries historical scan results and calculates:
        1. Daily/weekly compliance scores
        2. Overall trend direction (improving/declining/stable)
        3. Rate of change (percentage points per day)

        Args:
            entity_id: UUID of entity to analyze (host, group, org)
            entity_type: Type of entity ("host", "group", "organization")
            days: Number of days to analyze (default: 30)

        Returns:
            TrendData with historical analysis, or None if insufficient data

        Example:
            >>> analyzer = TrendAnalyzer(db, score_calculator)
            >>> trend = await analyzer.analyze_trend(host_id, "host", days=30)
            >>> if trend.trend_direction == TrendDirection.DECLINING:
            ...     print(f"ALERT: Compliance declining at {trend.improvement_rate}%/day")

        Security:
            Uses QueryBuilder for SQL injection protection in all database queries.
        """
        if entity_type != "host":
            # For group/organization, would aggregate across multiple hosts
            # Currently only host-level trends are implemented
            logger.warning(f"Trend analysis for {entity_type} not yet implemented")
            return None

        # Get historical scan results for the time period
        data_points = await self._get_historical_data(entity_id, days)

        if len(data_points) < 2:
            logger.info(f"Insufficient data for trend analysis: {len(data_points)} points " f"(need at least 2)")
            return None

        # Calculate trend direction and improvement rate
        trend_direction, improvement_rate = self._calculate_trend(data_points)

        return TrendData(
            entity_id=entity_id,
            entity_type=entity_type,
            time_period_days=days,
            data_points=data_points,
            trend_direction=trend_direction,
            improvement_rate=improvement_rate,
            calculated_at=datetime.utcnow(),
        )

    async def _get_historical_data(self, host_id: UUID, days: int) -> List[TrendDataPoint]:
        """
        Retrieve historical compliance data points.

        PRIMARY SOURCE: posture_snapshots table (daily compliance snapshots)
        FALLBACK: live scans table (for hosts without snapshots)

        This unified approach ensures TrendAnalyzer uses the same historical
        data source as Temporal Compliance, providing consistent trend analysis.

        Args:
            host_id: UUID of the host
            days: Number of days to retrieve

        Returns:
            List of TrendDataPoint objects sorted by date (oldest first)

        Security:
            Uses parameterized SQL queries to prevent SQL injection attacks.
        """
        # Try posture_snapshots first (unified data source)
        data_points = await self._get_historical_data_from_snapshots(host_id, days)

        # Fallback to scan-based data if no snapshots exist
        if not data_points:
            logger.debug(f"No snapshots found for host {host_id}, falling back to scan-based data")
            data_points = await self._get_historical_data_from_scans(host_id, days)

        logger.info(f"Retrieved {len(data_points)} historical data points for trend analysis")
        return data_points

    async def _get_historical_data_from_snapshots(self, host_id: UUID, days: int) -> List[TrendDataPoint]:
        """
        Retrieve historical compliance data from posture_snapshots table.

        This is the PRIMARY data source for trend analysis, providing consistent
        daily snapshots of compliance posture.

        Args:
            host_id: UUID of the host
            days: Number of days to retrieve

        Returns:
            List of TrendDataPoint objects sorted by date (oldest first)
        """
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        query = text(
            """
            SELECT
                DATE(snapshot_date) AS snapshot_day,
                compliance_score AS overall_score,
                severity_critical_passed,
                severity_critical_failed,
                severity_high_passed,
                severity_high_failed,
                severity_medium_passed,
                severity_medium_failed,
                severity_low_passed,
                severity_low_failed,
                source_scan_id
            FROM posture_snapshots
            WHERE host_id = :host_id
              AND snapshot_date >= :start_date
              AND snapshot_date <= :end_date
            ORDER BY snapshot_day ASC
            """
        )

        results = self.db.execute(
            query,
            {
                "host_id": str(host_id),
                "start_date": start_date,
                "end_date": end_date,
            },
        ).fetchall()

        data_points = []
        for row in results:
            data_points.append(
                TrendDataPoint(
                    date=row.snapshot_day.strftime("%Y-%m-%d"),
                    overall_score=float(row.overall_score),
                    critical_passed=row.severity_critical_passed or 0,
                    critical_failed=row.severity_critical_failed or 0,
                    high_passed=row.severity_high_passed or 0,
                    high_failed=row.severity_high_failed or 0,
                    medium_passed=row.severity_medium_passed or 0,
                    medium_failed=row.severity_medium_failed or 0,
                    low_passed=row.severity_low_passed or 0,
                    low_failed=row.severity_low_failed or 0,
                    source_scan_id=row.source_scan_id,
                )
            )

        if data_points:
            logger.debug(f"Retrieved {len(data_points)} data points from posture_snapshots")

        return data_points

    async def _get_historical_data_from_scans(self, host_id: UUID, days: int) -> List[TrendDataPoint]:
        """
        Retrieve historical compliance data from scans table (FALLBACK).

        Used when posture_snapshots don't exist for a host (e.g., new hosts
        or hosts that haven't had daily snapshot task run).

        Args:
            host_id: UUID of the host
            days: Number of days to retrieve

        Returns:
            List of TrendDataPoint objects sorted by date (oldest first)
        """
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        query = text(
            """
            WITH daily_scans AS (
                SELECT DISTINCT ON (DATE(s.completed_at))
                    DATE(s.completed_at) AS scan_date,
                    s.id AS scan_id,
                    sr.passed_rules,
                    sr.failed_rules,
                    sr.total_rules,
                    sr.severity_critical_passed,
                    sr.severity_critical_failed,
                    sr.severity_high_passed,
                    sr.severity_high_failed,
                    sr.severity_medium_passed,
                    sr.severity_medium_failed,
                    sr.severity_low_passed,
                    sr.severity_low_failed,
                    s.completed_at
                FROM scans s
                JOIN scan_results sr ON s.id = sr.scan_id
                WHERE s.host_id = :host_id
                  AND s.status = 'completed'
                  AND s.completed_at >= :start_date
                  AND s.completed_at <= :end_date
                ORDER BY DATE(s.completed_at), s.completed_at DESC
            )
            SELECT
                scan_date,
                passed_rules,
                failed_rules,
                total_rules,
                severity_critical_passed,
                severity_critical_failed,
                severity_high_passed,
                severity_high_failed,
                severity_medium_passed,
                severity_medium_failed,
                severity_low_passed,
                severity_low_failed,
                CASE
                    WHEN total_rules > 0
                    THEN ROUND((passed_rules::numeric / total_rules::numeric) * 100, 2)
                    ELSE 0
                END AS overall_score
            FROM daily_scans
            ORDER BY scan_date ASC
            """
        )

        results = self.db.execute(
            query,
            {
                "host_id": str(host_id),
                "start_date": start_date,
                "end_date": end_date,
            },
        ).fetchall()

        data_points = []
        for row in results:
            data_points.append(
                TrendDataPoint(
                    date=row.scan_date.strftime("%Y-%m-%d"),
                    overall_score=float(row.overall_score),
                    critical_passed=row.severity_critical_passed or 0,
                    critical_failed=row.severity_critical_failed or 0,
                    high_passed=row.severity_high_passed or 0,
                    high_failed=row.severity_high_failed or 0,
                    medium_passed=row.severity_medium_passed or 0,
                    medium_failed=row.severity_medium_failed or 0,
                    low_passed=row.severity_low_passed or 0,
                    low_failed=row.severity_low_failed or 0,
                )
            )

        if data_points:
            logger.debug(f"Retrieved {len(data_points)} data points from scans (fallback)")

        return data_points

    def _calculate_trend(self, data_points: List[TrendDataPoint]) -> tuple[TrendDirection, Optional[float]]:
        """
        Calculate trend direction and improvement rate using linear regression.

        Uses simple linear regression (least squares method) to determine
        the overall trend direction and rate of change.

        Args:
            data_points: List of historical data points (chronological order)

        Returns:
            Tuple of (TrendDirection, improvement_rate in % per day)

        Algorithm:
            1. Assign x-values as day indices (0, 1, 2, ...)
            2. Use y-values as compliance scores
            3. Calculate slope using least squares linear regression
            4. Classify trend based on slope thresholds
        """
        if len(data_points) < 2:
            return TrendDirection.STABLE, None

        # Extract scores and create x-values (day indices)
        scores = [point.overall_score for point in data_points]
        n = len(scores)
        x_values = list(range(n))

        # Calculate linear regression slope using least squares method
        # Formula: slope = (n*Σxy - Σx*Σy) / (n*Σx² - (Σx)²)
        sum_x = sum(x_values)
        sum_y = sum(scores)
        sum_xy = sum(x * y for x, y in zip(x_values, scores))
        sum_x_squared = sum(x * x for x in x_values)

        # Calculate slope (rate of change per day)
        denominator = n * sum_x_squared - sum_x * sum_x
        if denominator == 0:
            # All x-values identical (shouldn't happen with sequential days)
            return TrendDirection.STABLE, 0.0

        slope = (n * sum_xy - sum_x * sum_y) / denominator

        # Classify trend based on slope
        if slope > self.THRESHOLD_IMPROVING:
            trend_direction = TrendDirection.IMPROVING
        elif slope < self.THRESHOLD_DECLINING:
            trend_direction = TrendDirection.DECLINING
        else:
            trend_direction = TrendDirection.STABLE

        # Round improvement rate to 3 decimal places
        improvement_rate = round(slope, 3)

        logger.debug(f"Trend analysis: direction={trend_direction}, " f"rate={improvement_rate}%/day (n={n} points)")

        return trend_direction, improvement_rate

    async def get_fleet_trend(self, days: int = 30) -> Optional[TrendData]:
        """
        Analyze fleet-wide compliance trend.

        Aggregates compliance trends across all hosts in the organization
        to provide an overall fleet trend analysis.

        PRIMARY SOURCE: posture_snapshots table (daily compliance snapshots)
        FALLBACK: live scans table (for systems without snapshots)

        Args:
            days: Number of days to analyze (default: 30)

        Returns:
            TrendData for the entire fleet, or None if insufficient data

        Example:
            >>> analyzer = TrendAnalyzer(db, score_calculator)
            >>> fleet_trend = await analyzer.get_fleet_trend(days=90)
            >>> print(f"Fleet trending: {fleet_trend.trend_direction}")
        """
        # Try posture_snapshots first (unified data source)
        data_points = await self._get_fleet_trend_from_snapshots(days)

        # Fallback to scan-based data if no snapshots exist
        if not data_points:
            logger.debug("No fleet snapshots found, falling back to scan-based data")
            data_points = await self._get_fleet_trend_from_scans(days)

        if len(data_points) < 2:
            logger.info(f"Insufficient fleet data for trend analysis: {len(data_points)} points")
            return None

        # Calculate trend
        trend_direction, improvement_rate = self._calculate_trend(data_points)

        # Use a placeholder UUID for fleet-level (could be organization ID)
        fleet_id = UUID("00000000-0000-0000-0000-000000000000")

        return TrendData(
            entity_id=fleet_id,
            entity_type="organization",
            time_period_days=days,
            data_points=data_points,
            trend_direction=trend_direction,
            improvement_rate=improvement_rate,
            calculated_at=datetime.utcnow(),
        )

    async def _get_fleet_trend_from_snapshots(self, days: int) -> List[TrendDataPoint]:
        """
        Retrieve fleet-wide trend data from posture_snapshots table.

        This is the PRIMARY data source for fleet trend analysis.

        Args:
            days: Number of days to retrieve

        Returns:
            List of TrendDataPoint objects sorted by date (oldest first)
        """
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        query = text(
            """
            SELECT
                DATE(snapshot_date) AS snapshot_day,
                COUNT(*) AS total_hosts,
                AVG(compliance_score) AS avg_score,
                SUM(severity_critical_passed) AS critical_passed,
                SUM(severity_critical_failed) AS critical_failed,
                SUM(severity_high_passed) AS high_passed,
                SUM(severity_high_failed) AS high_failed,
                SUM(severity_medium_passed) AS medium_passed,
                SUM(severity_medium_failed) AS medium_failed,
                SUM(severity_low_passed) AS low_passed,
                SUM(severity_low_failed) AS low_failed
            FROM posture_snapshots
            WHERE snapshot_date >= :start_date
              AND snapshot_date <= :end_date
            GROUP BY DATE(snapshot_date)
            ORDER BY snapshot_day ASC
            """
        )

        results = self.db.execute(query, {"start_date": start_date, "end_date": end_date}).fetchall()

        data_points = []
        for row in results:
            data_points.append(
                TrendDataPoint(
                    date=row.snapshot_day.strftime("%Y-%m-%d"),
                    overall_score=round(float(row.avg_score), 2),
                    critical_passed=int(row.critical_passed or 0),
                    critical_failed=int(row.critical_failed or 0),
                    high_passed=int(row.high_passed or 0),
                    high_failed=int(row.high_failed or 0),
                    medium_passed=int(row.medium_passed or 0),
                    medium_failed=int(row.medium_failed or 0),
                    low_passed=int(row.low_passed or 0),
                    low_failed=int(row.low_failed or 0),
                )
            )

        if data_points:
            logger.debug(f"Retrieved {len(data_points)} fleet trend points from posture_snapshots")

        return data_points

    async def _get_fleet_trend_from_scans(self, days: int) -> List[TrendDataPoint]:
        """
        Retrieve fleet-wide trend data from scans table (FALLBACK).

        Used when posture_snapshots don't exist.

        Args:
            days: Number of days to retrieve

        Returns:
            List of TrendDataPoint objects sorted by date (oldest first)
        """
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        query = text(
            """
            WITH daily_fleet_scores AS (
                SELECT
                    DATE(s.completed_at) AS scan_date,
                    AVG(
                        CASE
                            WHEN sr.total_rules > 0
                            THEN (sr.passed_rules::numeric / sr.total_rules::numeric) * 100
                            ELSE 0
                        END
                    ) AS avg_score,
                    SUM(sr.severity_critical_passed) AS critical_passed,
                    SUM(sr.severity_critical_failed) AS critical_failed,
                    SUM(sr.severity_high_passed) AS high_passed,
                    SUM(sr.severity_high_failed) AS high_failed,
                    SUM(sr.severity_medium_passed) AS medium_passed,
                    SUM(sr.severity_medium_failed) AS medium_failed,
                    SUM(sr.severity_low_passed) AS low_passed,
                    SUM(sr.severity_low_failed) AS low_failed
                FROM scans s
                JOIN scan_results sr ON s.id = sr.scan_id
                WHERE s.status = 'completed'
                  AND s.completed_at >= :start_date
                  AND s.completed_at <= :end_date
                GROUP BY DATE(s.completed_at)
                ORDER BY scan_date ASC
            )
            SELECT * FROM daily_fleet_scores
            """
        )

        results = self.db.execute(query, {"start_date": start_date, "end_date": end_date}).fetchall()

        data_points = []
        for row in results:
            data_points.append(
                TrendDataPoint(
                    date=row.scan_date.strftime("%Y-%m-%d"),
                    overall_score=round(float(row.avg_score), 2),
                    critical_passed=int(row.critical_passed or 0),
                    critical_failed=int(row.critical_failed or 0),
                    high_passed=int(row.high_passed or 0),
                    high_failed=int(row.high_failed or 0),
                    medium_passed=int(row.medium_passed or 0),
                    medium_failed=int(row.medium_failed or 0),
                    low_passed=int(row.low_passed or 0),
                    low_failed=int(row.low_failed or 0),
                )
            )

        if data_points:
            logger.debug(f"Retrieved {len(data_points)} fleet trend points from scans (fallback)")

        return data_points
