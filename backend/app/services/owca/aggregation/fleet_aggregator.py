"""
OWCA Aggregation Layer - Fleet Statistics

Provides organization-wide compliance aggregation and fleet statistics.
Replaces frontend calculation logic with optimized backend queries.

Unified Data Source:
    This aggregator now provides fleet-level historical trends from posture_snapshots,
    unifying OWCA's fleet analytics with Temporal Compliance.
"""

import logging
from datetime import date, datetime, timedelta
from typing import List, Optional
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from ....utils.query_builder import QueryBuilder
from ..core.score_calculator import ComplianceScoreCalculator
from ..models import ComplianceScore, FleetComplianceTrend, FleetStatistics, FleetTrendDataPoint, TrendDirection

logger = logging.getLogger(__name__)


class FleetAggregator:
    """
    Fleet-wide compliance aggregation service.

    Provides comprehensive statistics across all hosts in the organization.
    """

    def __init__(self, db: Session, score_calculator: ComplianceScoreCalculator, cache=None):
        """
        Initialize fleet aggregator.

        Args:
            db: SQLAlchemy database session
            score_calculator: ComplianceScoreCalculator instance for score calculations
            cache: Optional OWCACache instance for caching results
        """
        self.db = db
        self.score_calculator = score_calculator
        self.cache = cache

    async def get_fleet_statistics(self) -> FleetStatistics:
        """
        Get comprehensive fleet-wide statistics.

        Calculates:
        - Total/online/offline host counts
        - Scanned vs never scanned
        - Average/median compliance scores
        - Hosts by compliance tier
        - Total issues by severity
        - Hosts with critical issues

        Returns:
            FleetStatistics with all aggregated metrics

        Example:
            >>> aggregator = FleetAggregator(db, score_calculator)
            >>> stats = await aggregator.get_fleet_statistics()
            >>> print(f"Fleet average: {stats.average_compliance}%")
        """
        # Check cache first
        if self.cache:
            cached = await self.cache.get("fleet_statistics")
            if cached:
                logger.debug("Cache HIT for fleet_statistics")
                return FleetStatistics(**cached)

        # Build optimized query with CTEs for different metrics
        query = text(
            """
            WITH host_counts AS (
                SELECT
                    COUNT(*) AS total_hosts,
                    COUNT(CASE WHEN status = 'online' THEN 1 END) AS online_hosts,
                    COUNT(CASE WHEN status = 'offline' THEN 1 END) AS offline_hosts
                FROM hosts
            ),
            scan_counts AS (
                SELECT
                    COUNT(DISTINCT host_id) AS scanned_hosts
                FROM scans
                WHERE status = 'completed'
            ),
            latest_scans AS (
                SELECT DISTINCT ON (s.host_id)
                    s.host_id,
                    sr.passed_rules,
                    sr.failed_rules,
                    sr.total_rules,
                    sr.severity_critical_failed AS critical_failed,
                    sr.severity_high_failed AS high_failed,
                    sr.severity_medium_failed AS medium_failed,
                    sr.severity_low_failed AS low_failed,
                    s.completed_at
                FROM scans s
                JOIN scan_results sr ON s.id = sr.scan_id
                WHERE s.status = 'completed'
                ORDER BY s.host_id, s.completed_at DESC
            ),
            compliance_scores AS (
                SELECT
                    host_id,
                    CASE
                        WHEN total_rules > 0
                        THEN ROUND((passed_rules::numeric / total_rules::numeric) * 100, 2)
                        ELSE 0
                    END AS score
                FROM latest_scans
            ),
            tier_counts AS (
                SELECT
                    COUNT(CASE WHEN score >= 90 THEN 1 END) AS excellent,
                    COUNT(CASE WHEN score >= 75 AND score < 90 THEN 1 END) AS good,
                    COUNT(CASE WHEN score >= 60 AND score < 75 THEN 1 END) AS fair,
                    COUNT(CASE WHEN score < 60 THEN 1 END) AS poor
                FROM compliance_scores
            ),
            issue_counts AS (
                SELECT
                    SUM(critical_failed) AS total_critical,
                    SUM(high_failed) AS total_high,
                    SUM(medium_failed) AS total_medium,
                    SUM(low_failed) AS total_low,
                    COUNT(CASE WHEN critical_failed > 0 THEN 1 END) AS hosts_with_critical
                FROM latest_scans
            ),
            needs_scan AS (
                SELECT COUNT(*) AS count
                FROM hosts h
                LEFT JOIN scans s ON h.id = s.host_id AND s.status = 'completed'
                WHERE s.completed_at IS NULL
                   OR s.completed_at < :threshold_date
            ),
            compliance_stats AS (
                SELECT
                    COALESCE(AVG(score), 0) AS average_compliance,
                    COALESCE(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY score), 0) AS median_compliance
                FROM compliance_scores
            )
            SELECT
                hc.total_hosts,
                hc.online_hosts,
                hc.offline_hosts,
                COALESCE(sc.scanned_hosts, 0) AS scanned_hosts,
                hc.total_hosts - COALESCE(sc.scanned_hosts, 0) AS never_scanned,
                COALESCE(ns.count, 0) AS needs_scan,
                cst.average_compliance,
                cst.median_compliance,
                COALESCE(tc.excellent, 0) AS hosts_excellent,
                COALESCE(tc.good, 0) AS hosts_good,
                COALESCE(tc.fair, 0) AS hosts_fair,
                COALESCE(tc.poor, 0) AS hosts_poor,
                COALESCE(ic.total_critical, 0) AS total_critical_issues,
                COALESCE(ic.total_high, 0) AS total_high_issues,
                COALESCE(ic.total_medium, 0) AS total_medium_issues,
                COALESCE(ic.total_low, 0) AS total_low_issues,
                COALESCE(ic.hosts_with_critical, 0) AS hosts_with_critical
            FROM host_counts hc
            CROSS JOIN scan_counts sc
            CROSS JOIN tier_counts tc
            CROSS JOIN issue_counts ic
            CROSS JOIN needs_scan ns
            CROSS JOIN compliance_stats cst
            """
        )

        # Threshold for "needs scan" - 7 days ago
        threshold_date = datetime.utcnow() - timedelta(days=7)

        result = self.db.execute(query, {"threshold_date": threshold_date}).fetchone()

        if not result:
            logger.warning("Failed to fetch fleet statistics")
            return FleetStatistics(calculated_at=datetime.utcnow())

        # Build FleetStatistics model
        stats = FleetStatistics(
            total_hosts=result.total_hosts or 0,
            online_hosts=result.online_hosts or 0,
            offline_hosts=result.offline_hosts or 0,
            scanned_hosts=result.scanned_hosts or 0,
            never_scanned=result.never_scanned or 0,
            needs_scan=result.needs_scan or 0,
            average_compliance=float(result.average_compliance or 0),
            median_compliance=float(result.median_compliance or 0),
            hosts_excellent=result.hosts_excellent or 0,
            hosts_good=result.hosts_good or 0,
            hosts_fair=result.hosts_fair or 0,
            hosts_poor=result.hosts_poor or 0,
            total_critical_issues=int(result.total_critical_issues or 0),
            total_high_issues=int(result.total_high_issues or 0),
            total_medium_issues=int(result.total_medium_issues or 0),
            total_low_issues=int(result.total_low_issues or 0),
            hosts_with_critical=result.hosts_with_critical or 0,
            calculated_at=datetime.utcnow(),
        )

        # Cache the result (5 min TTL)
        if self.cache:
            await self.cache.set("fleet_statistics", stats.dict(), ttl=300)

        logger.info(
            f"Fleet statistics: {stats.total_hosts} hosts, "
            f"{stats.average_compliance}% avg compliance, "
            f"{stats.total_critical_issues} critical issues"
        )

        return stats

    async def get_group_compliance(self, group_id: UUID) -> Optional[ComplianceScore]:
        """
        Get aggregated compliance score for a host group.

        Args:
            group_id: UUID of the host group

        Returns:
            Aggregated ComplianceScore for the group, or None if no hosts

        Example:
            >>> aggregator = FleetAggregator(db, score_calculator)
            >>> group_score = await aggregator.get_group_compliance(group_id)
        """
        # Query all hosts in the group
        query_builder = (
            QueryBuilder("host_group_memberships hgm")
            .select("hgm.host_id")
            .where("hgm.group_id = :group_id", group_id, "group_id")
        )

        query, params = query_builder.build()
        results = self.db.execute(text(query), params).fetchall()

        if not results:
            logger.info(f"No hosts found in group {group_id}")
            return None

        # Get compliance scores for all hosts in the group
        host_scores: List[ComplianceScore] = []
        for row in results:
            host_id = row.host_id
            score = await self.score_calculator.get_host_compliance_score(host_id)
            if score:
                host_scores.append(score)

        if not host_scores:
            logger.info(f"No compliance scores available for group {group_id}")
            return None

        # Aggregate scores using score calculator
        group_score = self.score_calculator.calculate_aggregate_score(host_scores)

        if group_score:
            # Update entity metadata
            group_score.entity_id = group_id
            group_score.entity_type = "group"

        return group_score

    async def get_top_priority_hosts(self, limit: int = 10) -> List[dict]:
        """
        Get top priority hosts for remediation.

        Prioritizes hosts with:
        1. Most critical issues
        2. Lowest compliance scores
        3. Most recent scans

        Args:
            limit: Maximum number of hosts to return (default: 10)

        Returns:
            List of host dictionaries with priority ranking

        Example:
            >>> aggregator = FleetAggregator(db, score_calculator)
            >>> priority_hosts = await aggregator.get_top_priority_hosts(limit=5)
        """
        query = text(
            """
            SELECT DISTINCT ON (s.host_id)
                h.id AS host_id,
                h.hostname,
                h.ip_address,
                s.id AS scan_id,
                sr.passed_rules,
                sr.failed_rules,
                sr.total_rules,
                sr.severity_critical_failed AS critical_failed,
                sr.severity_high_failed AS high_failed,
                s.completed_at,
                CASE
                    WHEN sr.total_rules > 0
                    THEN ROUND((sr.passed_rules::numeric / sr.total_rules::numeric) * 100, 2)
                    ELSE 0
                END AS compliance_score,
                (sr.severity_critical_failed * 10 + sr.severity_high_failed * 5) AS priority_score
            FROM hosts h
            JOIN scans s ON h.id = s.host_id
            JOIN scan_results sr ON s.id = sr.scan_id
            WHERE s.status = 'completed'
            ORDER BY s.host_id, s.completed_at DESC
            LIMIT :limit
            """
        )

        results = self.db.execute(query, {"limit": limit}).fetchall()

        # Sort by priority score (highest first) then by compliance score (lowest first)
        priority_hosts = [
            {
                "host_id": str(row.host_id),
                "hostname": row.hostname,
                "ip_address": row.ip_address,
                "compliance_score": float(row.compliance_score),
                "critical_issues": row.critical_failed,
                "high_issues": row.high_failed,
                "priority_score": row.priority_score,
                "last_scan": row.completed_at.isoformat() if row.completed_at else None,
            }
            for row in results
        ]

        # Sort: highest priority score first, then lowest compliance score
        priority_hosts.sort(key=lambda x: (-x["priority_score"], x["compliance_score"]))

        # Add rank
        for i, host in enumerate(priority_hosts, start=1):
            host["rank"] = i

        logger.info(f"Retrieved {len(priority_hosts)} top priority hosts")

        return priority_hosts

    async def get_fleet_statistics_at_date(self, as_of: date) -> Optional[FleetStatistics]:
        """
        Get fleet statistics for a specific historical date.

        Uses posture_snapshots as the data source for historical queries.

        Args:
            as_of: Date to get statistics for

        Returns:
            FleetStatistics for the specified date, or None if no data

        Example:
            >>> aggregator = FleetAggregator(db, score_calculator)
            >>> stats = await aggregator.get_fleet_statistics_at_date(date(2026, 2, 1))
        """
        query = text(
            """
            WITH host_counts AS (
                SELECT
                    COUNT(*) AS total_hosts,
                    COUNT(CASE WHEN status = 'online' THEN 1 END) AS online_hosts,
                    COUNT(CASE WHEN status = 'offline' THEN 1 END) AS offline_hosts
                FROM hosts
            ),
            snapshot_data AS (
                SELECT
                    host_id,
                    compliance_score,
                    severity_critical_failed AS critical_failed,
                    severity_high_failed AS high_failed,
                    severity_medium_failed AS medium_failed,
                    severity_low_failed AS low_failed
                FROM posture_snapshots
                WHERE DATE(snapshot_date) = :as_of
            ),
            tier_counts AS (
                SELECT
                    COUNT(CASE WHEN compliance_score >= 90 THEN 1 END) AS excellent,
                    COUNT(CASE WHEN compliance_score >= 75 AND compliance_score < 90 THEN 1 END) AS good,
                    COUNT(CASE WHEN compliance_score >= 60 AND compliance_score < 75 THEN 1 END) AS fair,
                    COUNT(CASE WHEN compliance_score < 60 THEN 1 END) AS poor
                FROM snapshot_data
            ),
            issue_counts AS (
                SELECT
                    SUM(critical_failed) AS total_critical,
                    SUM(high_failed) AS total_high,
                    SUM(medium_failed) AS total_medium,
                    SUM(low_failed) AS total_low,
                    COUNT(CASE WHEN critical_failed > 0 THEN 1 END) AS hosts_with_critical
                FROM snapshot_data
            ),
            compliance_stats AS (
                SELECT
                    COUNT(*) AS scanned_hosts,
                    COALESCE(AVG(compliance_score), 0) AS average_compliance,
                    COALESCE(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY compliance_score), 0) AS median_compliance
                FROM snapshot_data
            )
            SELECT
                hc.total_hosts,
                hc.online_hosts,
                hc.offline_hosts,
                COALESCE(cs.scanned_hosts, 0) AS scanned_hosts,
                hc.total_hosts - COALESCE(cs.scanned_hosts, 0) AS never_scanned,
                0 AS needs_scan,
                cs.average_compliance,
                cs.median_compliance,
                COALESCE(tc.excellent, 0) AS hosts_excellent,
                COALESCE(tc.good, 0) AS hosts_good,
                COALESCE(tc.fair, 0) AS hosts_fair,
                COALESCE(tc.poor, 0) AS hosts_poor,
                COALESCE(ic.total_critical, 0) AS total_critical_issues,
                COALESCE(ic.total_high, 0) AS total_high_issues,
                COALESCE(ic.total_medium, 0) AS total_medium_issues,
                COALESCE(ic.total_low, 0) AS total_low_issues,
                COALESCE(ic.hosts_with_critical, 0) AS hosts_with_critical
            FROM host_counts hc
            CROSS JOIN compliance_stats cs
            CROSS JOIN tier_counts tc
            CROSS JOIN issue_counts ic
            """
        )

        result = self.db.execute(query, {"as_of": as_of}).fetchone()

        if not result or result.scanned_hosts == 0:
            logger.info(f"No fleet statistics available for date {as_of}")
            return None

        return FleetStatistics(
            total_hosts=result.total_hosts or 0,
            online_hosts=result.online_hosts or 0,
            offline_hosts=result.offline_hosts or 0,
            scanned_hosts=result.scanned_hosts or 0,
            never_scanned=result.never_scanned or 0,
            needs_scan=result.needs_scan or 0,
            average_compliance=float(result.average_compliance or 0),
            median_compliance=float(result.median_compliance or 0),
            hosts_excellent=result.hosts_excellent or 0,
            hosts_good=result.hosts_good or 0,
            hosts_fair=result.hosts_fair or 0,
            hosts_poor=result.hosts_poor or 0,
            total_critical_issues=int(result.total_critical_issues or 0),
            total_high_issues=int(result.total_high_issues or 0),
            total_medium_issues=int(result.total_medium_issues or 0),
            total_low_issues=int(result.total_low_issues or 0),
            hosts_with_critical=result.hosts_with_critical or 0,
            calculated_at=datetime.combine(as_of, datetime.min.time()),
        )

    async def get_fleet_trend(
        self,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None,
    ) -> Optional[FleetComplianceTrend]:
        """
        Get fleet-wide compliance trend over a date range.

        Uses posture_snapshots as the single source of truth for historical
        fleet compliance data.

        Args:
            start_date: Start date (default: 30 days ago)
            end_date: End date (default: today)

        Returns:
            FleetComplianceTrend with daily statistics, or None if no data

        Example:
            >>> aggregator = FleetAggregator(db, score_calculator)
            >>> trend = await aggregator.get_fleet_trend(
            ...     start_date=date(2026, 1, 1),
            ...     end_date=date(2026, 2, 1)
            ... )
            >>> print(f"Fleet trend: {trend.trend_direction}")
        """
        if end_date is None:
            end_date = date.today()
        if start_date is None:
            start_date = end_date - timedelta(days=30)

        query = text(
            """
            SELECT
                DATE(snapshot_date) AS snapshot_day,
                COUNT(*) AS total_hosts,
                AVG(compliance_score) AS avg_compliance,
                PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY compliance_score) AS median_compliance,
                COUNT(CASE WHEN compliance_score >= 90 THEN 1 END) AS hosts_excellent,
                COUNT(CASE WHEN compliance_score >= 75 AND compliance_score < 90 THEN 1 END) AS hosts_good,
                COUNT(CASE WHEN compliance_score >= 60 AND compliance_score < 75 THEN 1 END) AS hosts_fair,
                COUNT(CASE WHEN compliance_score < 60 THEN 1 END) AS hosts_poor,
                SUM(severity_critical_failed) AS total_critical,
                SUM(severity_high_failed) AS total_high,
                SUM(severity_medium_failed) AS total_medium,
                SUM(severity_low_failed) AS total_low
            FROM posture_snapshots
            WHERE snapshot_date >= :start_date AND snapshot_date <= :end_date
            GROUP BY DATE(snapshot_date)
            ORDER BY snapshot_day ASC
            """
        )

        results = self.db.execute(
            query,
            {"start_date": start_date, "end_date": end_date},
        ).fetchall()

        if not results:
            logger.info(f"No fleet trend data available for {start_date} to {end_date}")
            return None

        # Convert to FleetTrendDataPoint objects
        data_points = []
        for row in results:
            data_points.append(
                FleetTrendDataPoint(
                    date=row.snapshot_day.strftime("%Y-%m-%d"),
                    average_compliance=round(float(row.avg_compliance), 2),
                    median_compliance=round(float(row.median_compliance), 2) if row.median_compliance else None,
                    total_hosts=row.total_hosts or 0,
                    hosts_excellent=row.hosts_excellent or 0,
                    hosts_good=row.hosts_good or 0,
                    hosts_fair=row.hosts_fair or 0,
                    hosts_poor=row.hosts_poor or 0,
                    total_critical_issues=int(row.total_critical or 0),
                    total_high_issues=int(row.total_high or 0),
                    total_medium_issues=int(row.total_medium or 0),
                    total_low_issues=int(row.total_low or 0),
                )
            )

        # Calculate trend direction and improvement rate
        trend_direction, improvement_rate = self._calculate_trend(data_points)

        logger.info(
            f"Fleet trend: {len(data_points)} days, direction={trend_direction}, " f"rate={improvement_rate}%/day"
        )

        return FleetComplianceTrend(
            start_date=start_date.strftime("%Y-%m-%d"),
            end_date=end_date.strftime("%Y-%m-%d"),
            data_points=data_points,
            trend_direction=trend_direction,
            improvement_rate=improvement_rate,
            calculated_at=datetime.utcnow(),
        )

    def _calculate_trend(self, data_points: List[FleetTrendDataPoint]) -> tuple[TrendDirection, Optional[float]]:
        """
        Calculate trend direction and improvement rate using linear regression.

        Uses simple linear regression (least squares method) to determine
        the overall trend direction and rate of change.

        Args:
            data_points: List of FleetTrendDataPoint (chronological order)

        Returns:
            Tuple of (TrendDirection, improvement_rate in % per day)
        """
        if len(data_points) < 2:
            return TrendDirection.STABLE, None

        # Extract scores and create x-values (day indices)
        scores = [point.average_compliance for point in data_points]
        n = len(scores)
        x_values = list(range(n))

        # Calculate linear regression slope using least squares method
        sum_x = sum(x_values)
        sum_y = sum(scores)
        sum_xy = sum(x * y for x, y in zip(x_values, scores))
        sum_x_squared = sum(x * x for x in x_values)

        # Calculate slope (rate of change per day)
        denominator = n * sum_x_squared - sum_x * sum_x
        if denominator == 0:
            return TrendDirection.STABLE, 0.0

        slope = (n * sum_xy - sum_x * sum_y) / denominator

        # Trend classification thresholds (percentage points per day)
        THRESHOLD_IMPROVING = 0.1  # >0.1% improvement per day
        THRESHOLD_DECLINING = -0.1  # <-0.1% decline per day

        # Classify trend based on slope
        if slope > THRESHOLD_IMPROVING:
            trend_direction = TrendDirection.IMPROVING
        elif slope < THRESHOLD_DECLINING:
            trend_direction = TrendDirection.DECLINING
        else:
            trend_direction = TrendDirection.STABLE

        # Round improvement rate to 3 decimal places
        improvement_rate = round(slope, 3)

        return trend_direction, improvement_rate
