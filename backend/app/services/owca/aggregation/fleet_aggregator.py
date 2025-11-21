"""
OWCA Aggregation Layer - Fleet Statistics

Provides organization-wide compliance aggregation and fleet statistics.
Replaces frontend calculation logic with optimized backend queries.
"""

import logging
from datetime import datetime, timedelta
from typing import List, Optional
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.utils.query_builder import QueryBuilder

from ..core.score_calculator import ComplianceScoreCalculator
from ..models import ComplianceScore, FleetStatistics

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
                SELECT DISTINCT ON (host_id)
                    host_id,
                    passed_rules,
                    failed_rules,
                    total_rules,
                    critical_failed,
                    high_failed,
                    medium_failed,
                    low_failed,
                    completed_at
                FROM scans
                WHERE status = 'completed'
                ORDER BY host_id, completed_at DESC
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
            )
            SELECT
                hc.total_hosts,
                hc.online_hosts,
                hc.offline_hosts,
                COALESCE(sc.scanned_hosts, 0) AS scanned_hosts,
                hc.total_hosts - COALESCE(sc.scanned_hosts, 0) AS never_scanned,
                COALESCE(ns.count, 0) AS needs_scan,
                COALESCE(AVG(cs.score), 0) AS average_compliance,
                COALESCE(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY cs.score), 0) AS median_compliance,
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
            CROSS JOIN compliance_scores cs
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
                s.passed_rules,
                s.failed_rules,
                s.total_rules,
                s.critical_failed,
                s.high_failed,
                s.completed_at,
                CASE
                    WHEN s.total_rules > 0
                    THEN ROUND((s.passed_rules::numeric / s.total_rules::numeric) * 100, 2)
                    ELSE 0
                END AS compliance_score,
                (s.critical_failed * 10 + s.high_failed * 5) AS priority_score
            FROM hosts h
            JOIN scans s ON h.id = s.host_id
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
