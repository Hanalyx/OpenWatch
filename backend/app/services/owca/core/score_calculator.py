"""
OWCA Core Layer - Compliance Score Calculator

Single source of truth for all compliance score calculations.
Eliminates duplicate calculation logic across the codebase.
"""

import logging
from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.utils.query_builder import QueryBuilder

from ..models import ComplianceScore, ComplianceTier, SeverityBreakdown

logger = logging.getLogger(__name__)


class ComplianceScoreCalculator:
    """
    Core compliance score calculator.

    Provides canonical implementations of:
    - Compliance score calculation (passed/total * 100)
    - Tier classification (EXCELLENT/GOOD/FAIR/POOR)
    - Severity breakdown aggregation

    Security: All calculations use parameterized queries via QueryBuilder
    to prevent SQL injection attacks.
    """

    def __init__(self, db: Session, cache=None):
        """
        Initialize score calculator.

        Args:
            db: SQLAlchemy database session
            cache: Optional OWCACache instance for caching results
        """
        self.db = db
        self.cache = cache

    def calculate_score(self, passed: int, total: int) -> float:
        """
        Calculate compliance score percentage.

        This is the canonical formula used throughout OpenWatch.
        Formula: (passed_rules / total_rules) * 100

        Args:
            passed: Number of passed rules
            total: Total number of rules evaluated

        Returns:
            Compliance score as percentage (0.0 to 100.0)

        Example:
            >>> calc = ComplianceScoreCalculator(db)
            >>> calc.calculate_score(passed=87, total=100)
            87.0
        """
        if total == 0:
            return 0.0
        return round((passed / total) * 100.0, 2)

    def get_compliance_tier(self, score: float) -> ComplianceTier:
        """
        Classify compliance score into tier.

        Tiers:
        - EXCELLENT: 90-100%
        - GOOD: 75-89%
        - FAIR: 60-74%
        - POOR: <60%

        Args:
            score: Compliance score percentage

        Returns:
            ComplianceTier enum value

        Example:
            >>> calc = ComplianceScoreCalculator(db)
            >>> calc.get_compliance_tier(92.5)
            ComplianceTier.EXCELLENT
        """
        if score >= 90:
            return ComplianceTier.EXCELLENT
        elif score >= 75:
            return ComplianceTier.GOOD
        elif score >= 60:
            return ComplianceTier.FAIR
        else:
            return ComplianceTier.POOR

    async def get_host_compliance_score(self, host_id: UUID) -> Optional[ComplianceScore]:
        """
        Get compliance score for a specific host.

        Retrieves latest scan results and calculates comprehensive
        compliance score with severity breakdown.

        Args:
            host_id: UUID of the host

        Returns:
            ComplianceScore with full breakdown, or None if no scans exist

        Example:
            >>> calc = ComplianceScoreCalculator(db)
            >>> score = await calc.get_host_compliance_score(host_id)
            >>> print(f"{score.overall_score}% - {score.tier}")
            87.5% - GOOD
        """
        # Check cache first
        if self.cache:
            cache_key = f"host_score:{host_id}"
            cached = await self.cache.get(cache_key)
            if cached:
                logger.debug(f"Cache HIT for host {host_id}")
                return ComplianceScore(**cached)

        # Query latest scan results for this host using QueryBuilder
        # Note: Compliance data is stored in scan_results table, not scans table
        query_builder = (
            QueryBuilder("scans s")
            .select(
                "s.id as scan_id",
                "sr.passed_rules",
                "sr.failed_rules",
                "sr.total_rules",
                "sr.severity_critical_passed as critical_passed",
                "sr.severity_critical_failed as critical_failed",
                "sr.severity_high_passed as high_passed",
                "sr.severity_high_failed as high_failed",
                "sr.severity_medium_passed as medium_passed",
                "sr.severity_medium_failed as medium_failed",
                "sr.severity_low_passed as low_passed",
                "sr.severity_low_failed as low_failed",
            )
            .join("scan_results sr", "s.id = sr.scan_id", "INNER")  # INNER join ensures we only get scans with results
            .where("s.host_id = :host_id", host_id, "host_id")
            .where("s.status = :status", "completed", "status")
            .order_by("s.completed_at", "DESC")
            .paginate(page=1, per_page=1)  # Get only the most recent scan
        )

        query, params = query_builder.build()
        result = self.db.execute(text(query), params).fetchone()

        if not result:
            logger.info(f"No completed scans found for host {host_id}")
            return None

        # Extract data
        scan_id = result.scan_id
        passed = result.passed_rules or 0
        failed = result.failed_rules or 0
        total = result.total_rules or 0

        # Calculate overall score using canonical formula
        overall_score = self.calculate_score(passed, total)
        tier = self.get_compliance_tier(overall_score)

        # Build severity breakdown
        severity_breakdown = SeverityBreakdown(
            critical_passed=result.critical_passed or 0,
            critical_failed=result.critical_failed or 0,
            critical_total=(result.critical_passed or 0) + (result.critical_failed or 0),
            high_passed=result.high_passed or 0,
            high_failed=result.high_failed or 0,
            high_total=(result.high_passed or 0) + (result.high_failed or 0),
            medium_passed=result.medium_passed or 0,
            medium_failed=result.medium_failed or 0,
            medium_total=(result.medium_passed or 0) + (result.medium_failed or 0),
            low_passed=result.low_passed or 0,
            low_failed=result.low_failed or 0,
            low_total=(result.low_passed or 0) + (result.low_failed or 0),
        )

        # Create ComplianceScore model
        compliance_score = ComplianceScore(
            entity_id=host_id,
            entity_type="host",
            overall_score=overall_score,
            tier=tier,
            passed_rules=passed,
            failed_rules=failed,
            total_rules=total,
            severity_breakdown=severity_breakdown,
            calculated_at=datetime.utcnow(),
            scan_id=scan_id,
        )

        # Cache the result
        if self.cache:
            await self.cache.set(f"host_score:{host_id}", compliance_score.dict(), ttl=300)  # 5 min TTL

        logger.info(
            f"Calculated compliance score for host {host_id}: " f"{overall_score}% ({tier.value}) from scan {scan_id}"
        )

        return compliance_score

    async def get_scan_compliance_score(self, scan_id: UUID) -> Optional[ComplianceScore]:
        """
        Get compliance score for a specific scan.

        Args:
            scan_id: UUID of the scan

        Returns:
            ComplianceScore for the scan, or None if scan not found

        Example:
            >>> calc = ComplianceScoreCalculator(db)
            >>> score = await calc.get_scan_compliance_score(scan_id)
        """
        # Query scan results using QueryBuilder
        # Note: Compliance data is stored in scan_results table, not scans table
        query_builder = (
            QueryBuilder("scans s")
            .select(
                "s.id as scan_id",
                "s.host_id",
                "sr.passed_rules",
                "sr.failed_rules",
                "sr.total_rules",
                "sr.severity_critical_passed as critical_passed",
                "sr.severity_critical_failed as critical_failed",
                "sr.severity_high_passed as high_passed",
                "sr.severity_high_failed as high_failed",
                "sr.severity_medium_passed as medium_passed",
                "sr.severity_medium_failed as medium_failed",
                "sr.severity_low_passed as low_passed",
                "sr.severity_low_failed as low_failed",
            )
            .join("scan_results sr", "s.id = sr.scan_id", "INNER")
            .where("s.id = :scan_id", scan_id, "scan_id")
            .where("s.status = :status", "completed", "status")
        )

        query, params = query_builder.build()
        result = self.db.execute(text(query), params).fetchone()

        if not result:
            logger.warning(f"Scan {scan_id} not found or not completed")
            return None

        # Calculate score
        passed = result.passed_rules or 0
        failed = result.failed_rules or 0
        total = result.total_rules or 0

        overall_score = self.calculate_score(passed, total)
        tier = self.get_compliance_tier(overall_score)

        # Build severity breakdown
        severity_breakdown = SeverityBreakdown(
            critical_passed=result.critical_passed or 0,
            critical_failed=result.critical_failed or 0,
            critical_total=(result.critical_passed or 0) + (result.critical_failed or 0),
            high_passed=result.high_passed or 0,
            high_failed=result.high_failed or 0,
            high_total=(result.high_passed or 0) + (result.high_failed or 0),
            medium_passed=result.medium_passed or 0,
            medium_failed=result.medium_failed or 0,
            medium_total=(result.medium_passed or 0) + (result.medium_failed or 0),
            low_passed=result.low_passed or 0,
            low_failed=result.low_failed or 0,
            low_total=(result.low_passed or 0) + (result.low_failed or 0),
        )

        return ComplianceScore(
            entity_id=result.host_id,
            entity_type="host",
            overall_score=overall_score,
            tier=tier,
            passed_rules=passed,
            failed_rules=failed,
            total_rules=total,
            severity_breakdown=severity_breakdown,
            calculated_at=datetime.utcnow(),
            scan_id=scan_id,
        )

    def calculate_aggregate_score(self, individual_scores: list[ComplianceScore]) -> Optional[ComplianceScore]:
        """
        Calculate aggregate compliance score from multiple individual scores.

        Used for group-level and organization-level aggregation.

        Args:
            individual_scores: List of ComplianceScore objects to aggregate

        Returns:
            Aggregated ComplianceScore or None if no scores provided

        Example:
            >>> calc = ComplianceScoreCalculator(db)
            >>> host_scores = [score1, score2, score3]
            >>> group_score = calc.calculate_aggregate_score(host_scores)
        """
        if not individual_scores:
            return None

        # Aggregate totals
        total_passed = sum(s.passed_rules for s in individual_scores)
        total_failed = sum(s.failed_rules for s in individual_scores)
        total_rules = sum(s.total_rules for s in individual_scores)

        # Calculate aggregate score
        overall_score = self.calculate_score(total_passed, total_rules)
        tier = self.get_compliance_tier(overall_score)

        # Aggregate severity breakdown
        severity_breakdown = SeverityBreakdown(
            critical_passed=sum(s.severity_breakdown.critical_passed for s in individual_scores),
            critical_failed=sum(s.severity_breakdown.critical_failed for s in individual_scores),
            critical_total=sum(s.severity_breakdown.critical_total for s in individual_scores),
            high_passed=sum(s.severity_breakdown.high_passed for s in individual_scores),
            high_failed=sum(s.severity_breakdown.high_failed for s in individual_scores),
            high_total=sum(s.severity_breakdown.high_total for s in individual_scores),
            medium_passed=sum(s.severity_breakdown.medium_passed for s in individual_scores),
            medium_failed=sum(s.severity_breakdown.medium_failed for s in individual_scores),
            medium_total=sum(s.severity_breakdown.medium_total for s in individual_scores),
            low_passed=sum(s.severity_breakdown.low_passed for s in individual_scores),
            low_failed=sum(s.severity_breakdown.low_failed for s in individual_scores),
            low_total=sum(s.severity_breakdown.low_total for s in individual_scores),
        )

        return ComplianceScore(
            entity_id=individual_scores[0].entity_id,  # Use first entity as reference
            entity_type="aggregate",
            overall_score=overall_score,
            tier=tier,
            passed_rules=total_passed,
            failed_rules=total_failed,
            total_rules=total_rules,
            severity_breakdown=severity_breakdown,
            calculated_at=datetime.utcnow(),
        )
