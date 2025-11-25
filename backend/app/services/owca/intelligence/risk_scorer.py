"""
OWCA Intelligence Layer - Risk Scoring

Calculates composite risk scores for hosts based on multiple factors:
- Compliance score (lower = higher risk)
- Critical and high severity issues
- Time since last scan (staleness)
- Baseline drift magnitude
- Business criticality (if available)

Used for prioritizing remediation efforts and resource allocation.

Security: All database queries use QueryBuilder for SQL injection protection.
"""

import logging
from datetime import datetime
from typing import List, Optional
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.utils.query_builder import QueryBuilder

from ..core.score_calculator import ComplianceScoreCalculator
from ..models import RiskScore

logger = logging.getLogger(__name__)


class RiskScorer:
    """
    Risk scoring engine for compliance prioritization.

    Combines multiple risk factors into a single composite score:
    1. Compliance score (40% weight) - lower compliance = higher risk
    2. Critical issues (25% weight) - more critical issues = higher risk
    3. Scan staleness (15% weight) - older scans = higher risk
    4. Baseline drift (15% weight) - larger drift = higher risk
    5. Business criticality (5% weight) - production > development

    Risk tiers:
    - critical: 80-100 risk score
    - high: 60-79 risk score
    - medium: 40-59 risk score
    - low: 0-39 risk score
    """

    # Risk factor weights (must sum to 1.0)
    WEIGHT_COMPLIANCE = 0.40
    WEIGHT_CRITICAL_ISSUES = 0.25
    WEIGHT_SCAN_AGE = 0.15
    WEIGHT_DRIFT = 0.15
    WEIGHT_BUSINESS = 0.05

    # Risk tier thresholds
    TIER_CRITICAL = 80
    TIER_HIGH = 60
    TIER_MEDIUM = 40

    # Business criticality multipliers
    BUSINESS_MULTIPLIERS = {
        "production": 100,
        "staging": 70,
        "development": 40,
        "testing": 30,
        None: 50,  # Default if not specified
    }

    def __init__(
        self,
        db: Session,
        score_calculator: ComplianceScoreCalculator,
        drift_detector=None,
    ):
        """
        Initialize risk scorer.

        Args:
            db: SQLAlchemy database session
            score_calculator: ComplianceScoreCalculator for current scores
            drift_detector: Optional BaselineDriftDetector for drift analysis
        """
        self.db = db
        self.score_calculator = score_calculator
        self.drift_detector = drift_detector

    async def calculate_risk(self, host_id: UUID, business_criticality: Optional[str] = None) -> Optional[RiskScore]:
        """
        Calculate composite risk score for a host.

        Combines compliance, critical issues, scan age, baseline drift,
        and business criticality into a single risk score (0-100).

        Args:
            host_id: UUID of the host to analyze
            business_criticality: Optional business tier ("production", "staging", etc.)

        Returns:
            RiskScore object, or None if no scan data available

        Example:
            >>> scorer = RiskScorer(db, score_calculator, drift_detector)
            >>> risk = await scorer.calculate_risk(host_id, "production")
            >>> if risk.risk_tier == "critical":
            ...     print(f"URGENT: Host {host_id} has critical risk score {risk.risk_score}")

        Security:
            Uses QueryBuilder for SQL injection protection in all database queries.
        """
        # Get current compliance score
        compliance_score_obj = await self.score_calculator.get_host_compliance_score(str(host_id))

        if not compliance_score_obj:
            logger.warning(f"No compliance data available for host {host_id}")
            return None

        # Extract risk factors
        compliance_score = compliance_score_obj.overall_score
        critical_issues = compliance_score_obj.severity_breakdown.critical_failed
        high_issues = compliance_score_obj.severity_breakdown.high_failed

        # Get scan age (days since last scan)
        days_since_scan = await self._get_scan_age(host_id)

        # Get baseline drift (if available)
        baseline_drift, has_baseline = await self._get_baseline_drift(host_id)

        # Calculate weighted risk score
        risk_score = self._calculate_composite_score(
            compliance_score=compliance_score,
            critical_issues=critical_issues,
            high_issues=high_issues,
            days_since_scan=days_since_scan,
            baseline_drift=baseline_drift,
            business_criticality=business_criticality,
        )

        # Classify risk tier
        risk_tier = self._classify_risk_tier(risk_score)

        return RiskScore(
            host_id=host_id,
            risk_score=round(risk_score, 2),
            risk_tier=risk_tier,
            compliance_score=compliance_score,
            critical_issues=critical_issues,
            high_issues=high_issues,
            days_since_scan=days_since_scan,
            has_baseline=has_baseline,
            baseline_drift=baseline_drift,
            business_criticality=business_criticality,
            priority_rank=0,  # Will be set by rank_hosts_by_risk()
            calculated_at=datetime.utcnow(),
        )

    async def rank_hosts_by_risk(self, limit: Optional[int] = None) -> List[RiskScore]:
        """
        Calculate risk scores for all hosts and rank by priority.

        Useful for generating "top priority hosts" lists for remediation
        workflows and executive dashboards.

        Args:
            limit: Optional maximum number of hosts to return (default: all)

        Returns:
            List of RiskScore objects sorted by risk (highest first)

        Example:
            >>> scorer = RiskScorer(db, score_calculator)
            >>> top_risks = await scorer.rank_hosts_by_risk(limit=10)
            >>> for rank, risk in enumerate(top_risks, start=1):
            ...     print(f"#{rank}: {risk.host_id} - {risk.risk_score}/100")
        """
        # Get all hosts with completed scans
        query_builder = (
            QueryBuilder("hosts h")
            .select("DISTINCT h.id")
            .join("scans s", "h.id = s.host_id", "INNER")
            .where("s.status = :status", "completed", "status")
        )

        query, params = query_builder.build()
        results = self.db.execute(text(query), params).fetchall()

        # Calculate risk for each host
        risk_scores = []
        for row in results:
            host_id = row.id
            risk = await self.calculate_risk(host_id)
            if risk:
                risk_scores.append(risk)

        # Sort by risk score (highest first)
        risk_scores.sort(key=lambda r: r.risk_score, reverse=True)

        # Assign priority ranks
        for rank, risk in enumerate(risk_scores, start=1):
            risk.priority_rank = rank

        # Apply limit if specified
        if limit:
            risk_scores = risk_scores[:limit]

        logger.info(f"Ranked {len(risk_scores)} hosts by risk " f"(limit={limit if limit else 'none'})")

        return risk_scores

    def _calculate_composite_score(
        self,
        compliance_score: float,
        critical_issues: int,
        high_issues: int,
        days_since_scan: int,
        baseline_drift: Optional[float],
        business_criticality: Optional[str],
    ) -> float:
        """
        Calculate weighted composite risk score.

        Combines multiple risk factors using configured weights to produce
        a single 0-100 risk score.

        Args:
            compliance_score: Current compliance percentage (0-100)
            critical_issues: Number of critical severity failures
            high_issues: Number of high severity failures (for tie-breaking)
            days_since_scan: Days since last scan
            baseline_drift: Percentage point drift from baseline (can be negative)
            business_criticality: Business tier ("production", "staging", etc.)

        Returns:
            Composite risk score (0-100, higher = more risk)

        Algorithm:
            risk = (
                (100 - compliance) * 0.40 +     # Lower compliance = higher risk
                min(critical * 10, 100) * 0.25 + # More critical issues = higher risk
                min(days / 30 * 100, 100) * 0.15 + # Older scans = higher risk
                min(abs(drift) * 5, 100) * 0.15 + # Larger drift = higher risk
                business_multiplier * 0.05       # Production = higher risk
            )
        """
        # Factor 1: Compliance score (inverted - lower compliance = higher risk)
        compliance_risk = (100 - compliance_score) * self.WEIGHT_COMPLIANCE

        # Factor 2: Critical issues (capped at 10 issues = 100% risk)
        # Rationale: 10+ critical issues is already extremely high risk
        critical_risk = min(critical_issues * 10, 100) * self.WEIGHT_CRITICAL_ISSUES

        # Factor 3: Scan age (capped at 30 days = 100% risk)
        # Rationale: Scans older than 30 days are considered severely stale
        scan_age_risk = min(days_since_scan / 30 * 100, 100) * self.WEIGHT_SCAN_AGE

        # Factor 4: Baseline drift (use absolute value, capped at 20% drift = 100% risk)
        # Rationale: ±20% drift from baseline is a massive change
        drift_risk = 0.0
        if baseline_drift is not None:
            drift_risk = min(abs(baseline_drift) * 5, 100) * self.WEIGHT_DRIFT

        # Factor 5: Business criticality
        business_multiplier = self.BUSINESS_MULTIPLIERS.get(business_criticality, self.BUSINESS_MULTIPLIERS[None])
        business_risk = business_multiplier * self.WEIGHT_BUSINESS

        # Composite score
        composite = compliance_risk + critical_risk + scan_age_risk + drift_risk + business_risk

        # Ensure result is within [0, 100]
        composite = max(0, min(100, composite))

        logger.debug(
            f"Risk calculation: compliance={compliance_risk:.1f}, "
            f"critical={critical_risk:.1f}, age={scan_age_risk:.1f}, "
            f"drift={drift_risk:.1f}, business={business_risk:.1f}, "
            f"total={composite:.1f}"
        )

        return composite

    def _classify_risk_tier(self, risk_score: float) -> str:
        """
        Classify risk score into tier (critical/high/medium/low).

        Args:
            risk_score: Composite risk score (0-100)

        Returns:
            Risk tier string

        Thresholds:
            - critical: 80-100
            - high: 60-79
            - medium: 40-59
            - low: 0-39
        """
        if risk_score >= self.TIER_CRITICAL:
            return "critical"
        elif risk_score >= self.TIER_HIGH:
            return "high"
        elif risk_score >= self.TIER_MEDIUM:
            return "medium"
        else:
            return "low"

    async def _get_scan_age(self, host_id: UUID) -> int:
        """
        Get days since last completed scan.

        Args:
            host_id: UUID of the host

        Returns:
            Number of days since last scan (0 if scanned today)

        Security:
            Uses QueryBuilder for parameterized SQL queries.
        """
        query_builder = (
            QueryBuilder("scans s")
            .select("MAX(s.completed_at) AS last_scan")
            .where("s.host_id = :host_id", str(host_id), "host_id")
            .where("s.status = :status", "completed", "status")
        )

        query, params = query_builder.build()
        result = self.db.execute(text(query), params).fetchone()

        if not result or not result.last_scan:
            # No scans found - treat as very old
            return 9999

        # Calculate days since last scan
        last_scan = result.last_scan
        days_since = (datetime.utcnow() - last_scan).days

        return max(0, days_since)

    async def _get_baseline_drift(self, host_id: UUID) -> tuple[Optional[float], bool]:
        """
        Get baseline drift percentage if available.

        Args:
            host_id: UUID of the host

        Returns:
            Tuple of (drift_percentage, has_baseline)
            - drift_percentage: Percentage point drift (can be negative), or None
            - has_baseline: Whether host has an active baseline

        Security:
            Uses QueryBuilder for parameterized SQL queries.
        """
        if not self.drift_detector:
            return None, False

        # Use drift detector to get current drift
        drift_obj = await self.drift_detector.detect_drift(host_id)

        if not drift_obj:
            return None, False

        return drift_obj.drift_percentage, True
