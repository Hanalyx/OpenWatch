"""
OpenWatch Compliance Algorithm (OWCA)

Single source of truth for all compliance calculations, analysis, and intelligence.

This module provides:
- Core compliance score calculations
- Framework-specific intelligence (NIST, CIS, STIG, PCI-DSS)
- Fleet-wide aggregation and statistics
- Trend analysis and predictions
- Baseline drift detection
- Risk scoring and priority ranking

Architecture:
    Entry Point → 4 Specialized Layers → Cached Results

Layers:
    1. Core Layer: Raw metric calculations (pass/fail/score)
    2. Framework Layer: Framework-specific mappings and intelligence
    3. Aggregation Layer: Multi-entity rollup (host → group → org)
    4. Intelligence Layer: Trends, predictions, risk scoring

Usage:
    >>> from backend.app.services.owca import get_owca_service
    >>> owca = get_owca_service(db)
    >>> score = await owca.get_host_compliance_score(host_id)
    >>> print(f"Host compliance: {score.overall_score}% ({score.tier})")
"""

from typing import Optional

from sqlalchemy.orm import Session

from .aggregation.fleet_aggregator import FleetAggregator
from .cache.redis_cache import OWCACache
from .core.score_calculator import ComplianceScoreCalculator
from .framework import get_framework_intelligence
from .intelligence import BaselineDriftDetector, CompliancePredictor, RiskScorer, TrendAnalyzer
from .models import (
    BaselineDrift,
    ComplianceForecast,
    ComplianceScore,
    ComplianceTier,
    FleetStatistics,
    RiskScore,
    TrendData,
)

__version__ = "1.0.0"
__all__ = [
    "OWCAService",
    "get_owca_service",
    "ComplianceScore",
    "ComplianceTier",
    "FleetStatistics",
    "BaselineDrift",
    "TrendData",
    "RiskScore",
]


class OWCAService:
    """
    Main entry point for OpenWatch Compliance Algorithm.

    Provides unified interface to all OWCA functionality while
    maintaining internal layer separation for maintainability.
    """

    def __init__(self, db: Session, use_cache: bool = True):
        """
        Initialize OWCA service with database session.

        Args:
            db: SQLAlchemy database session
            use_cache: Whether to use Redis caching (default: True)
        """
        self.db = db
        self.use_cache = use_cache

        # Initialize layers
        self.cache = OWCACache() if use_cache else None
        self.score_calculator = ComplianceScoreCalculator(db, self.cache)
        self.fleet_aggregator = FleetAggregator(db, self.score_calculator, self.cache)

        # Intelligence Layer components
        self.drift_detector = BaselineDriftDetector(db, self.score_calculator)
        self.trend_analyzer = TrendAnalyzer(db, self.score_calculator)
        self.risk_scorer = RiskScorer(db, self.score_calculator, self.drift_detector)
        self.predictor = CompliancePredictor(db, self.score_calculator, self.trend_analyzer)

    async def get_host_compliance_score(self, host_id: str) -> Optional[ComplianceScore]:
        """
        Get compliance score for a specific host.

        Args:
            host_id: UUID of the host

        Returns:
            ComplianceScore with full breakdown or None if no scans
        """
        return await self.score_calculator.get_host_compliance_score(host_id)

    async def get_fleet_statistics(self) -> FleetStatistics:
        """
        Get organization-wide fleet statistics.

        Returns:
            FleetStatistics with all aggregated metrics
        """
        return await self.fleet_aggregator.get_fleet_statistics()

    async def detect_baseline_drift(self, host_id: str) -> Optional[BaselineDrift]:
        """
        Detect compliance drift from active baseline.

        Args:
            host_id: UUID of the host

        Returns:
            BaselineDrift analysis or None if no baseline
        """
        return await self.drift_detector.detect_drift(host_id)

    async def get_framework_intelligence(self, framework: str, host_id: str, scan_results: Optional[dict] = None):
        """
        Get framework-specific compliance intelligence for a host.

        This method provides deep framework-specific analysis including:
        - NIST 800-53: Control families, baselines, enhancements
        - CIS Benchmarks: Levels and implementation groups
        - STIG: CAT I/II/III severity analysis

        Args:
            framework: Framework identifier ("NIST_800_53", "CIS", "STIG")
            host_id: UUID of the host to analyze
            scan_results: Optional pre-fetched scan results (optimization)

        Returns:
            Framework-specific intelligence object (NISTFrameworkIntelligence,
            CISFrameworkIntelligence, or STIGFrameworkIntelligence) or None
            if framework not supported

        Example:
            >>> owca = get_owca_service(db)
            >>> nist_intel = await owca.get_framework_intelligence("NIST_800_53", host_id)
            >>> print(f"Control family AC: {nist_intel.control_families[0].score}%")
        """
        intelligence_provider = get_framework_intelligence(framework, self.db, self.score_calculator)

        if not intelligence_provider:
            return None

        return await intelligence_provider.analyze_host_compliance(host_id, scan_results)

    async def get_framework_summary(self, framework: str, scan_results: dict) -> Optional[dict]:
        """
        Get lightweight framework summary (for multi-framework views).

        Unlike get_framework_intelligence() which provides complete analysis,
        this method returns a lightweight summary suitable for dashboard views
        showing multiple frameworks at once.

        Args:
            framework: Framework identifier ("NIST_800_53", "CIS", "STIG")
            scan_results: Scan results dictionary

        Returns:
            Dictionary with framework, score, tier, and key metrics

        Example:
            >>> summaries = []
            >>> for fw in ["NIST_800_53", "CIS", "STIG"]:
            ...     summary = await owca.get_framework_summary(fw, scan_results)
            ...     summaries.append(summary)
        """
        intelligence_provider = get_framework_intelligence(framework, self.db, self.score_calculator)

        if not intelligence_provider:
            return None

        return await intelligence_provider.get_framework_summary(scan_results)

    async def analyze_trend(self, entity_id: str, entity_type: str = "host", days: int = 30) -> Optional[TrendData]:
        """
        Analyze compliance trend over time.

        Args:
            entity_id: UUID of entity to analyze
            entity_type: Type of entity ("host", "group", "organization")
            days: Number of days to analyze (default: 30)

        Returns:
            TrendData with historical analysis and trend direction

        Example:
            >>> owca = get_owca_service(db)
            >>> trend = await owca.analyze_trend(host_id, days=60)
            >>> print(f"Trend: {trend.trend_direction}, Rate: {trend.improvement_rate}%/day")
        """
        from uuid import UUID

        return await self.trend_analyzer.analyze_trend(UUID(entity_id), entity_type, days)

    async def calculate_risk(self, host_id: str, business_criticality: Optional[str] = None) -> Optional[RiskScore]:
        """
        Calculate risk score for a host.

        Args:
            host_id: UUID of the host
            business_criticality: Optional business tier ("production", "staging", etc.)

        Returns:
            RiskScore with composite risk analysis

        Example:
            >>> owca = get_owca_service(db)
            >>> risk = await owca.calculate_risk(host_id, "production")
            >>> if risk.risk_tier == "critical":
            ...     print(f"URGENT: Risk score {risk.risk_score}/100")
        """
        from uuid import UUID

        return await self.risk_scorer.calculate_risk(UUID(host_id), business_criticality)

    async def rank_hosts_by_risk(self, limit: Optional[int] = None) -> list:
        """
        Rank all hosts by risk score.

        Args:
            limit: Optional maximum number of hosts to return

        Returns:
            List of RiskScore objects sorted by risk (highest first)

        Example:
            >>> owca = get_owca_service(db)
            >>> top_risks = await owca.rank_hosts_by_risk(limit=10)
        """
        return await self.risk_scorer.rank_hosts_by_risk(limit)

    async def forecast_compliance(
        self,
        entity_id: str,
        entity_type: str = "host",
        days_ahead: int = 30,
        historical_days: int = 90,
    ) -> Optional[ComplianceForecast]:
        """
        Forecast future compliance scores.

        Args:
            entity_id: UUID of entity to forecast
            entity_type: Type of entity ("host", "group", "organization")
            days_ahead: Number of days to forecast (default: 30)
            historical_days: Historical days for regression (default: 90)

        Returns:
            ComplianceForecast with predicted scores and confidence intervals

        Example:
            >>> owca = get_owca_service(db)
            >>> forecast = await owca.forecast_compliance(host_id, days_ahead=30)
            >>> for point in forecast.forecast_points[:5]:
            ...     print(f"{point.date}: {point.predicted_score}%")
        """
        from uuid import UUID

        return await self.predictor.forecast_compliance(UUID(entity_id), entity_type, days_ahead, historical_days)

    async def detect_anomalies(self, entity_id: str, entity_type: str = "host", lookback_days: int = 60) -> list:
        """
        Detect anomalous compliance scores.

        Args:
            entity_id: UUID of entity to analyze
            entity_type: Type of entity ("host", "group", "organization")
            lookback_days: Days of history to analyze (default: 60)

        Returns:
            List of ComplianceAnomaly objects

        Example:
            >>> owca = get_owca_service(db)
            >>> anomalies = await owca.detect_anomalies(host_id)
            >>> for anomaly in anomalies:
            ...     if anomaly.severity == AnomalySeverity.CRITICAL:
            ...         print(f"CRITICAL ANOMALY: {anomaly.description}")
        """
        from uuid import UUID

        return await self.predictor.detect_anomalies(UUID(entity_id), entity_type, lookback_days)

    def get_version(self) -> str:
        """Get OWCA algorithm version."""
        return __version__


def get_owca_service(db: Session, use_cache: bool = True) -> OWCAService:
    """
    Factory function to create OWCA service instance.

    Args:
        db: SQLAlchemy database session
        use_cache: Whether to use Redis caching (default: True)

    Returns:
        Configured OWCAService instance
    """
    return OWCAService(db, use_cache)
