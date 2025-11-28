"""
OpenWatch Compliance Algorithm (OWCA)

Single source of truth for all compliance calculations, analysis, and intelligence.

This module provides:
- SCAP result extraction and parsing (XML, XCCDF)
- Severity-weighted risk scoring
- Core compliance score calculations
- Framework-specific intelligence (NIST, CIS, STIG, PCI-DSS)
- Fleet-wide aggregation and statistics
- Trend analysis and predictions
- Baseline drift detection
- Risk scoring and priority ranking

Architecture:
    Entry Point → 5 Specialized Layers → Cached Results

Layers:
    0. Extraction Layer: XCCDF parsing, severity risk calculation
    1. Core Layer: Raw metric calculations (pass/fail/score)
    2. Framework Layer: Framework-specific mappings and intelligence
    3. Aggregation Layer: Multi-entity rollup (host → group → org)
    4. Intelligence Layer: Trends, predictions, risk scoring

Usage:
    >>> from backend.app.services.owca import get_owca_service
    >>> owca = get_owca_service(db)
    >>>
    >>> # Extract XCCDF score from XML
    >>> xccdf_result = await owca.extract_xccdf_score("/app/data/results/scan_123.xml")
    >>>
    >>> # Calculate severity-based risk
    >>> severity_risk = await owca.calculate_severity_risk(critical=5, high=10)
    >>>
    >>> # Get compliance score
    >>> score = await owca.get_host_compliance_score(host_id)
    >>> print(f"Host compliance: {score.overall_score}% ({score.tier})")
"""

from typing import Optional, Union
from uuid import UUID

from sqlalchemy.orm import Session

from .aggregation.fleet_aggregator import FleetAggregator
from .cache.redis_cache import OWCACache
from .core.score_calculator import ComplianceScoreCalculator
from .extraction import SeverityCalculator, SeverityRiskResult, XCCDFParser, XCCDFScoreResult
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
    # Main service
    "OWCAService",
    "get_owca_service",
    # Extraction Layer (Layer 0)
    "XCCDFParser",
    "XCCDFScoreResult",
    "SeverityCalculator",
    "SeverityRiskResult",
    # Core models
    "ComplianceScore",
    "ComplianceTier",
    "FleetStatistics",
    "BaselineDrift",
    "TrendData",
    "RiskScore",
    "ComplianceForecast",
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

        # Initialize cache
        self.cache = OWCACache() if use_cache else None

        # Layer 0: Extraction Layer
        # Provides SCAP XML parsing and severity-based risk scoring
        self.xccdf_parser = XCCDFParser()
        self.severity_calculator = SeverityCalculator()

        # Layer 1: Core Layer
        self.score_calculator = ComplianceScoreCalculator(db, self.cache)

        # Layer 3: Aggregation Layer
        self.fleet_aggregator = FleetAggregator(db, self.score_calculator, self.cache)

        # Layer 4: Intelligence Layer components
        self.drift_detector = BaselineDriftDetector(db, self.score_calculator)
        self.trend_analyzer = TrendAnalyzer(db, self.score_calculator)
        self.risk_scorer = RiskScorer(db, self.score_calculator, self.drift_detector)
        self.predictor = CompliancePredictor(db, self.score_calculator, self.trend_analyzer)

    async def get_host_compliance_score(
        self, host_id: Union[str, UUID]
    ) -> Optional[ComplianceScore]:
        """
        Get compliance score for a specific host.

        Args:
            host_id: UUID of the host (string or UUID)

        Returns:
            ComplianceScore with full breakdown or None if no scans
        """
        host_uuid = UUID(host_id) if isinstance(host_id, str) else host_id
        return await self.score_calculator.get_host_compliance_score(host_uuid)

    async def get_fleet_statistics(self) -> FleetStatistics:
        """
        Get organization-wide fleet statistics.

        Returns:
            FleetStatistics with all aggregated metrics
        """
        return await self.fleet_aggregator.get_fleet_statistics()

    async def detect_baseline_drift(self, host_id: Union[str, UUID]) -> Optional[BaselineDrift]:
        """
        Detect compliance drift from active baseline.

        Args:
            host_id: UUID of the host (string or UUID)

        Returns:
            BaselineDrift analysis or None if no baseline
        """
        host_uuid = UUID(host_id) if isinstance(host_id, str) else host_id
        return await self.drift_detector.detect_drift(host_uuid)

    async def get_framework_intelligence(
        self, framework: str, host_id: str, scan_results: Optional[dict] = None
    ):
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
        intelligence_provider = get_framework_intelligence(
            framework, self.db, self.score_calculator
        )

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
        intelligence_provider = get_framework_intelligence(
            framework, self.db, self.score_calculator
        )

        if not intelligence_provider:
            return None

        return await intelligence_provider.get_framework_summary(scan_results)

    async def analyze_trend(
        self, entity_id: str, entity_type: str = "host", days: int = 30
    ) -> Optional[TrendData]:
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

    async def calculate_risk(
        self, host_id: str, business_criticality: Optional[str] = None
    ) -> Optional[RiskScore]:
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

        return await self.predictor.forecast_compliance(
            UUID(entity_id), entity_type, days_ahead, historical_days
        )

    async def detect_anomalies(
        self, entity_id: str, entity_type: str = "host", lookback_days: int = 60
    ) -> list:
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

    async def extract_xccdf_score(
        self, result_file: str, user_id: Optional[str] = None
    ) -> XCCDFScoreResult:
        """
        Extract native XCCDF score from scan result XML file.

        Part of OWCA Extraction Layer (Layer 0).
        Provides secure XML parsing with comprehensive security controls.

        Args:
            result_file: Absolute path to XCCDF/ARF result file
            user_id: Optional user ID for audit logging

        Returns:
            XCCDFScoreResult with extracted score data or error information

        Security:
            - XXE attack prevention (secure XML parser)
            - Path traversal validation (no ../ sequences)
            - File size limit enforcement (10MB maximum)
            - Comprehensive audit logging

        Example:
            >>> owca = get_owca_service(db)
            >>> result = await owca.extract_xccdf_score("/app/data/results/scan_123.xml")
            >>> if result.found:
            ...     print(f"XCCDF Score: {result.xccdf_score}/{result.xccdf_score_max}")
            ... else:
            ...     print(f"Error: {result.error}")
        """
        # Check cache first to avoid re-parsing same file
        if self.cache:
            cache_key = f"xccdf_score:{result_file}"
            cached_result = await self.cache.get(cache_key)
            if cached_result:
                return XCCDFScoreResult(**cached_result)

        # Parse XML file using secure parser
        result = self.xccdf_parser.extract_native_score(result_file, user_id)

        # Cache successful results for 5 minutes
        # Rationale: XML files don't change frequently, caching reduces file I/O
        if self.cache and result.found:
            cache_key = f"xccdf_score:{result_file}"
            await self.cache.set(cache_key, result.dict(), ttl=300)

        return result

    def calculate_severity_risk(
        self,
        critical: int = 0,
        high: int = 0,
        medium: int = 0,
        low: int = 0,
        info: int = 0,
        user_id: Optional[str] = None,
        scan_id: Optional[str] = None,
    ) -> SeverityRiskResult:
        """
        Calculate severity-weighted risk score from finding counts.

        Part of OWCA Extraction Layer (Layer 0).
        Applies industry-standard weights from NIST SP 800-30.

        Risk Scoring Formula:
            risk_score = (critical * 10.0) + (high * 5.0) + (medium * 2.0) +
                         (low * 0.5) + (info * 0.0)

        Risk Levels:
            0-20:    Low risk
            21-50:   Medium risk
            51-100:  High risk
            100+:    Critical risk

        Args:
            critical: Number of critical severity findings
            high: Number of high severity findings
            medium: Number of medium severity findings
            low: Number of low severity findings
            info: Number of informational findings
            user_id: Optional user ID for audit logging
            scan_id: Optional scan ID for audit logging

        Returns:
            SeverityRiskResult with calculated score, risk level, and breakdown

        Example:
            >>> owca = get_owca_service(db)
            >>> risk = owca.calculate_severity_risk(critical=5, high=10, medium=20)
            >>> print(f"Risk: {risk.risk_score} ({risk.risk_level})")
            Risk: 155.0 (critical)
            >>>
            >>> # Check severity breakdown
            >>> print(f"Critical contribution: {risk.weighted_breakdown['critical']}")
            Critical contribution: 50.0
        """
        return self.severity_calculator.calculate_risk_score(
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            info_count=info,
            user_id=user_id,
            scan_id=scan_id,
        )

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
