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
from .intelligence.baseline_drift import BaselineDriftDetector
from .models import BaselineDrift, ComplianceScore, ComplianceTier, FleetStatistics, RiskScore, TrendData

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
        self.drift_detector = BaselineDriftDetector(db, self.score_calculator)

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
