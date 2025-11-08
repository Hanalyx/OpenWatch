"""
SCAP Scoring Services Module

Provides comprehensive scoring capabilities for SCAP compliance scans:
- XCCDF native score extraction
- Severity-weighted risk scoring
- Framework-specific scoring (DISA STIG, CIS, NIST)

This module implements the three-tier scoring system per the
XCCDF Scoring Implementation Plan (Revised).

Modules:
    xccdf_score_extractor: Extract native XCCDF scores from TestResult elements
    severity_weighting_service: Calculate risk scores based on severity weights
    constants: Severity weights and risk level thresholds
    framework_score_calculator: Framework-specific scoring breakdowns (Phase 3)

Security:
    - XXE prevention via secure XML parsing
    - Path traversal validation
    - File size limits
    - Comprehensive audit logging
    - Input validation via Pydantic models
"""

from backend.app.services.scoring.constants import (
    SEVERITY_WEIGHT_CRITICAL,
    SEVERITY_WEIGHT_HIGH,
    SEVERITY_WEIGHT_INFO,
    SEVERITY_WEIGHT_LOW,
    SEVERITY_WEIGHT_MEDIUM,
    SEVERITY_WEIGHTS,
    get_risk_level,
    get_severity_weight,
)
from backend.app.services.scoring.severity_weighting_service import (
    RiskScoreResult,
    SeverityDistribution,
    SeverityWeightingService,
)
from backend.app.services.scoring.xccdf_score_extractor import XCCDFScoreExtractor, XCCDFScoreResult

__all__ = [
    # XCCDF Score Extraction (Phase 1)
    "XCCDFScoreExtractor",
    "XCCDFScoreResult",
    # Severity Weighting (Phase 2)
    "SeverityWeightingService",
    "RiskScoreResult",
    "SeverityDistribution",
    # Constants
    "SEVERITY_WEIGHTS",
    "SEVERITY_WEIGHT_CRITICAL",
    "SEVERITY_WEIGHT_HIGH",
    "SEVERITY_WEIGHT_MEDIUM",
    "SEVERITY_WEIGHT_LOW",
    "SEVERITY_WEIGHT_INFO",
    "get_risk_level",
    "get_severity_weight",
]
