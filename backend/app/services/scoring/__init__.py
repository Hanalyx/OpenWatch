"""
SCAP Scoring Services Module

DEPRECATED: This module has been migrated to OWCA Extraction Layer.

Please use backend.app.services.owca.extraction instead:
    - XCCDFScoreExtractor  →  XCCDFParser
    - SeverityWeightingService  →  SeverityCalculator
    - RiskScoreResult  →  SeverityRiskResult

Migration Example:
    # OLD (deprecated)
    from backend.app.services.scoring import XCCDFScoreExtractor, SeverityWeightingService
    extractor = XCCDFScoreExtractor()
    severity_service = SeverityWeightingService()

    # NEW (recommended)
    from backend.app.services.owca import get_owca_service
    owca = get_owca_service(db)
    xccdf_result = owca.extract_xccdf_score(xml_file)
    severity_risk = owca.calculate_severity_risk(critical=5, high=10)

This module will be removed in a future release.
See: docs/OWCA_EXTRACTION_LAYER_MIGRATION.md

Modules:
    xccdf_score_extractor: Extract native XCCDF scores from TestResult elements (DEPRECATED)
    severity_weighting_service: Calculate risk scores based on severity weights (DEPRECATED)
    constants: Severity weights and risk level thresholds (DEPRECATED)

Security:
    - XXE prevention via secure XML parsing
    - Path traversal validation
    - File size limits
    - Comprehensive audit logging
    - Input validation via Pydantic models
"""

import warnings

# Imports must come after module docstring per PEP 257
# Deprecation warning issued before imports to notify users immediately
from backend.app.services.scoring.constants import (  # noqa: E402
    SEVERITY_WEIGHT_CRITICAL,
    SEVERITY_WEIGHT_HIGH,
    SEVERITY_WEIGHT_INFO,
    SEVERITY_WEIGHT_LOW,
    SEVERITY_WEIGHT_MEDIUM,
    SEVERITY_WEIGHTS,
    get_risk_level,
    get_severity_weight,
)
from backend.app.services.scoring.severity_weighting_service import (  # noqa: E402
    RiskScoreResult,
    SeverityDistribution,
    SeverityWeightingService,
)
from backend.app.services.scoring.xccdf_score_extractor import XCCDFScoreExtractor, XCCDFScoreResult  # noqa: E402

# Issue deprecation warning when module is imported
warnings.warn(
    "backend.app.services.scoring is deprecated and will be removed in a future release. "
    "Use backend.app.services.owca.extraction instead. "
    "See migration guide: docs/OWCA_EXTRACTION_LAYER_MIGRATION.md",
    DeprecationWarning,
    stacklevel=2,
)

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
