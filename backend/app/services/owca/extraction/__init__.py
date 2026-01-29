"""
OWCA Extraction Layer (Layer 0)

Provides data extraction and initial risk scoring from SCAP scan results.
This is the foundation layer that feeds data into OWCA's higher analytical layers.

Components:
    XCCDFParser: Secure XML parsing and native XCCDF score extraction
    SeverityCalculator: Severity-weighted risk score calculation
    Constants: Industry-standard severity weights and thresholds

Architecture:
    Layer 0: Extraction (THIS LAYER)
        ↓
    Layer 1: Core (score_calculator.py)
        ↓
    Layer 2: Framework (nist_800_53.py, cis.py, stig.py)
        ↓
    Layer 3: Aggregation (fleet_aggregator.py)
        ↓
    Layer 4: Intelligence (trends, forecasting, risk scoring)

Security:
    - XXE attack prevention (secure XML parsing)
    - Path traversal validation
    - File size limits (10MB max)
    - Input validation via Pydantic models
    - Comprehensive audit logging

Example:
    >>> from app.services.owca import get_owca_service
    >>> owca = get_owca_service(db)
    >>>
    >>> # Extract XCCDF native score from XML file
    >>> xccdf_result = await owca.extract_xccdf_score("/app/data/results/scan_123.xml")
    >>> print(f"XCCDF Score: {xccdf_result.xccdf_score}/{xccdf_result.xccdf_score_max}")
    >>>
    >>> # Calculate severity-weighted risk score
    >>> severity_risk = await owca.calculate_severity_risk(
    ...     critical=5, high=10, medium=20, low=50
    ... )
    >>> print(f"Severity Risk: {severity_risk.risk_score} ({severity_risk.risk_level})")
"""

from .constants import (
    RISK_LEVELS,
    RISK_THRESHOLD_HIGH,
    RISK_THRESHOLD_LOW,
    RISK_THRESHOLD_MEDIUM,
    SEVERITY_WEIGHT_CRITICAL,
    SEVERITY_WEIGHT_HIGH,
    SEVERITY_WEIGHT_INFO,
    SEVERITY_WEIGHT_LOW,
    SEVERITY_WEIGHT_MEDIUM,
    SEVERITY_WEIGHTS,
    get_risk_level,
    get_severity_weight,
)
from .severity_calculator import SeverityCalculator, SeverityDistribution, SeverityRiskResult
from .xccdf_parser import XCCDFParser, XCCDFScoreResult

__version__ = "1.0.0"
__all__ = [
    # XCCDF Parsing
    "XCCDFParser",
    "XCCDFScoreResult",
    # Severity Risk Calculation
    "SeverityCalculator",
    "SeverityRiskResult",
    "SeverityDistribution",
    # Constants
    "SEVERITY_WEIGHTS",
    "SEVERITY_WEIGHT_CRITICAL",
    "SEVERITY_WEIGHT_HIGH",
    "SEVERITY_WEIGHT_MEDIUM",
    "SEVERITY_WEIGHT_LOW",
    "SEVERITY_WEIGHT_INFO",
    "RISK_LEVELS",
    "RISK_THRESHOLD_LOW",
    "RISK_THRESHOLD_MEDIUM",
    "RISK_THRESHOLD_HIGH",
    "get_risk_level",
    "get_severity_weight",
]
