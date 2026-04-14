"""
OWCA Extraction Layer (Layer 0)

Provides initial risk scoring from compliance scan results.
This is the foundation layer that feeds data into OWCA's higher analytical layers.

Components:
    SeverityCalculator: Severity-weighted risk score calculation
    Constants: Industry-standard severity weights and thresholds

Architecture:
    Layer 0: Extraction (THIS LAYER)
        |
    Layer 1: Core (score_calculator.py)
        |
    Layer 2: Framework (nist_800_53.py, cis.py, stig.py)
        |
    Layer 3: Aggregation (fleet_aggregator.py)
        |
    Layer 4: Intelligence (trends, forecasting, risk scoring)

Example:
    >>> from app.services.owca import get_owca_service
    >>> owca = get_owca_service(db)
    >>>
    >>> # Calculate severity-weighted risk score
    >>> severity_risk = owca.calculate_severity_risk(
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

__version__ = "1.0.0"
__all__ = [
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
