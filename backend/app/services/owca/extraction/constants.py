"""
OWCA Extraction Layer - Severity Weighting Constants

Defines standardized severity weights used across OpenWatch for calculating
risk scores from compliance scan results.

Part of OWCA Layer 0 (Extraction Layer).

These weights are based on industry standards:
- NIST SP 800-30 Risk Management Guide
- DISA STIG severity categorization
- CVSS v3.1 severity ratings

The risk scoring formula:
    risk_score = (critical_count * 10.0) + (high_count * 5.0) +
                 (medium_count * 2.0) + (low_count * 0.5) + (info_count * 0.0)

Risk score interpretation:
    0-20:    Low risk
    21-50:   Medium risk
    51-100:  High risk
    100+:    Critical risk

Example:
    >>> from backend.app.services.owca.extraction.constants import SEVERITY_WEIGHTS
    >>> critical_findings = 3
    >>> high_findings = 10
    >>> risk = (critical_findings * SEVERITY_WEIGHTS['critical']) + (high_findings * SEVERITY_WEIGHTS['high'])
    >>> print(f"Risk score: {risk}")
    Risk score: 80.0
"""

from typing import Dict, Final

# Severity weight constants (immutable)
SEVERITY_WEIGHT_CRITICAL: Final[float] = 10.0
SEVERITY_WEIGHT_HIGH: Final[float] = 5.0
SEVERITY_WEIGHT_MEDIUM: Final[float] = 2.0
SEVERITY_WEIGHT_LOW: Final[float] = 0.5
SEVERITY_WEIGHT_INFO: Final[float] = 0.0

# Severity weights dictionary (for iteration)
SEVERITY_WEIGHTS: Final[Dict[str, float]] = {
    "critical": SEVERITY_WEIGHT_CRITICAL,
    "high": SEVERITY_WEIGHT_HIGH,
    "medium": SEVERITY_WEIGHT_MEDIUM,
    "low": SEVERITY_WEIGHT_LOW,
    "info": SEVERITY_WEIGHT_INFO,
    "informational": SEVERITY_WEIGHT_INFO,  # Alias for 'info'
    "unknown": SEVERITY_WEIGHT_LOW,  # Treat unknown as low severity
}

# Risk score thresholds
RISK_THRESHOLD_LOW: Final[float] = 20.0
RISK_THRESHOLD_MEDIUM: Final[float] = 50.0
RISK_THRESHOLD_HIGH: Final[float] = 100.0

# Risk score interpretations
RISK_LEVELS: Final[Dict[str, str]] = {
    "low": "Low risk - Minimal security impact",
    "medium": "Medium risk - Moderate security concerns",
    "high": "High risk - Significant security issues",
    "critical": "Critical risk - Severe security vulnerabilities",
}


def get_risk_level(risk_score: float) -> str:
    """
    Determine risk level from calculated risk score.

    Args:
        risk_score: Calculated risk score value

    Returns:
        Risk level string: 'low', 'medium', 'high', or 'critical'

    Example:
        >>> get_risk_level(15.0)
        'low'
        >>> get_risk_level(75.0)
        'high'
        >>> get_risk_level(150.0)
        'critical'
    """
    if risk_score <= RISK_THRESHOLD_LOW:
        return "low"
    elif risk_score <= RISK_THRESHOLD_MEDIUM:
        return "medium"
    elif risk_score <= RISK_THRESHOLD_HIGH:
        return "high"
    else:
        return "critical"


def get_severity_weight(severity: str) -> float:
    """
    Get weight for a given severity level.

    Args:
        severity: Severity level (critical, high, medium, low, info, unknown)

    Returns:
        Float weight for the severity level (defaults to 0.5 for unknown)

    Example:
        >>> get_severity_weight('critical')
        10.0
        >>> get_severity_weight('medium')
        2.0
        >>> get_severity_weight('invalid')
        0.5
    """
    # Normalize to lowercase for case-insensitive lookup
    normalized = severity.lower() if severity else "unknown"
    return SEVERITY_WEIGHTS.get(normalized, SEVERITY_WEIGHT_LOW)
