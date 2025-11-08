"""
Severity-Weighted Risk Score Calculation Service

Provides risk scoring based on severity-weighted finding counts from SCAP scans.
Uses industry-standard weights aligned with NIST SP 800-30 and DISA STIG guidance.

This service implements Phase 2 of the XCCDF Scoring Implementation Plan:
- Calculates risk scores from severity distribution
- Provides risk level categorization
- Supports severity breakdown analysis
- Includes audit logging for scoring operations

Risk Scoring Formula:
    risk_score = (critical * 10.0) + (high * 5.0) + (medium * 2.0) +
                 (low * 0.5) + (info * 0.0)

Security Controls:
- Input validation via Pydantic models
- Comprehensive audit logging
- Type safety with strict type hints

Example:
    >>> from backend.app.services.scoring.severity_weighting_service import SeverityWeightingService
    >>> service = SeverityWeightingService()
    >>> result = service.calculate_risk_score(
    ...     critical_count=3,
    ...     high_count=10,
    ...     medium_count=25,
    ...     low_count=50
    ... )
    >>> print(f"Risk score: {result.risk_score}, Level: {result.risk_level}")
    Risk score: 155.0, Level: critical
"""

import logging
from typing import Dict, Optional

from pydantic import BaseModel, Field, validator

from .constants import SEVERITY_WEIGHTS, get_risk_level, get_severity_weight

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("openwatch.audit")


class SeverityDistribution(BaseModel):
    """
    Pydantic model for severity distribution counts.

    Attributes:
        critical: Count of critical severity findings
        high: Count of high severity findings
        medium: Count of medium severity findings
        low: Count of low severity findings
        info: Count of informational findings
    """

    critical: int = Field(0, ge=0, description="Critical severity finding count")
    high: int = Field(0, ge=0, description="High severity finding count")
    medium: int = Field(0, ge=0, description="Medium severity finding count")
    low: int = Field(0, ge=0, description="Low severity finding count")
    info: int = Field(0, ge=0, description="Informational finding count")

    @validator("critical", "high", "medium", "low", "info")
    def validate_non_negative(cls, v):
        """Ensure all counts are non-negative"""
        if v < 0:
            raise ValueError("Severity counts must be non-negative")
        return v

    def total_findings(self) -> int:
        """Calculate total number of findings across all severities"""
        return self.critical + self.high + self.medium + self.low + self.info


class RiskScoreResult(BaseModel):
    """
    Pydantic model for risk score calculation results.

    Attributes:
        risk_score: Calculated weighted risk score
        risk_level: Risk level categorization (low, medium, high, critical)
        severity_distribution: Breakdown of findings by severity
        total_findings: Total count of findings
        weighted_breakdown: Contribution of each severity to total score
    """

    risk_score: float = Field(..., ge=0.0, description="Calculated risk score")
    risk_level: str = Field(..., description="Risk level (low, medium, high, critical)")
    severity_distribution: SeverityDistribution = Field(..., description="Finding counts by severity")
    total_findings: int = Field(..., ge=0, description="Total finding count")
    weighted_breakdown: Dict[str, float] = Field(..., description="Score contribution by severity")

    @validator("risk_level")
    def validate_risk_level(cls, v):
        """Validate risk level is one of the allowed values"""
        allowed = ["low", "medium", "high", "critical"]
        if v not in allowed:
            raise ValueError(f"Risk level must be one of: {allowed}")
        return v


class SeverityWeightingService:
    """
    Service for calculating severity-weighted risk scores from compliance scans.

    This service provides standardized risk scoring based on finding severity
    distribution, using weights aligned with NIST SP 800-30 guidance.

    Methods:
        calculate_risk_score: Calculate risk score from severity counts
        calculate_from_failed_rules: Calculate risk from list of failed rules
    """

    def __init__(self):
        """Initialize severity weighting service"""
        self.weights = SEVERITY_WEIGHTS
        logger.debug("SeverityWeightingService initialized with weights: %s", self.weights)

    def calculate_risk_score(
        self,
        critical_count: int = 0,
        high_count: int = 0,
        medium_count: int = 0,
        low_count: int = 0,
        info_count: int = 0,
        user_id: Optional[str] = None,
        scan_id: Optional[str] = None,
    ) -> RiskScoreResult:
        """
        Calculate severity-weighted risk score from finding counts.

        This method applies industry-standard weights to calculate an overall
        risk score from the distribution of findings by severity.

        Args:
            critical_count: Number of critical severity findings
            high_count: Number of high severity findings
            medium_count: Number of medium severity findings
            low_count: Number of low severity findings
            info_count: Number of informational findings
            user_id: Optional user ID for audit logging
            scan_id: Optional scan ID for audit logging

        Returns:
            RiskScoreResult with calculated score, risk level, and breakdown

        Example:
            >>> service = SeverityWeightingService()
            >>> result = service.calculate_risk_score(
            ...     critical_count=2,
            ...     high_count=5,
            ...     medium_count=10,
            ...     low_count=20
            ... )
            >>> print(f"Risk: {result.risk_score} ({result.risk_level})")
            Risk: 75.0 (high)
        """
        # Validate inputs using Pydantic model
        severity_dist = SeverityDistribution(
            critical=critical_count,
            high=high_count,
            medium=medium_count,
            low=low_count,
            info=info_count,
        )

        # Calculate weighted score for each severity
        weighted_breakdown = {
            "critical": critical_count * get_severity_weight("critical"),
            "high": high_count * get_severity_weight("high"),
            "medium": medium_count * get_severity_weight("medium"),
            "low": low_count * get_severity_weight("low"),
            "info": info_count * get_severity_weight("info"),
        }

        # Calculate total risk score
        risk_score = sum(weighted_breakdown.values())

        # Determine risk level
        risk_level = get_risk_level(risk_score)

        # Create result
        result = RiskScoreResult(
            risk_score=round(risk_score, 2),
            risk_level=risk_level,
            severity_distribution=severity_dist,
            total_findings=severity_dist.total_findings(),
            weighted_breakdown=weighted_breakdown,
        )

        # Audit log the calculation
        audit_logger.info(
            f"Risk score calculated: {result.risk_score} ({result.risk_level})",
            extra={
                "event_type": "RISK_SCORE_CALCULATED",
                "user_id": user_id,
                "scan_id": scan_id,
                "risk_score": result.risk_score,
                "risk_level": result.risk_level,
                "severity_distribution": severity_dist.dict(),
                "total_findings": result.total_findings,
            },
        )

        logger.info(
            f"Risk score: {result.risk_score} ({result.risk_level}) - "
            f"Critical: {critical_count}, High: {high_count}, "
            f"Medium: {medium_count}, Low: {low_count}, Info: {info_count}"
        )

        return result

    def calculate_from_failed_rules(
        self,
        failed_rules: Dict[str, int],
        user_id: Optional[str] = None,
        scan_id: Optional[str] = None,
    ) -> RiskScoreResult:
        """
        Calculate risk score from failed rules grouped by severity.

        Convenience method for calculating risk from a dictionary of
        failed rule counts by severity level.

        Args:
            failed_rules: Dict mapping severity -> count (e.g., {'high': 10, 'medium': 25})
            user_id: Optional user ID for audit logging
            scan_id: Optional scan ID for audit logging

        Returns:
            RiskScoreResult with calculated score and breakdown

        Example:
            >>> service = SeverityWeightingService()
            >>> failed = {'critical': 1, 'high': 5, 'medium': 15, 'low': 30}
            >>> result = service.calculate_from_failed_rules(failed)
            >>> print(f"Risk level: {result.risk_level}")
            Risk level: high
        """
        # Extract counts from dictionary, defaulting to 0
        critical = failed_rules.get("critical", 0)
        high = failed_rules.get("high", 0)
        medium = failed_rules.get("medium", 0)
        low = failed_rules.get("low", 0)
        info = failed_rules.get("info", 0) + failed_rules.get("informational", 0)

        return self.calculate_risk_score(
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            info_count=info,
            user_id=user_id,
            scan_id=scan_id,
        )

    def get_severity_contribution(self, severity: str, count: int) -> float:
        """
        Calculate the risk score contribution for a specific severity level.

        Args:
            severity: Severity level (critical, high, medium, low, info)
            count: Number of findings at this severity

        Returns:
            Float contribution to overall risk score

        Example:
            >>> service = SeverityWeightingService()
            >>> contribution = service.get_severity_contribution('critical', 3)
            >>> print(f"Critical contribution: {contribution}")
            Critical contribution: 30.0
        """
        weight = get_severity_weight(severity)
        contribution = count * weight
        logger.debug(f"Severity '{severity}' count={count} weight={weight} contribution={contribution}")
        return contribution
