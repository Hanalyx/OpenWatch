"""
OWCA Data Models

Type-safe Pydantic models for all OWCA calculations and results.
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, model_validator


class ComplianceTier(str, Enum):
    """Compliance tier classification based on score."""

    EXCELLENT = "excellent"  # 90-100%
    GOOD = "good"  # 75-89%
    FAIR = "fair"  # 60-74%
    POOR = "poor"  # <60%


class DriftSeverity(str, Enum):
    """Severity of baseline drift."""

    CRITICAL = "critical"  # >10% decline
    HIGH = "high"  # 5-10% decline
    MEDIUM = "medium"  # 2-5% decline
    LOW = "low"  # <2% change
    NONE = "none"  # No significant drift


class TrendDirection(str, Enum):
    """Direction of compliance trend."""

    IMPROVING = "improving"
    DECLINING = "declining"
    STABLE = "stable"


class SeverityBreakdown(BaseModel):
    """Breakdown of compliance by severity level."""

    critical_passed: int = Field(0, ge=0)
    critical_failed: int = Field(0, ge=0)
    critical_total: int = Field(0, ge=0)

    high_passed: int = Field(0, ge=0)
    high_failed: int = Field(0, ge=0)
    high_total: int = Field(0, ge=0)

    medium_passed: int = Field(0, ge=0)
    medium_failed: int = Field(0, ge=0)
    medium_total: int = Field(0, ge=0)

    low_passed: int = Field(0, ge=0)
    low_failed: int = Field(0, ge=0)
    low_total: int = Field(0, ge=0)

    @model_validator(mode="after")
    def validate_totals(self) -> "SeverityBreakdown":
        """
        Validate that all total fields equal passed + failed.

        Security: Ensures data integrity for compliance calculations.
        Each severity total must match the sum of passed and failed counts.

        Raises:
            ValueError: If any total does not equal passed + failed
        """
        for severity in ["critical", "high", "medium", "low"]:
            passed = getattr(self, f"{severity}_passed")
            failed = getattr(self, f"{severity}_failed")
            total = getattr(self, f"{severity}_total")

            if total != passed + failed:
                raise ValueError(
                    f"{severity} total ({total}) must equal "
                    f"passed ({passed}) + failed ({failed}) = {passed + failed}"
                )

        return self


class ComplianceScore(BaseModel):
    """
    Compliance score for a single entity (host/group/org).

    This is the canonical compliance score representation
    used throughout OpenWatch.
    """

    entity_id: UUID = Field(..., description="UUID of the entity (host/group)")
    entity_type: str = Field(..., description="Type: host, group, organization")

    overall_score: float = Field(..., ge=0, le=100, description="Overall compliance percentage")
    tier: ComplianceTier = Field(..., description="Compliance tier classification")

    passed_rules: int = Field(0, ge=0, description="Total passed rules")
    failed_rules: int = Field(0, ge=0, description="Total failed rules")
    total_rules: int = Field(0, ge=0, description="Total evaluated rules")

    severity_breakdown: SeverityBreakdown = Field(..., description="Breakdown by severity")

    calculated_at: datetime = Field(default_factory=datetime.utcnow, description="When score was calculated")

    scan_id: Optional[UUID] = Field(None, description="Associated scan ID if applicable")

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class FleetStatistics(BaseModel):
    """
    Organization-wide fleet statistics.

    Aggregates compliance data across all hosts.
    """

    total_hosts: int = Field(0, ge=0, description="Total hosts in inventory")
    online_hosts: int = Field(0, ge=0, description="Hosts currently online")
    offline_hosts: int = Field(0, ge=0, description="Hosts currently offline")

    scanned_hosts: int = Field(0, ge=0, description="Hosts with at least one scan")
    never_scanned: int = Field(0, ge=0, description="Hosts never scanned")
    needs_scan: int = Field(0, ge=0, description="Hosts needing scan (>7 days)")

    average_compliance: float = Field(0, ge=0, le=100, description="Fleet average score")
    median_compliance: float = Field(0, ge=0, le=100, description="Fleet median score")

    hosts_excellent: int = Field(0, ge=0, description="Hosts with excellent compliance (90+%)")
    hosts_good: int = Field(0, ge=0, description="Hosts with good compliance (75-89%)")
    hosts_fair: int = Field(0, ge=0, description="Hosts with fair compliance (60-74%)")
    hosts_poor: int = Field(0, ge=0, description="Hosts with poor compliance (<60%)")

    total_critical_issues: int = Field(0, ge=0, description="Total critical severity failures")
    total_high_issues: int = Field(0, ge=0, description="Total high severity failures")
    total_medium_issues: int = Field(0, ge=0, description="Total medium severity failures")
    total_low_issues: int = Field(0, ge=0, description="Total low severity failures")

    hosts_with_critical: int = Field(0, ge=0, description="Hosts with at least 1 critical issue")

    calculated_at: datetime = Field(
        default_factory=datetime.utcnow, description="When statistics were calculated"
    )

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class BaselineDrift(BaseModel):
    """
    Baseline drift detection analysis.

    Compares current compliance against established baseline.
    """

    host_id: UUID = Field(..., description="Host being analyzed")
    baseline_id: UUID = Field(..., description="Active baseline ID")

    current_score: float = Field(..., ge=0, le=100, description="Current compliance score")
    baseline_score: float = Field(..., ge=0, le=100, description="Baseline compliance score")

    drift_percentage: float = Field(..., description="Percentage point difference (+ or -)")
    drift_severity: DriftSeverity = Field(..., description="Severity of drift")

    rules_changed: int = Field(0, ge=0, description="Number of rules with changed results")
    newly_failed: int = Field(0, ge=0, description="Rules that newly failed")
    newly_passed: int = Field(0, ge=0, description="Rules that newly passed")

    critical_regressions: int = Field(0, ge=0, description="Critical rules that regressed")
    high_regressions: int = Field(0, ge=0, description="High rules that regressed")

    detected_at: datetime = Field(
        default_factory=datetime.utcnow, description="When drift was detected"
    )

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class TrendDataPoint(BaseModel):
    """Single data point in compliance trend."""

    date: str = Field(..., description="Date in YYYY-MM-DD format")
    overall_score: float = Field(..., ge=0, le=100, description="Overall compliance")
    critical_passed: int = Field(0, ge=0, description="Critical rules passed")
    critical_failed: int = Field(0, ge=0, description="Critical rules failed")
    high_passed: int = Field(0, ge=0, description="High rules passed")
    high_failed: int = Field(0, ge=0, description="High rules failed")
    medium_passed: int = Field(0, ge=0, description="Medium rules passed")
    medium_failed: int = Field(0, ge=0, description="Medium rules failed")
    low_passed: int = Field(0, ge=0, description="Low rules passed")
    low_failed: int = Field(0, ge=0, description="Low rules failed")


class TrendData(BaseModel):
    """
    Compliance trend analysis over time.

    Provides historical compliance data and trend direction.
    """

    entity_id: UUID = Field(..., description="Entity being analyzed")
    entity_type: str = Field(..., description="Type: host, group, organization")

    time_period_days: int = Field(..., ge=1, description="Number of days analyzed")
    data_points: List[TrendDataPoint] = Field(..., description="Historical data points")

    trend_direction: TrendDirection = Field(..., description="Overall trend direction")
    improvement_rate: Optional[float] = Field(
        None, description="Rate of improvement (percentage points per day)"
    )

    calculated_at: datetime = Field(
        default_factory=datetime.utcnow, description="When trend was calculated"
    )

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class RiskScore(BaseModel):
    """
    Host risk score based on compliance and business context.

    Used for prioritizing remediation efforts.
    """

    host_id: UUID = Field(..., description="Host being scored")

    risk_score: float = Field(..., ge=0, le=100, description="Overall risk score (0-100)")
    risk_tier: str = Field(..., description="critical, high, medium, low")

    compliance_score: float = Field(..., ge=0, le=100, description="Current compliance")
    critical_issues: int = Field(0, ge=0, description="Critical severity failures")
    high_issues: int = Field(0, ge=0, description="High severity failures")

    days_since_scan: int = Field(0, ge=0, description="Days since last scan")
    has_baseline: bool = Field(False, description="Whether baseline is established")
    baseline_drift: Optional[float] = Field(None, description="Drift from baseline")

    business_criticality: Optional[str] = Field(None, description="Business criticality tier")

    priority_rank: int = Field(..., ge=1, description="Priority ranking (1 = highest)")

    calculated_at: datetime = Field(
        default_factory=datetime.utcnow, description="When risk was calculated"
    )

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class FrameworkCompliance(BaseModel):
    """
    Compliance breakdown by specific framework.

    Example: NIST SP 800-53 Rev 5, CIS Benchmarks, DISA STIG
    """

    framework_name: str = Field(..., description="Framework identifier (nist_800_53_r5)")
    framework_display_name: str = Field(..., description="Human-readable name")

    total_controls: int = Field(0, ge=0, description="Total framework controls")
    compliant_controls: int = Field(0, ge=0, description="Compliant controls")
    compliance_percentage: float = Field(..., ge=0, le=100, description="Compliance %")

    critical_compliant: int = Field(0, ge=0)
    critical_total: int = Field(0, ge=0)
    high_compliant: int = Field(0, ge=0)
    high_total: int = Field(0, ge=0)

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}
