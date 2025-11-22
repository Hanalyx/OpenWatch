"""
OWCA Framework Layer - Data Models

Provides data models for framework-specific compliance intelligence.
Each compliance framework (NIST 800-53, CIS, STIG) has unique characteristics
that require specialized data structures.

Security: All models use Pydantic validation to ensure data integrity.
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field

# NIST 800-53 Models


class NISTControlFamily(str, Enum):
    """
    NIST 800-53 Control Families.

    Reference: NIST SP 800-53 Rev 5
    """

    ACCESS_CONTROL = "AC"
    AWARENESS_TRAINING = "AT"
    AUDIT_ACCOUNTABILITY = "AU"
    ASSESSMENT_AUTHORIZATION = "CA"
    CONFIGURATION_MANAGEMENT = "CM"
    CONTINGENCY_PLANNING = "CP"
    IDENTIFICATION_AUTHENTICATION = "IA"
    INCIDENT_RESPONSE = "IR"
    MAINTENANCE = "MA"
    MEDIA_PROTECTION = "MP"
    PHYSICAL_PROTECTION = "PE"
    PLANNING = "PL"
    PERSONNEL_SECURITY = "PS"
    RISK_ASSESSMENT = "RA"
    SYSTEM_SERVICES_ACQUISITION = "SA"
    SYSTEM_COMMUNICATIONS_PROTECTION = "SC"
    SYSTEM_INFORMATION_INTEGRITY = "SI"
    SUPPLY_CHAIN_RISK_MANAGEMENT = "SR"
    PROGRAM_MANAGEMENT = "PM"


class NISTBaseline(str, Enum):
    """
    NIST 800-53 Security Control Baselines.

    LOW: Minimal impact on confidentiality, integrity, availability
    MODERATE: Serious adverse effects
    HIGH: Severe or catastrophic adverse effects

    Reference: FIPS 199, NIST SP 800-53 Rev 5
    """

    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


class NISTControlFamilyScore(BaseModel):
    """
    Compliance score for a specific NIST 800-53 control family.

    Provides detailed metrics for control families like AC, AU, IA, etc.
    """

    family: NISTControlFamily = Field(..., description="Control family (AC, AU, etc.)")
    family_name: str = Field(..., description="Full family name (e.g., 'Access Control')")
    controls_total: int = Field(..., description="Total controls in family")
    controls_tested: int = Field(..., description="Controls with test results")
    controls_passed: int = Field(..., description="Controls that passed")
    controls_failed: int = Field(..., description="Controls that failed")
    score: float = Field(..., description="Family compliance score (0-100)")
    tier: str = Field(..., description="OWCA compliance tier")


class NISTBaselineScore(BaseModel):
    """
    Compliance score for a specific NIST 800-53 baseline.

    Assesses compliance against LOW, MODERATE, or HIGH baselines.
    """

    baseline: NISTBaseline = Field(..., description="Security control baseline")
    controls_required: int = Field(..., description="Controls required for this baseline")
    controls_tested: int = Field(..., description="Required controls tested")
    controls_passed: int = Field(..., description="Required controls passed")
    score: float = Field(..., description="Baseline compliance score (0-100)")
    tier: str = Field(..., description="OWCA compliance tier")
    compliant: bool = Field(..., description="Meets baseline requirements (>= 90% score)")


class NISTFrameworkIntelligence(BaseModel):
    """
    Comprehensive NIST 800-53 compliance intelligence.

    Provides detailed analysis of NIST 800-53 compliance including:
    - Control family breakdown
    - Baseline assessments
    - Enhancement coverage
    """

    framework: str = Field(default="NIST_800_53", description="Framework identifier")
    overall_score: float = Field(..., description="Overall NIST compliance score")
    overall_tier: str = Field(..., description="OWCA compliance tier")
    control_families: List[NISTControlFamilyScore] = Field(
        default_factory=list, description="Score breakdown by control family"
    )
    baseline_scores: List[NISTBaselineScore] = Field(
        default_factory=list, description="Compliance against LOW/MODERATE/HIGH baselines"
    )
    enhancements_total: int = Field(default=0, description="Total control enhancements available")
    enhancements_tested: int = Field(default=0, description="Control enhancements tested")
    enhancements_coverage: float = Field(default=0.0, description="Enhancement coverage percentage")
    recommended_baseline: NISTBaseline = Field(..., description="Recommended baseline for organization")
    calculated_at: datetime = Field(default_factory=datetime.utcnow)


# CIS Benchmark Models


class CISLevel(str, Enum):
    """
    CIS Benchmark Implementation Levels.

    Level 1: Basic cyber hygiene, minimal impact on business
    Level 2: Defense in depth, may impact business operations

    Reference: CIS Benchmarks methodology
    """

    LEVEL_1 = "level_1"
    LEVEL_2 = "level_2"


class CISImplementationGroup(str, Enum):
    """
    CIS Implementation Groups (IG1, IG2, IG3).

    IG1: Basic cyber hygiene for small organizations
    IG2: Builds on IG1, for organizations with moderate resources
    IG3: Advanced security for organizations with significant resources

    Reference: CIS Controls v8
    """

    IG1 = "ig1"
    IG2 = "ig2"
    IG3 = "ig3"


class CISLevelScore(BaseModel):
    """
    Compliance score for a CIS Benchmark level.

    Assesses compliance against Level 1 (basic) or Level 2 (advanced).
    """

    level: CISLevel = Field(..., description="CIS Level (1 or 2)")
    recommendations_total: int = Field(..., description="Total recommendations in level")
    recommendations_scored: int = Field(..., description="Scored recommendations (not Not Scored)")
    recommendations_tested: int = Field(..., description="Recommendations tested")
    recommendations_passed: int = Field(..., description="Recommendations passed")
    score: float = Field(..., description="Level compliance score (0-100)")
    tier: str = Field(..., description="OWCA compliance tier")
    compliant: bool = Field(..., description="Meets level requirements (>= 80% score)")


class CISImplementationGroupScore(BaseModel):
    """
    Compliance score for a CIS Implementation Group.

    Assesses compliance against IG1, IG2, or IG3 requirements.
    """

    implementation_group: CISImplementationGroup = Field(..., description="Implementation Group")
    safeguards_total: int = Field(..., description="Total safeguards in IG")
    safeguards_tested: int = Field(..., description="Safeguards tested")
    safeguards_passed: int = Field(..., description="Safeguards passed")
    score: float = Field(..., description="IG compliance score (0-100)")
    tier: str = Field(..., description="OWCA compliance tier")


class CISFrameworkIntelligence(BaseModel):
    """
    Comprehensive CIS Benchmark compliance intelligence.

    Provides detailed analysis of CIS Benchmark compliance including:
    - Level 1/2 assessment
    - Implementation Group scoring
    - Platform-specific recommendations
    """

    framework: str = Field(default="CIS", description="Framework identifier")
    platform: str = Field(..., description="Platform (e.g., 'RHEL 8', 'Ubuntu 20.04')")
    benchmark_version: str = Field(..., description="Benchmark version (e.g., '2.0.0')")
    overall_score: float = Field(..., description="Overall CIS compliance score")
    overall_tier: str = Field(..., description="OWCA compliance tier")
    level_scores: List[CISLevelScore] = Field(default_factory=list, description="Score breakdown by Level 1/2")
    implementation_group_scores: List[CISImplementationGroupScore] = Field(
        default_factory=list, description="Score breakdown by IG1/IG2/IG3"
    )
    scored_recommendations: int = Field(..., description="Total scored recommendations")
    not_scored_recommendations: int = Field(..., description="Total not-scored recommendations")
    automated_tests: int = Field(..., description="Recommendations with automated tests")
    manual_tests: int = Field(..., description="Recommendations requiring manual verification")
    calculated_at: datetime = Field(default_factory=datetime.utcnow)


# STIG Models


class STIGSeverity(str, Enum):
    """
    STIG Finding Severity Categories.

    CAT I: High severity (immediate remediation required)
    CAT II: Medium severity (remediation within reasonable timeframe)
    CAT III: Low severity (remediation when feasible)

    Reference: DOD STIG methodology
    """

    CAT_I = "cat_i"
    CAT_II = "cat_ii"
    CAT_III = "cat_iii"


class STIGFindingStatus(str, Enum):
    """
    STIG Finding Status Classifications.

    Reference: DISA STIG Viewer
    """

    OPEN = "open"
    NOT_A_FINDING = "not_a_finding"
    NOT_APPLICABLE = "not_applicable"
    NOT_REVIEWED = "not_reviewed"


class STIGSeverityScore(BaseModel):
    """
    Compliance score for a STIG severity category.

    Provides detailed metrics for CAT I, CAT II, and CAT III findings.
    """

    severity: STIGSeverity = Field(..., description="STIG severity category")
    findings_total: int = Field(..., description="Total findings in category")
    findings_open: int = Field(..., description="Open findings (failed)")
    findings_not_a_finding: int = Field(..., description="Not a Finding (passed)")
    findings_not_applicable: int = Field(..., description="Not Applicable findings")
    findings_not_reviewed: int = Field(..., description="Not Reviewed findings")
    score: float = Field(..., description="Category compliance score (0-100)")
    tier: str = Field(..., description="OWCA compliance tier")


class STIGFrameworkIntelligence(BaseModel):
    """
    Comprehensive STIG compliance intelligence.

    Provides detailed analysis of STIG compliance including:
    - CAT I/II/III severity breakdown
    - Finding status distribution
    - Automated vs manual checks
    """

    framework: str = Field(default="STIG", description="Framework identifier")
    stig_id: str = Field(..., description="STIG identifier (e.g., 'RHEL_8_STIG')")
    stig_version: str = Field(..., description="STIG version (e.g., 'V1R9')")
    release_date: Optional[str] = Field(None, description="STIG release date")
    overall_score: float = Field(..., description="Overall STIG compliance score")
    overall_tier: str = Field(..., description="OWCA compliance tier")
    severity_scores: List[STIGSeverityScore] = Field(
        default_factory=list, description="Score breakdown by CAT I/II/III"
    )
    total_findings: int = Field(..., description="Total STIG findings")
    open_findings: int = Field(..., description="Open findings (failed)")
    not_a_finding: int = Field(..., description="Not a Finding (passed)")
    not_applicable: int = Field(..., description="Not Applicable findings")
    not_reviewed: int = Field(..., description="Not Reviewed findings")
    automated_checks: int = Field(..., description="Findings with automated checks")
    manual_checks: int = Field(..., description="Findings requiring manual review")
    calculated_at: datetime = Field(default_factory=datetime.utcnow)


# Generic Framework Intelligence


class FrameworkIntelligence(BaseModel):
    """
    Generic framework intelligence container.

    Used when framework-specific intelligence is not available.
    Provides basic compliance metrics without framework-specific analysis.
    """

    framework: str = Field(..., description="Framework identifier")
    overall_score: float = Field(..., description="Overall compliance score")
    overall_tier: str = Field(..., description="OWCA compliance tier")
    controls_total: int = Field(..., description="Total controls tested")
    controls_passed: int = Field(..., description="Controls passed")
    controls_failed: int = Field(..., description="Controls failed")
    calculated_at: datetime = Field(default_factory=datetime.utcnow)
