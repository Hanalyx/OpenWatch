"""
Host Groups Pydantic Models

Request and response models for host group management and scanning endpoints.
These models ensure type safety and provide automatic validation for all API inputs.

Model Categories:
    - CRUD Models: Create, read, update operations for host groups
    - Membership Models: Host assignment and removal
    - Validation Models: Compatibility checking and smart grouping
    - Scan Models: Group scan requests, sessions, and progress tracking

Security:
    - All models use Pydantic validation to prevent injection attacks
    - Optional fields have safe defaults
    - String lengths are implicitly limited by database constraints
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from backend.app.models.enums import ScanPriority, ScanSessionStatus

# =============================================================================
# HOST GROUP CRUD MODELS
# =============================================================================


class HostGroupCreate(BaseModel):
    """
    Request model for creating a new host group.

    Attributes:
        name: Unique name for the host group (required).
        description: Optional description of the group's purpose.
        color: Optional hex color code for UI display.
        os_family: Optional OS family filter (rhel, debian, etc.).
        os_version_pattern: Optional regex pattern for OS version matching.
        architecture: Optional CPU architecture filter (x86_64, aarch64).
        default_profile_id: Default compliance profile ID for scans.
        compliance_framework: Compliance framework (nist_800_53, cis, stig).
        auto_scan_enabled: Enable automatic scheduled scanning.
        scan_schedule: Cron expression for scan schedule.
        validation_rules: Custom validation rules as JSON object.
    """

    name: str = Field(..., min_length=1, max_length=255, description="Unique group name")
    description: Optional[str] = Field(None, max_length=1000)
    color: Optional[str] = Field(None, pattern=r"^#[0-9A-Fa-f]{6}$")
    os_family: Optional[str] = Field(None, max_length=50)
    os_version_pattern: Optional[str] = Field(None, max_length=100)
    architecture: Optional[str] = Field(None, max_length=20)
    default_profile_id: Optional[str] = Field(None, max_length=255)
    compliance_framework: Optional[str] = Field(None, max_length=50)
    auto_scan_enabled: Optional[bool] = False
    scan_schedule: Optional[str] = Field(None, max_length=100)
    validation_rules: Optional[Dict[str, Any]] = None


class HostGroupUpdate(BaseModel):
    """
    Request model for updating an existing host group.

    All fields are optional - only provided fields will be updated.
    """

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    color: Optional[str] = Field(None, pattern=r"^#[0-9A-Fa-f]{6}$")
    os_family: Optional[str] = Field(None, max_length=50)
    os_version_pattern: Optional[str] = Field(None, max_length=100)
    architecture: Optional[str] = Field(None, max_length=20)
    default_profile_id: Optional[str] = Field(None, max_length=255)
    compliance_framework: Optional[str] = Field(None, max_length=50)
    auto_scan_enabled: Optional[bool] = None
    scan_schedule: Optional[str] = Field(None, max_length=100)
    validation_rules: Optional[Dict[str, Any]] = None


class HostGroupResponse(BaseModel):
    """
    Response model for host group data.

    Includes computed fields like host_count from membership table.
    """

    id: int
    name: str
    description: Optional[str]
    color: Optional[str]
    host_count: int
    created_by: int
    created_at: datetime
    updated_at: datetime
    os_family: Optional[str]
    os_version_pattern: Optional[str]
    architecture: Optional[str]
    default_profile_id: Optional[str]
    compliance_framework: Optional[str]
    auto_scan_enabled: bool
    scan_schedule: Optional[str]
    validation_rules: Optional[Dict[str, Any]]
    compatibility_summary: Optional[Dict[str, Any]] = None

    class Config:
        """Pydantic configuration."""

        from_attributes = True


# =============================================================================
# HOST MEMBERSHIP MODELS
# =============================================================================


class AssignHostsRequest(BaseModel):
    """
    Request model for assigning hosts to a group.

    Attributes:
        host_ids: List of host UUIDs to assign.
        validate_compatibility: Run compatibility checks before assignment.
        force_assignment: Assign compatible hosts even if some are incompatible.
    """

    host_ids: List[str] = Field(..., min_length=1)
    validate_compatibility: Optional[bool] = True
    force_assignment: Optional[bool] = False


class ValidateHostsRequest(BaseModel):
    """Request model for validating host compatibility."""

    host_ids: List[str] = Field(..., min_length=1)


class SmartGroupCreateRequest(BaseModel):
    """
    Request model for creating a smart group based on host analysis.

    Analyzes the provided hosts and creates an optimally configured group.
    """

    host_ids: List[str] = Field(..., min_length=1)
    group_name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    auto_configure: Optional[bool] = True


class CompatibilityValidationResponse(BaseModel):
    """Response model for host compatibility validation."""

    group: Dict[str, Any]
    compatible: List[Dict[str, Any]]
    incompatible: List[Dict[str, Any]]
    warnings: List[str]
    suggestions: Dict[str, Any]
    summary: Dict[str, Any]


# =============================================================================
# GROUP SCAN MODELS - NEW for Phase 1
# =============================================================================


class GroupScanRequest(BaseModel):
    """
    Request model for starting a group scan.

    This model aligns with frontend scanService.ts GroupScanRequest interface.

    Attributes:
        scan_name: Optional custom name for the scan session.
        profile_id: Compliance profile to use for scanning.
        priority: Scan execution priority.
        template_id: Scan template ID or 'auto' for automatic selection.
        framework: Compliance framework (optional, uses group default if not provided).
        platform: Platform identifier (optional, auto-detected if not provided).
        platform_version: Platform version (optional, auto-detected if not provided).
    """

    scan_name: Optional[str] = Field(None, max_length=255)
    profile_id: str = Field(..., description="Compliance profile ID")
    priority: Optional[ScanPriority] = ScanPriority.NORMAL
    template_id: Optional[str] = Field("auto", max_length=100)
    framework: Optional[str] = Field(None, max_length=50)
    platform: Optional[str] = Field(None, max_length=50)
    platform_version: Optional[str] = Field(None, max_length=20)


class GroupScanSessionResponse(BaseModel):
    """
    Response model for group scan session creation.

    This model aligns with frontend scanService.ts GroupScanSessionResponse interface.
    """

    session_id: str
    session_name: str
    total_hosts: int
    status: ScanSessionStatus
    created_at: datetime
    estimated_completion: Optional[datetime] = None
    group_id: int
    group_name: str
    authorized_hosts: Optional[int] = None
    unauthorized_hosts: Optional[int] = None

    class Config:
        """Pydantic configuration."""

        from_attributes = True


class IndividualScanProgress(BaseModel):
    """Progress details for an individual host scan within a group session."""

    scan_id: str
    scan_name: str
    hostname: str
    display_name: str
    status: ScanSessionStatus
    progress: int = Field(ge=0, le=100)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    compliance_score: Optional[float] = None
    failed_rules: Optional[int] = None
    total_rules: Optional[int] = None


class ScanProgressResponse(BaseModel):
    """
    Response model for group scan progress.

    This model aligns with frontend scanService.ts ScanProgressResponse interface.
    """

    session_id: str
    session_name: str
    status: ScanSessionStatus
    progress_percent: int = Field(ge=0, le=100)
    total_hosts: int
    completed_hosts: int
    failed_hosts: int
    running_hosts: int
    started_at: Optional[datetime] = None
    estimated_completion: Optional[datetime] = None
    individual_scans: List[IndividualScanProgress]

    class Config:
        """Pydantic configuration."""

        from_attributes = True


class CancelScanResponse(BaseModel):
    """Response model for scan cancellation."""

    session_id: str
    status: str
    message: str
    cancelled_scans: int


# =============================================================================
# COMPLIANCE MODELS (from group_compliance.py)
# =============================================================================


class ComplianceMetricsResponse(BaseModel):
    """Response model for group compliance metrics."""

    group_id: int
    timeframe: str
    metrics_generated_at: datetime
    total_hosts: int
    total_scans: int
    average_compliance_score: float
    total_violations: int
    critical_issues: int
    high_issues: int
    medium_issues: int
    frameworks_evaluated: int
    compliance_trend: List[Dict[str, Any]]


class GroupScanHistoryResponse(BaseModel):
    """Response model for group scan history entry."""

    session_id: str
    status: str
    total_hosts: int
    hosts_scanned: int
    successful_hosts: int
    failed_hosts: int
    average_progress: float
    started_at: datetime
    completed_at: Optional[datetime]
    scan_config: Dict[str, Any]


class GroupScanScheduleRequest(BaseModel):
    """Request model for scheduling recurring group scans."""

    enabled: bool
    cron_expression: str = Field(..., max_length=100)
    profile_id: str = Field(..., max_length=255)
    compliance_framework: Optional[str] = Field(None, max_length=50)


class GroupComplianceReportResponse(BaseModel):
    """Response model for comprehensive group compliance report."""

    group_id: int
    group_name: str
    report_generated_at: datetime
    compliance_framework: Optional[str]
    total_hosts: int
    overall_compliance_score: float
    total_rules_evaluated: int
    total_passed_rules: int
    total_failed_rules: int
    high_risk_hosts: int
    medium_risk_hosts: int
    framework_distribution: Dict[str, Dict[str, Any]]
    compliance_trend: List[Dict[str, Any]]
    top_failed_rules: List[Dict[str, Any]]
    host_compliance_summary: List[Dict[str, Any]]
