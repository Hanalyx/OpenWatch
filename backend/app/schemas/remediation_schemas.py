"""
Remediation Schemas for Phase 4

Pydantic models for remediation job requests and responses.

Part of Phase 4: Remediation + Subscription (Kensa Integration Plan)
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class RemediationStatus(str, Enum):
    """Remediation job status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    CANCELLED = "cancelled"
    MANUAL = "manual"


class RemediationJobCreate(BaseModel):
    """Request model for creating a remediation job."""

    host_id: UUID = Field(..., description="Target host for remediation")
    rule_ids: List[str] = Field(..., min_length=1, description="List of rule IDs to remediate")
    scan_id: Optional[UUID] = Field(None, description="Source scan ID (optional)")
    dry_run: bool = Field(False, description="If true, simulate remediation without making changes")
    framework: Optional[str] = Field(None, description="Optional framework filter (cis, stig, nist)")


class RemediationJobResponse(BaseModel):
    """Response model for a remediation job."""

    id: UUID
    host_id: UUID
    scan_id: Optional[UUID] = None
    rule_ids: List[str]
    dry_run: bool

    # Status
    status: RemediationStatus
    progress: int = Field(ge=0, le=100, description="Percentage complete")
    total_rules: int
    completed_rules: int
    failed_rules: int
    skipped_rules: int

    # Error info
    error_message: Optional[str] = None

    # Rollback
    rollback_available: bool
    rollback_job_id: Optional[UUID] = None

    # Audit
    requested_by: int
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # Computed
    duration_seconds: Optional[float] = Field(None, description="Total duration if completed")

    class Config:
        from_attributes = True


class RemediationStepResponse(BaseModel):
    """Per-step result within a rule remediation."""

    id: UUID
    result_id: UUID
    step_index: int
    mechanism: str
    success: bool
    detail: Optional[str] = None
    pre_state_data: Optional[Dict[str, Any]] = None
    pre_state_capturable: Optional[bool] = None
    verified: Optional[bool] = None
    verify_detail: Optional[str] = None
    risk_level: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class RemediationResultResponse(BaseModel):
    """Response model for individual rule remediation result."""

    id: UUID
    job_id: UUID
    rule_id: str
    status: RemediationStatus
    exit_code: Optional[int] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    duration_ms: Optional[int] = None
    error_message: Optional[str] = None
    rollback_available: bool
    rollback_executed: bool
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # Kensa-specific fields
    remediated: Optional[bool] = None
    remediation_detail: Optional[str] = None
    rolled_back: Optional[bool] = None
    step_count: Optional[int] = None
    risk_level: Optional[str] = None

    # Kensa evidence (K-1)
    evidence: Optional[List[Dict[str, Any]]] = None
    framework_refs: Optional[Dict[str, str]] = None

    class Config:
        from_attributes = True


class RemediationResultDetailResponse(BaseModel):
    """Result response including step-level detail."""

    id: UUID
    job_id: UUID
    rule_id: str
    status: RemediationStatus
    exit_code: Optional[int] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    duration_ms: Optional[int] = None
    error_message: Optional[str] = None
    rollback_available: bool
    rollback_executed: bool
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # Kensa-specific fields
    remediated: Optional[bool] = None
    remediation_detail: Optional[str] = None
    rolled_back: Optional[bool] = None
    step_count: Optional[int] = None
    risk_level: Optional[str] = None

    # Kensa evidence (K-1)
    evidence: Optional[List[Dict[str, Any]]] = None
    framework_refs: Optional[Dict[str, str]] = None

    # Steps
    steps: List[RemediationStepResponse] = []

    class Config:
        from_attributes = True


class RemediationJobListResponse(BaseModel):
    """Response model for job list queries."""

    items: List[RemediationJobResponse]
    total: int
    page: int
    per_page: int
    total_pages: int


class RemediationJobDetailResponse(BaseModel):
    """Detailed response including individual results."""

    job: RemediationJobResponse
    results: List[RemediationResultResponse]


class RollbackRequest(BaseModel):
    """Request model for rolling back a remediation job."""

    job_id: UUID = Field(..., description="Job ID to rollback")
    rule_ids: Optional[List[str]] = Field(None, description="Specific rules to rollback (all if not specified)")


class RollbackResponse(BaseModel):
    """Response model for rollback operation."""

    rollback_job_id: UUID
    original_job_id: UUID
    status: RemediationStatus
    rules_rolled_back: int
    rules_failed: int
    message: str


class RemediationSummary(BaseModel):
    """Summary statistics for remediation operations."""

    total_jobs: int = 0
    pending_jobs: int = 0
    running_jobs: int = 0
    completed_jobs: int = 0
    failed_jobs: int = 0
    rolled_back_jobs: int = 0

    total_rules_remediated: int = 0
    total_rules_failed: int = 0
    success_rate: float = Field(0.0, description="Percentage of successful remediations")

    rollback_available_count: int = 0


class RemediationPlanRuleDetail(BaseModel):
    """Per-rule detail in a dry-run plan."""

    rule_id: str
    title: str
    severity: str
    risk_level: str
    steps: List[Dict[str, Any]]
    estimated_duration_seconds: int
    requires_reboot: bool = False
    warnings: List[str] = []


class RemediationPlanResponse(BaseModel):
    """Response for remediation plan (dry-run preview)."""

    host_id: UUID
    rule_count: int
    rules: List[RemediationPlanRuleDetail]
    estimated_duration_seconds: int
    warnings: List[str] = []
    requires_reboot: bool = False
    dependencies: List[str] = []
    risk_summary: Dict[str, int] = Field(
        default_factory=dict,
        description="Count of rules per risk level",
    )


class RemediationAuditEntry(BaseModel):
    """Audit log entry for remediation actions."""

    id: UUID
    job_id: UUID
    action: str  # created, started, completed, failed, rolled_back
    user_id: int
    timestamp: datetime
    details: Optional[Dict[str, Any]] = None


__all__ = [
    "RemediationStatus",
    "RemediationJobCreate",
    "RemediationJobResponse",
    "RemediationStepResponse",
    "RemediationResultResponse",
    "RemediationResultDetailResponse",
    "RemediationJobListResponse",
    "RemediationJobDetailResponse",
    "RollbackRequest",
    "RollbackResponse",
    "RemediationSummary",
    "RemediationPlanRuleDetail",
    "RemediationPlanResponse",
    "RemediationAuditEntry",
]
