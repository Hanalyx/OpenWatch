"""
MongoDB models for remediation tracking and execution results.

This module defines the data structures for tracking remediation execution,
status, and results in MongoDB. Part of the ORSA (OpenWatch Remediation and
Security Automation) plugin architecture.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, List, Any
from pydantic import BaseModel, Field
from beanie import Document


class RemediationStatus(str, Enum):
    """Status of remediation execution."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class ScanTargetType(str, Enum):
    """Type of scan/remediation target."""

    SSH_HOST = "ssh_host"
    LOCAL = "local"
    KUBERNETES = "kubernetes"
    AWS_ACCOUNT = "aws_account"
    AZURE_SUBSCRIPTION = "azure_subscription"
    GCP_PROJECT = "gcp_project"


class RemediationTarget(BaseModel):
    """Target system for remediation execution."""

    type: ScanTargetType
    identifier: str = Field(..., description="Host address, cluster name, account ID, etc.")
    credentials: Optional[Dict[str, str]] = Field(
        default=None, description="Encrypted credentials (SSH keys, API tokens, etc.)"
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default=None, description="Additional target-specific metadata"
    )


class RemediationExecutionResult(BaseModel):
    """Result of a single remediation execution attempt."""

    success: bool
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    exit_code: Optional[int] = None
    duration_seconds: Optional[float] = None
    changes_made: Optional[List[str]] = Field(
        default=None, description="List of changes applied (for rollback tracking)"
    )
    error_message: Optional[str] = None


class RemediationResult(Document):
    """
    MongoDB document storing complete remediation execution record.

    Tracks remediation execution status, content, results, and rollback capability.
    Supports audit logging and compliance reporting.
    """

    # Identifiers
    remediation_id: str = Field(..., description="Unique remediation execution ID")
    rule_id: str = Field(..., description="XCCDF rule ID being remediated")
    rule_title: str = Field(..., description="Human-readable rule title")

    # Execution details
    executor_type: str = Field(..., description="Executor used (ansible, bash, terraform, etc.)")
    target: RemediationTarget = Field(..., description="Target system")
    status: RemediationStatus = Field(default=RemediationStatus.PENDING)

    # Timing
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # Configuration
    dry_run: bool = Field(default=False, description="Preview mode (no actual changes)")
    content_executed: str = Field(..., description="Remediation content (playbook, script, etc.)")
    variables_applied: Dict[str, str] = Field(
        default_factory=dict, description="Variable values applied during execution"
    )

    # Results
    execution_result: Optional[RemediationExecutionResult] = None

    # Tracking
    executed_by: str = Field(..., description="Username who triggered remediation")
    scan_id: Optional[str] = Field(
        default=None,
        description="Related scan ID if remediation triggered from scan results",
    )

    # Rollback support
    rollback_available: bool = Field(default=False)
    rollback_content: Optional[str] = Field(
        default=None,
        description="Rollback remediation content (Ansible playbook, script, etc.)",
    )
    rollback_executed: bool = Field(default=False)
    rollback_result: Optional[RemediationExecutionResult] = None

    # Audit
    audit_log: List[Dict[str, Any]] = Field(
        default_factory=list, description="Audit trail of status changes and actions"
    )

    class Settings:
        name = "remediation_results"
        indexes = [
            "remediation_id",
            "rule_id",
            "status",
            "executed_by",
            "scan_id",
            "created_at",
            [("rule_id", 1), ("created_at", -1)],  # Composite index
        ]

    def add_audit_entry(self, action: str, details: Optional[Dict[str, Any]] = None):
        """Add entry to audit log."""
        entry = {
            "timestamp": datetime.utcnow(),
            "action": action,
            "details": details or {},
        }
        self.audit_log.append(entry)

    def calculate_duration(self) -> Optional[float]:
        """Calculate execution duration in seconds."""
        if self.started_at and self.completed_at:
            delta = self.completed_at - self.started_at
            return delta.total_seconds()
        return None


class BulkRemediationJob(Document):
    """
    MongoDB document for tracking bulk remediation jobs.

    When multiple remediations are executed together (e.g., all failed rules
    from a scan), this document tracks the overall job status.
    """

    job_id: str = Field(..., description="Unique bulk job ID")
    scan_id: Optional[str] = Field(default=None, description="Source scan ID")

    # Configuration
    rule_filter: Optional[Dict[str, Any]] = Field(
        default=None, description="Filter criteria for rules to remediate"
    )
    target: RemediationTarget
    dry_run: bool = Field(default=False)

    # Status
    status: RemediationStatus = Field(default=RemediationStatus.PENDING)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # Progress tracking
    total_remediations: int = Field(default=0)
    completed_remediations: int = Field(default=0)
    failed_remediations: int = Field(default=0)
    remediation_ids: List[str] = Field(
        default_factory=list, description="Individual remediation IDs in this job"
    )

    # User tracking
    executed_by: str

    class Settings:
        name = "bulk_remediation_jobs"
        indexes = ["job_id", "scan_id", "status", "executed_by", "created_at"]

    def calculate_success_rate(self) -> float:
        """Calculate percentage of successful remediations."""
        if self.total_remediations == 0:
            return 0.0
        return (self.completed_remediations / self.total_remediations) * 100


# Pydantic schemas for API requests/responses


class RemediationRequest(BaseModel):
    """API request schema for executing a single remediation."""

    rule_id: str
    target: RemediationTarget
    variable_overrides: Optional[Dict[str, str]] = None
    dry_run: bool = False
    scan_id: Optional[str] = None


class BulkRemediationRequest(BaseModel):
    """API request schema for bulk remediation."""

    scan_id: Optional[str] = None
    rule_ids: Optional[List[str]] = Field(
        default=None,
        description="Specific rule IDs to remediate (if not using scan_id)",
    )
    rule_filter: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Filter for rules (e.g., {'status': 'fail', 'severity': ['high']})",
    )
    target: RemediationTarget
    variable_overrides: Optional[Dict[str, str]] = None
    dry_run: bool = False


class RemediationSummary(BaseModel):
    """Summary statistics for remediation operations."""

    total: int = 0
    pending: int = 0
    running: int = 0
    completed: int = 0
    failed: int = 0
    rolled_back: int = 0
    success_rate: float = 0.0

    by_executor: Dict[str, int] = Field(default_factory=dict)
    by_severity: Dict[str, int] = Field(default_factory=dict)
