#!/usr/bin/env python3
"""
MongoDB Models for Scan Results

Stores scan execution results with rule-level details, variable overrides,
and scanner metadata.
"""

from beanie import Document
from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum


class ScanStatus(str, Enum):
    """Scan execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RuleResultStatus(str, Enum):
    """Individual rule check result"""
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    NOT_APPLICABLE = "notapplicable"
    NOT_CHECKED = "notchecked"
    NOT_SELECTED = "notselected"
    INFORMATIONAL = "informational"
    FIXED = "fixed"


class ScanTargetType(str, Enum):
    """Type of scan target"""
    SSH_HOST = "ssh_host"
    LOCAL = "local"
    KUBERNETES = "kubernetes"
    AWS_ACCOUNT = "aws_account"
    AZURE_SUBSCRIPTION = "azure_subscription"
    GCP_PROJECT = "gcp_project"
    DOCKER_CONTAINER = "docker_container"


class ScanTarget(BaseModel):
    """Target system to scan"""
    type: ScanTargetType
    identifier: str = Field(description="Host address, cluster name, account ID, etc.")
    credentials: Optional[Dict[str, str]] = Field(
        default=None,
        description="Encrypted credentials (SSH key, kubeconfig, cloud creds)"
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional target metadata (OS version, K8s version, etc.)"
    )


class ScanConfiguration(BaseModel):
    """Configuration for scan execution"""
    target: ScanTarget
    framework: str = Field(description="Framework to scan against (nist, cis, stig)")
    framework_version: str = Field(description="Framework version (800-53r5, v2.0.0)")
    profile_id: Optional[str] = Field(
        default=None,
        description="XCCDF profile ID (auto-generated if not provided)"
    )
    variable_overrides: Dict[str, str] = Field(
        default_factory=dict,
        description="Custom XCCDF variable values"
    )
    rule_filter: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional MongoDB query to filter rules"
    )
    scan_options: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Scanner-specific options (timeout, verbosity, etc.)"
    )


class RuleResult(BaseModel):
    """Result for a single compliance rule"""
    rule_id: str
    scap_rule_id: Optional[str] = None
    title: str
    severity: str
    status: RuleResultStatus
    message: Optional[str] = Field(
        default=None,
        description="Human-readable result message"
    )
    scanner_output: Optional[str] = Field(
        default=None,
        description="Raw scanner output for this rule"
    )
    scanner_type: str = Field(
        default="oscap",
        description="Scanner that executed this rule"
    )
    variables_applied: Optional[Dict[str, str]] = Field(
        default=None,
        description="Variable values used for this check"
    )
    check_time: Optional[float] = Field(
        default=None,
        description="Execution time in seconds"
    )
    frameworks: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Framework mappings for this rule"
    )


class ScanResultSummary(BaseModel):
    """Summary statistics for scan results"""
    total_rules: int = 0
    passed: int = 0
    failed: int = 0
    error: int = 0
    not_applicable: int = 0
    not_checked: int = 0
    not_selected: int = 0
    informational: int = 0
    fixed: int = 0
    
    # Compliance percentage
    compliance_percentage: float = Field(
        default=0.0,
        description="(passed / (passed + failed)) * 100"
    )
    
    # Results by severity
    by_severity: Dict[str, Dict[str, int]] = Field(
        default_factory=dict,
        description="Breakdown by severity: {high: {passed: X, failed: Y}, ...}"
    )
    
    # Results by scanner
    by_scanner: Dict[str, Dict[str, int]] = Field(
        default_factory=dict,
        description="Breakdown by scanner type"
    )


class ScanResult(Document):
    """
    Complete scan execution result
    
    Stores scan configuration, execution metadata, and per-rule results.
    """
    
    # Scan identification
    scan_id: str = Field(description="Unique scan identifier (UUID)")
    scan_name: Optional[str] = Field(
        default=None,
        description="Human-readable scan name"
    )
    
    # Scan configuration
    config: ScanConfiguration
    
    # Execution metadata
    status: ScanStatus = ScanStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    
    # User who initiated scan
    started_by: str = Field(description="Username or user ID")
    
    # Results
    summary: ScanResultSummary = Field(default_factory=ScanResultSummary)
    results_by_rule: List[RuleResult] = Field(default_factory=list)
    
    # Scanner metadata
    scanner_versions: Optional[Dict[str, str]] = Field(
        default=None,
        description="Version info for each scanner used (oscap: 1.3.7, etc.)"
    )
    benchmark_version: Optional[str] = Field(
        default=None,
        description="Version of benchmark used for scan"
    )
    tailoring_applied: bool = Field(
        default=False,
        description="Whether variable tailoring was applied"
    )
    
    # Error tracking
    errors: List[str] = Field(
        default_factory=list,
        description="Error messages if scan failed"
    )
    warnings: List[str] = Field(
        default_factory=list,
        description="Non-fatal warnings during scan"
    )
    
    # Raw outputs (optional, for debugging)
    raw_outputs: Optional[Dict[str, str]] = Field(
        default=None,
        description="Raw scanner outputs (XCCDF XML, JSON, etc.)"
    )

    class Settings:
        name = "scan_results"
        use_state_management = True
        validate_on_save = True
        indexes = [
            "scan_id",
            "status",
            "started_by",
            "started_at",
            [("config.framework", 1), ("config.framework_version", 1)],
            [("config.target.type", 1), ("config.target.identifier", 1)],
        ]


class ScanSchedule(Document):
    """
    Scheduled scan configuration for recurring scans
    
    Future enhancement for automated compliance monitoring.
    """
    schedule_id: str
    name: str
    description: Optional[str] = None
    config: ScanConfiguration
    
    # Schedule configuration
    enabled: bool = True
    cron_expression: str = Field(
        description="Cron expression for schedule (e.g., '0 2 * * *' for daily at 2am)"
    )
    timezone: str = Field(default="UTC")
    
    # Execution tracking
    last_run_at: Optional[datetime] = None
    last_scan_id: Optional[str] = None
    next_run_at: Optional[datetime] = None
    
    # Notification settings
    notify_on_completion: bool = False
    notify_on_failure: bool = True
    notification_channels: List[str] = Field(
        default_factory=list,
        description="Email addresses, Slack webhooks, etc."
    )
    
    # Created/updated metadata
    created_by: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "scan_schedules"
        use_state_management = True
        validate_on_save = True
        indexes = [
            "schedule_id",
            "enabled",
            "next_run_at",
            "created_by",
        ]
