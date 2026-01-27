"""
Group Compliance Scanning Schemas
Pydantic models for group compliance scanning API requests and responses
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks"""

    DISA_STIG = "disa-stig"
    CIS = "cis"
    NIST_800_53 = "nist-800-53"
    PCI_DSS = "pci-dss"
    HIPAA = "hipaa"
    SOC2 = "soc2"
    ISO_27001 = "iso-27001"
    CMMC = "cmmc"


class ScanStatus(str, Enum):
    """Scan status enumeration"""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RemediationMode(str, Enum):
    """Remediation mode options"""

    NONE = "none"
    REPORT_ONLY = "report_only"
    AUTO_APPLY = "auto_apply"
    MANUAL_REVIEW = "manual_review"


# Request Schemas
class GroupComplianceScanRequest(BaseModel):
    """Request schema for starting group compliance scan"""

    scap_content_id: Optional[int] = Field(None, description="SCAP content ID (uses group default if not specified)")
    profile_id: Optional[str] = Field(None, description="Compliance profile ID (uses group default if not specified)")
    compliance_framework: Optional[ComplianceFramework] = Field(None, description="Target compliance framework")
    remediation_mode: RemediationMode = Field(RemediationMode.REPORT_ONLY, description="Remediation handling mode")
    scan_options: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional scan options")
    email_notifications: bool = Field(False, description="Send email notifications on completion")
    generate_reports: bool = Field(True, description="Generate compliance reports")
    concurrent_scans: int = Field(5, ge=1, le=20, description="Maximum concurrent scans")
    scan_timeout: int = Field(3600, ge=300, le=7200, description="Scan timeout in seconds")


class GroupScanScheduleRequest(BaseModel):
    """Request schema for scheduling recurring group scans"""

    enabled: bool = Field(True, description="Enable/disable scheduled scanning")
    cron_expression: str = Field(..., description="Cron expression for schedule")
    scap_content_id: int = Field(..., description="SCAP content ID for scheduled scans")
    profile_id: str = Field(..., description="Compliance profile ID")
    compliance_framework: ComplianceFramework = Field(..., description="Target compliance framework")
    scan_options: Optional[Dict[str, Any]] = Field(default_factory=dict)
    email_notifications: bool = Field(True, description="Send notifications for scheduled scans")

    class Config:
        json_schema_extra = {
            "example": {
                "enabled": True,
                "cron_expression": "0 2 * * 0",  # Weekly on Sunday at 2 AM
                "scap_content_id": 1,
                "profile_id": "stig_rhel8_disa",
                "compliance_framework": "disa-stig",
                "email_notifications": True,
            }
        }


# Response Schemas
class GroupComplianceScanResponse(BaseModel):
    """Response schema for group compliance scan initiation"""

    session_id: str = Field(..., description="Unique session identifier")
    group_id: int = Field(..., description="Host group ID")
    group_name: str = Field(..., description="Host group name")
    total_hosts: int = Field(..., description="Total number of hosts to scan")
    status: ScanStatus = Field(..., description="Current scan status")
    estimated_completion: datetime = Field(..., description="Estimated completion time")
    compliance_framework: Optional[str] = Field(..., description="Target compliance framework")
    profile_id: Optional[str] = Field(..., description="Compliance profile being used")
    scan_started_at: datetime = Field(default_factory=datetime.utcnow)


class HostComplianceSummary(BaseModel):
    """Individual host compliance summary"""

    host_id: str
    hostname: str
    ip_address: str
    os_family: str
    compliance_score: float = Field(..., ge=0, le=100)
    total_rules: int
    passed_rules: int
    failed_rules: int
    high_severity_issues: int
    last_scan_date: datetime


class FailedRule(BaseModel):
    """Details about a failed compliance rule"""

    rule_id: str
    rule_title: str
    severity: str
    failure_count: int
    failure_percentage: float


class ComplianceTrendPoint(BaseModel):
    """Single point in compliance trend data"""

    date: str
    score: float
    scan_count: int


class GroupComplianceReportResponse(BaseModel):
    """Comprehensive group compliance report"""

    group_id: int
    group_name: str
    report_generated_at: datetime
    compliance_framework: Optional[str]

    # Summary metrics
    total_hosts: int
    overall_compliance_score: float = Field(..., ge=0, le=100)
    total_rules_evaluated: int
    total_passed_rules: int
    total_failed_rules: int

    # Risk assessment
    high_risk_hosts: int
    medium_risk_hosts: int

    # Framework distribution
    framework_distribution: Dict[str, Dict[str, Any]]

    # Trend analysis
    compliance_trend: List[ComplianceTrendPoint]

    # Top issues
    top_failed_rules: List[FailedRule]

    # Host-level details
    host_compliance_summary: List[HostComplianceSummary]


class ComplianceMetricsTrend(BaseModel):
    """Compliance metrics trend point"""

    period: str
    average_score: float
    scan_count: int
    total_failures: int


class ComplianceMetricsResponse(BaseModel):
    """Detailed compliance metrics and KPIs"""

    group_id: int
    timeframe: str
    metrics_generated_at: datetime

    # Key metrics
    total_hosts: int
    total_scans: int
    average_compliance_score: float
    total_violations: int
    critical_issues: int
    high_issues: int
    medium_issues: int
    frameworks_evaluated: int

    # Trend data
    compliance_trend: List[ComplianceMetricsTrend]


class GroupScanHistoryResponse(BaseModel):
    """Historical group scan information"""

    session_id: str
    status: ScanStatus
    total_hosts: int
    hosts_scanned: int
    successful_hosts: int
    failed_hosts: int
    average_progress: float
    started_at: datetime
    completed_at: Optional[datetime]
    scan_config: Dict[str, Any]


# Additional specialized schemas
class ComplianceGapAnalysis(BaseModel):
    """Analysis of compliance gaps and recommendations"""

    framework: ComplianceFramework
    total_controls: int
    implemented_controls: int
    gap_percentage: float
    critical_gaps: List[str]
    recommendations: List[str]


class ComplianceRiskAssessment(BaseModel):
    """Risk assessment based on compliance results"""

    overall_risk_score: float = Field(..., ge=0, le=100)
    risk_category: str  # Low, Medium, High, Critical
    key_risk_factors: List[str]
    mitigation_priorities: List[str]
    estimated_remediation_effort: str  # Low, Medium, High


class GroupComplianceReportAdvanced(GroupComplianceReportResponse):
    """Extended compliance report with additional analysis"""

    gap_analysis: Dict[str, ComplianceGapAnalysis]
    risk_assessment: ComplianceRiskAssessment
    compliance_history: List[Dict[str, Any]]  # Historical compliance scores
    benchmark_comparison: Optional[Dict[str, float]]  # Industry benchmarks


# Webhook and notification schemas
class ComplianceScanNotification(BaseModel):
    """Notification payload for compliance scan events"""

    event_type: str  # scan_started, scan_completed, scan_failed
    session_id: str
    group_id: int
    group_name: str
    timestamp: datetime
    compliance_framework: Optional[str]
    summary: Optional[Dict[str, Any]]


class ComplianceAlertRule(BaseModel):
    """Rules for compliance alerting"""

    rule_id: str
    name: str
    description: str
    condition: str  # score_below_threshold, critical_issues_detected, etc.
    threshold_value: Optional[float]
    notification_channels: List[str]  # email, slack, webhook
    active: bool = True
