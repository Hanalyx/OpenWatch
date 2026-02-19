"""
Plugin Governance Models

Data models for plugin governance including compliance standards, policies,
violations, audit events, and governance configuration.

These models support:
- Regulatory compliance standards (SOC2, ISO27001, NIST, GDPR, etc.)
- Policy-based plugin management with enforcement levels
- Compliance violation tracking and reporting
- Comprehensive audit trail persistence
- Governance configuration management

Security Considerations:
    - All audit events are immutable once created
    - Violation severity levels map to NIST SP 800-30 risk ratings
    - Policy enforcement levels provide graduated response options
    - Compliance reports include cryptographic checksums for integrity

Compliance Standards Supported:
    - SOC2 Type II
    - ISO 27001:2022
    - NIST Cybersecurity Framework
    - GDPR (EU General Data Protection Regulation)
    - HIPAA (Healthcare)
    - PCI-DSS (Payment Card Industry)
    - SOX (Sarbanes-Oxley)
    - FedRAMP (Federal)
    - FISMA (Federal Information Security)
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# =============================================================================
# GOVERNANCE ENUMS
# =============================================================================


class ComplianceStandard(str, Enum):
    """
    Regulatory compliance standards for plugin governance.

    These standards represent major regulatory frameworks that may apply
    to plugin operations in enterprise environments. Each standard has
    specific requirements for security, data handling, and auditability.

    Standards:
        SOC2: Service Organization Control 2 (Type I/II)
            - Trust Service Criteria: Security, Availability, Processing
              Integrity, Confidentiality, Privacy
            - Required for cloud service providers

        ISO27001: ISO/IEC 27001:2022 Information Security Management
            - Annex A controls for information security
            - Risk-based approach to security management

        NIST_CSF: NIST Cybersecurity Framework
            - Five core functions: Identify, Protect, Detect, Respond, Recover
            - Widely adopted by US federal agencies and contractors

        GDPR: EU General Data Protection Regulation
            - Data subject rights and privacy requirements
            - Applicable to EU personal data processing

        HIPAA: Health Insurance Portability and Accountability Act
            - Protected Health Information (PHI) requirements
            - Required for healthcare-related plugins

        PCI_DSS: Payment Card Industry Data Security Standard
            - Cardholder data protection requirements
            - Required for payment processing plugins

        SOX: Sarbanes-Oxley Act Section 404
            - Internal controls over financial reporting
            - Required for plugins handling financial data

        FEDRAMP: Federal Risk and Authorization Management Program
            - Cloud security authorization for US federal agencies
            - Required for government cloud deployments

        FISMA: Federal Information Security Management Act
            - Federal agency security requirements
            - Aligned with NIST SP 800-53 controls
    """

    SOC2 = "soc2"
    ISO27001 = "iso27001"
    NIST_CSF = "nist_csf"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    SOX = "sox"
    FEDRAMP = "fedramp"
    FISMA = "fisma"


class PolicyType(str, Enum):
    """
    Types of governance policies for plugin management.

    Policies are categorized by the aspect of plugin behavior they govern.
    Each policy type has specific evaluation criteria and enforcement
    mechanisms appropriate to its domain.

    Policy Types:
        SECURITY: Security-related policies
            - Vulnerability thresholds
            - Authentication requirements
            - Encryption mandates
            - Access control rules

        PERFORMANCE: Performance and resource policies
            - Response time limits
            - Throughput minimums
            - Resource consumption caps
            - Efficiency targets

        COMPATIBILITY: Compatibility and interoperability policies
            - Version compatibility rules
            - API contract requirements
            - Dependency constraints
            - Platform requirements

        DEPLOYMENT: Deployment and lifecycle policies
            - Deployment approval workflows
            - Rollback requirements
            - Update schedules
            - Staging requirements

        LICENSING: Software licensing policies
            - License type restrictions
            - Commercial use rules
            - Open source compliance
            - Attribution requirements

        DATA_PRIVACY: Data privacy and protection policies
            - Data classification requirements
            - Retention limits
            - Cross-border transfer rules
            - Anonymization requirements

        OPERATIONAL: Operational and runtime policies
            - Monitoring requirements
            - Logging standards
            - Alerting thresholds
            - Incident response procedures
    """

    SECURITY = "security"
    PERFORMANCE = "performance"
    COMPATIBILITY = "compatibility"
    DEPLOYMENT = "deployment"
    LICENSING = "licensing"
    DATA_PRIVACY = "data_privacy"
    OPERATIONAL = "operational"


class PolicyEnforcementLevel(str, Enum):
    """
    Enforcement levels for policy violations.

    Enforcement levels provide graduated response options for policy
    violations, from informational advisories to complete quarantine.
    The level determines what actions are taken when a violation occurs.

    Levels (increasing severity):
        ADVISORY: Informational only
            - Logs the violation for awareness
            - No operational impact
            - Used for new policies during rollout

        WARNING: Warning with continued operation
            - Logs the violation prominently
            - Sends notifications to administrators
            - Plugin continues to operate normally

        BLOCKING: Blocks specific operations
            - Prevents the violating operation
            - Plugin remains active for compliant operations
            - Requires remediation for blocked functionality

        QUARANTINE: Complete isolation
            - Disables the plugin entirely
            - Requires manual review and approval to re-enable
            - Used for critical security violations
    """

    ADVISORY = "advisory"
    WARNING = "warning"
    BLOCKING = "blocking"
    QUARANTINE = "quarantine"


class ViolationSeverity(str, Enum):
    """
    Severity levels for policy violations.

    Severity levels align with NIST SP 800-30 risk assessment guidelines
    and help prioritize remediation efforts. Each level has associated
    response time expectations and escalation procedures.

    Severity Levels:
        LOW: Minor violations with minimal impact
            - Remediation: Within 30 days
            - Impact: Operational inconvenience
            - Example: Missing optional documentation

        MEDIUM: Moderate violations requiring attention
            - Remediation: Within 7 days
            - Impact: Reduced functionality or efficiency
            - Example: Performance threshold exceeded

        HIGH: Serious violations requiring prompt action
            - Remediation: Within 24 hours
            - Impact: Significant security or operational risk
            - Example: Known vulnerability in dependency

        CRITICAL: Severe violations requiring immediate action
            - Remediation: Immediate (within hours)
            - Impact: Active security threat or compliance breach
            - Example: Data exfiltration detected
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuditEventType(str, Enum):
    """
    Types of audit events for plugin governance.

    Audit events provide a complete history of all governance-related
    actions for compliance reporting and forensic analysis. Events are
    immutable once created and include full context for reconstruction.

    Event Types:
        PLUGIN_INSTALL: New plugin installation
            - Records: plugin_id, version, installer, approval chain
            - Triggers: Initial compliance check

        PLUGIN_UPDATE: Plugin version update
            - Records: old_version, new_version, update_method
            - Triggers: Re-evaluation of all policies

        PLUGIN_REMOVE: Plugin removal/uninstallation
            - Records: plugin_id, remover, reason
            - Triggers: Cleanup verification

        PLUGIN_ENABLE: Plugin enabled after being disabled
            - Records: plugin_id, enabler, justification
            - Triggers: Compliance re-check

        PLUGIN_DISABLE: Plugin disabled (temporary)
            - Records: plugin_id, disabler, reason, duration
            - Triggers: Notification to stakeholders

        POLICY_VIOLATION: Policy violation detected
            - Records: policy_id, violation_details, severity
            - Triggers: Enforcement action per policy level

        COMPLIANCE_CHECK: Scheduled compliance evaluation
            - Records: standards_checked, results, coverage
            - Triggers: Report generation

        ACCESS_GRANTED: Access permission granted
            - Records: user, resource, permission, grantor
            - Triggers: Access log update

        ACCESS_DENIED: Access permission denied
            - Records: user, resource, reason, denier
            - Triggers: Security alert if repeated

        CONFIGURATION_CHANGE: Governance configuration modified
            - Records: old_config, new_config, changer
            - Triggers: Re-evaluation of affected plugins
    """

    PLUGIN_INSTALL = "plugin_install"
    PLUGIN_UPDATE = "plugin_update"
    PLUGIN_REMOVE = "plugin_remove"
    PLUGIN_ENABLE = "plugin_enable"
    PLUGIN_DISABLE = "plugin_disable"
    POLICY_VIOLATION = "policy_violation"
    COMPLIANCE_CHECK = "compliance_check"
    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED = "access_denied"
    CONFIGURATION_CHANGE = "configuration_change"


# =============================================================================
# POLICY MODELS
# =============================================================================


class PluginPolicy(BaseModel):
    """
    Plugin governance policy definition.

    Policies define rules that plugins must comply with during their
    lifecycle. Each policy has evaluation criteria and enforcement
    actions that are automatically applied when violations occur.

    Attributes:
        policy_id: Unique identifier for the policy.
        name: Human-readable policy name.
        description: Detailed description of the policy purpose.
        policy_type: Category of the policy (security, performance, etc.).
        enforcement_level: Action taken on violation.
        enabled: Whether the policy is actively enforced.
        priority: Evaluation order (lower = higher priority).
        conditions: JSON conditions that define violation criteria.
        actions: Actions to take on violation.
        applicable_standards: Compliance standards this policy supports.
        created_at: When the policy was created.
        updated_at: When the policy was last modified.
        created_by: User who created the policy.
        version: Policy version for change tracking.
        metadata: Additional policy metadata.

    Example:
        >>> policy = PluginPolicy(
        ...     policy_id="sec-001",
        ...     name="No Critical Vulnerabilities",
        ...     description="Plugins must not have critical CVEs",
        ...     policy_type=PolicyType.SECURITY,
        ...     enforcement_level=PolicyEnforcementLevel.BLOCKING,
        ...     conditions={"max_critical_cves": 0},
        ...     applicable_standards=[ComplianceStandard.SOC2, ComplianceStandard.FEDRAMP],
        ... )
    """

    policy_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    policy_type: PolicyType
    enforcement_level: PolicyEnforcementLevel = PolicyEnforcementLevel.WARNING
    enabled: bool = True
    priority: int = Field(default=100, ge=1, le=1000)

    # Policy definition
    conditions: Dict[str, Any] = Field(default_factory=dict)
    actions: List[str] = Field(default_factory=list)
    applicable_standards: List[ComplianceStandard] = Field(default_factory=list)

    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[str] = None
    version: str = "1.0.0"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PolicyViolation(BaseModel):
    """
    Record of a policy violation.

    Violations are created when a plugin fails to meet policy conditions.
    They include full context for remediation and compliance reporting.

    Attributes:
        violation_id: Unique identifier for the violation.
        policy_id: ID of the violated policy.
        plugin_id: ID of the violating plugin.
        severity: Violation severity level.
        description: Human-readable violation description.
        details: Detailed violation information.
        detected_at: When the violation was detected.
        resolved_at: When the violation was resolved (if resolved).
        resolved_by: User who resolved the violation.
        resolution_notes: Notes about how the violation was resolved.
        evidence: Supporting evidence for the violation.
        remediation_steps: Recommended steps to resolve.

    Example:
        >>> violation = PolicyViolation(
        ...     policy_id="sec-001",
        ...     plugin_id="vulnerable-plugin@1.0.0",
        ...     severity=ViolationSeverity.CRITICAL,
        ...     description="Plugin has 3 critical CVEs",
        ...     details={"cves": ["CVE-2024-1234", "CVE-2024-5678", "CVE-2024-9012"]},
        ... )
    """

    violation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    policy_id: str
    plugin_id: str
    severity: ViolationSeverity
    description: str
    details: Dict[str, Any] = Field(default_factory=dict)

    # Timing
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    resolution_notes: Optional[str] = None

    # Evidence and remediation
    evidence: Dict[str, Any] = Field(default_factory=dict)
    remediation_steps: List[str] = Field(default_factory=list)


# =============================================================================
# COMPLIANCE MODELS
# =============================================================================


class ComplianceReport(BaseModel):
    """
    Compliance assessment report.

    Reports provide a point-in-time assessment of plugin compliance
    against one or more regulatory standards. They include detailed
    findings and recommendations for remediation.

    Attributes:
        report_id: Unique identifier for the report.
        plugin_id: ID of the assessed plugin.
        standards: Standards evaluated in this report.
        overall_score: Overall compliance score (0.0-100.0).
        status: Current compliance status.
        findings: Detailed compliance findings.
        recommendations: Recommended remediation actions.
        generated_at: When the report was generated.
        valid_until: Expiration date for the report.
        assessor: System or user that generated the report.
        checksum: SHA-256 checksum for report integrity.
        metadata: Additional report metadata.

    Example:
        >>> report = await governance.generate_compliance_report(
        ...     plugin_id="my-plugin@1.0.0",
        ...     standards=[ComplianceStandard.SOC2, ComplianceStandard.HIPAA],
        ... )
        >>> print(f"Compliance Score: {report.overall_score:.1f}%")
    """

    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    plugin_id: str
    standards: List[ComplianceStandard]

    # Assessment results
    overall_score: float = Field(..., ge=0.0, le=100.0)
    status: str = Field(..., description="compliant, non_compliant, partial, unknown")
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)

    # Report metadata
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    valid_until: Optional[datetime] = None
    assessor: str = "governance_service"
    checksum: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# AUDIT MODELS
# =============================================================================


class AuditEvent(BaseModel):
    """
    Audit event for plugin governance.

    Audit events provide an immutable record of all governance-related
    actions for compliance reporting and forensic analysis.

    Attributes:
        event_id: Unique identifier for the event.
        event_type: Type of audit event.
        plugin_id: ID of the affected plugin (if applicable).
        actor: User or system that triggered the event.
        timestamp: When the event occurred.
        action: Description of the action taken.
        details: Detailed event information.
        outcome: Result of the action (success, failure, partial).
        ip_address: Source IP address (if applicable).
        user_agent: User agent string (if applicable).
        correlation_id: ID for correlating related events.
        metadata: Additional event metadata.
    """

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: AuditEventType
    plugin_id: Optional[str] = None
    actor: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    action: str
    details: Dict[str, Any] = Field(default_factory=dict)
    outcome: str = Field(default="success", description="success, failure, partial")

    # Request context
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    correlation_id: Optional[str] = None

    # Additional metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# CONFIGURATION MODELS
# =============================================================================


class PluginGovernanceConfig(BaseModel):
    """
    Configuration for plugin governance service.

    Defines global settings for the governance service including
    default policies, compliance requirements, and operational parameters.

    Attributes:
        enabled: Whether governance is enabled globally.
        default_enforcement_level: Default enforcement for new policies.
        required_standards: Standards required for all plugins.
        audit_retention_days: Days to retain audit events.
        compliance_check_interval: Hours between scheduled compliance checks.
        auto_quarantine_on_critical: Automatically quarantine on critical violations.
        notification_channels: Channels for violation notifications.
        exemption_approval_required: Require approval for policy exemptions.
        max_violations_before_quarantine: Violation threshold for auto-quarantine.
        metadata: Additional configuration metadata.

    Example:
        >>> config = PluginGovernanceConfig(
        ...     required_standards=[ComplianceStandard.SOC2],
        ...     auto_quarantine_on_critical=True,
        ...     compliance_check_interval=24,
        ... )
    """

    enabled: bool = True
    default_enforcement_level: PolicyEnforcementLevel = PolicyEnforcementLevel.WARNING
    required_standards: List[ComplianceStandard] = Field(default_factory=list)

    # Audit settings
    audit_retention_days: int = Field(default=365, ge=90, le=3650)
    compliance_check_interval: int = Field(default=24, ge=1, le=168)

    # Enforcement settings
    auto_quarantine_on_critical: bool = True
    notification_channels: List[str] = Field(default_factory=list)
    exemption_approval_required: bool = True
    max_violations_before_quarantine: int = Field(default=3, ge=1, le=10)

    # Additional settings
    metadata: Dict[str, Any] = Field(default_factory=dict)
