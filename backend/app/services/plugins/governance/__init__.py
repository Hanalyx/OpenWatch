"""
Plugin Governance Subpackage

Provides comprehensive governance capabilities for plugin management including
policy-based compliance, audit trails, and regulatory standard enforcement.

Components:
    - PluginGovernanceService: Main service for plugin governance operations
    - Models: Policies, violations, compliance reports, audit events

Governance Capabilities:
    - Policy lifecycle management (create, update, delete, evaluate)
    - Compliance assessment against regulatory standards
    - Audit event recording and querying
    - Violation tracking and remediation
    - Governance configuration management

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

Policy Types:
    - SECURITY: Vulnerability thresholds, authentication, encryption
    - PERFORMANCE: Response time limits, throughput, efficiency
    - COMPATIBILITY: Version rules, API contracts, dependencies
    - DEPLOYMENT: Approval workflows, rollback, staging
    - LICENSING: License types, commercial use, attribution
    - DATA_PRIVACY: Classification, retention, transfers
    - OPERATIONAL: Monitoring, logging, alerting

Enforcement Levels:
    - ADVISORY: Informational only, no operational impact
    - WARNING: Logs violation, sends notifications
    - BLOCKING: Prevents violating operations
    - QUARANTINE: Complete plugin isolation

Usage:
    from app.services.plugins.governance import PluginGovernanceService

    governance = PluginGovernanceService()
    await governance.start()

    # Register a policy
    policy = await governance.register_policy(
        name="No Critical Vulnerabilities",
        description="Plugins must not have critical CVEs",
        policy_type=PolicyType.SECURITY,
        enforcement_level=PolicyEnforcementLevel.BLOCKING,
        conditions={"max_critical_cves": 0},
    )

    # Evaluate plugin compliance
    report = await governance.evaluate_plugin_compliance(
        plugin_id="my-plugin@1.0.0",
        standards=[ComplianceStandard.SOC2],
    )
    print(f"Compliance Score: {report.overall_score:.1f}%")

Example:
    >>> from app.services.plugins.governance import (
    ...     PluginGovernanceService,
    ...     PolicyType,
    ...     ComplianceStandard,
    ... )
    >>> governance = PluginGovernanceService()
    >>> await governance.start()
    >>> summary = await governance.get_governance_summary()
    >>> print(f"Active policies: {summary['policies']['enabled']}")
"""

from .models import (
    AuditEvent,
    AuditEventType,
    ComplianceReport,
    ComplianceStandard,
    PluginGovernanceConfig,
    PluginPolicy,
    PolicyEnforcementLevel,
    PolicyType,
    PolicyViolation,
    ViolationSeverity,
)
from .service import PluginGovernanceService

__all__ = [
    # Service
    "PluginGovernanceService",
    # Enums
    "ComplianceStandard",
    "PolicyType",
    "PolicyEnforcementLevel",
    "ViolationSeverity",
    "AuditEventType",
    # Models
    "PluginPolicy",
    "PolicyViolation",
    "ComplianceReport",
    "AuditEvent",
    "PluginGovernanceConfig",
]
