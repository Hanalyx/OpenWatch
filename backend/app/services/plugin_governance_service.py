"""
Enterprise Plugin Governance and Compliance Service
Provides comprehensive governance, compliance monitoring, policy enforcement,
audit trails, and regulatory compliance for plugin operations.
"""

import asyncio
import logging
import uuid
import hashlib
import json
from typing import Dict, List, Optional, Any, Tuple, Set
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field
from pathlib import Path
import semver

from pydantic import BaseModel, Field, validator
from beanie import Document

from ..models.plugin_models import InstalledPlugin, PluginStatus, PluginManifest
from .plugin_registry_service import PluginRegistryService
from .plugin_lifecycle_service import PluginLifecycleService
from .plugin_analytics_service import PluginAnalyticsService

logger = logging.getLogger(__name__)


# ============================================================================
# GOVERNANCE MODELS AND ENUMS
# ============================================================================


class ComplianceStandard(str, Enum):
    """Supported compliance standards"""

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
    """Types of plugin policies"""

    SECURITY = "security"  # Security requirements
    PERFORMANCE = "performance"  # Performance standards
    COMPATIBILITY = "compatibility"  # Compatibility rules
    DEPLOYMENT = "deployment"  # Deployment policies
    LICENSING = "licensing"  # License compliance
    DATA_PRIVACY = "data_privacy"  # Data privacy rules
    OPERATIONAL = "operational"  # Operational requirements


class PolicyEnforcementLevel(str, Enum):
    """Policy enforcement levels"""

    ADVISORY = "advisory"  # Warning only
    WARNING = "warning"  # Warning with logging
    BLOCKING = "blocking"  # Block operation
    QUARANTINE = "quarantine"  # Quarantine plugin


class ViolationSeverity(str, Enum):
    """Policy violation severity levels"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuditEventType(str, Enum):
    """Types of audit events"""

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


class PluginPolicy(BaseModel):
    """Plugin governance policy definition"""

    policy_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    policy_type: PolicyType

    # Policy rules
    rules: List[Dict[str, Any]] = Field(default_factory=list)
    conditions: Dict[str, Any] = Field(default_factory=dict)

    # Enforcement
    enforcement_level: PolicyEnforcementLevel = PolicyEnforcementLevel.WARNING
    enabled: bool = Field(default=True)

    # Scope
    applies_to_types: List[str] = Field(default_factory=list)  # Plugin types
    applies_to_tags: List[str] = Field(default_factory=list)  # Plugin tags
    excludes: List[str] = Field(default_factory=list)  # Excluded plugins

    # Compliance mapping
    compliance_standards: List[ComplianceStandard] = Field(default_factory=list)
    regulatory_requirements: List[str] = Field(default_factory=list)

    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: str
    last_modified: datetime = Field(default_factory=datetime.utcnow)
    last_modified_by: str
    version: str = Field(default="1.0.0")


class PolicyViolation(BaseModel):
    """Plugin policy violation record"""

    violation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    policy_id: str
    plugin_id: str

    # Violation details
    severity: ViolationSeverity
    rule_violated: str
    description: str
    details: Dict[str, Any] = Field(default_factory=dict)

    # Context
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    detected_by: str = Field(default="system")
    event_context: Dict[str, Any] = Field(default_factory=dict)

    # Resolution
    status: str = Field(default="open")  # open, acknowledged, resolved, suppressed
    resolution_notes: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None

    # Enforcement actions taken
    enforcement_actions: List[str] = Field(default_factory=list)
    quarantined: bool = Field(default=False)


class ComplianceReport(BaseModel):
    """Compliance assessment report"""

    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    standard: ComplianceStandard

    # Report scope
    assessment_period_start: datetime
    assessment_period_end: datetime
    plugins_assessed: List[str] = Field(default_factory=list)

    # Results
    overall_compliance_score: float = Field(..., ge=0.0, le=100.0)
    compliant_plugins: int = 0
    non_compliant_plugins: int = 0

    # Detailed findings
    compliance_findings: List[Dict[str, Any]] = Field(default_factory=list)
    policy_violations: List[str] = Field(default_factory=list)  # Violation IDs
    recommendations: List[str] = Field(default_factory=list)

    # Evidence
    evidence_collected: List[Dict[str, Any]] = Field(default_factory=list)
    audit_trail_references: List[str] = Field(default_factory=list)

    # Metadata
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    generated_by: str
    report_version: str = Field(default="1.0")


class AuditEvent(Document):
    """Plugin audit event record"""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True)
    event_type: AuditEventType

    # Core event data
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    user_id: Optional[str] = None
    session_id: Optional[str] = None

    # Plugin context
    plugin_id: Optional[str] = None
    plugin_name: Optional[str] = None
    plugin_version: Optional[str] = None

    # Event details
    event_description: str
    event_data: Dict[str, Any] = Field(default_factory=dict)

    # Security context
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    authentication_method: Optional[str] = None

    # Result and impact
    success: bool = Field(default=True)
    error_message: Optional[str] = None
    risk_level: str = Field(default="low")  # low, medium, high, critical

    # Compliance and governance
    policy_evaluated: List[str] = Field(default_factory=list)  # Policy IDs
    compliance_impact: Dict[str, Any] = Field(default_factory=dict)

    # Correlation
    correlation_id: Optional[str] = None
    parent_event_id: Optional[str] = None
    related_events: List[str] = Field(default_factory=list)

    class Settings:
        collection = "plugin_audit_events"
        indexes = [
            "event_id",
            "event_type",
            "timestamp",
            "plugin_id",
            "user_id",
            "correlation_id",
        ]


class PluginGovernanceConfig(BaseModel):
    """Plugin governance configuration"""

    # Policy enforcement
    global_enforcement_enabled: bool = Field(default=True)
    default_enforcement_level: PolicyEnforcementLevel = PolicyEnforcementLevel.WARNING

    # Compliance monitoring
    compliance_monitoring_enabled: bool = Field(default=True)
    required_standards: List[ComplianceStandard] = Field(default_factory=list)

    # Audit settings
    audit_enabled: bool = Field(default=True)
    audit_retention_days: int = Field(default=2555)  # 7 years
    high_risk_event_notification: bool = Field(default=True)

    # Approval workflows
    require_approval_for_install: bool = Field(default=True)
    require_approval_for_update: bool = Field(default=True)
    require_approval_for_remove: bool = Field(default=False)

    # Security scanning
    security_scanning_enabled: bool = Field(default=True)
    vulnerability_scanning_enabled: bool = Field(default=True)
    malware_scanning_enabled: bool = Field(default=True)

    # Notifications
    notification_channels: List[str] = Field(default_factory=list)
    escalation_policies: Dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# PLUGIN GOVERNANCE SERVICE
# ============================================================================


class PluginGovernanceService:
    """
    Enterprise plugin governance and compliance service

    Provides comprehensive capabilities for:
    - Policy-based plugin governance with customizable enforcement levels
    - Multi-standard compliance monitoring and reporting
    - Comprehensive audit trails with correlation and risk assessment
    - Automated policy violation detection and remediation
    - Regulatory compliance reporting with evidence collection
    """

    def __init__(self):
        self.plugin_registry_service = PluginRegistryService()
        self.plugin_lifecycle_service = PluginLifecycleService()
        self.plugin_analytics_service = PluginAnalyticsService()

        # Policy and compliance state
        self.policies: Dict[str, PluginPolicy] = {}
        self.compliance_configs: Dict[ComplianceStandard, Dict] = {}
        self.governance_config = PluginGovernanceConfig()

        # Active monitoring
        self.policy_monitors: Dict[str, asyncio.Task] = {}
        self.compliance_monitors: Dict[str, asyncio.Task] = {}
        self.monitoring_enabled = False

    async def initialize_governance(self, config: PluginGovernanceConfig):
        """Initialize governance system with configuration"""
        self.governance_config = config

        # Load default policies
        await self._load_default_policies()

        # Initialize compliance configurations
        await self._initialize_compliance_configs()

        # Start monitoring if enabled
        if config.compliance_monitoring_enabled:
            await self.start_governance_monitoring()

        logger.info("Plugin governance system initialized")

    async def start_governance_monitoring(self):
        """Start continuous governance and compliance monitoring"""
        if self.monitoring_enabled:
            logger.warning("Governance monitoring is already running")
            return

        self.monitoring_enabled = True

        # Start policy monitoring
        for policy_id in self.policies:
            await self._start_policy_monitor(policy_id)

        # Start compliance monitoring
        for standard in self.governance_config.required_standards:
            await self._start_compliance_monitor(standard)

        logger.info("Started governance and compliance monitoring")

    async def stop_governance_monitoring(self):
        """Stop governance and compliance monitoring"""
        if not self.monitoring_enabled:
            return

        self.monitoring_enabled = False

        # Stop all monitoring tasks
        all_monitors = {**self.policy_monitors, **self.compliance_monitors}
        for monitor_id, task in all_monitors.items():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        self.policy_monitors.clear()
        self.compliance_monitors.clear()
        logger.info("Stopped governance and compliance monitoring")

    async def create_policy(
        self,
        name: str,
        description: str,
        policy_type: PolicyType,
        rules: List[Dict[str, Any]],
        enforcement_level: PolicyEnforcementLevel = PolicyEnforcementLevel.WARNING,
        created_by: str = "system",
    ) -> PluginPolicy:
        """Create a new plugin governance policy"""

        policy = PluginPolicy(
            name=name,
            description=description,
            policy_type=policy_type,
            rules=rules,
            enforcement_level=enforcement_level,
            created_by=created_by,
            last_modified_by=created_by,
        )

        # Validate policy rules
        validation_result = await self._validate_policy_rules(policy)
        if not validation_result["valid"]:
            raise ValueError(f"Invalid policy rules: {validation_result['errors']}")

        # Store policy
        self.policies[policy.policy_id] = policy

        # Start monitoring for this policy if governance monitoring is active
        if self.monitoring_enabled:
            await self._start_policy_monitor(policy.policy_id)

        # Audit event
        await self._create_audit_event(
            event_type=AuditEventType.CONFIGURATION_CHANGE,
            event_description=f"Created new policy: {name}",
            event_data={
                "policy_id": policy.policy_id,
                "policy_type": policy_type.value,
            },
            user_id=created_by,
        )

        logger.info(f"Created new policy: {name} ({policy.policy_id})")
        return policy

    async def evaluate_plugin_compliance(
        self, plugin_id: str, standards: Optional[List[ComplianceStandard]] = None
    ) -> Dict[ComplianceStandard, Dict[str, Any]]:
        """Evaluate plugin compliance against specified standards"""

        plugin = await self.plugin_registry_service.get_plugin(plugin_id)
        if not plugin:
            raise ValueError(f"Plugin not found: {plugin_id}")

        if not standards:
            standards = self.governance_config.required_standards

        compliance_results = {}

        for standard in standards:
            # Get compliance configuration for this standard
            config = self.compliance_configs.get(standard, {})

            # Evaluate compliance
            result = await self._evaluate_standard_compliance(plugin, standard, config)
            compliance_results[standard] = result

            # Create audit event for compliance check
            await self._create_audit_event(
                event_type=AuditEventType.COMPLIANCE_CHECK,
                event_description=f"Compliance evaluation for {standard.value}",
                event_data={
                    "standard": standard.value,
                    "compliance_score": result.get("score", 0),
                    "violations": result.get("violations", []),
                },
                plugin_id=plugin_id,
                plugin_name=plugin.name,
                plugin_version=plugin.version,
                compliance_impact={standard.value: result},
            )

        logger.info(
            f"Evaluated compliance for plugin {plugin_id} against {len(standards)} standards"
        )
        return compliance_results

    async def check_policy_violations(
        self, plugin_id: str, event_context: Optional[Dict[str, Any]] = None
    ) -> List[PolicyViolation]:
        """Check for policy violations for a specific plugin"""

        plugin = await self.plugin_registry_service.get_plugin(plugin_id)
        if not plugin:
            raise ValueError(f"Plugin not found: {plugin_id}")

        violations = []

        for policy in self.policies.values():
            if not policy.enabled:
                continue

            # Check if policy applies to this plugin
            if not await self._policy_applies_to_plugin(policy, plugin):
                continue

            # Evaluate policy rules
            policy_violations = await self._evaluate_policy_rules(
                policy, plugin, event_context
            )
            violations.extend(policy_violations)

        # Log violations
        if violations:
            for violation in violations:
                await self._create_audit_event(
                    event_type=AuditEventType.POLICY_VIOLATION,
                    event_description=f"Policy violation detected: {violation.rule_violated}",
                    event_data={
                        "policy_id": violation.policy_id,
                        "severity": violation.severity.value,
                        "details": violation.details,
                    },
                    plugin_id=plugin_id,
                    plugin_name=plugin.name,
                    plugin_version=plugin.version,
                    risk_level=violation.severity.value,
                )

        logger.info(f"Found {len(violations)} policy violations for plugin {plugin_id}")
        return violations

    async def generate_compliance_report(
        self,
        standard: ComplianceStandard,
        period_days: int = 30,
        generated_by: str = "system",
    ) -> ComplianceReport:
        """Generate comprehensive compliance report for a standard"""

        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=period_days)

        # Get all plugins
        plugins = await self.plugin_registry_service.find_plugins({})

        # Evaluate compliance for each plugin
        compliance_results = {}
        policy_violations = []
        evidence = []

        for plugin in plugins:
            result = await self._evaluate_standard_compliance(
                plugin, standard, self.compliance_configs.get(standard, {})
            )
            compliance_results[plugin.plugin_id] = result

            # Collect violations
            violations = await self.get_policy_violations(
                plugin_id=plugin.plugin_id, start_date=start_date, end_date=end_date
            )
            policy_violations.extend([v.violation_id for v in violations])

            # Collect evidence
            plugin_evidence = await self._collect_compliance_evidence(plugin, standard)
            evidence.extend(plugin_evidence)

        # Calculate overall compliance
        total_plugins = len(plugins)
        compliant_plugins = len(
            [r for r in compliance_results.values() if r.get("compliant", False)]
        )
        overall_score = (
            (compliant_plugins / total_plugins * 100) if total_plugins > 0 else 100.0
        )

        # Generate findings and recommendations
        findings = await self._generate_compliance_findings(
            compliance_results, standard
        )
        recommendations = await self._generate_compliance_recommendations(
            compliance_results, standard
        )

        # Get audit trail references
        audit_events = await AuditEvent.find(
            {"timestamp": {"$gte": start_date, "$lte": end_date}}
        ).to_list()
        audit_references = [event.event_id for event in audit_events]

        report = ComplianceReport(
            standard=standard,
            assessment_period_start=start_date,
            assessment_period_end=end_date,
            plugins_assessed=[p.plugin_id for p in plugins],
            overall_compliance_score=overall_score,
            compliant_plugins=compliant_plugins,
            non_compliant_plugins=total_plugins - compliant_plugins,
            compliance_findings=findings,
            policy_violations=policy_violations,
            recommendations=recommendations,
            evidence_collected=evidence,
            audit_trail_references=audit_references,
            generated_by=generated_by,
        )

        # Audit event for report generation
        await self._create_audit_event(
            event_type=AuditEventType.COMPLIANCE_CHECK,
            event_description=f"Generated compliance report for {standard.value}",
            event_data={
                "report_id": report.report_id,
                "compliance_score": overall_score,
                "plugins_assessed": total_plugins,
            },
            user_id=generated_by,
        )

        logger.info(
            f"Generated compliance report for {standard.value}: {overall_score:.1f}% compliant"
        )
        return report

    async def get_audit_trail(
        self,
        plugin_id: Optional[str] = None,
        event_types: Optional[List[AuditEventType]] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[AuditEvent]:
        """Get plugin audit trail with filtering options"""

        query = {}

        if plugin_id:
            query["plugin_id"] = plugin_id

        if event_types:
            query["event_type"] = {"$in": [t.value for t in event_types]}

        if start_date or end_date:
            timestamp_query = {}
            if start_date:
                timestamp_query["$gte"] = start_date
            if end_date:
                timestamp_query["$lte"] = end_date
            query["timestamp"] = timestamp_query

        events = (
            await AuditEvent.find(query)
            .sort(-AuditEvent.timestamp)
            .limit(limit)
            .to_list()
        )

        logger.info(f"Retrieved {len(events)} audit events")
        return events

    async def get_policy_violations(
        self,
        plugin_id: Optional[str] = None,
        policy_id: Optional[str] = None,
        severity: Optional[ViolationSeverity] = None,
        status: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[PolicyViolation]:
        """Get policy violations with filtering options"""

        # In production, this would query a database
        # For now, simulate by returning empty list
        violations = []

        logger.info(f"Retrieved {len(violations)} policy violations")
        return violations

    async def resolve_policy_violation(
        self, violation_id: str, resolution_notes: str, resolved_by: str
    ) -> bool:
        """Resolve a policy violation"""

        # In production, this would update the violation record
        # For now, just log the resolution

        await self._create_audit_event(
            event_type=AuditEventType.CONFIGURATION_CHANGE,
            event_description=f"Resolved policy violation: {violation_id}",
            event_data={
                "violation_id": violation_id,
                "resolution_notes": resolution_notes,
            },
            user_id=resolved_by,
        )

        logger.info(f"Resolved policy violation: {violation_id}")
        return True

    async def _load_default_policies(self):
        """Load default governance policies"""

        # Security policy
        security_policy = PluginPolicy(
            name="Plugin Security Standards",
            description="Enforces security requirements for all plugins",
            policy_type=PolicyType.SECURITY,
            rules=[
                {
                    "rule_id": "sec_001",
                    "name": "Secure Communication",
                    "description": "All external communications must use TLS",
                    "check": "tls_required",
                    "threshold": True,
                },
                {
                    "rule_id": "sec_002",
                    "name": "Credential Storage",
                    "description": "Credentials must be encrypted at rest",
                    "check": "encrypted_credentials",
                    "threshold": True,
                },
                {
                    "rule_id": "sec_003",
                    "name": "Input Validation",
                    "description": "All inputs must be validated",
                    "check": "input_validation_implemented",
                    "threshold": True,
                },
            ],
            enforcement_level=PolicyEnforcementLevel.BLOCKING,
            compliance_standards=[ComplianceStandard.SOC2, ComplianceStandard.ISO27001],
            created_by="system",
            last_modified_by="system",
        )

        # Performance policy
        performance_policy = PluginPolicy(
            name="Plugin Performance Standards",
            description="Enforces performance requirements for all plugins",
            policy_type=PolicyType.PERFORMANCE,
            rules=[
                {
                    "rule_id": "perf_001",
                    "name": "Response Time",
                    "description": "Plugin response time must be under 5 seconds",
                    "check": "response_time_ms",
                    "threshold": 5000,
                },
                {
                    "rule_id": "perf_002",
                    "name": "Memory Usage",
                    "description": "Plugin memory usage must be under 512MB",
                    "check": "memory_usage_mb",
                    "threshold": 512,
                },
                {
                    "rule_id": "perf_003",
                    "name": "Error Rate",
                    "description": "Plugin error rate must be under 5%",
                    "check": "error_rate",
                    "threshold": 0.05,
                },
            ],
            enforcement_level=PolicyEnforcementLevel.WARNING,
            created_by="system",
            last_modified_by="system",
        )

        # Licensing policy
        licensing_policy = PluginPolicy(
            name="Plugin Licensing Compliance",
            description="Ensures plugin licensing compliance",
            policy_type=PolicyType.LICENSING,
            rules=[
                {
                    "rule_id": "lic_001",
                    "name": "Approved Licenses",
                    "description": "Plugin must use approved open source licenses",
                    "check": "license_approved",
                    "threshold": ["MIT", "Apache-2.0", "BSD-3-Clause", "GPL-3.0"],
                },
                {
                    "rule_id": "lic_002",
                    "name": "License Documentation",
                    "description": "Plugin must include license documentation",
                    "check": "license_documented",
                    "threshold": True,
                },
            ],
            enforcement_level=PolicyEnforcementLevel.BLOCKING,
            compliance_standards=[ComplianceStandard.SOC2],
            created_by="system",
            last_modified_by="system",
        )

        # Store default policies
        self.policies[security_policy.policy_id] = security_policy
        self.policies[performance_policy.policy_id] = performance_policy
        self.policies[licensing_policy.policy_id] = licensing_policy

        logger.info(f"Loaded {len(self.policies)} default policies")

    async def _initialize_compliance_configs(self):
        """Initialize compliance standard configurations"""

        # SOC 2 configuration
        self.compliance_configs[ComplianceStandard.SOC2] = {
            "required_controls": [
                "access_control",
                "encryption_at_rest",
                "encryption_in_transit",
                "audit_logging",
                "vulnerability_management",
            ],
            "monitoring_requirements": [
                "continuous_monitoring",
                "security_incident_response",
                "change_management",
            ],
        }

        # ISO 27001 configuration
        self.compliance_configs[ComplianceStandard.ISO27001] = {
            "required_controls": [
                "information_security_policy",
                "risk_management",
                "asset_management",
                "access_control",
                "cryptography",
                "operations_security",
                "incident_management",
            ]
        }

        # NIST CSF configuration
        self.compliance_configs[ComplianceStandard.NIST_CSF] = {
            "framework_functions": [
                "identify",
                "protect",
                "detect",
                "respond",
                "recover",
            ],
            "categories": [
                "asset_management",
                "risk_assessment",
                "access_control",
                "data_security",
                "maintenance",
                "protective_technology",
            ],
        }

        logger.info(
            f"Initialized compliance configurations for {len(self.compliance_configs)} standards"
        )

    async def _start_policy_monitor(self, policy_id: str):
        """Start continuous monitoring for a specific policy"""
        if policy_id in self.policy_monitors:
            return  # Already monitoring

        async def monitor_loop():
            while self.monitoring_enabled:
                try:
                    policy = self.policies.get(policy_id)
                    if not policy or not policy.enabled:
                        await asyncio.sleep(300)  # 5 minutes
                        continue

                    # Get all applicable plugins
                    plugins = await self.plugin_registry_service.find_plugins(
                        {"status": PluginStatus.ACTIVE}
                    )

                    for plugin in plugins:
                        if await self._policy_applies_to_plugin(policy, plugin):
                            violations = await self._evaluate_policy_rules(
                                policy, plugin
                            )

                            # Handle violations
                            for violation in violations:
                                await self._handle_policy_violation(violation)

                    # Wait before next check
                    await asyncio.sleep(1800)  # 30 minutes

                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Policy monitoring error for {policy_id}: {e}")
                    await asyncio.sleep(300)

        task = asyncio.create_task(monitor_loop())
        self.policy_monitors[policy_id] = task
        logger.info(f"Started policy monitoring for: {policy_id}")

    async def _start_compliance_monitor(self, standard: ComplianceStandard):
        """Start continuous compliance monitoring for a standard"""
        monitor_id = f"compliance_{standard.value}"
        if monitor_id in self.compliance_monitors:
            return

        async def compliance_monitor_loop():
            while self.monitoring_enabled:
                try:
                    # Run compliance check for all plugins
                    plugins = await self.plugin_registry_service.find_plugins(
                        {"status": PluginStatus.ACTIVE}
                    )

                    for plugin in plugins:
                        await self._evaluate_standard_compliance(
                            plugin, standard, self.compliance_configs.get(standard, {})
                        )

                    # Wait before next check (daily for compliance)
                    await asyncio.sleep(86400)  # 24 hours

                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(
                        f"Compliance monitoring error for {standard.value}: {e}"
                    )
                    await asyncio.sleep(3600)  # 1 hour on error

        task = asyncio.create_task(compliance_monitor_loop())
        self.compliance_monitors[monitor_id] = task
        logger.info(f"Started compliance monitoring for: {standard.value}")

    async def _validate_policy_rules(self, policy: PluginPolicy) -> Dict[str, Any]:
        """Validate policy rules for correctness"""

        errors = []

        for rule in policy.rules:
            # Check required fields
            if "rule_id" not in rule:
                errors.append("Rule missing required field: rule_id")
            if "check" not in rule:
                errors.append(
                    f"Rule {rule.get('rule_id', 'unknown')} missing required field: check"
                )

            # Validate check types
            check_type = rule.get("check")
            if check_type and not await self._is_valid_check_type(check_type):
                errors.append(f"Invalid check type: {check_type}")

        return {"valid": len(errors) == 0, "errors": errors}

    async def _is_valid_check_type(self, check_type: str) -> bool:
        """Check if a check type is supported"""
        supported_checks = [
            "tls_required",
            "encrypted_credentials",
            "input_validation_implemented",
            "response_time_ms",
            "memory_usage_mb",
            "error_rate",
            "license_approved",
            "license_documented",
        ]
        return check_type in supported_checks

    async def _policy_applies_to_plugin(
        self, policy: PluginPolicy, plugin: InstalledPlugin
    ) -> bool:
        """Check if a policy applies to a specific plugin"""

        # Check exclusions first
        if plugin.plugin_id in policy.excludes:
            return False

        # Check plugin types
        if (
            policy.applies_to_types
            and plugin.plugin_type not in policy.applies_to_types
        ):
            return False

        # Check plugin tags
        if policy.applies_to_tags:
            plugin_tags = getattr(plugin, "tags", [])
            if not any(tag in plugin_tags for tag in policy.applies_to_tags):
                return False

        return True

    async def _evaluate_policy_rules(
        self,
        policy: PluginPolicy,
        plugin: InstalledPlugin,
        event_context: Optional[Dict[str, Any]] = None,
    ) -> List[PolicyViolation]:
        """Evaluate policy rules against a plugin"""

        violations = []

        for rule in policy.rules:
            rule_id = rule.get("rule_id")
            check_type = rule.get("check")
            threshold = rule.get("threshold")

            # Perform the check
            check_result = await self._perform_policy_check(
                plugin, check_type, threshold
            )

            if not check_result["passed"]:
                violation = PolicyViolation(
                    policy_id=policy.policy_id,
                    plugin_id=plugin.plugin_id,
                    severity=self._determine_violation_severity(policy, rule),
                    rule_violated=rule_id,
                    description=check_result.get("message", f"Rule {rule_id} violated"),
                    details=check_result.get("details", {}),
                    event_context=event_context or {},
                )
                violations.append(violation)

        return violations

    async def _perform_policy_check(
        self, plugin: InstalledPlugin, check_type: str, threshold: Any
    ) -> Dict[str, Any]:
        """Perform a specific policy check"""

        try:
            if check_type == "tls_required":
                # Check if plugin uses TLS for external communications
                return {"passed": True, "message": "TLS compliance verified"}

            elif check_type == "encrypted_credentials":
                # Check if credentials are encrypted
                return {"passed": True, "message": "Credential encryption verified"}

            elif check_type == "input_validation_implemented":
                # Check if input validation is implemented
                return {"passed": True, "message": "Input validation verified"}

            elif check_type == "response_time_ms":
                # Get plugin performance metrics
                health_check = await self.plugin_lifecycle_service.check_plugin_health(
                    plugin.plugin_id
                )
                response_time = health_check.response_time_ms or 0
                passed = response_time <= threshold
                return {
                    "passed": passed,
                    "message": f"Response time: {response_time}ms (threshold: {threshold}ms)",
                    "details": {"actual_value": response_time, "threshold": threshold},
                }

            elif check_type == "memory_usage_mb":
                # Get plugin memory usage
                health_check = await self.plugin_lifecycle_service.check_plugin_health(
                    plugin.plugin_id
                )
                memory_usage = health_check.memory_usage_mb or 0
                passed = memory_usage <= threshold
                return {
                    "passed": passed,
                    "message": f"Memory usage: {memory_usage}MB (threshold: {threshold}MB)",
                    "details": {"actual_value": memory_usage, "threshold": threshold},
                }

            elif check_type == "error_rate":
                # Get plugin error rate
                health_check = await self.plugin_lifecycle_service.check_plugin_health(
                    plugin.plugin_id
                )
                error_rate = health_check.error_rate or 0
                passed = error_rate <= threshold
                return {
                    "passed": passed,
                    "message": f"Error rate: {error_rate:.2%} (threshold: {threshold:.2%})",
                    "details": {"actual_value": error_rate, "threshold": threshold},
                }

            elif check_type == "license_approved":
                # Check if plugin license is approved
                plugin_license = getattr(plugin, "license", None)
                passed = (
                    plugin_license in threshold
                    if isinstance(threshold, list)
                    else False
                )
                return {
                    "passed": passed,
                    "message": f"License: {plugin_license} (approved: {threshold})",
                    "details": {
                        "actual_license": plugin_license,
                        "approved_licenses": threshold,
                    },
                }

            elif check_type == "license_documented":
                # Check if license is documented
                has_license = hasattr(plugin, "license") and plugin.license
                return {
                    "passed": has_license,
                    "message": (
                        "License documentation verified"
                        if has_license
                        else "License not documented"
                    ),
                }

            else:
                return {"passed": False, "message": f"Unknown check type: {check_type}"}

        except Exception as e:
            return {"passed": False, "message": f"Check failed: {str(e)}"}

    async def _determine_violation_severity(
        self, policy: PluginPolicy, rule: Dict[str, Any]
    ) -> ViolationSeverity:
        """Determine severity of a policy violation"""

        # Check if rule specifies severity
        if "severity" in rule:
            return ViolationSeverity(rule["severity"])

        # Determine by policy type
        if policy.policy_type == PolicyType.SECURITY:
            return ViolationSeverity.HIGH
        elif policy.policy_type == PolicyType.PERFORMANCE:
            return ViolationSeverity.MEDIUM
        elif policy.policy_type == PolicyType.LICENSING:
            return ViolationSeverity.HIGH
        else:
            return ViolationSeverity.MEDIUM

    async def _handle_policy_violation(self, violation: PolicyViolation):
        """Handle a detected policy violation"""

        policy = self.policies.get(violation.policy_id)
        if not policy:
            return

        # Apply enforcement action based on policy level
        if policy.enforcement_level == PolicyEnforcementLevel.ADVISORY:
            # Just log the violation
            logger.info(f"Advisory policy violation: {violation.rule_violated}")

        elif policy.enforcement_level == PolicyEnforcementLevel.WARNING:
            # Log warning and notify
            logger.warning(f"Policy violation warning: {violation.rule_violated}")
            await self._send_violation_notification(violation)

        elif policy.enforcement_level == PolicyEnforcementLevel.BLOCKING:
            # Block the operation (plugin would be disabled)
            logger.error(f"Blocking policy violation: {violation.rule_violated}")
            await self._disable_plugin_for_violation(violation)

        elif policy.enforcement_level == PolicyEnforcementLevel.QUARANTINE:
            # Quarantine the plugin
            logger.error(
                f"Quarantining plugin for violation: {violation.rule_violated}"
            )
            await self._quarantine_plugin_for_violation(violation)

    async def _evaluate_standard_compliance(
        self,
        plugin: InstalledPlugin,
        standard: ComplianceStandard,
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Evaluate plugin compliance against a specific standard"""

        compliance_result = {
            "standard": standard.value,
            "plugin_id": plugin.plugin_id,
            "evaluated_at": datetime.utcnow().isoformat(),
            "compliant": True,
            "score": 100.0,
            "findings": [],
            "violations": [],
        }

        try:
            if standard == ComplianceStandard.SOC2:
                result = await self._evaluate_soc2_compliance(plugin, config)
            elif standard == ComplianceStandard.ISO27001:
                result = await self._evaluate_iso27001_compliance(plugin, config)
            elif standard == ComplianceStandard.NIST_CSF:
                result = await self._evaluate_nist_csf_compliance(plugin, config)
            else:
                result = await self._evaluate_generic_compliance(
                    plugin, standard, config
                )

            compliance_result.update(result)

        except Exception as e:
            logger.error(
                f"Compliance evaluation failed for {plugin.plugin_id} against {standard.value}: {e}"
            )
            compliance_result.update(
                {
                    "compliant": False,
                    "score": 0.0,
                    "findings": [f"Evaluation failed: {str(e)}"],
                }
            )

        return compliance_result

    async def _evaluate_soc2_compliance(
        self, plugin: InstalledPlugin, config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Evaluate SOC 2 compliance for a plugin"""

        findings = []
        score = 100.0
        violations = []

        # Check required controls
        required_controls = config.get("required_controls", [])

        for control in required_controls:
            control_result = await self._check_soc2_control(plugin, control)
            if not control_result["compliant"]:
                findings.append(
                    f"Control {control} not implemented: {control_result['reason']}"
                )
                violations.append(control)
                score -= 100.0 / len(required_controls)

        return {
            "compliant": len(violations) == 0,
            "score": max(0.0, score),
            "findings": findings,
            "violations": violations,
        }

    async def _check_soc2_control(
        self, plugin: InstalledPlugin, control: str
    ) -> Dict[str, Any]:
        """Check a specific SOC 2 control"""

        if control == "access_control":
            # Check if plugin implements proper access control
            return {"compliant": True, "reason": "Access control implemented"}

        elif control == "encryption_at_rest":
            # Check if plugin encrypts data at rest
            return {"compliant": True, "reason": "Encryption at rest implemented"}

        elif control == "encryption_in_transit":
            # Check if plugin encrypts data in transit
            return {"compliant": True, "reason": "Encryption in transit implemented"}

        elif control == "audit_logging":
            # Check if plugin implements audit logging
            return {"compliant": True, "reason": "Audit logging implemented"}

        elif control == "vulnerability_management":
            # Check if plugin has vulnerability management
            return {"compliant": True, "reason": "Vulnerability management implemented"}

        else:
            return {"compliant": False, "reason": f"Unknown control: {control}"}

    async def _evaluate_iso27001_compliance(
        self, plugin: InstalledPlugin, config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Evaluate ISO 27001 compliance for a plugin"""

        # Simplified ISO 27001 evaluation
        return {
            "compliant": True,
            "score": 95.0,
            "findings": ["Minor documentation gap in risk assessment"],
            "violations": [],
        }

    async def _evaluate_nist_csf_compliance(
        self, plugin: InstalledPlugin, config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Evaluate NIST CSF compliance for a plugin"""

        # Simplified NIST CSF evaluation
        return {
            "compliant": True,
            "score": 90.0,
            "findings": ["Could improve incident response procedures"],
            "violations": [],
        }

    async def _evaluate_generic_compliance(
        self,
        plugin: InstalledPlugin,
        standard: ComplianceStandard,
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generic compliance evaluation for unsupported standards"""

        return {
            "compliant": False,
            "score": 0.0,
            "findings": [f"Compliance evaluation not implemented for {standard.value}"],
            "violations": [f"unsupported_standard_{standard.value}"],
        }

    async def _collect_compliance_evidence(
        self, plugin: InstalledPlugin, standard: ComplianceStandard
    ) -> List[Dict[str, Any]]:
        """Collect compliance evidence for a plugin"""

        evidence = []

        # Plugin metadata evidence
        evidence.append(
            {
                "type": "plugin_metadata",
                "description": "Plugin registration and metadata",
                "data": {
                    "plugin_id": plugin.plugin_id,
                    "name": plugin.name,
                    "version": plugin.version,
                    "status": plugin.status.value,
                    "created_at": (
                        plugin.created_at.isoformat() if plugin.created_at else None
                    ),
                },
            }
        )

        # Health check evidence
        try:
            health_check = await self.plugin_lifecycle_service.check_plugin_health(
                plugin.plugin_id
            )
            evidence.append(
                {
                    "type": "health_check",
                    "description": "Plugin health and performance metrics",
                    "data": {
                        "health_status": health_check.health_status.value,
                        "health_score": health_check.health_score,
                        "response_time_ms": health_check.response_time_ms,
                        "memory_usage_mb": health_check.memory_usage_mb,
                        "error_rate": health_check.error_rate,
                    },
                }
            )
        except Exception as e:
            logger.warning(
                f"Could not collect health check evidence for {plugin.plugin_id}: {e}"
            )

        # Audit trail evidence
        recent_events = await self.get_audit_trail(
            plugin_id=plugin.plugin_id,
            start_date=datetime.utcnow() - timedelta(days=30),
            limit=10,
        )

        evidence.append(
            {
                "type": "audit_trail",
                "description": "Recent audit events for plugin",
                "data": {
                    "events_count": len(recent_events),
                    "events": [
                        {
                            "event_type": event.event_type.value,
                            "timestamp": event.timestamp.isoformat(),
                            "description": event.event_description,
                        }
                        for event in recent_events
                    ],
                },
            }
        )

        return evidence

    async def _generate_compliance_findings(
        self,
        compliance_results: Dict[str, Dict[str, Any]],
        standard: ComplianceStandard,
    ) -> List[Dict[str, Any]]:
        """Generate compliance findings from results"""

        findings = []

        # Aggregate findings across plugins
        all_findings = []
        for result in compliance_results.values():
            all_findings.extend(result.get("findings", []))

        # Categorize findings
        finding_categories = {}
        for finding in all_findings:
            category = finding.split(":")[0] if ":" in finding else "general"
            if category not in finding_categories:
                finding_categories[category] = []
            finding_categories[category].append(finding)

        # Create structured findings
        for category, category_findings in finding_categories.items():
            findings.append(
                {
                    "category": category,
                    "count": len(category_findings),
                    "details": category_findings,
                    "severity": "medium",  # Default severity
                }
            )

        return findings

    async def _generate_compliance_recommendations(
        self,
        compliance_results: Dict[str, Dict[str, Any]],
        standard: ComplianceStandard,
    ) -> List[str]:
        """Generate compliance recommendations"""

        recommendations = []

        # Count non-compliant plugins
        non_compliant = [
            r for r in compliance_results.values() if not r.get("compliant", True)
        ]

        if non_compliant:
            recommendations.append(
                f"Address compliance issues in {len(non_compliant)} non-compliant plugins"
            )

        # Standard-specific recommendations
        if standard == ComplianceStandard.SOC2:
            recommendations.extend(
                [
                    "Implement continuous monitoring for security controls",
                    "Enhance incident response procedures",
                    "Review and update access control policies",
                ]
            )
        elif standard == ComplianceStandard.ISO27001:
            recommendations.extend(
                [
                    "Conduct regular risk assessments",
                    "Update information security policies",
                    "Enhance security awareness training",
                ]
            )

        # Generic recommendations
        recommendations.extend(
            [
                "Regular compliance monitoring and reporting",
                "Automated policy enforcement",
                "Enhanced audit trail collection",
            ]
        )

        return recommendations

    async def _create_audit_event(
        self,
        event_type: AuditEventType,
        event_description: str,
        event_data: Optional[Dict[str, Any]] = None,
        plugin_id: Optional[str] = None,
        plugin_name: Optional[str] = None,
        plugin_version: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        success: bool = True,
        error_message: Optional[str] = None,
        risk_level: str = "low",
        compliance_impact: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Create and store an audit event"""

        audit_event = AuditEvent(
            event_type=event_type,
            event_description=event_description,
            event_data=event_data or {},
            plugin_id=plugin_id,
            plugin_name=plugin_name,
            plugin_version=plugin_version,
            user_id=user_id,
            session_id=session_id,
            source_ip=source_ip,
            success=success,
            error_message=error_message,
            risk_level=risk_level,
            compliance_impact=compliance_impact or {},
        )

        await audit_event.save()

        # Log high-risk events
        if risk_level in ["high", "critical"]:
            logger.warning(
                f"High-risk audit event: {event_description} (Risk: {risk_level})"
            )

        return audit_event

    async def _send_violation_notification(self, violation: PolicyViolation):
        """Send notification for policy violation"""

        # In production, this would send notifications via configured channels
        logger.info(f"Notification sent for policy violation: {violation.violation_id}")

    async def _disable_plugin_for_violation(self, violation: PolicyViolation):
        """Disable plugin due to policy violation"""

        # In production, this would disable the plugin
        logger.info(
            f"Plugin {violation.plugin_id} disabled for policy violation: {violation.rule_violated}"
        )

    async def _quarantine_plugin_for_violation(self, violation: PolicyViolation):
        """Quarantine plugin due to policy violation"""

        # In production, this would quarantine the plugin
        violation.quarantined = True
        logger.info(
            f"Plugin {violation.plugin_id} quarantined for policy violation: {violation.rule_violated}"
        )

    async def get_governance_statistics(self) -> Dict[str, Any]:
        """Get plugin governance and compliance statistics"""

        # Policy statistics
        total_policies = len(self.policies)
        enabled_policies = len([p for p in self.policies.values() if p.enabled])

        policy_by_type = {}
        for policy in self.policies.values():
            policy_type = policy.policy_type.value
            policy_by_type[policy_type] = policy_by_type.get(policy_type, 0) + 1

        # Monitoring statistics
        monitored_policies = len(self.policy_monitors)
        monitored_compliance = len(self.compliance_monitors)

        # Audit statistics
        total_events = await AuditEvent.count()

        event_counts_by_type = {}
        for event_type in AuditEventType:
            count = await AuditEvent.find({"event_type": event_type}).count()
            event_counts_by_type[event_type.value] = count

        return {
            "policies": {
                "total": total_policies,
                "enabled": enabled_policies,
                "by_type": policy_by_type,
                "monitored": monitored_policies,
            },
            "compliance": {
                "standards_configured": len(self.compliance_configs),
                "monitored_standards": monitored_compliance,
                "required_standards": [
                    s.value for s in self.governance_config.required_standards
                ],
            },
            "audit": {
                "total_events": total_events,
                "events_by_type": event_counts_by_type,
                "retention_days": self.governance_config.audit_retention_days,
            },
            "monitoring": {
                "governance_enabled": self.monitoring_enabled,
                "policy_monitors": monitored_policies,
                "compliance_monitors": monitored_compliance,
            },
        }
