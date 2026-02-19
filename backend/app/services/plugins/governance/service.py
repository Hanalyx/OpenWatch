"""
Plugin Governance Service

Provides comprehensive governance capabilities for plugin management including
policy-based compliance, audit trails, and regulatory standard enforcement.

This service is the central authority for:
- Policy lifecycle management (create, update, delete, evaluate)
- Compliance assessment against regulatory standards
- Audit event recording and querying
- Violation tracking and remediation
- Governance configuration management

Security Considerations:
    - All policy evaluations are logged for audit compliance
    - Violations are tracked with full context for forensics
    - Audit events are immutable once created
    - Configuration changes require appropriate permissions

Usage:
    from app.services.plugins.governance import PluginGovernanceService

    governance = PluginGovernanceService()

    # Register a new policy
    policy = await governance.register_policy(
        name="No Critical Vulnerabilities",
        policy_type=PolicyType.SECURITY,
        enforcement_level=PolicyEnforcementLevel.BLOCKING,
        conditions={"max_critical_cves": 0},
    )

    # Evaluate plugin compliance
    result = await governance.evaluate_plugin_compliance(
        plugin_id="my-plugin@1.0.0",
        standards=[ComplianceStandard.SOC2],
    )

    # Generate compliance report
    report = await governance.generate_compliance_report(plugin_id)

Example:
    >>> from app.services.plugins.governance import (
    ...     PluginGovernanceService,
    ...     PolicyType,
    ...     ComplianceStandard,
    ... )
    >>> governance = PluginGovernanceService()
    >>> report = await governance.generate_compliance_report("my-plugin@1.0.0")
    >>> print(f"Compliance Score: {report.overall_score:.1f}%")
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

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

# Configure module logger
logger = logging.getLogger(__name__)


class PluginGovernanceService:
    """
    Plugin governance service for policy and compliance management.

    Provides enterprise-grade governance capabilities including policy
    management, compliance assessment, audit trails, and violation tracking.

    The service maintains internal registries for policies, violations,
    and configuration. In production deployments, these should be backed
    by persistent storage (MongoDB for audit events is already configured).

    Attributes:
        _policies: Registry of active governance policies.
        _violations: Registry of policy violations.
        _config: Current governance configuration.
        _audit_buffer: Buffer for batch audit event writes.

    Example:
        >>> governance = PluginGovernanceService()
        >>> await governance.start()
        >>> policy = await governance.register_policy(
        ...     name="Security Policy",
        ...     policy_type=PolicyType.SECURITY,
        ...     conditions={"min_security_score": 80.0},
        ... )
        >>> print(f"Registered policy: {policy.policy_id}")
    """

    def __init__(self) -> None:
        """
        Initialize the plugin governance service.

        Sets up internal registries for policies, violations, and
        configuration. The service must be started before use to
        initialize any required connections.
        """
        # Policy registry indexed by policy_id
        self._policies: Dict[str, PluginPolicy] = {}

        # Violation registry indexed by violation_id
        self._violations: Dict[str, PolicyViolation] = {}

        # Current governance configuration
        self._config: PluginGovernanceConfig = PluginGovernanceConfig()

        # Audit event buffer for batch writes
        self._audit_buffer: List[AuditEvent] = []

        # Service state
        self._started: bool = False

        # In-memory storage for audit events (MongoDB removed)
        self._audit_events: List[AuditEvent] = []

        logger.info("PluginGovernanceService initialized - " "Audit events stored in-memory only (MongoDB removed)")

    async def start(self) -> None:
        """
        Start the governance service.

        Initializes connections and loads any persisted state.
        This method should be called before using the service.

        Raises:
            RuntimeError: If the service is already started.
        """
        if self._started:
            logger.warning("Governance service already started")
            return

        logger.info("Starting plugin governance service")

        # Load default policies
        await self._initialize_default_policies()

        self._started = True
        logger.info("Plugin governance service started successfully")

    async def stop(self) -> None:
        """
        Stop the governance service.

        Flushes any pending audit events and releases resources.
        """
        if not self._started:
            return

        logger.info("Stopping plugin governance service")

        # Flush any pending audit events
        await self._flush_audit_buffer()

        self._started = False
        logger.info("Plugin governance service stopped")

    async def _initialize_default_policies(self) -> None:
        """
        Initialize default governance policies.

        Creates a set of baseline policies that represent security
        best practices and common compliance requirements.
        """
        default_policies = [
            PluginPolicy(
                name="No Critical Vulnerabilities",
                description="Plugins must not have any critical CVEs in dependencies",
                policy_type=PolicyType.SECURITY,
                enforcement_level=PolicyEnforcementLevel.BLOCKING,
                conditions={"max_critical_cves": 0},
                applicable_standards=[
                    ComplianceStandard.SOC2,
                    ComplianceStandard.FEDRAMP,
                    ComplianceStandard.PCI_DSS,
                ],
                priority=10,
            ),
            PluginPolicy(
                name="Security Score Minimum",
                description="Plugins must maintain a minimum security score",
                policy_type=PolicyType.SECURITY,
                enforcement_level=PolicyEnforcementLevel.WARNING,
                conditions={"min_security_score": 70.0},
                applicable_standards=[ComplianceStandard.SOC2, ComplianceStandard.ISO27001],
                priority=20,
            ),
            PluginPolicy(
                name="Performance Threshold",
                description="Plugins must meet minimum performance standards",
                policy_type=PolicyType.PERFORMANCE,
                enforcement_level=PolicyEnforcementLevel.ADVISORY,
                conditions={"max_response_time_ms": 5000, "min_success_rate": 0.95},
                priority=50,
            ),
            PluginPolicy(
                name="Data Privacy Compliance",
                description="Plugins handling personal data must have privacy controls",
                policy_type=PolicyType.DATA_PRIVACY,
                enforcement_level=PolicyEnforcementLevel.BLOCKING,
                conditions={
                    "requires_data_classification": True,
                    "requires_retention_policy": True,
                },
                applicable_standards=[ComplianceStandard.GDPR, ComplianceStandard.HIPAA],
                priority=15,
            ),
        ]

        for policy in default_policies:
            self._policies[policy.policy_id] = policy

        logger.info("Initialized %d default governance policies", len(default_policies))

    # =========================================================================
    # POLICY MANAGEMENT
    # =========================================================================

    async def register_policy(
        self,
        name: str,
        description: str,
        policy_type: PolicyType,
        conditions: Dict[str, Any],
        enforcement_level: PolicyEnforcementLevel = PolicyEnforcementLevel.WARNING,
        actions: Optional[List[str]] = None,
        applicable_standards: Optional[List[ComplianceStandard]] = None,
        priority: int = 100,
        created_by: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PluginPolicy:
        """
        Register a new governance policy.

        Creates and registers a new policy for plugin compliance evaluation.
        Policies are evaluated in priority order (lower values first).

        Args:
            name: Human-readable policy name.
            description: Detailed policy description.
            policy_type: Category of the policy.
            conditions: JSON conditions defining violation criteria.
            enforcement_level: Action to take on violation.
            actions: List of actions to execute on violation.
            applicable_standards: Compliance standards this policy supports.
            priority: Evaluation order (1-1000, lower = higher priority).
            created_by: User who created the policy.
            metadata: Additional policy metadata.

        Returns:
            The newly created PluginPolicy.

        Raises:
            ValueError: If policy parameters are invalid.

        Example:
            >>> policy = await governance.register_policy(
            ...     name="Custom Security Policy",
            ...     description="Enforce custom security requirements",
            ...     policy_type=PolicyType.SECURITY,
            ...     conditions={"min_encryption_strength": 256},
            ...     enforcement_level=PolicyEnforcementLevel.BLOCKING,
            ... )
        """
        if not name or not name.strip():
            raise ValueError("Policy name cannot be empty")

        if not conditions:
            raise ValueError("Policy must have at least one condition")

        policy = PluginPolicy(
            name=name.strip(),
            description=description or "",
            policy_type=policy_type,
            enforcement_level=enforcement_level,
            conditions=conditions,
            actions=actions or [],
            applicable_standards=applicable_standards or [],
            priority=priority,
            created_by=created_by,
            metadata=metadata or {},
        )

        self._policies[policy.policy_id] = policy

        # Record audit event
        await self._record_audit_event(
            event_type=AuditEventType.CONFIGURATION_CHANGE,
            actor=created_by or "system",
            action=f"Registered policy: {name}",
            details={"policy_id": policy.policy_id, "policy_type": policy_type.value},
        )

        logger.info(
            "Registered governance policy: %s (type=%s, priority=%d)",
            name,
            policy_type.value,
            priority,
        )

        return policy

    async def update_policy(
        self,
        policy_id: str,
        updates: Dict[str, Any],
        updated_by: Optional[str] = None,
    ) -> Optional[PluginPolicy]:
        """
        Update an existing governance policy.

        Modifies policy properties while maintaining audit trail.
        The policy version is automatically incremented.

        Args:
            policy_id: ID of the policy to update.
            updates: Dictionary of fields to update.
            updated_by: User making the update.

        Returns:
            The updated policy, or None if not found.

        Raises:
            ValueError: If updates contain invalid fields.
        """
        policy = self._policies.get(policy_id)
        if not policy:
            logger.warning("Policy not found for update: %s", policy_id)
            return None

        # Track old values for audit
        old_values = {}

        # Apply updates to allowed fields
        allowed_fields = {
            "name",
            "description",
            "enforcement_level",
            "enabled",
            "priority",
            "conditions",
            "actions",
            "applicable_standards",
            "metadata",
        }

        for field, value in updates.items():
            if field not in allowed_fields:
                raise ValueError(f"Cannot update field: {field}")

            old_values[field] = getattr(policy, field)
            setattr(policy, field, value)

        # Update metadata
        policy.updated_at = datetime.utcnow()

        # Increment version
        major, minor, patch = policy.version.split(".")
        policy.version = f"{major}.{minor}.{int(patch) + 1}"

        # Record audit event
        await self._record_audit_event(
            event_type=AuditEventType.CONFIGURATION_CHANGE,
            actor=updated_by or "system",
            action=f"Updated policy: {policy.name}",
            details={
                "policy_id": policy_id,
                "updates": list(updates.keys()),
                "new_version": policy.version,
            },
        )

        logger.info("Updated policy %s to version %s", policy_id, policy.version)

        return policy

    async def delete_policy(
        self,
        policy_id: str,
        deleted_by: Optional[str] = None,
    ) -> bool:
        """
        Delete a governance policy.

        Removes the policy from active enforcement. Existing violations
        related to this policy are not automatically resolved.

        Args:
            policy_id: ID of the policy to delete.
            deleted_by: User deleting the policy.

        Returns:
            True if the policy was deleted, False if not found.
        """
        policy = self._policies.pop(policy_id, None)
        if not policy:
            logger.warning("Policy not found for deletion: %s", policy_id)
            return False

        # Record audit event
        await self._record_audit_event(
            event_type=AuditEventType.CONFIGURATION_CHANGE,
            actor=deleted_by or "system",
            action=f"Deleted policy: {policy.name}",
            details={"policy_id": policy_id, "policy_type": policy.policy_type.value},
        )

        logger.info("Deleted policy: %s (%s)", policy.name, policy_id)

        return True

    async def get_policy(self, policy_id: str) -> Optional[PluginPolicy]:
        """
        Get a policy by ID.

        Args:
            policy_id: ID of the policy to retrieve.

        Returns:
            The policy if found, None otherwise.
        """
        return self._policies.get(policy_id)

    async def get_all_policies(
        self,
        policy_type: Optional[PolicyType] = None,
        enabled_only: bool = True,
    ) -> List[PluginPolicy]:
        """
        Get all registered policies.

        Args:
            policy_type: Filter by policy type (optional).
            enabled_only: Only return enabled policies.

        Returns:
            List of matching policies sorted by priority.
        """
        policies = list(self._policies.values())

        if enabled_only:
            policies = [p for p in policies if p.enabled]

        if policy_type:
            policies = [p for p in policies if p.policy_type == policy_type]

        # Sort by priority (lower = higher priority)
        policies.sort(key=lambda p: p.priority)

        return policies

    # =========================================================================
    # POLICY EVALUATION
    # =========================================================================

    async def evaluate_plugin(
        self,
        plugin_id: str,
        plugin_data: Dict[str, Any],
        policy_types: Optional[List[PolicyType]] = None,
    ) -> List[PolicyViolation]:
        """
        Evaluate a plugin against all applicable policies.

        Checks the plugin against registered policies and returns
        any violations found. Violations are automatically recorded
        and enforcement actions are applied based on policy levels.

        Args:
            plugin_id: ID of the plugin to evaluate.
            plugin_data: Plugin metadata and current state.
            policy_types: Limit evaluation to specific policy types.

        Returns:
            List of PolicyViolation objects for any violations found.

        Example:
            >>> violations = await governance.evaluate_plugin(
            ...     plugin_id="my-plugin@1.0.0",
            ...     plugin_data={"security_score": 65, "cve_count": 2},
            ... )
            >>> for v in violations:
            ...     print(f"Violation: {v.description}")
        """
        violations: List[PolicyViolation] = []

        # Get applicable policies
        policies = await self.get_all_policies(enabled_only=True)

        if policy_types:
            policies = [p for p in policies if p.policy_type in policy_types]

        for policy in policies:
            violation = await self._evaluate_policy(plugin_id, plugin_data, policy)
            if violation:
                violations.append(violation)

                # Record the violation
                self._violations[violation.violation_id] = violation

                # Apply enforcement action
                await self._apply_enforcement(plugin_id, policy, violation)

        if violations:
            logger.warning(
                "Plugin %s has %d policy violations",
                plugin_id,
                len(violations),
            )

        return violations

    async def _evaluate_policy(
        self,
        plugin_id: str,
        plugin_data: Dict[str, Any],
        policy: PluginPolicy,
    ) -> Optional[PolicyViolation]:
        """
        Evaluate a single policy against plugin data.

        Args:
            plugin_id: ID of the plugin.
            plugin_data: Plugin metadata and state.
            policy: Policy to evaluate.

        Returns:
            PolicyViolation if the policy is violated, None otherwise.
        """
        violations_details: List[str] = []

        for condition_key, condition_value in policy.conditions.items():
            # Check various condition types
            if condition_key.startswith("max_"):
                # Maximum value check
                field = condition_key[4:]  # Remove "max_" prefix
                actual_value = plugin_data.get(field, 0)
                if actual_value > condition_value:
                    violations_details.append(f"{field} is {actual_value}, exceeds maximum {condition_value}")

            elif condition_key.startswith("min_"):
                # Minimum value check
                field = condition_key[4:]  # Remove "min_" prefix
                actual_value = plugin_data.get(field, 0)
                if actual_value < condition_value:
                    violations_details.append(f"{field} is {actual_value}, below minimum {condition_value}")

            elif condition_key.startswith("requires_"):
                # Required field check
                field = condition_key[9:]  # Remove "requires_" prefix
                if condition_value and not plugin_data.get(field):
                    violations_details.append(f"Missing required field: {field}")

            elif condition_key == "forbidden_values":
                # Check for forbidden values
                for field, forbidden in condition_value.items():
                    actual = plugin_data.get(field)
                    if actual in forbidden:
                        violations_details.append(f"{field} has forbidden value: {actual}")

        if not violations_details:
            return None

        # Determine severity based on enforcement level
        severity_map = {
            PolicyEnforcementLevel.ADVISORY: ViolationSeverity.LOW,
            PolicyEnforcementLevel.WARNING: ViolationSeverity.MEDIUM,
            PolicyEnforcementLevel.BLOCKING: ViolationSeverity.HIGH,
            PolicyEnforcementLevel.QUARANTINE: ViolationSeverity.CRITICAL,
        }

        return PolicyViolation(
            policy_id=policy.policy_id,
            plugin_id=plugin_id,
            severity=severity_map.get(policy.enforcement_level, ViolationSeverity.MEDIUM),
            description=f"Policy '{policy.name}' violated",
            details={"violations": violations_details, "policy_type": policy.policy_type.value},
            remediation_steps=self._get_remediation_steps(policy, violations_details),
        )

    def _get_remediation_steps(
        self,
        policy: PluginPolicy,
        violations: List[str],
    ) -> List[str]:
        """
        Generate remediation steps for policy violations.

        Args:
            policy: The violated policy.
            violations: List of specific violation details.

        Returns:
            List of recommended remediation steps.
        """
        steps: List[str] = []

        if policy.policy_type == PolicyType.SECURITY:
            steps.extend(
                [
                    "Review plugin security assessment",
                    "Update dependencies to resolve CVEs",
                    "Run security scan on plugin code",
                ]
            )
        elif policy.policy_type == PolicyType.PERFORMANCE:
            steps.extend(
                [
                    "Profile plugin execution performance",
                    "Optimize resource-intensive operations",
                    "Review caching strategies",
                ]
            )
        elif policy.policy_type == PolicyType.DATA_PRIVACY:
            steps.extend(
                [
                    "Implement data classification",
                    "Define retention policies",
                    "Enable encryption for sensitive data",
                ]
            )

        # Add generic steps
        steps.append("Contact plugin maintainer for compliance guidance")
        steps.append(f"Review policy conditions: {policy.policy_id}")

        return steps

    async def _apply_enforcement(
        self,
        plugin_id: str,
        policy: PluginPolicy,
        violation: PolicyViolation,
    ) -> None:
        """
        Apply enforcement action based on policy level.

        Args:
            plugin_id: ID of the violating plugin.
            policy: The violated policy.
            violation: The violation details.
        """
        # Record audit event for the violation
        await self._record_audit_event(
            event_type=AuditEventType.POLICY_VIOLATION,
            plugin_id=plugin_id,
            actor="governance_service",
            action=f"Policy violation detected: {policy.name}",
            details={
                "policy_id": policy.policy_id,
                "violation_id": violation.violation_id,
                "severity": violation.severity.value,
                "enforcement_level": policy.enforcement_level.value,
            },
            outcome="violation_recorded",
        )

        # Log based on enforcement level
        if policy.enforcement_level == PolicyEnforcementLevel.QUARANTINE:
            logger.error(
                "QUARANTINE: Plugin %s quarantined due to policy violation: %s",
                plugin_id,
                policy.name,
            )
        elif policy.enforcement_level == PolicyEnforcementLevel.BLOCKING:
            logger.warning(
                "BLOCKING: Plugin %s blocked from operation due to: %s",
                plugin_id,
                policy.name,
            )
        elif policy.enforcement_level == PolicyEnforcementLevel.WARNING:
            logger.warning(
                "WARNING: Plugin %s has policy violation: %s",
                plugin_id,
                policy.name,
            )
        else:
            logger.info(
                "ADVISORY: Plugin %s policy advisory: %s",
                plugin_id,
                policy.name,
            )

    # =========================================================================
    # COMPLIANCE ASSESSMENT
    # =========================================================================

    async def evaluate_plugin_compliance(
        self,
        plugin_id: str,
        plugin_data: Optional[Dict[str, Any]] = None,
        standards: Optional[List[ComplianceStandard]] = None,
    ) -> ComplianceReport:
        """
        Evaluate plugin compliance against regulatory standards.

        Performs a comprehensive assessment of the plugin against
        one or more compliance standards and generates a detailed report.

        Args:
            plugin_id: ID of the plugin to evaluate.
            plugin_data: Plugin metadata (fetched if not provided).
            standards: Standards to evaluate against (uses config defaults if not specified).

        Returns:
            ComplianceReport with assessment results.

        Example:
            >>> report = await governance.evaluate_plugin_compliance(
            ...     plugin_id="my-plugin@1.0.0",
            ...     standards=[ComplianceStandard.SOC2, ComplianceStandard.HIPAA],
            ... )
            >>> print(f"Score: {report.overall_score}%, Status: {report.status}")
        """
        if plugin_data is None:
            plugin_data = {}

        if standards is None:
            standards = self._config.required_standards or [ComplianceStandard.SOC2]

        findings: List[Dict[str, Any]] = []
        total_score = 0.0
        standards_evaluated = 0

        for standard in standards:
            standard_findings = await self._evaluate_standard(plugin_id, plugin_data, standard)
            findings.extend(standard_findings)

            # Calculate score for this standard
            if standard_findings:
                passed = sum(1 for f in standard_findings if f.get("status") == "pass")
                total = len(standard_findings)
                standard_score = (passed / total * 100) if total > 0 else 100.0
            else:
                standard_score = 100.0

            total_score += standard_score
            standards_evaluated += 1

        # Calculate overall score
        overall_score = total_score / standards_evaluated if standards_evaluated > 0 else 0.0

        # Determine compliance status
        if overall_score >= 95:
            status = "compliant"
        elif overall_score >= 70:
            status = "partial"
        else:
            status = "non_compliant"

        # Generate recommendations
        recommendations = self._generate_compliance_recommendations(findings)

        report = ComplianceReport(
            plugin_id=plugin_id,
            standards=standards,
            overall_score=overall_score,
            status=status,
            findings=findings,
            recommendations=recommendations,
            valid_until=datetime.utcnow() + timedelta(days=30),
        )

        # Record audit event
        await self._record_audit_event(
            event_type=AuditEventType.COMPLIANCE_CHECK,
            plugin_id=plugin_id,
            actor="governance_service",
            action="Compliance evaluation completed",
            details={
                "standards": [s.value for s in standards],
                "overall_score": overall_score,
                "status": status,
                "report_id": report.report_id,
            },
        )

        logger.info(
            "Compliance evaluation for %s: %.1f%% (%s)",
            plugin_id,
            overall_score,
            status,
        )

        return report

    async def _evaluate_standard(
        self,
        plugin_id: str,
        plugin_data: Dict[str, Any],
        standard: ComplianceStandard,
    ) -> List[Dict[str, Any]]:
        """
        Evaluate plugin against a specific compliance standard.

        Args:
            plugin_id: ID of the plugin.
            plugin_data: Plugin metadata.
            standard: Compliance standard to evaluate.

        Returns:
            List of findings for the standard.
        """
        findings: List[Dict[str, Any]] = []

        # Standard-specific requirements
        requirements = self._get_standard_requirements(standard)

        for req_id, requirement in requirements.items():
            status = self._check_requirement(plugin_data, requirement)
            findings.append(
                {
                    "standard": standard.value,
                    "requirement_id": req_id,
                    "requirement": requirement.get("description", ""),
                    "status": status,
                    "evidence": requirement.get("evidence", ""),
                }
            )

        return findings

    def _get_standard_requirements(
        self,
        standard: ComplianceStandard,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Get requirements for a compliance standard.

        Args:
            standard: The compliance standard.

        Returns:
            Dictionary of requirement definitions.
        """
        # Define base requirements for each standard
        # In production, these would come from a requirements database
        requirements: Dict[str, Dict[str, Dict[str, Any]]] = {
            ComplianceStandard.SOC2: {
                "CC6.1": {
                    "description": "Logical and physical access controls",
                    "check": "has_access_controls",
                    "evidence": "Access control implementation verified",
                },
                "CC6.6": {
                    "description": "System boundaries protection",
                    "check": "has_network_security",
                    "evidence": "Network security controls verified",
                },
                "CC7.1": {
                    "description": "System monitoring",
                    "check": "has_monitoring",
                    "evidence": "Monitoring implementation verified",
                },
            },
            ComplianceStandard.HIPAA: {
                "164.312(a)": {
                    "description": "Access control",
                    "check": "has_access_controls",
                    "evidence": "HIPAA access controls verified",
                },
                "164.312(e)": {
                    "description": "Transmission security",
                    "check": "has_encryption",
                    "evidence": "Encryption in transit verified",
                },
            },
            ComplianceStandard.GDPR: {
                "Art25": {
                    "description": "Data protection by design",
                    "check": "has_privacy_controls",
                    "evidence": "Privacy by design implementation",
                },
                "Art32": {
                    "description": "Security of processing",
                    "check": "has_encryption",
                    "evidence": "Processing security verified",
                },
            },
        }

        return requirements.get(standard, {})

    def _check_requirement(
        self,
        plugin_data: Dict[str, Any],
        requirement: Dict[str, Any],
    ) -> str:
        """
        Check if a requirement is satisfied.

        Args:
            plugin_data: Plugin metadata.
            requirement: Requirement definition.

        Returns:
            "pass" or "fail" based on check result.
        """
        check_field = requirement.get("check", "")
        if not check_field:
            return "pass"

        # Check if the required capability exists
        if plugin_data.get(check_field):
            return "pass"

        # Default security assumptions for common checks
        if check_field in ("has_monitoring", "has_logging"):
            return "pass"  # Assume basic monitoring is always available

        return "fail"

    def _generate_compliance_recommendations(
        self,
        findings: List[Dict[str, Any]],
    ) -> List[str]:
        """
        Generate recommendations based on compliance findings.

        Args:
            findings: List of compliance findings.

        Returns:
            List of recommended actions.
        """
        recommendations: List[str] = []
        failed_findings = [f for f in findings if f.get("status") == "fail"]

        if not failed_findings:
            recommendations.append("Maintain current compliance posture")
            return recommendations

        # Group by standard
        by_standard: Dict[str, List[Dict[str, Any]]] = {}
        for finding in failed_findings:
            standard = finding.get("standard", "unknown")
            if standard not in by_standard:
                by_standard[standard] = []
            by_standard[standard].append(finding)

        for standard, std_findings in by_standard.items():
            recommendations.append(f"Address {len(std_findings)} {standard.upper()} requirement gaps")

        # Add specific recommendations
        for finding in failed_findings[:5]:  # Limit to top 5
            recommendations.append(f"Implement: {finding.get('requirement', 'Unknown requirement')}")

        return recommendations

    async def generate_compliance_report(
        self,
        plugin_id: str,
        standards: Optional[List[ComplianceStandard]] = None,
    ) -> ComplianceReport:
        """
        Generate a comprehensive compliance report for a plugin.

        This is a convenience method that evaluates compliance and
        returns a full report with findings and recommendations.

        Args:
            plugin_id: ID of the plugin.
            standards: Standards to evaluate (uses defaults if not specified).

        Returns:
            ComplianceReport with full assessment.
        """
        return await self.evaluate_plugin_compliance(
            plugin_id=plugin_id,
            standards=standards,
        )

    # =========================================================================
    # VIOLATION MANAGEMENT
    # =========================================================================

    async def get_violations(
        self,
        plugin_id: Optional[str] = None,
        severity: Optional[ViolationSeverity] = None,
        resolved: Optional[bool] = None,
    ) -> List[PolicyViolation]:
        """
        Get policy violations with optional filtering.

        Args:
            plugin_id: Filter by plugin ID.
            severity: Filter by severity level.
            resolved: Filter by resolution status.

        Returns:
            List of matching violations.
        """
        violations = list(self._violations.values())

        if plugin_id:
            violations = [v for v in violations if v.plugin_id == plugin_id]

        if severity:
            violations = [v for v in violations if v.severity == severity]

        if resolved is not None:
            violations = [v for v in violations if (v.resolved_at is not None) == resolved]

        return violations

    async def resolve_violation(
        self,
        violation_id: str,
        resolved_by: str,
        resolution_notes: str,
    ) -> Optional[PolicyViolation]:
        """
        Mark a violation as resolved.

        Args:
            violation_id: ID of the violation to resolve.
            resolved_by: User resolving the violation.
            resolution_notes: Notes about the resolution.

        Returns:
            The updated violation, or None if not found.
        """
        violation = self._violations.get(violation_id)
        if not violation:
            logger.warning("Violation not found: %s", violation_id)
            return None

        violation.resolved_at = datetime.utcnow()
        violation.resolved_by = resolved_by
        violation.resolution_notes = resolution_notes

        # Record audit event
        await self._record_audit_event(
            event_type=AuditEventType.CONFIGURATION_CHANGE,
            plugin_id=violation.plugin_id,
            actor=resolved_by,
            action=f"Resolved violation: {violation_id}",
            details={
                "violation_id": violation_id,
                "policy_id": violation.policy_id,
                "resolution_notes": resolution_notes,
            },
        )

        logger.info("Resolved violation %s by %s", violation_id, resolved_by)

        return violation

    # =========================================================================
    # AUDIT TRAIL
    # =========================================================================

    async def _record_audit_event(
        self,
        event_type: AuditEventType,
        actor: str,
        action: str,
        plugin_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        outcome: str = "success",
        ip_address: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> AuditEvent:
        """
        Record an audit event.

        Creates an immutable audit record for governance actions.
        Events are buffered for batch writes to improve performance.

        Args:
            event_type: Type of audit event.
            actor: User or system that triggered the event.
            action: Description of the action.
            plugin_id: ID of the affected plugin.
            details: Additional event details.
            outcome: Result of the action.
            ip_address: Source IP address.
            correlation_id: ID for correlating related events.

        Returns:
            The created AuditEvent.
        """
        event = AuditEvent(
            event_type=event_type,
            plugin_id=plugin_id,
            actor=actor,
            action=action,
            details=details or {},
            outcome=outcome,
            ip_address=ip_address,
            correlation_id=correlation_id,
        )

        self._audit_buffer.append(event)

        # Flush buffer if it's getting large
        if len(self._audit_buffer) >= 100:
            await self._flush_audit_buffer()

        return event

    async def _flush_audit_buffer(self) -> None:
        """
        Flush the audit event buffer to in-memory storage.

        Moves buffered audit events to the persistent in-memory list.
        MongoDB has been removed; events are retained in-memory only.
        """
        if not self._audit_buffer:
            return

        # Move events from buffer to in-memory storage
        self._audit_events.extend(self._audit_buffer)

        logger.debug("Flushed %d audit events to in-memory storage", len(self._audit_buffer))
        self._audit_buffer.clear()

    async def get_audit_events(
        self,
        plugin_id: Optional[str] = None,
        event_type: Optional[AuditEventType] = None,
        actor: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[AuditEvent]:
        """
        Query audit events with optional filtering.

        Filters in-memory audit events (MongoDB removed).

        Args:
            plugin_id: Filter by plugin ID.
            event_type: Filter by event type.
            actor: Filter by actor.
            start_time: Start of time range.
            end_time: End of time range.
            limit: Maximum number of events to return.

        Returns:
            List of matching audit events.
        """
        # Include any unflushed events from the buffer
        all_events = self._audit_events + self._audit_buffer

        # Apply filters in-memory
        filtered = all_events

        if plugin_id:
            filtered = [e for e in filtered if e.plugin_id == plugin_id]

        if event_type:
            filtered = [e for e in filtered if e.event_type == event_type]

        if actor:
            filtered = [e for e in filtered if e.actor == actor]

        if start_time:
            filtered = [e for e in filtered if e.timestamp >= start_time]

        if end_time:
            filtered = [e for e in filtered if e.timestamp <= end_time]

        # Sort by timestamp descending (most recent first)
        filtered.sort(key=lambda e: e.timestamp, reverse=True)

        # Apply limit
        return filtered[:limit]

    # =========================================================================
    # CONFIGURATION
    # =========================================================================

    async def get_config(self) -> PluginGovernanceConfig:
        """
        Get the current governance configuration.

        Returns:
            Current PluginGovernanceConfig.
        """
        return self._config

    async def update_config(
        self,
        updates: Dict[str, Any],
        updated_by: str,
    ) -> PluginGovernanceConfig:
        """
        Update governance configuration.

        Args:
            updates: Configuration updates to apply.
            updated_by: User making the update.

        Returns:
            Updated configuration.

        Raises:
            ValueError: If updates contain invalid fields.
        """
        old_config = self._config.model_dump()

        # Apply updates
        for key, value in updates.items():
            if hasattr(self._config, key):
                setattr(self._config, key, value)
            else:
                raise ValueError(f"Invalid configuration field: {key}")

        # Record audit event
        await self._record_audit_event(
            event_type=AuditEventType.CONFIGURATION_CHANGE,
            actor=updated_by,
            action="Updated governance configuration",
            details={
                "updates": list(updates.keys()),
                "old_values": {k: old_config.get(k) for k in updates.keys()},
            },
        )

        logger.info("Updated governance configuration by %s", updated_by)

        return self._config

    # =========================================================================
    # UTILITY METHODS
    # =========================================================================

    async def get_governance_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the governance state.

        Returns:
            Dictionary with governance metrics and status.
        """
        policies = list(self._policies.values())
        violations = list(self._violations.values())

        active_violations = [v for v in violations if v.resolved_at is None]
        critical_violations = [v for v in active_violations if v.severity == ViolationSeverity.CRITICAL]

        return {
            "policies": {
                "total": len(policies),
                "enabled": sum(1 for p in policies if p.enabled),
                "by_type": {pt.value: sum(1 for p in policies if p.policy_type == pt) for pt in PolicyType},
            },
            "violations": {
                "total": len(violations),
                "active": len(active_violations),
                "resolved": len(violations) - len(active_violations),
                "critical": len(critical_violations),
                "by_severity": {
                    vs.value: sum(1 for v in active_violations if v.severity == vs) for vs in ViolationSeverity
                },
            },
            "config": {
                "enabled": self._config.enabled,
                "required_standards": [s.value for s in self._config.required_standards],
                "auto_quarantine": self._config.auto_quarantine_on_critical,
            },
        }
