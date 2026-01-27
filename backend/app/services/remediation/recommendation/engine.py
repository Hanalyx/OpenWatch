"""
OpenWatch Remediation Recommendation Engine
Generates structured remediation recommendations for ORSA-compatible systems

This engine analyzes compliance gaps and provides detailed remediation guidance
that external systems can consume via the OpenWatch Remediation System Adapter (ORSA)
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional

from backend.app.models.unified_rule_models import (
    ComplianceStatus,
    FrameworkMapping,
    PlatformImplementation,
    RuleExecution,
    UnifiedComplianceRule,
)
from backend.app.services.multi_framework_scanner import FrameworkResult, HostResult, ScanResult


# Simplified ORSA models for PR #12 implementation
class RemediationSystemCapability(str, Enum):
    """Remediation system capabilities"""

    CONFIGURATION_MANAGEMENT = "config_mgmt"
    PACKAGE_MANAGEMENT = "pkg_mgmt"
    SECURITY_HARDENING = "sec_hardening"
    COMPLIANCE_REMEDIATION = "compliance"
    CUSTOM_SCRIPTING = "scripting"


@dataclass
class RemediationRule:
    """ORSA-compatible remediation rule"""

    semantic_name: str
    title: str
    description: str
    category: str
    severity: str
    tags: List[str] = field(default_factory=list)
    framework_mappings: Dict[str, Dict[str, str]] = field(default_factory=dict)
    implementations: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    reversible: bool = False
    requires_reboot: bool = False
    prerequisites: List[str] = field(default_factory=list)
    side_effects: List[str] = field(default_factory=list)


@dataclass
class RemediationJob:
    """ORSA-compatible remediation job"""

    target_host_id: str
    platform: str
    rules: List[str]
    framework: Optional[str] = None
    dry_run: bool = True
    timeout: int = 1800
    parallel_execution: bool = False
    openwatch_context: Dict[str, Any] = field(default_factory=dict)


logger = logging.getLogger(__name__)


# ============================================================================
# Core Data Models for Remediation Recommendations
# ============================================================================


class RemediationPriority(str, Enum):
    """Priority levels for remediation recommendations"""

    CRITICAL = "critical"  # Immediate security risks
    HIGH = "high"  # Significant compliance gaps
    MEDIUM = "medium"  # Standard compliance issues
    LOW = "low"  # Minor improvements
    INFORMATIONAL = "info"  # Best practice suggestions


class RemediationComplexity(str, Enum):
    """Complexity levels for remediation procedures"""

    TRIVIAL = "trivial"  # Single command/setting
    SIMPLE = "simple"  # Multiple steps, low risk
    MODERATE = "moderate"  # Requires planning, medium risk
    COMPLEX = "complex"  # Significant changes, high risk
    EXPERT = "expert"  # Requires specialized knowledge


class RemediationCategory(str, Enum):
    """Categories of remediation procedures"""

    CONFIGURATION = "configuration"  # Config file changes
    PACKAGE_MANAGEMENT = "packages"  # Software install/remove
    SERVICE_MANAGEMENT = "services"  # Service start/stop/enable
    FIREWALL_RULES = "firewall"  # Network access controls
    FILE_PERMISSIONS = "permissions"  # File/directory permissions
    USER_MANAGEMENT = "users"  # User/group management
    REGISTRY_CHANGES = "registry"  # Windows registry (future)
    CUSTOM_SCRIPTS = "scripts"  # Custom remediation scripts


@dataclass
class RemediationStep:
    """Single step in a remediation procedure"""

    step_number: int
    action: str
    command: str
    description: str
    expected_result: str = ""
    error_handling: str = ""
    rollback_command: Optional[str] = None


@dataclass
class ComplianceGap:
    """Represents a compliance gap that needs remediation"""

    gap_id: str
    rule_id: str
    framework_id: str
    control_id: str
    host_id: str

    # Gap description
    title: str
    description: str
    current_status: ComplianceStatus
    expected_status: ComplianceStatus

    # Impact assessment
    priority: RemediationPriority
    risk_level: str
    business_impact: str
    security_implications: List[str]

    # Technical details
    platform: str
    failed_checks: List[str] = field(default_factory=list)
    error_details: Optional[str] = None
    last_scan_time: datetime = field(default_factory=datetime.utcnow)

    # Framework context
    regulatory_requirements: List[str] = field(default_factory=list)
    compliance_deadline: Optional[datetime] = None


@dataclass
class RemediationProcedure:
    """Detailed remediation procedure for a specific platform/framework"""

    procedure_id: str
    title: str
    description: str
    category: RemediationCategory
    complexity: RemediationComplexity

    # Platform/framework specifics
    platform: str
    framework_id: str
    rule_id: str

    # Implementation steps
    pre_conditions: List[str] = field(default_factory=list)
    steps: List[Dict[str, Any]] = field(default_factory=list)
    post_validation: List[str] = field(default_factory=list)
    rollback_steps: List[str] = field(default_factory=list)

    # Execution metadata
    estimated_time_minutes: int = 5
    requires_reboot: bool = False
    backup_recommended: bool = True
    rollback_available: bool = True

    # Risk assessment
    risk_level: str = "low"
    potential_side_effects: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)

    # Framework-specific procedure text
    stig_fix_text: Optional[str] = None
    cis_remediation_procedure: Optional[str] = None
    nist_implementation_guidance: Optional[str] = None
    custom_procedure_text: Optional[str] = None


@dataclass
class RemediationRecommendation:
    """Complete remediation recommendation with all necessary data for ORSA systems"""

    recommendation_id: str
    compliance_gap: ComplianceGap

    # Primary remediation approach
    primary_procedure: RemediationProcedure
    alternative_procedures: List[RemediationProcedure] = field(default_factory=list)

    # ORSA integration data
    orsa_compatible_rules: List[RemediationRule] = field(default_factory=list)
    remediation_job_template: Optional[RemediationJob] = None

    # Analysis and context
    root_cause_analysis: str = ""
    business_justification: str = ""
    compliance_benefit: str = ""

    # Implementation guidance
    recommended_approach: str = ""
    testing_recommendations: List[str] = field(default_factory=list)
    monitoring_recommendations: List[str] = field(default_factory=list)

    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    confidence_score: float = 0.8  # 0.0 to 1.0
    framework_citations: List[str] = field(default_factory=list)
    related_controls: List[str] = field(default_factory=list)


# ============================================================================
# Remediation Recommendation Engine
# ============================================================================


class RemediationRecommendationEngine:
    """
    Generates structured remediation recommendations for ORSA-compatible systems

    This engine analyzes compliance gaps from scan results and provides detailed
    remediation guidance that external systems can consume and execute.
    """

    def __init__(self):
        self.recommendation_cache: Dict[str, RemediationRecommendation] = {}
        self.procedure_library: Dict[str, Dict[str, RemediationProcedure]] = {}
        self.framework_mappings: Dict[str, Dict[str, Any]] = {}

        # Initialize built-in procedures and mappings
        self._initialize_procedure_library()
        self._initialize_framework_mappings()

        logger.info("Remediation Recommendation Engine initialized")

    async def analyze_compliance_gaps(
        self,
        scan_result: ScanResult,
        unified_rules: Dict[str, UnifiedComplianceRule],
        target_frameworks: Optional[List[str]] = None,
    ) -> List[ComplianceGap]:
        """
        Analyze scan results to identify compliance gaps requiring remediation

        Args:
            scan_result: Results from compliance scanning
            unified_rules: Available unified compliance rules
            target_frameworks: Specific frameworks to analyze (optional)

        Returns:
            List of identified compliance gaps
        """
        logger.info(f"Analyzing compliance gaps for scan {scan_result.scan_id}")

        compliance_gaps = []

        for host_result in scan_result.host_results:
            host_gaps = await self._analyze_host_compliance_gaps(host_result, unified_rules, target_frameworks)
            compliance_gaps.extend(host_gaps)

        # Sort by priority (critical first)
        priority_order = {
            RemediationPriority.CRITICAL: 0,
            RemediationPriority.HIGH: 1,
            RemediationPriority.MEDIUM: 2,
            RemediationPriority.LOW: 3,
            RemediationPriority.INFORMATIONAL: 4,
        }

        compliance_gaps.sort(key=lambda gap: priority_order.get(gap.priority, 999))

        logger.info(f"Identified {len(compliance_gaps)} compliance gaps")
        return compliance_gaps

    async def generate_remediation_recommendations(
        self,
        compliance_gaps: List[ComplianceGap],
        unified_rules: Dict[str, UnifiedComplianceRule],
        orsa_capabilities: Optional[List[RemediationSystemCapability]] = None,
    ) -> List[RemediationRecommendation]:
        """
        Generate comprehensive remediation recommendations for compliance gaps

        Args:
            compliance_gaps: Identified compliance gaps
            unified_rules: Available unified compliance rules
            orsa_capabilities: Available ORSA system capabilities (optional)

        Returns:
            List of detailed remediation recommendations
        """
        logger.info(f"Generating remediation recommendations for {len(compliance_gaps)} gaps")

        recommendations = []

        for gap in compliance_gaps:
            try:
                recommendation = await self._generate_single_recommendation(gap, unified_rules, orsa_capabilities)
                if recommendation:
                    recommendations.append(recommendation)
            except Exception as e:
                logger.error(f"Failed to generate recommendation for gap {gap.gap_id}: {e}")
                continue

        logger.info(f"Generated {len(recommendations)} remediation recommendations")
        return recommendations

    async def map_to_orsa_format(
        self, recommendations: List[RemediationRecommendation]
    ) -> Dict[str, List[RemediationRule]]:
        """
        Map remediation recommendations to ORSA-compatible format

        Args:
            recommendations: Generated remediation recommendations

        Returns:
            Dictionary mapping platform -> list of ORSA RemediationRules
        """
        logger.info(f"Mapping {len(recommendations)} recommendations to ORSA format")

        orsa_rules_by_platform = {}

        for recommendation in recommendations:
            platform = recommendation.compliance_gap.platform

            if platform not in orsa_rules_by_platform:
                orsa_rules_by_platform[platform] = []

            # Convert primary procedure to ORSA rule
            orsa_rule = await self._convert_procedure_to_orsa_rule(
                recommendation.primary_procedure, recommendation.compliance_gap
            )

            if orsa_rule:
                orsa_rules_by_platform[platform].append(orsa_rule)

            # Add alternative procedures as separate rules
            for alt_procedure in recommendation.alternative_procedures:
                alt_orsa_rule = await self._convert_procedure_to_orsa_rule(
                    alt_procedure, recommendation.compliance_gap, is_alternative=True
                )
                if alt_orsa_rule:
                    orsa_rules_by_platform[platform].append(alt_orsa_rule)

        total_rules = sum(len(rules) for rules in orsa_rules_by_platform.values())
        logger.info(f"Mapped to {total_rules} ORSA rules across {len(orsa_rules_by_platform)} platforms")

        return orsa_rules_by_platform

    async def get_framework_specific_procedures(
        self, framework_id: str, control_id: str, platform: str
    ) -> List[RemediationProcedure]:
        """
        Get framework-specific remediation procedures

        Args:
            framework_id: Target compliance framework
            control_id: Specific control identifier
            platform: Target platform

        Returns:
            List of relevant remediation procedures
        """
        cache_key = f"{framework_id}:{control_id}:{platform}"

        if cache_key in self.procedure_library:
            return list(self.procedure_library[cache_key].values())

        procedures = await self._load_framework_procedures(framework_id, control_id, platform)

        # Cache for future use
        if cache_key not in self.procedure_library:
            self.procedure_library[cache_key] = {}

        for procedure in procedures:
            self.procedure_library[cache_key][procedure.procedure_id] = procedure

        return procedures

    async def create_remediation_job_template(
        self,
        recommendation: RemediationRecommendation,
        target_host_id: str,
        dry_run: bool = True,
    ) -> RemediationJob:
        """
        Create ORSA-compatible remediation job template

        Args:
            recommendation: Remediation recommendation
            target_host_id: Target host for remediation
            dry_run: Whether to create as dry-run job

        Returns:
            ORSA RemediationJob template
        """
        gap = recommendation.compliance_gap
        procedure = recommendation.primary_procedure

        # Create job template
        job_template = RemediationJob(
            target_host_id=target_host_id,
            platform=gap.platform,
            rules=[procedure.rule_id],
            framework=gap.framework_id,
            dry_run=dry_run,
            timeout=procedure.estimated_time_minutes * 60,  # Convert to seconds
            parallel_execution=False,  # Conservative approach
            openwatch_context={
                "scan_id": "template",
                "compliance_gap_id": gap.gap_id,
                "recommendation_id": recommendation.recommendation_id,
                "framework_id": gap.framework_id,
                "control_id": gap.control_id,
                "priority": gap.priority.value,
                "complexity": procedure.complexity.value,
                "requires_reboot": procedure.requires_reboot,
                "backup_recommended": procedure.backup_recommended,
            },
        )

        return job_template

    # Private implementation methods

    async def _analyze_host_compliance_gaps(
        self,
        host_result: HostResult,
        unified_rules: Dict[str, UnifiedComplianceRule],
        target_frameworks: Optional[List[str]] = None,
    ) -> List[ComplianceGap]:
        """Analyze compliance gaps for a single host"""
        gaps = []

        for framework_result in host_result.framework_results:
            if target_frameworks and framework_result.framework_id not in target_frameworks:
                continue

            framework_gaps = await self._analyze_framework_gaps(framework_result, host_result, unified_rules)
            gaps.extend(framework_gaps)

        return gaps

    async def _analyze_framework_gaps(
        self,
        framework_result: FrameworkResult,
        host_result: HostResult,
        unified_rules: Dict[str, UnifiedComplianceRule],
    ) -> List[ComplianceGap]:
        """Analyze compliance gaps for a specific framework"""
        gaps = []

        for rule_execution in framework_result.rule_executions:
            if rule_execution.compliance_status in [
                ComplianceStatus.NON_COMPLIANT,
                ComplianceStatus.PARTIAL,
                ComplianceStatus.ERROR,
            ]:
                gap = await self._create_compliance_gap(rule_execution, framework_result, host_result, unified_rules)
                if gap:
                    gaps.append(gap)

        return gaps

    async def _create_compliance_gap(
        self,
        rule_execution: RuleExecution,
        framework_result: FrameworkResult,
        host_result: HostResult,
        unified_rules: Dict[str, UnifiedComplianceRule],
    ) -> Optional[ComplianceGap]:
        """Create a compliance gap from failed rule execution"""
        unified_rule = unified_rules.get(rule_execution.rule_id)
        if not unified_rule:
            logger.warning(f"No unified rule found for {rule_execution.rule_id}")
            return None

        # Find framework mapping for this specific framework
        framework_mapping = None
        for mapping in unified_rule.framework_mappings:
            if mapping.framework_id == framework_result.framework_id:
                framework_mapping = mapping
                break

        if not framework_mapping:
            logger.warning(f"No framework mapping found for {framework_result.framework_id}")
            return None

        # Determine priority based on rule risk level and compliance status
        priority = self._calculate_remediation_priority(
            unified_rule.risk_level,
            rule_execution.compliance_status,
            unified_rule.security_function,
        )

        # Extract failed checks and error details
        failed_checks = []
        if rule_execution.output_data:
            failed_checks = rule_execution.output_data.get("failed_checks", [])

        gap = ComplianceGap(
            gap_id=f"GAP-{framework_result.framework_id}-{rule_execution.rule_id}-{host_result.host_id}-{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",  # noqa: E501
            rule_id=rule_execution.rule_id,
            framework_id=framework_result.framework_id,
            control_id=(framework_mapping.control_ids[0] if framework_mapping.control_ids else "unknown"),
            host_id=host_result.host_id,
            title=unified_rule.title,
            description=unified_rule.description,
            current_status=rule_execution.compliance_status,
            expected_status=ComplianceStatus.COMPLIANT,
            priority=priority,
            risk_level=unified_rule.risk_level,
            business_impact=self._assess_business_impact(unified_rule, rule_execution),
            security_implications=self._assess_security_implications(unified_rule, rule_execution),
            platform=host_result.platform_info.get("platform", "unknown"),
            failed_checks=failed_checks,
            error_details=rule_execution.error_message,
            last_scan_time=rule_execution.executed_at or datetime.utcnow(),
            regulatory_requirements=self._get_regulatory_requirements(framework_result.framework_id),
            compliance_deadline=self._calculate_compliance_deadline(priority, unified_rule.risk_level),
        )

        return gap

    async def _generate_single_recommendation(
        self,
        gap: ComplianceGap,
        unified_rules: Dict[str, UnifiedComplianceRule],
        orsa_capabilities: Optional[List[RemediationSystemCapability]] = None,
    ) -> Optional[RemediationRecommendation]:
        """Generate a single remediation recommendation"""
        unified_rule = unified_rules.get(gap.rule_id)
        if not unified_rule:
            return None

        # Get primary remediation procedure
        primary_procedure = await self._create_remediation_procedure(gap, unified_rule, is_primary=True)

        if not primary_procedure:
            logger.warning(f"Could not create primary procedure for gap {gap.gap_id}")
            return None

        # Get alternative procedures
        alternative_procedures = await self._get_alternative_procedures(gap, unified_rule, orsa_capabilities)

        # Create ORSA-compatible rules
        orsa_rules = await self._create_orsa_compatible_rules(primary_procedure, alternative_procedures, gap)

        # Create remediation job template
        job_template = await self.create_remediation_job_template(
            RemediationRecommendation(
                recommendation_id="temp",
                compliance_gap=gap,
                primary_procedure=primary_procedure,
            ),
            gap.host_id,
        )

        recommendation = RemediationRecommendation(
            recommendation_id=f"REC-{gap.framework_id}-{gap.rule_id}-{gap.host_id}-{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",  # noqa: E501
            compliance_gap=gap,
            primary_procedure=primary_procedure,
            alternative_procedures=alternative_procedures,
            orsa_compatible_rules=orsa_rules,
            remediation_job_template=job_template,
            root_cause_analysis=await self._analyze_root_cause(gap, unified_rule),
            business_justification=await self._generate_business_justification(gap, unified_rule),
            compliance_benefit=await self._generate_compliance_benefit(gap, unified_rule),
            recommended_approach=await self._generate_recommended_approach(primary_procedure, gap),
            testing_recommendations=await self._generate_testing_recommendations(primary_procedure),
            monitoring_recommendations=await self._generate_monitoring_recommendations(unified_rule, gap),
            confidence_score=self._calculate_confidence_score(gap, primary_procedure),
            framework_citations=self._get_framework_citations(gap.framework_id),
            related_controls=await self._find_related_controls(gap, unified_rules),
        )

        return recommendation

    async def _create_remediation_procedure(
        self,
        gap: ComplianceGap,
        unified_rule: UnifiedComplianceRule,
        is_primary: bool = True,
    ) -> Optional[RemediationProcedure]:
        """Create a detailed remediation procedure"""

        # Find platform implementation
        platform_impl = None
        for impl in unified_rule.platform_implementations:
            if impl.platform.value.lower() == gap.platform.lower():
                platform_impl = impl
                break

        if not platform_impl and unified_rule.platform_implementations:
            # Use the first available implementation as fallback
            platform_impl = unified_rule.platform_implementations[0]

        if not platform_impl:
            logger.warning(f"No platform implementation found for {gap.rule_id} on {gap.platform}")
            return None

        # Get framework-specific procedure text
        framework_mapping = None
        for mapping in unified_rule.framework_mappings:
            if mapping.framework_id == gap.framework_id:
                framework_mapping = mapping
                break

        # Create remediation steps from platform implementation
        steps = self._create_remediation_steps(platform_impl, gap)

        # Determine complexity based on steps and risk
        complexity = self._determine_complexity(steps, unified_rule.risk_level, platform_impl)

        procedure = RemediationProcedure(
            procedure_id=f"PROC-{gap.rule_id}-{gap.platform}-{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            title=f"Remediate {unified_rule.title} on {gap.platform}",
            description=unified_rule.description,
            category=self._determine_category(platform_impl),
            complexity=complexity,
            platform=gap.platform,
            framework_id=gap.framework_id,
            rule_id=gap.rule_id,
            pre_conditions=self._generate_pre_conditions(platform_impl, unified_rule),
            steps=steps,
            post_validation=self._generate_post_validation(platform_impl),
            rollback_steps=self._generate_rollback_steps(platform_impl, steps),
            estimated_time_minutes=self._estimate_execution_time(steps, complexity),
            requires_reboot=self._requires_reboot(platform_impl, steps),
            backup_recommended=True,  # Always recommend backup
            rollback_available=True,  # Most procedures can be rolled back
            risk_level=unified_rule.risk_level,
            potential_side_effects=self._identify_side_effects(platform_impl, unified_rule),
            prerequisites=self._generate_prerequisites(platform_impl),
            stig_fix_text=self._get_stig_fix_text(gap.framework_id, framework_mapping),
            cis_remediation_procedure=self._get_cis_procedure(gap.framework_id, framework_mapping),
            nist_implementation_guidance=self._get_nist_guidance(gap.framework_id, framework_mapping),
            custom_procedure_text=(framework_mapping.justification if framework_mapping else None),
        )

        return procedure

    def _initialize_procedure_library(self):
        """Initialize built-in procedure library"""
        self.procedure_library = {
            "session_timeout": {
                "rhel": RemediationProcedure(
                    procedure_id="session_timeout_rhel",
                    title="Configure Session Timeout",
                    description="Set automatic session timeout to prevent unauthorized access",
                    category=RemediationCategory.CONFIGURATION,
                    complexity=RemediationComplexity.SIMPLE,
                    platform="rhel",
                    framework_id="nist_800_53_r5",
                    rule_id="session_timeout_001",
                    steps=[
                        {
                            "step": 1,
                            "action": "create_tmout_config",
                            "command": "echo 'TMOUT=900' >> /etc/profile.d/tmout.sh",
                            "description": "Create session timeout configuration",
                        },
                        {
                            "step": 2,
                            "action": "set_permissions",
                            "command": "chmod 644 /etc/profile.d/tmout.sh",
                            "description": "Set appropriate permissions",
                        },
                    ],
                    post_validation=["grep TMOUT /etc/profile.d/tmout.sh"],
                    estimated_time_minutes=2,
                )
            }
        }

    def _initialize_framework_mappings(self):
        """Initialize framework-specific mappings"""
        self.framework_mappings = {
            "nist_800_53_r5": {
                "citations": ["NIST SP 800-53 Rev 5", "FISMA"],
                "deadline_days": 90,
            },
            "cis_v8": {
                "citations": ["CIS Critical Security Controls Version 8"],
                "deadline_days": 60,
            },
            "stig_rhel9": {
                "citations": ["DISA STIG for RHEL 9", "DoD Instruction 8500.01"],
                "deadline_days": 30,
            },
            "iso_27001_2022": {
                "citations": ["ISO/IEC 27001:2022"],
                "deadline_days": 120,
            },
            "pci_dss_v4": {"citations": ["PCI DSS v4.0"], "deadline_days": 45},
        }

    # Helper methods for analysis and generation

    def _calculate_remediation_priority(
        self,
        risk_level: str,
        compliance_status: ComplianceStatus,
        security_function: str,
    ) -> RemediationPriority:
        """Calculate remediation priority based on multiple factors"""
        if risk_level == "critical":
            return RemediationPriority.CRITICAL
        elif risk_level == "high":
            if compliance_status == ComplianceStatus.NON_COMPLIANT:
                return RemediationPriority.HIGH
            else:
                return RemediationPriority.MEDIUM
        elif risk_level == "medium":
            if compliance_status == ComplianceStatus.NON_COMPLIANT:
                return RemediationPriority.MEDIUM
            else:
                return RemediationPriority.LOW
        else:
            return RemediationPriority.LOW

    def _assess_business_impact(self, unified_rule: UnifiedComplianceRule, rule_execution: RuleExecution) -> str:
        """Assess business impact of the compliance gap"""
        risk_impact = {
            "critical": "Severe business disruption risk, potential regulatory violations",
            "high": "Significant business impact, compliance audit findings likely",
            "medium": "Moderate business risk, may affect compliance certification",
            "low": "Minimal business impact, routine compliance maintenance",
        }

        return risk_impact.get(unified_rule.risk_level, "Unknown business impact")

    def _assess_security_implications(
        self, unified_rule: UnifiedComplianceRule, rule_execution: RuleExecution
    ) -> List[str]:
        """Assess security implications of the compliance gap"""
        implications = []

        if unified_rule.security_function == "prevention":
            implications.append("Preventive security controls not active")
            implications.append("Increased vulnerability to security incidents")
        elif unified_rule.security_function == "detection":
            implications.append("Reduced visibility into security events")
            implications.append("Delayed incident response capabilities")
        elif unified_rule.security_function == "response":
            implications.append("Compromised incident response procedures")
            implications.append("Potential for extended security incidents")

        if unified_rule.risk_level in ["critical", "high"]:
            implications.append("Immediate security attention required")

        return implications

    def _get_regulatory_requirements(self, framework_id: str) -> List[str]:
        """Get regulatory requirements for framework"""
        return self.framework_mappings.get(framework_id, {}).get("citations", [])

    def _calculate_compliance_deadline(self, priority: RemediationPriority, risk_level: str) -> Optional[datetime]:
        """Calculate compliance deadline based on priority and risk"""
        deadline_days = {
            RemediationPriority.CRITICAL: 7,
            RemediationPriority.HIGH: 30,
            RemediationPriority.MEDIUM: 60,
            RemediationPriority.LOW: 90,
            RemediationPriority.INFORMATIONAL: 180,
        }

        days = deadline_days.get(priority, 90)
        if risk_level == "critical":
            days = min(days, 3)  # Critical risk = max 3 days

        return datetime.utcnow() + timedelta(days=days)

    def _create_remediation_steps(
        self, platform_impl: PlatformImplementation, gap: ComplianceGap
    ) -> List[Dict[str, Any]]:
        """Create detailed remediation steps"""
        steps = []

        for i, command in enumerate(platform_impl.commands, 1):
            steps.append(
                {
                    "step": i,
                    "action": f"execute_command_{i}",
                    "command": command,
                    "description": f"Execute remediation command {i}",
                    "expected_result": "Command completes successfully",
                    "error_handling": "Check command exit code and output",
                }
            )

        return steps

    def _determine_complexity(
        self,
        steps: List[Dict[str, Any]],
        risk_level: str,
        platform_impl: PlatformImplementation,
    ) -> RemediationComplexity:
        """Determine procedure complexity"""
        if len(steps) == 1 and not platform_impl.services_affected:
            return RemediationComplexity.TRIVIAL
        elif len(steps) <= 3 and risk_level in ["low", "medium"]:
            return RemediationComplexity.SIMPLE
        elif len(steps) <= 5 and risk_level != "critical":
            return RemediationComplexity.MODERATE
        elif len(steps) > 5 or risk_level == "critical":
            return RemediationComplexity.COMPLEX
        else:
            return RemediationComplexity.EXPERT

    def _determine_category(self, platform_impl: PlatformImplementation) -> RemediationCategory:
        """Determine remediation category from implementation"""
        if platform_impl.implementation_type == "package":
            return RemediationCategory.PACKAGE_MANAGEMENT
        elif platform_impl.implementation_type == "service":
            return RemediationCategory.SERVICE_MANAGEMENT
        elif platform_impl.files_modified:
            return RemediationCategory.CONFIGURATION
        else:
            return RemediationCategory.CONFIGURATION

    async def _convert_procedure_to_orsa_rule(
        self,
        procedure: RemediationProcedure,
        gap: ComplianceGap,
        is_alternative: bool = False,
    ) -> Optional[RemediationRule]:
        """Convert remediation procedure to ORSA-compatible rule"""

        semantic_name = f"ow-{gap.rule_id.replace('_', '-')}"
        if is_alternative:
            semantic_name += f"-alt-{procedure.procedure_id[-8:]}"

        # Create framework mappings
        framework_mappings = {gap.framework_id: {gap.platform: gap.control_id}}

        # Create implementations dict
        implementations = {
            gap.platform: {
                "category": procedure.category.value,
                "complexity": procedure.complexity.value,
                "steps": procedure.steps,
                "estimated_time": procedure.estimated_time_minutes,
                "requires_reboot": procedure.requires_reboot,
                "rollback_available": procedure.rollback_available,
            }
        }

        orsa_rule = RemediationRule(
            semantic_name=semantic_name,
            title=procedure.title,
            description=procedure.description,
            category=procedure.category.value,
            severity=gap.priority.value,
            tags=[gap.framework_id, procedure.category.value, gap.rule_id],
            framework_mappings=framework_mappings,
            implementations=implementations,
            reversible=procedure.rollback_available,
            requires_reboot=procedure.requires_reboot,
            prerequisites=procedure.prerequisites,
            side_effects=procedure.potential_side_effects,
        )

        return orsa_rule

    # Additional helper methods would continue here...
    # For brevity, including key methods that complete the core functionality

    async def _load_framework_procedures(
        self, framework_id: str, control_id: str, platform: str
    ) -> List[RemediationProcedure]:
        """Load framework-specific procedures (placeholder for future expansion)"""
        return []

    async def _get_alternative_procedures(
        self,
        gap: ComplianceGap,
        unified_rule: UnifiedComplianceRule,
        orsa_capabilities: Optional[List[RemediationSystemCapability]] = None,
    ) -> List[RemediationProcedure]:
        """Get alternative remediation procedures"""
        return []  # Placeholder for future implementation

    async def _create_orsa_compatible_rules(
        self,
        primary_procedure: RemediationProcedure,
        alternative_procedures: List[RemediationProcedure],
        gap: ComplianceGap,
    ) -> List[RemediationRule]:
        """Create ORSA-compatible rules from procedures"""
        rules = []

        # Convert primary procedure
        primary_rule = await self._convert_procedure_to_orsa_rule(primary_procedure, gap)
        if primary_rule:
            rules.append(primary_rule)

        # Convert alternative procedures
        for alt_procedure in alternative_procedures:
            alt_rule = await self._convert_procedure_to_orsa_rule(alt_procedure, gap, is_alternative=True)
            if alt_rule:
                rules.append(alt_rule)

        return rules

    # Placeholder methods for additional functionality
    async def _analyze_root_cause(self, gap: ComplianceGap, unified_rule: UnifiedComplianceRule) -> str:
        return f"Root cause analysis for {gap.title} - requires detailed implementation"

    async def _generate_business_justification(self, gap: ComplianceGap, unified_rule: UnifiedComplianceRule) -> str:
        return f"Business justification for remediating {gap.title}"

    async def _generate_compliance_benefit(self, gap: ComplianceGap, unified_rule: UnifiedComplianceRule) -> str:
        return f"Compliance benefit of addressing {gap.title}"

    async def _generate_recommended_approach(self, procedure: RemediationProcedure, gap: ComplianceGap) -> str:
        return f"Recommended approach: Execute {procedure.title} with {procedure.complexity.value} complexity"

    async def _generate_testing_recommendations(self, procedure: RemediationProcedure) -> List[str]:
        return [
            "Test in non-production environment",
            "Verify rollback procedures",
            "Monitor system performance",
        ]

    async def _generate_monitoring_recommendations(
        self, unified_rule: UnifiedComplianceRule, gap: ComplianceGap
    ) -> List[str]:
        return [
            "Set up continuous compliance monitoring",
            "Configure alerting for configuration drift",
        ]

    def _calculate_confidence_score(self, gap: ComplianceGap, procedure: RemediationProcedure) -> float:
        score = 0.5  # Base score

        if procedure.complexity in [
            RemediationComplexity.TRIVIAL,
            RemediationComplexity.SIMPLE,
        ]:
            score += 0.2

        if gap.priority in [RemediationPriority.HIGH, RemediationPriority.CRITICAL]:
            score += 0.1

        if procedure.rollback_available:
            score += 0.2

        return min(score, 1.0)

    def _get_framework_citations(self, framework_id: str) -> List[str]:
        return self.framework_mappings.get(framework_id, {}).get("citations", [])

    async def _find_related_controls(
        self, gap: ComplianceGap, unified_rules: Dict[str, UnifiedComplianceRule]
    ) -> List[str]:
        related = []

        for rule_id, rule in unified_rules.items():
            if rule_id != gap.rule_id and rule.category == unified_rules[gap.rule_id].category:
                for mapping in rule.framework_mappings:
                    if mapping.framework_id == gap.framework_id:
                        related.extend(mapping.control_ids)
                        break

        return list(set(related))[:5]  # Limit to 5 related controls

    # Additional helper methods for step generation
    def _generate_pre_conditions(
        self, platform_impl: PlatformImplementation, unified_rule: UnifiedComplianceRule
    ) -> List[str]:
        conditions = ["System backup completed", "Administrative privileges available"]

        if platform_impl.services_affected:
            conditions.append("Services can be safely restarted")

        return conditions

    def _generate_post_validation(self, platform_impl: PlatformImplementation) -> List[str]:
        validation = []

        for cmd in platform_impl.validation_commands:
            validation.append(cmd)

        if not validation:
            validation.append("Verify configuration changes applied successfully")

        return validation

    def _generate_rollback_steps(self, platform_impl: PlatformImplementation, steps: List[Dict[str, Any]]) -> List[str]:
        rollback = []

        # Generate reverse operations for file modifications
        for file_path in platform_impl.files_modified:
            rollback.append(f"Restore backup of {file_path}")

        # Generate service restart if services affected
        for service in platform_impl.services_affected:
            rollback.append(f"Restart service: {service}")

        if not rollback:
            rollback.append("Reverse configuration changes if needed")

        return rollback

    def _estimate_execution_time(self, steps: List[Dict[str, Any]], complexity: RemediationComplexity) -> int:
        base_time = len(steps) * 2  # 2 minutes per step

        complexity_multiplier = {
            RemediationComplexity.TRIVIAL: 0.5,
            RemediationComplexity.SIMPLE: 1.0,
            RemediationComplexity.MODERATE: 1.5,
            RemediationComplexity.COMPLEX: 2.0,
            RemediationComplexity.EXPERT: 3.0,
        }

        return int(base_time * complexity_multiplier.get(complexity, 1.0))

    def _requires_reboot(self, platform_impl: PlatformImplementation, steps: List[Dict[str, Any]]) -> bool:
        # Check if any services that typically require reboot are affected
        reboot_services = ["kernel", "systemd", "init"]

        for service in platform_impl.services_affected:
            if any(reboot_svc in service.lower() for reboot_svc in reboot_services):
                return True

        # Check if any commands suggest reboot requirement
        for step in steps:
            command = step.get("command", "").lower()
            if "reboot" in command or "restart" in command:
                return True

        return False

    def _identify_side_effects(
        self, platform_impl: PlatformImplementation, unified_rule: UnifiedComplianceRule
    ) -> List[str]:
        effects = []

        if platform_impl.services_affected:
            effects.append(f"Services may restart: {', '.join(platform_impl.services_affected)}")

        if unified_rule.risk_level in ["high", "critical"]:
            effects.append("May impact system performance")

        if platform_impl.files_modified:
            effects.append("Configuration files will be modified")

        return effects

    def _generate_prerequisites(self, platform_impl: PlatformImplementation) -> List[str]:
        prereqs = ["Administrative privileges", "Network connectivity"]

        if platform_impl.services_affected:
            prereqs.append("Ability to restart services")

        return prereqs

    def _get_stig_fix_text(self, framework_id: str, framework_mapping: Optional[FrameworkMapping]) -> Optional[str]:
        if framework_id.startswith("stig") and framework_mapping:
            return framework_mapping.justification
        return None

    def _get_cis_procedure(self, framework_id: str, framework_mapping: Optional[FrameworkMapping]) -> Optional[str]:
        if framework_id.startswith("cis") and framework_mapping:
            return framework_mapping.justification
        return None

    def _get_nist_guidance(self, framework_id: str, framework_mapping: Optional[FrameworkMapping]) -> Optional[str]:
        if framework_id.startswith("nist") and framework_mapping:
            return framework_mapping.justification
        return None

    def clear_cache(self):
        """Clear recommendation cache"""
        self.recommendation_cache.clear()
        logger.info("Remediation recommendation cache cleared")
