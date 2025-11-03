"""
Compliance Justification Engine
Generates detailed justifications for compliance status and audit documentation
"""

import asyncio
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import json
import logging

from backend.app.models.unified_rule_models import (
    UnifiedComplianceRule,
    RuleExecution,
    ComplianceStatus,
    Platform,
)
from backend.app.services.multi_framework_scanner import (
    ScanResult,
    FrameworkResult,
    HostResult,
)
from backend.app.services.framework_mapping_engine import (
    ControlMapping,
    MappingType,
    MappingConfidence,
)


class JustificationType(str, Enum):
    """Types of compliance justifications"""

    COMPLIANT = "compliant"  # Standard compliance
    EXCEEDS = "exceeds"  # Exceeds baseline requirements
    PARTIAL = "partial"  # Partial compliance with plan
    NOT_APPLICABLE = "not_applicable"  # Control not applicable
    COMPENSATING = "compensating"  # Alternative control implementation
    RISK_ACCEPTED = "risk_accepted"  # Documented risk acceptance
    EXCEPTION_GRANTED = "exception_granted"  # Formal exception
    REMEDIATION_PLANNED = "remediation_planned"  # Fix scheduled


class AuditEvidence(str, Enum):
    """Types of audit evidence"""

    TECHNICAL = "technical"  # Technical implementation evidence
    POLICY = "policy"  # Policy documentation
    PROCEDURAL = "procedural"  # Process documentation
    COMPENSATING = "compensating"  # Alternative controls
    MONITORING = "monitoring"  # Continuous monitoring evidence
    TRAINING = "training"  # Training/awareness evidence
    VENDOR = "vendor"  # Third-party attestations


@dataclass
class JustificationEvidence:
    """Evidence supporting a compliance justification"""

    evidence_type: AuditEvidence
    description: str
    source: str
    timestamp: datetime
    evidence_data: Dict[str, Any]
    verification_method: str
    confidence_level: str  # high, medium, low
    evidence_path: Optional[str] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


@dataclass
class ComplianceJustification:
    """Comprehensive compliance justification"""

    justification_id: str
    rule_id: str
    framework_id: str
    control_id: str
    host_id: str
    justification_type: JustificationType
    compliance_status: ComplianceStatus

    # Core justification
    summary: str
    detailed_explanation: str
    implementation_description: str

    # Evidence
    evidence: List[JustificationEvidence]
    technical_details: Dict[str, Any]

    # Risk and business context
    risk_assessment: str
    business_justification: str
    impact_analysis: str

    # Enhancement and exceeding scenarios
    enhancement_details: Optional[str] = None
    baseline_comparison: Optional[str] = None
    exceeding_rationale: Optional[str] = None

    # Compliance metadata
    auditor_notes: List[str] = None
    regulatory_citations: List[str] = None
    standards_references: List[str] = None

    # Lifecycle
    created_at: datetime = None
    last_updated: datetime = None
    next_review_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        if self.last_updated is None:
            self.last_updated = datetime.utcnow()
        if self.auditor_notes is None:
            self.auditor_notes = []
        if self.regulatory_citations is None:
            self.regulatory_citations = []
        if self.standards_references is None:
            self.standards_references = []


@dataclass
class ExceedingComplianceAnalysis:
    """Analysis of how implementation exceeds baseline requirements"""

    baseline_requirement: str
    actual_implementation: str
    enhancement_level: str  # minimal, moderate, significant, exceptional
    security_benefits: List[str]
    compliance_value: str
    additional_frameworks_satisfied: List[str]
    business_value_statement: str
    audit_advantage: str


class ComplianceJustificationEngine:
    """Engine for generating detailed compliance justifications and audit documentation"""

    def __init__(self):
        """Initialize the compliance justification engine"""
        self.justification_cache: Dict[str, ComplianceJustification] = {}
        self.template_library: Dict[str, Dict] = {}
        self.regulatory_mappings: Dict[str, List[str]] = {}

        # Load common templates and patterns
        self._initialize_templates()
        self._initialize_regulatory_mappings()

    def _initialize_templates(self):
        """Initialize justification templates for common scenarios"""
        self.template_library = {
            "session_timeout": {
                "summary_template": "Session timeout configured to {timeout} minutes on {platform}",
                "implementation_template": "Implemented via {method} with automatic enforcement",
                "risk_mitigation": "Prevents unauthorized access to unattended sessions",
                "business_value": "Reduces security exposure window and meets regulatory requirements",
            },
            "fips_cryptography": {
                "summary_template": "FIPS {mode} cryptographic mode enabled on {platform}",
                "implementation_template": "System-wide FIPS compliance enforced at kernel level",
                "exceeding_rationale": "FIPS mode automatically disables weak algorithms including {disabled_algs}",
                "security_enhancement": "Provides cryptographic protection beyond baseline requirements",
            },
            "access_control": {
                "summary_template": "Access control implemented via {mechanism} with {enforcement_level} enforcement",
                "implementation_template": "Role-based access control with principle of least privilege",
                "audit_benefits": "Comprehensive audit trail and automated access reviews",
            },
            "patch_management": {
                "summary_template": "Automated patch management with {frequency} update schedule",
                "implementation_template": "Centralized patch deployment with testing and rollback capabilities",
                "risk_reduction": "Systematic vulnerability remediation within {sla} timeframe",
            },
        }

    def _initialize_regulatory_mappings(self):
        """Initialize mappings to regulatory citations"""
        self.regulatory_mappings = {
            "nist_800_53_r5": [
                "NIST SP 800-53 Rev 5",
                "Federal Information Security Modernization Act (FISMA)",
                "OMB Circular A-130",
            ],
            "cis_v8": [
                "CIS Critical Security Controls Version 8",
                "SANS Top 20 Critical Security Controls",
            ],
            "iso_27001_2022": [
                "ISO/IEC 27001:2022",
                "ISO/IEC 27002:2022 Code of Practice",
                "EU GDPR (where applicable)",
            ],
            "pci_dss_v4": [
                "PCI DSS v4.0",
                "Payment Card Industry Security Standards Council",
                "PCI PIN Security Requirements",
            ],
            "stig_rhel9": [
                "DISA Security Technical Implementation Guide (STIG)",
                "DoD Instruction 8500.01",
                "NIST SP 800-53 (DoD baseline)",
            ],
        }

    async def generate_justification(
        self,
        rule_execution: RuleExecution,
        unified_rule: UnifiedComplianceRule,
        framework_id: str,
        control_id: str,
        host_id: str,
        platform_info: Dict[str, Any],
        context_data: Optional[Dict[str, Any]] = None,
    ) -> ComplianceJustification:
        """Generate comprehensive compliance justification"""

        # Determine justification type based on compliance status
        justification_type = self._determine_justification_type(rule_execution.compliance_status)

        # Generate unique justification ID
        justification_id = f"JUST-{framework_id}-{control_id}-{host_id}-{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

        # Build technical evidence
        evidence = await self._generate_technical_evidence(
            rule_execution, unified_rule, platform_info
        )

        # Generate core justification text
        summary, detailed_explanation, implementation_description = (
            await self._generate_justification_text(
                unified_rule, rule_execution, framework_id, platform_info, context_data
            )
        )

        # Analyze enhancement/exceeding scenarios
        enhancement_analysis = None
        if rule_execution.compliance_status == ComplianceStatus.EXCEEDS:
            enhancement_analysis = await self._analyze_exceeding_compliance(
                unified_rule, framework_id, control_id, context_data
            )

        # Build comprehensive justification
        justification = ComplianceJustification(
            justification_id=justification_id,
            rule_id=unified_rule.rule_id,
            framework_id=framework_id,
            control_id=control_id,
            host_id=host_id,
            justification_type=justification_type,
            compliance_status=rule_execution.compliance_status,
            # Core justification
            summary=summary,
            detailed_explanation=detailed_explanation,
            implementation_description=implementation_description,
            # Evidence
            evidence=evidence,
            technical_details=self._extract_technical_details(rule_execution, unified_rule),
            # Risk and business context
            risk_assessment=await self._generate_risk_assessment(unified_rule, rule_execution),
            business_justification=await self._generate_business_justification(
                unified_rule, framework_id
            ),
            impact_analysis=await self._generate_impact_analysis(unified_rule, rule_execution),
            # Enhancement details for exceeding compliance
            enhancement_details=(
                enhancement_analysis.enhancement_level if enhancement_analysis else None
            ),
            baseline_comparison=(
                enhancement_analysis.baseline_requirement if enhancement_analysis else None
            ),
            exceeding_rationale=(
                enhancement_analysis.audit_advantage if enhancement_analysis else None
            ),
            # Regulatory context
            regulatory_citations=self.regulatory_mappings.get(framework_id, []),
            standards_references=self._get_standards_references(unified_rule, framework_id),
        )

        # Cache the justification
        self.justification_cache[justification_id] = justification

        return justification

    def _determine_justification_type(
        self, compliance_status: ComplianceStatus
    ) -> JustificationType:
        """Determine appropriate justification type"""
        status_mapping = {
            ComplianceStatus.COMPLIANT: JustificationType.COMPLIANT,
            ComplianceStatus.EXCEEDS: JustificationType.EXCEEDS,
            ComplianceStatus.PARTIAL: JustificationType.PARTIAL,
            ComplianceStatus.NOT_APPLICABLE: JustificationType.NOT_APPLICABLE,
            ComplianceStatus.NON_COMPLIANT: JustificationType.REMEDIATION_PLANNED,
            ComplianceStatus.ERROR: JustificationType.REMEDIATION_PLANNED,
        }
        return status_mapping.get(compliance_status, JustificationType.REMEDIATION_PLANNED)

    async def _generate_technical_evidence(
        self,
        rule_execution: RuleExecution,
        unified_rule: UnifiedComplianceRule,
        platform_info: Dict[str, Any],
    ) -> List[JustificationEvidence]:
        """Generate technical evidence for the compliance justification"""
        evidence = []

        # Execution evidence
        if rule_execution.output_data:
            execution_evidence = JustificationEvidence(
                evidence_type=AuditEvidence.TECHNICAL,
                description=f"Rule execution output for {unified_rule.rule_id}",
                source="OpenWatch Scanner",
                timestamp=rule_execution.executed_at,
                evidence_data={
                    "execution_output": rule_execution.output_data,
                    "execution_time": rule_execution.execution_time,
                    "execution_success": rule_execution.execution_success,
                },
                verification_method="Automated technical scanning",
                confidence_level=("high" if rule_execution.execution_success else "medium"),
            )
            evidence.append(execution_evidence)

        # Platform evidence
        platform_evidence = JustificationEvidence(
            evidence_type=AuditEvidence.TECHNICAL,
            description=f"Platform configuration for {platform_info.get('platform', 'unknown')}",
            source="Platform Detection Service",
            timestamp=datetime.utcnow(),
            evidence_data=platform_info,
            verification_method="Automated platform detection",
            confidence_level="high",
        )
        evidence.append(platform_evidence)

        # Implementation evidence
        if unified_rule.platform_implementations:
            for platform_impl in unified_rule.platform_implementations:
                impl_evidence = JustificationEvidence(
                    evidence_type=AuditEvidence.TECHNICAL,
                    description=f"Implementation details for {platform_impl.platform.value}",
                    source="Unified Rule Definition",
                    timestamp=datetime.utcnow(),
                    evidence_data={
                        "implementation_type": platform_impl.implementation_type,
                        "commands": platform_impl.commands,
                        "files_modified": platform_impl.files_modified,
                        "services_affected": platform_impl.services_affected,
                        "validation_commands": platform_impl.validation_commands,
                    },
                    verification_method="Technical specification review",
                    confidence_level="high",
                )
                evidence.append(impl_evidence)

        return evidence

    async def _generate_justification_text(
        self,
        unified_rule: UnifiedComplianceRule,
        rule_execution: RuleExecution,
        framework_id: str,
        platform_info: Dict[str, Any],
        context_data: Optional[Dict[str, Any]],
    ) -> Tuple[str, str, str]:
        """Generate justification text components"""

        # Use template if available
        rule_category = unified_rule.category.lower().replace(" ", "_")
        template = self.template_library.get(rule_category, {})

        # Generate summary
        if "summary_template" in template:
            summary = template["summary_template"].format(
                platform=platform_info.get("platform", "system"),
                **rule_execution.output_data if rule_execution.output_data else {},
            )
        else:
            summary = (
                f"{unified_rule.title} implemented on {platform_info.get('platform', 'system')}"
            )

        # Generate detailed explanation
        detailed_explanation = f"""
Implementation of {unified_rule.title} for {framework_id} compliance on {platform_info.get('platform', 'target system')}.

Rule Description: {unified_rule.description}

Security Function: {unified_rule.security_function.title()} control designed to {self._get_security_purpose(unified_rule.security_function)}.

Risk Level: {unified_rule.risk_level.title()} - This control addresses {self._get_risk_description(unified_rule.risk_level)} security risks.

Compliance Status: {rule_execution.compliance_status.value.replace('_', ' ').title()}
        """.strip()

        # Generate implementation description
        if rule_execution.compliance_status == ComplianceStatus.COMPLIANT:
            implementation_description = f"""
The control has been successfully implemented and validated on the target system. 
Technical verification confirms that the implementation meets the required security objectives.

Execution Time: {rule_execution.execution_time:.3f} seconds
Validation Method: {self._get_validation_method(unified_rule)}
            """.strip()
        elif rule_execution.compliance_status == ComplianceStatus.EXCEEDS:
            implementation_description = f"""
The implementation exceeds the baseline requirements for this control.
The enhanced configuration provides additional security benefits beyond the minimum standard.

Execution Time: {rule_execution.execution_time:.3f} seconds
Enhancement Level: Above baseline requirements
Validation Method: {self._get_validation_method(unified_rule)}
            """.strip()
        else:
            implementation_description = f"""
The control implementation requires attention or remediation.
Current status: {rule_execution.compliance_status.value.replace('_', ' ').title()}

{rule_execution.error_message if rule_execution.error_message else 'See technical details for specific requirements.'}

Execution Time: {rule_execution.execution_time:.3f} seconds
            """.strip()

        return summary, detailed_explanation, implementation_description

    async def _analyze_exceeding_compliance(
        self,
        unified_rule: UnifiedComplianceRule,
        framework_id: str,
        control_id: str,
        context_data: Optional[Dict[str, Any]],
    ) -> ExceedingComplianceAnalysis:
        """Analyze how implementation exceeds baseline requirements"""

        # Find the framework mapping for this control
        framework_mapping = None
        for mapping in unified_rule.framework_mappings:
            if mapping.framework_id == framework_id and control_id in mapping.control_ids:
                framework_mapping = mapping
                break

        # Extract enhancement details
        enhancement_details = framework_mapping.enhancement_details if framework_mapping else ""
        justification = framework_mapping.justification if framework_mapping else ""

        # Determine enhancement level
        enhancement_level = "moderate"
        if (
            "significantly" in enhancement_details.lower()
            or "substantially" in enhancement_details.lower()
        ):
            enhancement_level = "significant"
        elif (
            "exceptionally" in enhancement_details.lower()
            or "far exceeds" in enhancement_details.lower()
        ):
            enhancement_level = "exceptional"
        elif "minimal" in enhancement_details.lower() or "slightly" in enhancement_details.lower():
            enhancement_level = "minimal"

        # Generate security benefits
        security_benefits = []
        if "fips" in enhancement_details.lower():
            security_benefits.extend(
                [
                    "NIST-approved cryptographic algorithms",
                    "Automatic disabling of weak ciphers",
                    "Enhanced key management",
                ]
            )
        if "timeout" in enhancement_details.lower():
            security_benefits.extend(
                [
                    "Reduced exposure window for unattended sessions",
                    "Improved access control enforcement",
                ]
            )
        if "encryption" in enhancement_details.lower():
            security_benefits.extend(
                [
                    "Data protection at rest and in transit",
                    "Compliance with cryptographic standards",
                ]
            )

        # Additional frameworks that benefit
        additional_frameworks = []
        for mapping in unified_rule.framework_mappings:
            if mapping.framework_id != framework_id and mapping.implementation_status in [
                "compliant",
                "exceeds",
            ]:
                additional_frameworks.append(mapping.framework_id)

        return ExceedingComplianceAnalysis(
            baseline_requirement=f"{framework_id} {control_id} baseline requirement",
            actual_implementation=enhancement_details or "Enhanced implementation",
            enhancement_level=enhancement_level,
            security_benefits=security_benefits,
            compliance_value=f"Exceeds {framework_id} baseline by implementing {enhancement_details}",
            additional_frameworks_satisfied=additional_frameworks,
            business_value_statement=f"Single implementation satisfies {len(additional_frameworks) + 1} framework requirements",
            audit_advantage="Demonstrates commitment to security excellence beyond minimum compliance",
        )

    async def _generate_risk_assessment(
        self, unified_rule: UnifiedComplianceRule, rule_execution: RuleExecution
    ) -> str:
        """Generate risk assessment for the control"""

        base_risk = f"This {unified_rule.risk_level} risk control addresses {unified_rule.security_function} requirements."

        if rule_execution.compliance_status == ComplianceStatus.COMPLIANT:
            return f"{base_risk} Risk is effectively mitigated through proper implementation."
        elif rule_execution.compliance_status == ComplianceStatus.EXCEEDS:
            return f"{base_risk} Risk mitigation exceeds baseline requirements, providing enhanced protection."
        elif rule_execution.compliance_status == ComplianceStatus.PARTIAL:
            return f"{base_risk} Partial implementation provides some risk reduction but requires completion."
        else:
            return f"{base_risk} Current non-compliance poses security risk requiring immediate attention."

    async def _generate_business_justification(
        self, unified_rule: UnifiedComplianceRule, framework_id: str
    ) -> str:
        """Generate business justification for the control"""

        framework_purpose = {
            "nist_800_53_r5": "federal compliance and cybersecurity framework adherence",
            "cis_v8": "industry best practices and cyber defense",
            "iso_27001_2022": "information security management and international standards",
            "pci_dss_v4": "payment card data protection and regulatory compliance",
            "stig_rhel9": "DoD security requirements and government standards",
        }

        purpose = framework_purpose.get(
            framework_id, "regulatory compliance and security best practices"
        )

        return f"""
Implementation of {unified_rule.title} supports {purpose}.
This control contributes to the organization's overall security posture and regulatory compliance objectives.
The {unified_rule.security_function} capability provided by this control is essential for maintaining 
security standards and meeting audit requirements.
        """.strip()

    async def _generate_impact_analysis(
        self, unified_rule: UnifiedComplianceRule, rule_execution: RuleExecution
    ) -> str:
        """Generate impact analysis for the control implementation"""

        if rule_execution.compliance_status in [
            ComplianceStatus.COMPLIANT,
            ComplianceStatus.EXCEEDS,
        ]:
            return f"""
Positive Impact: Successfully implemented {unified_rule.security_function} control.
- Security posture improved through {unified_rule.category} measures
- Compliance requirements met for audit purposes  
- Risk reduction achieved at {unified_rule.risk_level} level
- No negative operational impact identified
            """.strip()
        else:
            return f"""
Current Impact: {unified_rule.security_function.title()} control requires attention.
- Security gap exists in {unified_rule.category} area
- Compliance objective not fully met
- Risk level: {unified_rule.risk_level}
- Remediation needed to achieve compliance
            """.strip()

    def _extract_technical_details(
        self, rule_execution: RuleExecution, unified_rule: UnifiedComplianceRule
    ) -> Dict[str, Any]:
        """Extract technical details for documentation"""
        return {
            "rule_id": unified_rule.rule_id,
            "rule_type": "unified_compliance_rule",
            "category": unified_rule.category,
            "security_function": unified_rule.security_function,
            "risk_level": unified_rule.risk_level,
            "execution_time": rule_execution.execution_time,
            "execution_success": rule_execution.execution_success,
            "compliance_status": rule_execution.compliance_status.value,
            "output_summary": (
                str(rule_execution.output_data)[:500] if rule_execution.output_data else None
            ),
            "error_details": rule_execution.error_message,
            "platform_count": len(unified_rule.platform_implementations),
            "framework_count": len(unified_rule.framework_mappings),
        }

    def _get_standards_references(
        self, unified_rule: UnifiedComplianceRule, framework_id: str
    ) -> List[str]:
        """Get relevant standards references"""
        references = []

        # Add framework-specific standards
        framework_standards = {
            "nist_800_53_r5": ["NIST Cybersecurity Framework", "FISMA", "FedRAMP"],
            "cis_v8": ["CIS Critical Security Controls", "SANS Top 20"],
            "iso_27001_2022": ["ISO 27001", "ISO 27002", "ISO 27005"],
            "pci_dss_v4": ["PCI DSS", "PA-DSS", "PCI PIN"],
            "stig_rhel9": ["DISA STIG", "DoD 8500", "CNSSI-1253"],
        }

        references.extend(framework_standards.get(framework_id, []))

        # Add category-specific standards
        category_standards = {
            "access_control": ["NIST SP 800-162", "ISO 27002:2022 A.9"],
            "cryptography": ["FIPS 140-2", "NIST SP 800-57", "RFC 3647"],
            "audit_logging": ["NIST SP 800-92", "ISO 27002:2022 A.12.4"],
            "system_configuration": ["NIST SP 800-123", "CIS Benchmarks"],
        }

        category = unified_rule.category.lower().replace(" ", "_")
        references.extend(category_standards.get(category, []))

        return list(set(references))  # Remove duplicates

    def _get_security_purpose(self, security_function: str) -> str:
        """Get description of security function purpose"""
        purposes = {
            "prevention": "prevent security incidents and unauthorized activities",
            "detection": "identify and alert on potential security threats",
            "response": "respond to and contain security incidents",
            "recovery": "restore operations after security incidents",
            "protection": "protect assets and data from security threats",
            "monitoring": "continuously monitor security status and compliance",
        }
        return purposes.get(security_function.lower(), "maintain security and compliance")

    def _get_risk_description(self, risk_level: str) -> str:
        """Get description of risk level"""
        descriptions = {
            "low": "routine operational",
            "medium": "moderate business impact",
            "high": "significant organizational",
            "critical": "severe enterprise-wide",
        }
        return descriptions.get(risk_level.lower(), "security")

    def _get_validation_method(self, unified_rule: UnifiedComplianceRule) -> str:
        """Get validation method description"""
        if unified_rule.platform_implementations:
            return "Automated technical validation with command execution and output verification"
        else:
            return "Policy and procedural validation"

    async def generate_batch_justifications(
        self, scan_result: ScanResult, unified_rules: Dict[str, UnifiedComplianceRule]
    ) -> Dict[str, List[ComplianceJustification]]:
        """Generate justifications for all results in a scan"""

        batch_justifications = {}

        for host_result in scan_result.host_results:
            host_justifications = []

            for framework_result in host_result.framework_results:
                framework_id = framework_result.framework_id

                for rule_execution in framework_result.rule_executions:
                    rule_id = rule_execution.rule_id
                    unified_rule = unified_rules.get(rule_id)

                    if unified_rule:
                        # Find the relevant control ID for this framework
                        control_id = None
                        for mapping in unified_rule.framework_mappings:
                            if mapping.framework_id == framework_id:
                                control_id = (
                                    mapping.control_ids[0] if mapping.control_ids else "unknown"
                                )
                                break

                        if control_id:
                            justification = await self.generate_justification(
                                rule_execution=rule_execution,
                                unified_rule=unified_rule,
                                framework_id=framework_id,
                                control_id=control_id,
                                host_id=host_result.host_id,
                                platform_info=host_result.platform_info,
                                context_data={"scan_id": scan_result.scan_id},
                            )
                            host_justifications.append(justification)

            batch_justifications[host_result.host_id] = host_justifications

        return batch_justifications

    async def export_audit_package(
        self,
        justifications: List[ComplianceJustification],
        framework_id: str,
        export_format: str = "json",
    ) -> str:
        """Export justifications as audit package"""

        if export_format == "json":
            audit_package = {
                "audit_package_metadata": {
                    "framework": framework_id,
                    "generated_at": datetime.utcnow().isoformat(),
                    "total_justifications": len(justifications),
                    "regulatory_citations": self.regulatory_mappings.get(framework_id, []),
                },
                "compliance_summary": {
                    "compliant": len(
                        [
                            j
                            for j in justifications
                            if j.compliance_status == ComplianceStatus.COMPLIANT
                        ]
                    ),
                    "exceeds": len(
                        [
                            j
                            for j in justifications
                            if j.compliance_status == ComplianceStatus.EXCEEDS
                        ]
                    ),
                    "partial": len(
                        [
                            j
                            for j in justifications
                            if j.compliance_status == ComplianceStatus.PARTIAL
                        ]
                    ),
                    "non_compliant": len(
                        [
                            j
                            for j in justifications
                            if j.compliance_status == ComplianceStatus.NON_COMPLIANT
                        ]
                    ),
                },
                "justifications": [
                    {
                        "justification_id": j.justification_id,
                        "control_id": j.control_id,
                        "host_id": j.host_id,
                        "compliance_status": j.compliance_status.value,
                        "summary": j.summary,
                        "detailed_explanation": j.detailed_explanation,
                        "implementation_description": j.implementation_description,
                        "risk_assessment": j.risk_assessment,
                        "business_justification": j.business_justification,
                        "regulatory_citations": j.regulatory_citations,
                        "evidence_count": len(j.evidence),
                        "enhancement_details": j.enhancement_details,
                        "created_at": j.created_at.isoformat(),
                    }
                    for j in justifications
                ],
            }

            return json.dumps(audit_package, indent=2)

        elif export_format == "csv":
            lines = [
                "Control_ID,Host_ID,Compliance_Status,Summary,Risk_Assessment,Business_Justification,Evidence_Count,Created_At"
            ]

            for j in justifications:
                # Escape double quotes in CSV fields
                summary_escaped = j.summary.replace('"', '""')
                risk_escaped = j.risk_assessment.replace('"', '""')
                justification_escaped = j.business_justification.replace('"', '""')

                lines.append(
                    f'"{j.control_id}","{j.host_id}","{j.compliance_status.value}",'
                    f'"{summary_escaped}","{risk_escaped}",'
                    f'"{justification_escaped}",{len(j.evidence)},{j.created_at.isoformat()}'
                )

            return "\n".join(lines)

        else:
            raise ValueError(f"Unsupported export format: {export_format}")

    def clear_cache(self):
        """Clear justification cache"""
        self.justification_cache.clear()
