"""
Compliance Framework Mapper Service
Maps SCAP rules to multiple compliance frameworks (NIST, CIS, STIG, CMMC 2.0)
"""

import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class ComplianceFramework(Enum):
    """Supported compliance frameworks"""

    DISA_STIG = "DISA-STIG"
    NIST_800_53 = "NIST-800-53"
    CIS_CONTROLS = "CIS-Controls"
    CMMC_2_0 = "CMMC-2.0"
    PCI_DSS = "PCI-DSS"
    HIPAA = "HIPAA"
    ISO_27001 = "ISO-27001"
    SOC2 = "SOC2"


@dataclass
class FrameworkMapping:
    """Framework mapping details"""

    framework: ComplianceFramework
    control_id: str
    control_title: str
    control_family: str
    implementation_guidance: str
    assessment_objectives: List[str]
    related_controls: List[str]
    severity: str  # low, medium, high, critical
    maturity_level: int  # 1-5 for CMMC


@dataclass
class ComplianceControl:
    """Unified compliance control across frameworks"""

    rule_id: str
    title: str
    description: str
    frameworks: List[FrameworkMapping]
    tags: List[str]
    categories: List[str]
    automated_remediation: bool
    aegis_rule_id: Optional[str]


class ComplianceFrameworkMapper:
    """Service for mapping SCAP rules to compliance frameworks"""

    def __init__(self):
        self.framework_mappings = self._initialize_mappings()
        self.control_families = self._initialize_control_families()
        self.cmmc_practices = self._initialize_cmmc_practices()

    def _initialize_mappings(self) -> Dict[str, List[FrameworkMapping]]:
        """Initialize comprehensive framework mappings"""
        # This would be loaded from a database or configuration file
        # For now, creating comprehensive mappings for common controls
        return {
            # SSH Configuration Controls
            "xccdf_mil.disa.stig_rule_SV-230221r792832_rule": [
                FrameworkMapping(
                    framework=ComplianceFramework.DISA_STIG,
                    control_id="SV-230221r792832",
                    control_title="SSH daemon must disable root login",
                    control_family="Access Control",
                    implementation_guidance="Configure SSH daemon to prevent root login by setting PermitRootLogin to 'no' in /etc/ssh/sshd_config",
                    assessment_objectives=[
                        "Verify PermitRootLogin is set to 'no'",
                        "Verify SSH service is restarted after changes",
                    ],
                    related_controls=["AC-6", "IA-2"],
                    severity="high",
                    maturity_level=3,
                ),
                FrameworkMapping(
                    framework=ComplianceFramework.NIST_800_53,
                    control_id="AC-6(2)",
                    control_title="Non-Privileged Access for Nonsecurity Functions",
                    control_family="Access Control",
                    implementation_guidance="Require users to use non-privileged accounts when accessing nonsecurity functions",
                    assessment_objectives=[
                        "Verify root access is restricted",
                        "Ensure privilege escalation is controlled",
                    ],
                    related_controls=["AC-6", "AC-6(1)", "AC-6(5)"],
                    severity="high",
                    maturity_level=3,
                ),
                FrameworkMapping(
                    framework=ComplianceFramework.CIS_CONTROLS,
                    control_id="5.4",
                    control_title="Restrict Administrator Privileges to Dedicated Administrator Accounts",
                    control_family="Account Management",
                    implementation_guidance="Ensure administrative privileges are restricted to dedicated admin accounts",
                    assessment_objectives=[
                        "Verify separation of admin and user accounts",
                        "Confirm root login restrictions",
                    ],
                    related_controls=["5.1", "5.2", "5.3"],
                    severity="high",
                    maturity_level=3,
                ),
                FrameworkMapping(
                    framework=ComplianceFramework.CMMC_2_0,
                    control_id="AC.L2-3.1.5",
                    control_title="Employ the principle of least privilege",
                    control_family="Access Control",
                    implementation_guidance="Employ the principle of least privilege, including for specific security functions and privileged accounts",
                    assessment_objectives=[
                        "Verify least privilege implementation",
                        "Assess privileged account restrictions",
                    ],
                    related_controls=["AC.L1-3.1.1", "AC.L2-3.1.6"],
                    severity="high",
                    maturity_level=2,
                ),
            ],
            # Password Policy Controls
            "xccdf_mil.disa.stig_rule_SV-230365r792936_rule": [
                FrameworkMapping(
                    framework=ComplianceFramework.DISA_STIG,
                    control_id="SV-230365r792936",
                    control_title="System must enforce minimum password length",
                    control_family="Identification and Authentication",
                    implementation_guidance="Configure PAM to enforce minimum password length of 15 characters",
                    assessment_objectives=[
                        "Verify password length configuration",
                        "Test password creation with various lengths",
                    ],
                    related_controls=["IA-5"],
                    severity="medium",
                    maturity_level=2,
                ),
                FrameworkMapping(
                    framework=ComplianceFramework.NIST_800_53,
                    control_id="IA-5(1)(a)",
                    control_title="Password-Based Authentication - Complexity",
                    control_family="Identification and Authentication",
                    implementation_guidance="Enforce minimum password complexity requirements including length",
                    assessment_objectives=[
                        "Verify password complexity settings",
                        "Validate enforcement mechanisms",
                    ],
                    related_controls=["IA-5", "IA-5(1)"],
                    severity="medium",
                    maturity_level=2,
                ),
                FrameworkMapping(
                    framework=ComplianceFramework.CIS_CONTROLS,
                    control_id="5.2",
                    control_title="Use Unique Passwords",
                    control_family="Account Management",
                    implementation_guidance="Ensure all accounts have unique, complex passwords meeting minimum requirements",
                    assessment_objectives=[
                        "Verify password policy enforcement",
                        "Check password uniqueness requirements",
                    ],
                    related_controls=["5.1", "5.3"],
                    severity="medium",
                    maturity_level=2,
                ),
                FrameworkMapping(
                    framework=ComplianceFramework.CMMC_2_0,
                    control_id="IA.L2-3.5.7",
                    control_title="Enforce a minimum password complexity",
                    control_family="Identification and Authentication",
                    implementation_guidance="Enforce a minimum password complexity and change of characters when new passwords are created",
                    assessment_objectives=[
                        "Verify password complexity requirements",
                        "Test password change enforcement",
                    ],
                    related_controls=["IA.L1-3.5.1", "IA.L1-3.5.2"],
                    severity="medium",
                    maturity_level=2,
                ),
            ],
            # Audit Configuration Controls
            "xccdf_mil.disa.stig_rule_SV-230423r793041_rule": [
                FrameworkMapping(
                    framework=ComplianceFramework.DISA_STIG,
                    control_id="SV-230423r793041",
                    control_title="Audit daemon must be enabled",
                    control_family="Audit and Accountability",
                    implementation_guidance="Enable and configure auditd service to capture security-relevant events",
                    assessment_objectives=[
                        "Verify auditd service is enabled",
                        "Confirm audit rules are loaded",
                    ],
                    related_controls=["AU-12", "AU-3"],
                    severity="high",
                    maturity_level=2,
                ),
                FrameworkMapping(
                    framework=ComplianceFramework.NIST_800_53,
                    control_id="AU-12",
                    control_title="Audit Record Generation",
                    control_family="Audit and Accountability",
                    implementation_guidance="Generate audit records for security-relevant events",
                    assessment_objectives=[
                        "Verify audit capability",
                        "Confirm event capture configuration",
                    ],
                    related_controls=["AU-2", "AU-3", "AU-12(1)"],
                    severity="high",
                    maturity_level=2,
                ),
                FrameworkMapping(
                    framework=ComplianceFramework.CIS_CONTROLS,
                    control_id="8.2",
                    control_title="Collect Audit Logs",
                    control_family="Audit Log Management",
                    implementation_guidance="Collect audit logs from all systems capable of generating audit records",
                    assessment_objectives=[
                        "Verify log collection",
                        "Assess log completeness",
                    ],
                    related_controls=["8.1", "8.3", "8.4"],
                    severity="high",
                    maturity_level=2,
                ),
                FrameworkMapping(
                    framework=ComplianceFramework.CMMC_2_0,
                    control_id="AU.L2-3.3.1",
                    control_title="Create and retain system audit logs",
                    control_family="Audit and Accountability",
                    implementation_guidance="Create and retain system audit logs and records to monitor, analyze, investigate, and report unlawful or unauthorized activity",
                    assessment_objectives=[
                        "Verify audit log generation",
                        "Confirm retention policies",
                    ],
                    related_controls=["AU.L2-3.3.2", "AU.L2-3.3.3"],
                    severity="high",
                    maturity_level=2,
                ),
            ],
        }

    def _initialize_control_families(self) -> Dict[ComplianceFramework, List[str]]:
        """Initialize control families for each framework"""
        return {
            ComplianceFramework.NIST_800_53: [
                "Access Control (AC)",
                "Awareness and Training (AT)",
                "Audit and Accountability (AU)",
                "Security Assessment and Authorization (CA)",
                "Configuration Management (CM)",
                "Contingency Planning (CP)",
                "Identification and Authentication (IA)",
                "Incident Response (IR)",
                "Maintenance (MA)",
                "Media Protection (MP)",
                "Physical and Environmental Protection (PE)",
                "Planning (PL)",
                "Program Management (PM)",
                "Personnel Security (PS)",
                "Risk Assessment (RA)",
                "System and Services Acquisition (SA)",
                "System and Communications Protection (SC)",
                "System and Information Integrity (SI)",
                "Supply Chain Risk Management (SR)",
            ],
            ComplianceFramework.CIS_CONTROLS: [
                "Inventory and Control of Enterprise Assets",
                "Inventory and Control of Software Assets",
                "Data Protection",
                "Secure Configuration of Enterprise Assets and Software",
                "Account Management",
                "Access Control Management",
                "Continuous Vulnerability Management",
                "Audit Log Management",
                "Email and Web Browser Protections",
                "Malware Defenses",
                "Data Recovery",
                "Network Infrastructure Management",
                "Network Monitoring and Defense",
                "Security Awareness and Skills Training",
                "Service Provider Management",
                "Application Software Security",
                "Incident Response Management",
                "Penetration Testing",
            ],
            ComplianceFramework.CMMC_2_0: [
                "Access Control (AC)",
                "Audit and Accountability (AU)",
                "Awareness and Training (AT)",
                "Configuration Management (CM)",
                "Identification and Authentication (IA)",
                "Incident Response (IR)",
                "Maintenance (MA)",
                "Media Protection (MP)",
                "Personnel Security (PS)",
                "Physical Protection (PE)",
                "Risk Assessment (RA)",
                "Security Assessment (CA)",
                "System and Communications Protection (SC)",
                "System and Information Integrity (SI)",
            ],
        }

    def _initialize_cmmc_practices(self) -> Dict[int, List[str]]:
        """Initialize CMMC maturity level practices"""
        return {
            1: [  # Foundational
                "AC.L1-3.1.1",
                "AC.L1-3.1.2",
                "AC.L1-3.1.20",
                "AC.L1-3.1.22",
                "IA.L1-3.5.1",
                "IA.L1-3.5.2",
                "MP.L1-3.8.3",
                "PE.L1-3.10.1",
                "PE.L1-3.10.3",
                "PE.L1-3.10.4",
                "PE.L1-3.10.5",
                "SC.L1-3.13.1",
                "SC.L1-3.13.5",
                "SI.L1-3.14.1",
                "SI.L1-3.14.2",
                "SI.L1-3.14.3",
            ],
            2: [  # Advanced
                "AC.L2-3.1.3",
                "AC.L2-3.1.4",
                "AC.L2-3.1.5",
                "AC.L2-3.1.6",
                "AC.L2-3.1.7",
                "AC.L2-3.1.8",
                "AC.L2-3.1.9",
                "AC.L2-3.1.10",
                "AC.L2-3.1.11",
                "AC.L2-3.1.12",
                "AT.L2-3.2.1",
                "AT.L2-3.2.2",
                "AT.L2-3.2.3",
                "AU.L2-3.3.1",
                "AU.L2-3.3.2",
                "AU.L2-3.3.3",
                "AU.L2-3.3.4",
                "AU.L2-3.3.5",
                "CM.L2-3.4.1",
                "CM.L2-3.4.2",
                "CM.L2-3.4.3",
                "CM.L2-3.4.4",
                "CM.L2-3.4.5",
                "IA.L2-3.5.3",
                "IA.L2-3.5.4",
                "IA.L2-3.5.5",
                "IA.L2-3.5.6",
                "IA.L2-3.5.7",
                "IR.L2-3.6.1",
                "IR.L2-3.6.2",
                "IR.L2-3.6.3",
                "MA.L2-3.7.1",
                "MA.L2-3.7.2",
                "MA.L2-3.7.3",
                "MA.L2-3.7.4",
                "MA.L2-3.7.5",
                "MP.L2-3.8.1",
                "MP.L2-3.8.2",
                "MP.L2-3.8.4",
                "MP.L2-3.8.5",
                "MP.L2-3.8.6",
                "PE.L2-3.10.2",
                "PE.L2-3.10.6",
                "PS.L2-3.9.1",
                "PS.L2-3.9.2",
                "RA.L2-3.11.1",
                "RA.L2-3.11.2",
                "RA.L2-3.11.3",
                "CA.L2-3.12.1",
                "CA.L2-3.12.2",
                "CA.L2-3.12.3",
                "CA.L2-3.12.4",
                "SC.L2-3.13.2",
                "SC.L2-3.13.3",
                "SC.L2-3.13.4",
                "SC.L2-3.13.6",
                "SC.L2-3.13.7",
                "SI.L2-3.14.4",
                "SI.L2-3.14.5",
                "SI.L2-3.14.6",
                "SI.L2-3.14.7",
            ],
            3: [  # Expert (includes all L1 and L2 plus additional)
                "AC.L3-3.1.13",
                "AC.L3-3.1.14",
                "AC.L3-3.1.15",
                "AC.L3-3.1.16",
                "AC.L3-3.1.17",
                "AT.L3-3.2.4",
                "AU.L3-3.3.6",
                "AU.L3-3.3.7",
                "AU.L3-3.3.8",
                "AU.L3-3.3.9",
                "CM.L3-3.4.6",
                "CM.L3-3.4.7",
                "CM.L3-3.4.8",
                "CM.L3-3.4.9",
                "IA.L3-3.5.8",
                "IA.L3-3.5.9",
                "IA.L3-3.5.10",
                "IA.L3-3.5.11",
                "IA.L3-3.5.12",
                "IR.L3-3.6.4",
                "IR.L3-3.6.5",
                "MA.L3-3.7.6",
                "MP.L3-3.8.7",
                "MP.L3-3.8.8",
                "MP.L3-3.8.9",
                "PE.L3-3.10.7",
                "RA.L3-3.11.4",
                "RA.L3-3.11.5",
                "RA.L3-3.11.6",
                "RA.L3-3.11.7",
                "CA.L3-3.12.5",
                "SC.L3-3.13.8",
                "SC.L3-3.13.9",
                "SC.L3-3.13.10",
                "SC.L3-3.13.11",
                "SC.L3-3.13.12",
                "SI.L3-3.14.8",
                "SI.L3-3.14.9",
                "SI.L3-3.14.10",
            ],
        }

    def map_scap_rule_to_frameworks(self, scap_rule_id: str) -> List[FrameworkMapping]:
        """Map a SCAP rule to all applicable compliance frameworks"""
        return self.framework_mappings.get(scap_rule_id, [])

    def get_unified_control(
        self, scap_rule_id: str, rule_title: str = "", rule_description: str = ""
    ) -> Optional[ComplianceControl]:
        """Get unified compliance control information across all frameworks"""
        mappings = self.map_scap_rule_to_frameworks(scap_rule_id)

        if not mappings:
            # Try to infer mappings from rule ID patterns
            mappings = self._infer_mappings_from_rule_id(scap_rule_id, rule_title)

        if not mappings:
            return None

        # Extract unique tags and categories
        tags = set()
        categories = set()

        for mapping in mappings:
            tags.add(mapping.control_family.lower().replace(" ", "_"))
            categories.add(mapping.control_family)

            # Add severity as tag
            tags.add(f"severity_{mapping.severity}")

            # Add framework as tag
            tags.add(mapping.framework.value.lower().replace("-", "_"))

        return ComplianceControl(
            rule_id=scap_rule_id,
            title=rule_title or mappings[0].control_title,
            description=rule_description or mappings[0].implementation_guidance,
            frameworks=mappings,
            tags=list(tags),
            categories=list(categories),
            automated_remediation=self._check_automated_remediation(scap_rule_id),
            aegis_rule_id=self._get_aegis_rule_id(scap_rule_id),
        )

    def _infer_mappings_from_rule_id(self, scap_rule_id: str, rule_title: str) -> List[FrameworkMapping]:
        """Infer framework mappings from SCAP rule ID patterns"""
        mappings = []

        # Extract STIG rule pattern
        stig_match = re.search(r"SV-\d+r\d+", scap_rule_id)
        if stig_match:
            stig_id = stig_match.group()

            # Infer control family from title
            control_family = self._infer_control_family(rule_title)
            severity = self._infer_severity(rule_title)

            mappings.append(
                FrameworkMapping(
                    framework=ComplianceFramework.DISA_STIG,
                    control_id=stig_id,
                    control_title=rule_title,
                    control_family=control_family,
                    implementation_guidance="Implement control as specified in STIG guidance",
                    assessment_objectives=[
                        "Verify control implementation",
                        "Validate effectiveness",
                    ],
                    related_controls=[],
                    severity=severity,
                    maturity_level=2,
                )
            )

            # Try to map to NIST based on common patterns
            nist_control = self._infer_nist_control(rule_title, control_family)
            if nist_control:
                mappings.append(
                    FrameworkMapping(
                        framework=ComplianceFramework.NIST_800_53,
                        control_id=nist_control,
                        control_title=rule_title,
                        control_family=control_family,
                        implementation_guidance="Implement per NIST 800-53 guidelines",
                        assessment_objectives=["Verify NIST control implementation"],
                        related_controls=[],
                        severity=severity,
                        maturity_level=2,
                    )
                )

        return mappings

    def _infer_control_family(self, rule_title: str) -> str:
        """Infer control family from rule title"""
        title_lower = rule_title.lower()

        if any(word in title_lower for word in ["ssh", "password", "authentication", "login"]):
            return "Identification and Authentication"
        elif any(word in title_lower for word in ["audit", "log", "logging"]):
            return "Audit and Accountability"
        elif any(word in title_lower for word in ["access", "permission", "privilege"]):
            return "Access Control"
        elif any(word in title_lower for word in ["firewall", "network", "port"]):
            return "System and Communications Protection"
        elif any(word in title_lower for word in ["update", "patch", "vulnerability"]):
            return "System and Information Integrity"
        else:
            return "Configuration Management"

    def _infer_severity(self, rule_title: str) -> str:
        """Infer severity from rule title keywords"""
        title_lower = rule_title.lower()

        critical_keywords = ["must not", "prohibited", "disabled", "root", "admin"]
        high_keywords = ["must", "required", "audit", "authentication", "firewall"]
        medium_keywords = ["should", "recommended", "configuration"]

        if any(word in title_lower for word in critical_keywords):
            return "critical"
        elif any(word in title_lower for word in high_keywords):
            return "high"
        elif any(word in title_lower for word in medium_keywords):
            return "medium"
        else:
            return "low"

    def _infer_nist_control(self, rule_title: str, control_family: str) -> Optional[str]:
        """Infer NIST control ID from rule title and family"""
        title_lower = rule_title.lower()

        # Common NIST control mappings
        nist_mappings = {
            "ssh": "AC-17",  # Remote Access
            "password": "IA-5",  # Authenticator Management
            "audit": "AU-12",  # Audit Generation
            "firewall": "SC-7",  # Boundary Protection
            "permission": "AC-3",  # Access Enforcement
            "update": "SI-2",  # Flaw Remediation
            "encryption": "SC-13",  # Cryptographic Protection
        }

        for keyword, control in nist_mappings.items():
            if keyword in title_lower:
                return control

        return None

    def _check_automated_remediation(self, scap_rule_id: str) -> bool:
        """Check if automated remediation is available for this rule"""
        # This would check against AEGIS rule database
        automated_rules = {
            "xccdf_mil.disa.stig_rule_SV-230221r792832_rule",  # SSH root login
            "xccdf_mil.disa.stig_rule_SV-230365r792936_rule",  # Password length
            "xccdf_mil.disa.stig_rule_SV-230423r793041_rule",  # Audit daemon
        }
        return scap_rule_id in automated_rules

    def _get_aegis_rule_id(self, scap_rule_id: str) -> Optional[str]:
        """Get corresponding AEGIS rule ID for automated remediation"""
        aegis_mappings = {
            "xccdf_mil.disa.stig_rule_SV-230221r792832_rule": "ssh_disable_root_login",
            "xccdf_mil.disa.stig_rule_SV-230365r792936_rule": "password_minimum_length",
            "xccdf_mil.disa.stig_rule_SV-230423r793041_rule": "auditd_service_enabled",
        }
        return aegis_mappings.get(scap_rule_id)

    def get_framework_summary(self, scap_rules: List[str]) -> Dict[str, Dict]:
        """Get compliance summary across all frameworks for a list of SCAP rules"""
        summary = {
            framework.value: {
                "total_controls": 0,
                "covered_controls": set(),
                "control_families": {},
                "maturity_levels": {},
                "severity_distribution": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                },
            }
            for framework in ComplianceFramework
        }

        for rule_id in scap_rules:
            control = self.get_unified_control(rule_id)
            if not control:
                continue

            for mapping in control.frameworks:
                framework_key = mapping.framework.value
                summary[framework_key]["total_controls"] += 1
                summary[framework_key]["covered_controls"].add(mapping.control_id)

                # Count by control family
                family = mapping.control_family
                if family not in summary[framework_key]["control_families"]:
                    summary[framework_key]["control_families"][family] = 0
                summary[framework_key]["control_families"][family] += 1

                # Count by maturity level (for CMMC)
                if mapping.maturity_level:
                    level = f"Level {mapping.maturity_level}"
                    if level not in summary[framework_key]["maturity_levels"]:
                        summary[framework_key]["maturity_levels"][level] = 0
                    summary[framework_key]["maturity_levels"][level] += 1

                # Count by severity
                summary[framework_key]["severity_distribution"][mapping.severity] += 1

        # Convert sets to lists for JSON serialization
        for framework in summary.values():
            framework["covered_controls"] = list(framework["covered_controls"])

        return summary

    def get_remediation_priorities(self, failed_rules: List[Dict[str, str]]) -> List[Dict]:
        """Prioritize failed rules for remediation based on framework requirements"""
        priorities = []

        for rule in failed_rules:
            rule_id = rule.get("rule_id", "")
            control = self.get_unified_control(rule_id)

            if not control:
                continue

            # Calculate priority score
            priority_score = 0
            severity_scores = {"critical": 4, "high": 3, "medium": 2, "low": 1}

            # Get highest severity across frameworks
            max_severity = "low"
            frameworks_affected = []

            for mapping in control.frameworks:
                if severity_scores.get(mapping.severity, 0) > severity_scores.get(max_severity, 0):
                    max_severity = mapping.severity
                frameworks_affected.append(mapping.framework.value)

                # Add extra weight for CMMC Level 2+ requirements
                if mapping.framework == ComplianceFramework.CMMC_2_0 and mapping.maturity_level >= 2:
                    priority_score += 10

            priority_score += severity_scores.get(max_severity, 0) * 10
            priority_score += len(frameworks_affected) * 5

            # Boost priority if automated remediation is available
            if control.automated_remediation:
                priority_score += 20

            priorities.append(
                {
                    "rule_id": rule_id,
                    "title": control.title,
                    "priority_score": priority_score,
                    "severity": max_severity,
                    "frameworks_affected": frameworks_affected,
                    "automated_remediation": control.automated_remediation,
                    "aegis_rule_id": control.aegis_rule_id,
                    "remediation_effort": self._estimate_remediation_effort(control),
                }
            )

        # Sort by priority score (highest first)
        priorities.sort(key=lambda x: x["priority_score"], reverse=True)

        return priorities

    def _estimate_remediation_effort(self, control: ComplianceControl) -> str:
        """Estimate remediation effort based on control characteristics"""
        if control.automated_remediation:
            return "minimal"

        # Check control categories
        if any(cat in ["Configuration Management", "Access Control"] for cat in control.categories):
            return "moderate"
        elif any(cat in ["Audit and Accountability", "System and Information Integrity"] for cat in control.categories):
            return "significant"
        else:
            return "moderate"

    def export_compliance_matrix(self, scap_rules: List[str]) -> Dict:
        """Export a compliance matrix showing coverage across all frameworks"""
        matrix = {
            "frameworks": list(ComplianceFramework.__members__.keys()),
            "rules": [],
        }

        for rule_id in scap_rules:
            control = self.get_unified_control(rule_id)
            if not control:
                continue

            rule_entry = {"rule_id": rule_id, "title": control.title, "mappings": {}}

            for framework in ComplianceFramework:
                framework_mappings = [m for m in control.frameworks if m.framework == framework]
                if framework_mappings:
                    mapping = framework_mappings[0]
                    rule_entry["mappings"][framework.value] = {
                        "control_id": mapping.control_id,
                        "severity": mapping.severity,
                        "family": mapping.control_family,
                    }
                else:
                    rule_entry["mappings"][framework.value] = None

            matrix["rules"].append(rule_entry)

        return matrix
