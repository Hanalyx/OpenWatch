"""
SCAP to AEGIS Mapper Service
Maps SCAP rules to AEGIS remediation actions and manages remediation workflows
"""

import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

import yaml

logger = logging.getLogger(__name__)


@dataclass
class AEGISMapping:
    """AEGIS remediation mapping for SCAP rule"""

    scap_rule_id: str
    aegis_rule_id: str
    rule_category: str  # authentication, audit, network, etc.
    remediation_type: str  # configuration, service, permission, etc.
    implementation_commands: List[str]
    verification_commands: List[str]
    rollback_commands: List[str]
    estimated_duration: int  # seconds
    requires_reboot: bool
    dependencies: List[str]
    platforms: List[str]  # rhel8, rhel9, ubuntu20, ubuntu22


@dataclass
class RemediationPlan:
    """Remediation plan for failed SCAP rules"""

    plan_id: str
    scan_id: str
    host_id: str
    total_rules: int
    remediable_rules: int
    estimated_duration: int
    requires_reboot: bool
    rule_groups: Dict[str, List[AEGISMapping]]  # Grouped by category
    execution_order: List[str]  # Rule IDs in execution order
    dependencies_resolved: bool


class SCAPAEGISMapper:
    """Service for mapping SCAP rules to AEGIS remediation actions"""

    def __init__(self, mappings_dir: str = "/app/data/mappings"):
        self.mappings_dir = Path(mappings_dir)
        self.mappings_dir.mkdir(parents=True, exist_ok=True)
        self.rule_mappings = self._load_mappings()
        self.category_priorities = self._initialize_category_priorities()

    def _load_mappings(self) -> Dict[str, AEGISMapping]:
        """Load SCAP to AEGIS mappings from configuration"""
        mappings = {}

        # Load from built-in mappings first
        mappings.update(self._load_builtin_mappings())

        # Load from custom mappings directory
        for mapping_file in self.mappings_dir.glob("*.yml"):
            try:
                with open(mapping_file, "r") as f:
                    custom_mappings = yaml.safe_load(f)

                for rule_id, mapping_data in custom_mappings.items():
                    mappings[rule_id] = AEGISMapping(
                        scap_rule_id=rule_id,
                        aegis_rule_id=mapping_data.get("aegis_rule_id", ""),
                        rule_category=mapping_data.get("category", "system"),
                        remediation_type=mapping_data.get("type", "configuration"),
                        implementation_commands=mapping_data.get("commands", []),
                        verification_commands=mapping_data.get("verify", []),
                        rollback_commands=mapping_data.get("rollback", []),
                        estimated_duration=mapping_data.get("duration", 60),
                        requires_reboot=mapping_data.get("requires_reboot", False),
                        dependencies=mapping_data.get("dependencies", []),
                        platforms=mapping_data.get("platforms", ["rhel8", "rhel9"]),
                    )

                logger.info(f"Loaded {len(custom_mappings)} mappings from {mapping_file}")

            except Exception as e:
                logger.error(f"Error loading mappings from {mapping_file}: {e}")

        return mappings

    def _load_builtin_mappings(self) -> Dict[str, AEGISMapping]:
        """Load built-in SCAP to AEGIS mappings"""
        return {
            # SSH Configuration
            "xccdf_mil.disa.stig_rule_SV-230221r792832_rule": AEGISMapping(
                scap_rule_id="xccdf_mil.disa.stig_rule_SV-230221r792832_rule",
                aegis_rule_id="RHEL-09-255045",
                rule_category="authentication",
                remediation_type="configuration",
                implementation_commands=[
                    "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
                    "grep -q '^PermitRootLogin' /etc/ssh/sshd_config || echo 'PermitRootLogin no' >> /etc/ssh/sshd_config",
                    "systemctl restart sshd",
                ],
                verification_commands=["grep -E '^PermitRootLogin\\s+no' /etc/ssh/sshd_config"],
                rollback_commands=[
                    "sed -i 's/^PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config",
                    "systemctl restart sshd",
                ],
                estimated_duration=30,
                requires_reboot=False,
                dependencies=[],
                platforms=["rhel8", "rhel9", "ubuntu20", "ubuntu22"],
            ),
            # Password Policy
            "xccdf_mil.disa.stig_rule_SV-230365r792936_rule": AEGISMapping(
                scap_rule_id="xccdf_mil.disa.stig_rule_SV-230365r792936_rule",
                aegis_rule_id="RHEL-09-611045",
                rule_category="authentication",
                remediation_type="configuration",
                implementation_commands=[
                    "sed -i 's/^#*\\s*minlen.*/minlen = 15/' /etc/security/pwquality.conf",
                    "grep -q '^minlen' /etc/security/pwquality.conf || echo 'minlen = 15' >> /etc/security/pwquality.conf",
                ],
                verification_commands=["grep -E '^minlen\\s*=\\s*(1[5-9]|[2-9][0-9])' /etc/security/pwquality.conf"],
                rollback_commands=["sed -i 's/^minlen.*/minlen = 8/' /etc/security/pwquality.conf"],
                estimated_duration=20,
                requires_reboot=False,
                dependencies=["libpwquality"],
                platforms=["rhel8", "rhel9", "ubuntu20", "ubuntu22"],
            ),
            # Audit Daemon
            "xccdf_mil.disa.stig_rule_SV-230423r793041_rule": AEGISMapping(
                scap_rule_id="xccdf_mil.disa.stig_rule_SV-230423r793041_rule",
                aegis_rule_id="RHEL-09-653015",
                rule_category="audit",
                remediation_type="service",
                implementation_commands=[
                    "systemctl enable auditd",
                    "systemctl start auditd",
                    "augenrules --load",
                ],
                verification_commands=[
                    "systemctl is-enabled auditd",
                    "systemctl is-active auditd",
                ],
                rollback_commands=["systemctl stop auditd", "systemctl disable auditd"],
                estimated_duration=45,
                requires_reboot=False,
                dependencies=["audit"],
                platforms=["rhel8", "rhel9"],
            ),
            # Firewall Configuration
            "xccdf_mil.disa.stig_rule_SV-230515r793185_rule": AEGISMapping(
                scap_rule_id="xccdf_mil.disa.stig_rule_SV-230515r793185_rule",
                aegis_rule_id="RHEL-09-251010",
                rule_category="network",
                remediation_type="service",
                implementation_commands=[
                    "systemctl enable firewalld",
                    "systemctl start firewalld",
                    "firewall-cmd --set-default-zone=public",
                    "firewall-cmd --reload",
                ],
                verification_commands=[
                    "systemctl is-enabled firewalld",
                    "systemctl is-active firewalld",
                    "firewall-cmd --state",
                ],
                rollback_commands=[
                    "systemctl stop firewalld",
                    "systemctl disable firewalld",
                ],
                estimated_duration=60,
                requires_reboot=False,
                dependencies=["firewalld"],
                platforms=["rhel8", "rhel9"],
            ),
            # File Permissions
            "xccdf_mil.disa.stig_rule_SV-230279r792861_rule": AEGISMapping(
                scap_rule_id="xccdf_mil.disa.stig_rule_SV-230279r792861_rule",
                aegis_rule_id="RHEL-09-232010",
                rule_category="system",
                remediation_type="permission",
                implementation_commands=[
                    "find /etc -type f -name '*.conf' -exec chmod 644 {} \\;",
                    "find /etc -type d -exec chmod 755 {} \\;",
                    "chmod 600 /etc/shadow",
                    "chmod 644 /etc/passwd",
                ],
                verification_commands=[
                    "stat -c '%a' /etc/shadow | grep -q '600'",
                    "stat -c '%a' /etc/passwd | grep -q '644'",
                ],
                rollback_commands=["# No rollback for security permissions"],
                estimated_duration=120,
                requires_reboot=False,
                dependencies=[],
                platforms=["rhel8", "rhel9", "ubuntu20", "ubuntu22"],
            ),
        }

    def _initialize_category_priorities(self) -> Dict[str, int]:
        """Initialize remediation category priorities"""
        return {
            "authentication": 1,  # Highest priority
            "audit": 2,
            "network": 3,
            "crypto": 4,
            "system": 5,
            "service": 6,
            "permission": 7,
            "configuration": 8,  # Lowest priority
        }

    def get_aegis_mapping(self, scap_rule_id: str) -> Optional[AEGISMapping]:
        """Get AEGIS mapping for a SCAP rule"""
        return self.rule_mappings.get(scap_rule_id)

    def create_remediation_plan(
        self,
        scan_id: str,
        host_id: str,
        failed_rules: List[Dict[str, str]],
        platform: str = "rhel9",
    ) -> RemediationPlan:
        """Create remediation plan for failed SCAP rules"""
        try:
            plan_id = f"plan_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            logger.info(f"Creating remediation plan {plan_id} for {len(failed_rules)} failed rules")

            # Categorize rules and check for mappings
            rule_groups = {}
            remediable_rules = 0
            total_duration = 0
            requires_reboot = False
            all_dependencies = set()

            for rule in failed_rules:
                rule_id = rule.get("rule_id", "")
                mapping = self.get_aegis_mapping(rule_id)

                if mapping and platform in mapping.platforms:
                    remediable_rules += 1

                    # Group by category
                    if mapping.rule_category not in rule_groups:
                        rule_groups[mapping.rule_category] = []
                    rule_groups[mapping.rule_category].append(mapping)

                    # Accumulate requirements
                    total_duration += mapping.estimated_duration
                    if mapping.requires_reboot:
                        requires_reboot = True
                    all_dependencies.update(mapping.dependencies)

            # Determine execution order based on dependencies and priorities
            execution_order = self._determine_execution_order(rule_groups, all_dependencies)

            # Check if all dependencies can be resolved
            dependencies_resolved = self._check_dependencies(all_dependencies, platform)

            plan = RemediationPlan(
                plan_id=plan_id,
                scan_id=scan_id,
                host_id=host_id,
                total_rules=len(failed_rules),
                remediable_rules=remediable_rules,
                estimated_duration=total_duration,
                requires_reboot=requires_reboot,
                rule_groups=rule_groups,
                execution_order=execution_order,
                dependencies_resolved=dependencies_resolved,
            )

            # Save plan for tracking
            self._save_remediation_plan(plan)

            logger.info(f"Created remediation plan with {remediable_rules}/{len(failed_rules)} remediable rules")
            return plan

        except Exception as e:
            logger.error(f"Error creating remediation plan: {e}")
            raise

    def _determine_execution_order(
        self, rule_groups: Dict[str, List[AEGISMapping]], dependencies: Set[str]
    ) -> List[str]:
        """Determine optimal execution order for remediation"""
        execution_order = []

        # Sort categories by priority
        sorted_categories = sorted(rule_groups.keys(), key=lambda x: self.category_priorities.get(x, 999))

        # Process rules in priority order
        for category in sorted_categories:
            # Within category, sort by dependencies
            category_rules = rule_groups[category]

            # Rules with no dependencies first
            no_deps = [r for r in category_rules if not r.dependencies]
            with_deps = [r for r in category_rules if r.dependencies]

            # Add to execution order
            for rule in no_deps:
                execution_order.append(rule.scap_rule_id)

            for rule in with_deps:
                execution_order.append(rule.scap_rule_id)

        return execution_order

    def _check_dependencies(self, dependencies: Set[str], platform: str) -> bool:
        """Check if all dependencies can be resolved"""
        # This would check against package manager or system state
        # For now, we'll assume common dependencies are available

        common_packages = {
            "rhel8": ["audit", "firewalld", "libpwquality", "openssh-server"],
            "rhel9": ["audit", "firewalld", "libpwquality", "openssh-server"],
            "ubuntu20": ["auditd", "ufw", "libpam-pwquality", "openssh-server"],
            "ubuntu22": ["auditd", "ufw", "libpam-pwquality", "openssh-server"],
        }

        platform_packages = set(common_packages.get(platform, []))

        # Check if all dependencies are in common packages
        unresolved = dependencies - platform_packages

        if unresolved:
            logger.warning(f"Unresolved dependencies for {platform}: {unresolved}")
            return False

        return True

    def _save_remediation_plan(self, plan: RemediationPlan):
        """Save remediation plan to file"""
        try:
            plan_file = self.mappings_dir / f"{plan.plan_id}.json"

            plan_data = {
                "plan_id": plan.plan_id,
                "scan_id": plan.scan_id,
                "host_id": plan.host_id,
                "created_at": datetime.now().isoformat(),
                "total_rules": plan.total_rules,
                "remediable_rules": plan.remediable_rules,
                "estimated_duration": plan.estimated_duration,
                "requires_reboot": plan.requires_reboot,
                "execution_order": plan.execution_order,
                "dependencies_resolved": plan.dependencies_resolved,
                "rule_groups": {},
            }

            # Convert AEGISMapping objects to dicts
            for category, mappings in plan.rule_groups.items():
                plan_data["rule_groups"][category] = [
                    {
                        "scap_rule_id": m.scap_rule_id,
                        "aegis_rule_id": m.aegis_rule_id,
                        "estimated_duration": m.estimated_duration,
                        "requires_reboot": m.requires_reboot,
                    }
                    for m in mappings
                ]

            with open(plan_file, "w") as f:
                json.dump(plan_data, f, indent=2)

            logger.info(f"Saved remediation plan to {plan_file}")

        except Exception as e:
            logger.error(f"Error saving remediation plan: {e}")

    def generate_aegis_job_request(self, plan: RemediationPlan) -> Dict:
        """Generate AEGIS job request from remediation plan"""
        try:
            # Extract all AEGIS rule IDs in execution order
            aegis_rules = []

            for scap_rule_id in plan.execution_order:
                mapping = self.get_aegis_mapping(scap_rule_id)
                if mapping:
                    aegis_rules.append(mapping.aegis_rule_id)

            # Create AEGIS job request
            job_request = {
                "host_id": plan.host_id,
                "rule_ids": aegis_rules,
                "options": {
                    "dry_run": False,
                    "force": False,
                    "parallel": False,  # Execute in order
                    "continue_on_error": True,
                    "create_restore_point": True,
                },
                "metadata": {
                    "source": "openwatch",
                    "scan_id": plan.scan_id,
                    "plan_id": plan.plan_id,
                    "total_rules": plan.remediable_rules,
                    "estimated_duration": plan.estimated_duration,
                    "requires_reboot": plan.requires_reboot,
                },
            }

            return job_request

        except Exception as e:
            logger.error(f"Error generating AEGIS job request: {e}")
            raise

    def map_aegis_results_to_scap(self, aegis_job_id: str, aegis_results: Dict) -> Dict[str, str]:
        """Map AEGIS remediation results back to SCAP rules"""
        try:
            scap_results = {}

            # Get job executions from AEGIS results
            executions = aegis_results.get("executions", [])

            for execution in executions:
                aegis_rule_id = execution.get("rule_id", "")
                status = execution.get("status", "unknown")

                # Find corresponding SCAP rule
                for scap_id, mapping in self.rule_mappings.items():
                    if mapping.aegis_rule_id == aegis_rule_id:
                        scap_results[scap_id] = "pass" if status == "completed" else "fail"
                        break

            return scap_results

        except Exception as e:
            logger.error(f"Error mapping AEGIS results: {e}")
            return {}

    def get_manual_remediation_steps(self, scap_rule_id: str) -> Optional[Dict]:
        """Get manual remediation steps for rules without AEGIS mapping"""
        try:
            # Check if we have a mapping
            mapping = self.get_aegis_mapping(scap_rule_id)

            if not mapping:
                return None

            return {
                "rule_id": scap_rule_id,
                "category": mapping.rule_category,
                "steps": [
                    {
                        "description": f"Execute command: {cmd}",
                        "command": cmd,
                        "type": "implementation",
                    }
                    for cmd in mapping.implementation_commands
                ],
                "verification": [
                    {
                        "description": f"Verify with: {cmd}",
                        "command": cmd,
                        "expected_result": "Command should return 0 exit code",
                    }
                    for cmd in mapping.verification_commands
                ],
                "rollback": (
                    [{"description": f"Rollback with: {cmd}", "command": cmd} for cmd in mapping.rollback_commands]
                    if mapping.rollback_commands
                    else None
                ),
            }

        except Exception as e:
            logger.error(f"Error getting manual remediation steps: {e}")
            return None

    def export_mappings(self, format: str = "yaml") -> str:
        """Export all SCAP to AEGIS mappings"""
        try:
            export_data = {}

            for scap_id, mapping in self.rule_mappings.items():
                export_data[scap_id] = {
                    "aegis_rule_id": mapping.aegis_rule_id,
                    "category": mapping.rule_category,
                    "type": mapping.remediation_type,
                    "commands": mapping.implementation_commands,
                    "verify": mapping.verification_commands,
                    "rollback": mapping.rollback_commands,
                    "duration": mapping.estimated_duration,
                    "requires_reboot": mapping.requires_reboot,
                    "dependencies": mapping.dependencies,
                    "platforms": mapping.platforms,
                }

            if format == "yaml":
                return yaml.dump(export_data, default_flow_style=False)
            elif format == "json":
                return json.dumps(export_data, indent=2)
            else:
                raise ValueError(f"Unsupported format: {format}")

        except Exception as e:
            logger.error(f"Error exporting mappings: {e}")
            raise
