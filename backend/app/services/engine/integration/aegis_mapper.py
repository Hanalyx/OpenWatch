#!/usr/bin/env python3
"""
AEGIS Integration Mapper

Maps SCAP compliance rules to AEGIS remediation actions and manages
automated remediation workflows. AEGIS (Automated Enterprise Governance
and Infrastructure Security) provides automated remediation capabilities
for compliance findings.

This module enables:
1. Rule-to-remediation mapping with category-based prioritization
2. Remediation plan generation with dependency resolution
3. AEGIS job request generation for automated execution
4. Result mapping from AEGIS back to SCAP rule status

Security Considerations:
- Commands stored in mappings are NOT executed by this module
- All command execution is delegated to AEGIS or remediation services
- No shell=True subprocess calls in this module
- Input validation on all external data

Architecture:
- Single Responsibility: Maps between SCAP and AEGIS formats only
- No database operations (pure transformation layer)
- Stateless operations except for mapping cache

Usage:
    from backend.app.services.engine.integration import (
        AegisMapper,
        get_aegis_mapper,
    )

    mapper = get_aegis_mapper()
    plan = mapper.create_remediation_plan(
        scan_id="scan-123",
        host_id="host-456",
        failed_rules=[{"rule_id": "xccdf_rule_1"}],
        platform="rhel9"
    )

    # Generate AEGIS job request
    job_request = mapper.generate_aegis_job_request(plan)
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml

logger = logging.getLogger(__name__)

# Module-level singleton instance for reuse across requests
_aegis_mapper_instance: Optional["AegisMapper"] = None


@dataclass
class AEGISMapping:
    """
    Represents a mapping between a SCAP rule and AEGIS remediation action.

    This dataclass contains all information needed to remediate a specific
    SCAP compliance finding through AEGIS automation.

    Attributes:
        scap_rule_id: Full SCAP/XCCDF rule identifier
        aegis_rule_id: Corresponding AEGIS rule identifier
        rule_category: Category for prioritization (authentication, audit, etc.)
        remediation_type: Type of remediation (configuration, service, permission)
        implementation_commands: Commands to apply the remediation
        verification_commands: Commands to verify remediation was successful
        rollback_commands: Commands to undo remediation if needed
        estimated_duration: Expected execution time in seconds
        requires_reboot: Whether system reboot is required after remediation
        dependencies: Package or service dependencies required
        platforms: Supported platform identifiers (rhel8, rhel9, ubuntu20, etc.)

    Note:
        Commands in this mapping are stored for AEGIS execution only.
        This module does NOT execute any shell commands directly.
    """

    scap_rule_id: str
    aegis_rule_id: str
    rule_category: str
    remediation_type: str
    implementation_commands: List[str] = field(default_factory=list)
    verification_commands: List[str] = field(default_factory=list)
    rollback_commands: List[str] = field(default_factory=list)
    estimated_duration: int = 60
    requires_reboot: bool = False
    dependencies: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=lambda: ["rhel8", "rhel9"])


@dataclass
class RemediationPlan:
    """
    A comprehensive remediation plan for failed SCAP compliance rules.

    This dataclass represents a complete execution plan including:
    - Rule grouping by category for organized execution
    - Dependency resolution status
    - Estimated total duration
    - Reboot requirements

    Attributes:
        plan_id: Unique identifier for this remediation plan
        scan_id: Source scan that generated the failed rules
        host_id: Target host for remediation
        total_rules: Total number of failed rules in source scan
        remediable_rules: Number of rules with AEGIS mappings
        estimated_duration: Total estimated time in seconds
        requires_reboot: Whether any rule requires system reboot
        rule_groups: Rules grouped by category for execution
        execution_order: Optimal order for rule remediation
        dependencies_resolved: Whether all dependencies are available

    Usage:
        plan = RemediationPlan(
            plan_id="plan_123",
            scan_id="scan_456",
            host_id="host_789",
            total_rules=50,
            remediable_rules=35,
            ...
        )
    """

    plan_id: str
    scan_id: str
    host_id: str
    total_rules: int
    remediable_rules: int
    estimated_duration: int
    requires_reboot: bool
    rule_groups: Dict[str, List[AEGISMapping]]
    execution_order: List[str]
    dependencies_resolved: bool


class AegisMapper:
    """
    Service for mapping SCAP rules to AEGIS remediation actions.

    This class provides the core integration between SCAP compliance
    scanning and AEGIS automated remediation. It handles:

    1. Loading and caching rule mappings from configuration
    2. Creating remediation plans with proper execution ordering
    3. Generating AEGIS job requests for automation
    4. Mapping AEGIS results back to SCAP rule status

    The mapper uses a category-based priority system to ensure
    critical remediations (authentication, audit) execute before
    less critical ones (general configuration).

    Attributes:
        mappings_dir: Directory containing custom mapping files
        rule_mappings: Cached SCAP to AEGIS mappings
        category_priorities: Priority order for remediation categories

    Example:
        mapper = AegisMapper(mappings_dir="/app/data/mappings")
        mapping = mapper.get_aegis_mapping("xccdf_rule_ssh_config")
        if mapping:
            print(f"AEGIS rule: {mapping.aegis_rule_id}")
    """

    def __init__(self, mappings_dir: str = "/app/data/mappings") -> None:
        """
        Initialize the AEGIS mapper with mapping directory.

        Args:
            mappings_dir: Path to directory containing custom YAML mappings.
                         Directory will be created if it doesn't exist.
        """
        self.mappings_dir = Path(mappings_dir)
        # Ensure directory exists for custom mappings
        self.mappings_dir.mkdir(parents=True, exist_ok=True)
        # Load all mappings (builtin + custom)
        self.rule_mappings: Dict[str, AEGISMapping] = self._load_mappings()
        # Initialize category priorities for execution ordering
        self.category_priorities: Dict[str, int] = self._initialize_category_priorities()

    def _load_mappings(self) -> Dict[str, AEGISMapping]:
        """
        Load SCAP to AEGIS mappings from all sources.

        Mappings are loaded in order:
        1. Built-in mappings (hardcoded for common rules)
        2. Custom mappings from YAML files in mappings_dir

        Custom mappings can override built-in mappings by using
        the same SCAP rule ID.

        Returns:
            Dictionary mapping SCAP rule IDs to AEGISMapping objects.

        Note:
            Uses yaml.safe_load to prevent arbitrary code execution
            from malicious YAML files.
        """
        mappings: Dict[str, AEGISMapping] = {}

        # Load built-in mappings first (baseline)
        mappings.update(self._load_builtin_mappings())

        # Load custom mappings from YAML files (can override builtins)
        for mapping_file in self.mappings_dir.glob("*.yml"):
            try:
                with open(mapping_file, "r", encoding="utf-8") as f:
                    # Use safe_load to prevent code execution from YAML
                    custom_mappings = yaml.safe_load(f)

                # Skip empty or invalid files
                if not custom_mappings or not isinstance(custom_mappings, dict):
                    logger.warning(f"Skipping invalid mapping file: {mapping_file}")
                    continue

                for rule_id, mapping_data in custom_mappings.items():
                    # Validate mapping_data is a dictionary
                    if not isinstance(mapping_data, dict):
                        logger.warning(f"Invalid mapping data for {rule_id} in {mapping_file}")
                        continue

                    mappings[rule_id] = AEGISMapping(
                        scap_rule_id=str(rule_id),
                        aegis_rule_id=str(mapping_data.get("aegis_rule_id", "")),
                        rule_category=str(mapping_data.get("category", "system")),
                        remediation_type=str(mapping_data.get("type", "configuration")),
                        implementation_commands=list(mapping_data.get("commands", [])),
                        verification_commands=list(mapping_data.get("verify", [])),
                        rollback_commands=list(mapping_data.get("rollback", [])),
                        estimated_duration=int(mapping_data.get("duration", 60)),
                        requires_reboot=bool(mapping_data.get("requires_reboot", False)),
                        dependencies=list(mapping_data.get("dependencies", [])),
                        platforms=list(mapping_data.get("platforms", ["rhel8", "rhel9"])),
                    )

                logger.info(f"Loaded {len(custom_mappings)} mappings from {mapping_file}")

            except yaml.YAMLError as e:
                logger.error(f"YAML parse error in {mapping_file}: {e}")
            except (OSError, IOError) as e:
                logger.error(f"Error reading mapping file {mapping_file}: {e}")
            except Exception as e:
                # Catch-all for unexpected errors, log and continue
                logger.error(f"Unexpected error loading {mapping_file}: {e}")

        return mappings

    def _load_builtin_mappings(self) -> Dict[str, AEGISMapping]:
        """
        Load built-in SCAP to AEGIS mappings for common rules.

        These mappings provide baseline coverage for frequently
        encountered STIG and CIS rules. Custom mappings can
        override these by providing the same SCAP rule ID.

        Returns:
            Dictionary of built-in AEGISMapping objects.

        Note:
            Commands here are stored for reference and AEGIS execution.
            This module does NOT execute any commands directly.
        """
        return {
            # SSH Configuration - Disable root login
            "xccdf_mil.disa.stig_rule_SV-230221r792832_rule": AEGISMapping(
                scap_rule_id="xccdf_mil.disa.stig_rule_SV-230221r792832_rule",
                aegis_rule_id="RHEL-09-255045",
                rule_category="authentication",
                remediation_type="configuration",
                implementation_commands=[
                    "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
                    "grep -q '^PermitRootLogin' /etc/ssh/sshd_config || echo 'PermitRootLogin no' >> /etc/ssh/sshd_config",  # noqa: E501
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
            # Password Policy - Minimum length
            "xccdf_mil.disa.stig_rule_SV-230365r792936_rule": AEGISMapping(
                scap_rule_id="xccdf_mil.disa.stig_rule_SV-230365r792936_rule",
                aegis_rule_id="RHEL-09-611045",
                rule_category="authentication",
                remediation_type="configuration",
                implementation_commands=[
                    "sed -i 's/^#*\\s*minlen.*/minlen = 15/' /etc/security/pwquality.conf",
                    "grep -q '^minlen' /etc/security/pwquality.conf || echo 'minlen = 15' >> /etc/security/pwquality.conf",  # noqa: E501
                ],
                verification_commands=["grep -E '^minlen\\s*=\\s*(1[5-9]|[2-9][0-9])' /etc/security/pwquality.conf"],
                rollback_commands=["sed -i 's/^minlen.*/minlen = 8/' /etc/security/pwquality.conf"],
                estimated_duration=20,
                requires_reboot=False,
                dependencies=["libpwquality"],
                platforms=["rhel8", "rhel9", "ubuntu20", "ubuntu22"],
            ),
            # Audit Daemon - Enable and start
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
                rollback_commands=[
                    "systemctl stop auditd",
                    "systemctl disable auditd",
                ],
                estimated_duration=45,
                requires_reboot=False,
                dependencies=["audit"],
                platforms=["rhel8", "rhel9"],
            ),
            # Firewall Configuration - Enable firewalld
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
            # File Permissions - Secure system files
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
                rollback_commands=["# No rollback for security permissions - manual review required"],
                estimated_duration=120,
                requires_reboot=False,
                dependencies=[],
                platforms=["rhel8", "rhel9", "ubuntu20", "ubuntu22"],
            ),
        }

    def _initialize_category_priorities(self) -> Dict[str, int]:
        """
        Initialize remediation category priorities.

        Categories are ordered by security criticality:
        - Authentication: Most critical (prevents unauthorized access)
        - Audit: High priority (enables security monitoring)
        - Network: High priority (controls network exposure)
        - Lower priorities for less critical configurations

        Returns:
            Dictionary mapping category names to priority values.
            Lower values indicate higher priority.
        """
        return {
            "authentication": 1,  # Highest priority - access control
            "audit": 2,  # High - security monitoring
            "network": 3,  # High - network security
            "crypto": 4,  # Medium-high - cryptographic controls
            "system": 5,  # Medium - system hardening
            "service": 6,  # Medium - service configuration
            "permission": 7,  # Medium-low - file permissions
            "configuration": 8,  # Lowest - general config
        }

    def get_aegis_mapping(self, scap_rule_id: str) -> Optional[AEGISMapping]:
        """
        Get AEGIS mapping for a specific SCAP rule.

        Args:
            scap_rule_id: Full SCAP/XCCDF rule identifier.

        Returns:
            AEGISMapping if found, None otherwise.

        Example:
            mapping = mapper.get_aegis_mapping("xccdf_rule_ssh_config")
            if mapping:
                print(f"Category: {mapping.rule_category}")
        """
        return self.rule_mappings.get(scap_rule_id)

    def create_remediation_plan(
        self,
        scan_id: str,
        host_id: str,
        failed_rules: List[Dict[str, Any]],
        platform: str = "rhel9",
    ) -> RemediationPlan:
        """
        Create a comprehensive remediation plan for failed SCAP rules.

        This method analyzes failed rules, matches them to AEGIS mappings,
        and creates an optimized execution plan considering:
        - Category-based priority ordering
        - Dependency resolution
        - Reboot requirements
        - Platform compatibility

        Args:
            scan_id: Source scan identifier for tracking.
            host_id: Target host identifier for remediation.
            failed_rules: List of failed rule dictionaries with 'rule_id' key.
            platform: Target platform (rhel8, rhel9, ubuntu20, ubuntu22).

        Returns:
            RemediationPlan with optimized execution order and metadata.

        Raises:
            ValueError: If scan_id or host_id is empty.

        Example:
            plan = mapper.create_remediation_plan(
                scan_id="scan-123",
                host_id="host-456",
                failed_rules=[{"rule_id": "xccdf_rule_1"}],
                platform="rhel9"
            )
            print(f"Remediable: {plan.remediable_rules}/{plan.total_rules}")
        """
        # Input validation
        if not scan_id or not scan_id.strip():
            raise ValueError("scan_id cannot be empty")
        if not host_id or not host_id.strip():
            raise ValueError("host_id cannot be empty")

        # Generate unique plan identifier with timestamp
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        plan_id = f"plan_{scan_id}_{timestamp}"

        logger.info(f"Creating remediation plan {plan_id} for {len(failed_rules)} failed rules")

        # Initialize tracking variables
        rule_groups: Dict[str, List[AEGISMapping]] = {}
        remediable_count = 0
        total_duration = 0
        needs_reboot = False
        all_dependencies: Set[str] = set()

        # Process each failed rule
        for rule in failed_rules:
            rule_id = rule.get("rule_id", "")
            if not rule_id:
                continue

            mapping = self.get_aegis_mapping(rule_id)

            # Check if mapping exists and supports target platform
            if mapping and platform in mapping.platforms:
                remediable_count += 1

                # Group rules by category for organized execution
                category = mapping.rule_category
                if category not in rule_groups:
                    rule_groups[category] = []
                rule_groups[category].append(mapping)

                # Accumulate execution requirements
                total_duration += mapping.estimated_duration
                if mapping.requires_reboot:
                    needs_reboot = True
                all_dependencies.update(mapping.dependencies)

        # Determine optimal execution order based on priorities and dependencies
        execution_order = self._determine_execution_order(rule_groups, all_dependencies)

        # Check if all dependencies can be resolved on target platform
        dependencies_ok = self._check_dependencies(all_dependencies, platform)

        plan = RemediationPlan(
            plan_id=plan_id,
            scan_id=scan_id,
            host_id=host_id,
            total_rules=len(failed_rules),
            remediable_rules=remediable_count,
            estimated_duration=total_duration,
            requires_reboot=needs_reboot,
            rule_groups=rule_groups,
            execution_order=execution_order,
            dependencies_resolved=dependencies_ok,
        )

        # Persist plan for tracking and audit
        self._save_remediation_plan(plan)

        logger.info(
            f"Created remediation plan: {remediable_count}/{len(failed_rules)} "
            f"rules remediable, estimated {total_duration}s"
        )

        return plan

    def _determine_execution_order(
        self,
        rule_groups: Dict[str, List[AEGISMapping]],
        dependencies: Set[str],
    ) -> List[str]:
        """
        Determine optimal execution order for remediation rules.

        Rules are ordered by:
        1. Category priority (authentication before configuration)
        2. Dependency order (rules without deps before those with deps)

        Args:
            rule_groups: Rules grouped by category.
            dependencies: All dependencies across all rules.

        Returns:
            List of SCAP rule IDs in execution order.
        """
        execution_order: List[str] = []

        # Sort categories by priority (lower value = higher priority)
        sorted_categories = sorted(
            rule_groups.keys(),
            key=lambda cat: self.category_priorities.get(cat, 999),
        )

        # Process rules in priority order
        for category in sorted_categories:
            category_rules = rule_groups[category]

            # Within category: rules without dependencies first
            rules_no_deps = [r for r in category_rules if not r.dependencies]
            rules_with_deps = [r for r in category_rules if r.dependencies]

            # Add rules without dependencies first
            for rule in rules_no_deps:
                execution_order.append(rule.scap_rule_id)

            # Add rules with dependencies second
            for rule in rules_with_deps:
                execution_order.append(rule.scap_rule_id)

        return execution_order

    def _check_dependencies(self, dependencies: Set[str], platform: str) -> bool:
        """
        Check if all dependencies can be resolved on the target platform.

        This performs a basic check against known common packages.
        Full dependency resolution would require package manager queries
        on the target system.

        Args:
            dependencies: Set of package/service dependencies.
            platform: Target platform identifier.

        Returns:
            True if all dependencies are in the known packages list,
            False otherwise.
        """
        # Common packages available on each platform
        # This is a baseline check - actual resolution requires target system query
        common_packages: Dict[str, List[str]] = {
            "rhel8": ["audit", "firewalld", "libpwquality", "openssh-server"],
            "rhel9": ["audit", "firewalld", "libpwquality", "openssh-server"],
            "ubuntu20": ["auditd", "ufw", "libpam-pwquality", "openssh-server"],
            "ubuntu22": ["auditd", "ufw", "libpam-pwquality", "openssh-server"],
        }

        platform_packages = set(common_packages.get(platform, []))
        unresolved = dependencies - platform_packages

        if unresolved:
            logger.warning(f"Unresolved dependencies for {platform}: {unresolved}")
            return False

        return True

    def _save_remediation_plan(self, plan: RemediationPlan) -> None:
        """
        Save remediation plan to file for tracking and audit.

        Plans are saved as JSON files with complete metadata for:
        - Audit trail
        - Plan retrieval and status tracking
        - Integration with external systems

        Args:
            plan: RemediationPlan to persist.
        """
        try:
            plan_file = self.mappings_dir / f"{plan.plan_id}.json"

            # Build serializable plan data
            plan_data = {
                "plan_id": plan.plan_id,
                "scan_id": plan.scan_id,
                "host_id": plan.host_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "total_rules": plan.total_rules,
                "remediable_rules": plan.remediable_rules,
                "estimated_duration": plan.estimated_duration,
                "requires_reboot": plan.requires_reboot,
                "execution_order": plan.execution_order,
                "dependencies_resolved": plan.dependencies_resolved,
                "rule_groups": {},
            }

            # Convert AEGISMapping objects to dictionaries
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

            with open(plan_file, "w", encoding="utf-8") as f:
                json.dump(plan_data, f, indent=2)

            logger.info(f"Saved remediation plan to {plan_file}")

        except (OSError, IOError) as e:
            logger.error(f"Error saving remediation plan: {e}")
        except Exception as e:
            logger.error(f"Unexpected error saving plan: {e}")

    def generate_aegis_job_request(self, plan: RemediationPlan) -> Dict[str, Any]:
        """
        Generate AEGIS job request from remediation plan.

        Creates a structured job request that can be submitted to
        AEGIS for automated remediation execution.

        Args:
            plan: RemediationPlan containing rules to remediate.

        Returns:
            Dictionary containing AEGIS job request specification.

        Raises:
            ValueError: If plan has no remediable rules.

        Example:
            job_request = mapper.generate_aegis_job_request(plan)
            # Submit to AEGIS API
            response = aegis_client.submit_job(job_request)
        """
        if plan.remediable_rules == 0:
            raise ValueError("Plan has no remediable rules")

        # Extract AEGIS rule IDs in execution order
        aegis_rules: List[str] = []
        for scap_rule_id in plan.execution_order:
            mapping = self.get_aegis_mapping(scap_rule_id)
            if mapping:
                aegis_rules.append(mapping.aegis_rule_id)

        # Build AEGIS job request structure
        job_request: Dict[str, Any] = {
            "host_id": plan.host_id,
            "rule_ids": aegis_rules,
            "options": {
                "dry_run": False,
                "force": False,
                "parallel": False,  # Execute in dependency order
                "continue_on_error": True,  # Allow partial success
                "create_restore_point": True,  # Enable rollback
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

    def map_aegis_results_to_scap(
        self,
        aegis_job_id: str,
        aegis_results: Dict[str, Any],
    ) -> Dict[str, str]:
        """
        Map AEGIS remediation results back to SCAP rule status.

        After AEGIS executes remediation, this maps the results
        back to SCAP rule IDs for updating scan status.

        Args:
            aegis_job_id: AEGIS job identifier (for logging).
            aegis_results: AEGIS job result containing execution status.

        Returns:
            Dictionary mapping SCAP rule IDs to status ("pass" or "fail").

        Example:
            results = mapper.map_aegis_results_to_scap(
                aegis_job_id="job-123",
                aegis_results={"executions": [{"rule_id": "RHEL-09-255045", "status": "completed"}]}
            )
            # Returns: {"xccdf_rule_ssh_config": "pass"}
        """
        scap_results: Dict[str, str] = {}

        # Get execution results from AEGIS response
        executions = aegis_results.get("executions", [])

        for execution in executions:
            aegis_rule_id = execution.get("rule_id", "")
            status = execution.get("status", "unknown")

            # Find corresponding SCAP rule
            for scap_id, mapping in self.rule_mappings.items():
                if mapping.aegis_rule_id == aegis_rule_id:
                    # Map AEGIS status to SCAP status
                    scap_results[scap_id] = "pass" if status == "completed" else "fail"
                    break

        logger.info(
            f"Mapped AEGIS job {aegis_job_id} results: "
            f"{sum(1 for s in scap_results.values() if s == 'pass')} passed, "
            f"{sum(1 for s in scap_results.values() if s == 'fail')} failed"
        )

        return scap_results

    def get_manual_remediation_steps(
        self,
        scap_rule_id: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Get manual remediation steps for a SCAP rule.

        Useful for rules that cannot be automatically remediated
        or when manual review is preferred.

        Args:
            scap_rule_id: SCAP rule identifier.

        Returns:
            Dictionary with implementation, verification, and rollback steps,
            or None if no mapping exists.

        Example:
            steps = mapper.get_manual_remediation_steps("xccdf_rule_ssh")
            if steps:
                for step in steps["steps"]:
                    print(f"- {step['description']}")
        """
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

    def export_mappings(self, export_format: str = "yaml") -> str:
        """
        Export all SCAP to AEGIS mappings.

        Useful for backup, sharing, or importing into other systems.

        Args:
            export_format: Output format ("yaml" or "json").

        Returns:
            String containing formatted mappings.

        Raises:
            ValueError: If unsupported format specified.

        Example:
            yaml_export = mapper.export_mappings("yaml")
            with open("mappings.yml", "w") as f:
                f.write(yaml_export)
        """
        export_data: Dict[str, Any] = {}

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

        if export_format == "yaml":
            return yaml.dump(export_data, default_flow_style=False)
        elif export_format == "json":
            return json.dumps(export_data, indent=2)
        else:
            raise ValueError(f"Unsupported format: {export_format}")


def get_aegis_mapper(mappings_dir: str = "/app/data/mappings") -> AegisMapper:
    """
    Get or create the singleton AegisMapper instance.

    This function provides a singleton pattern to reuse the same
    mapper instance across requests, avoiding repeated loading
    of mapping files.

    Args:
        mappings_dir: Directory containing custom mapping files.

    Returns:
        Singleton AegisMapper instance.

    Example:
        mapper = get_aegis_mapper()
        plan = mapper.create_remediation_plan(...)
    """
    global _aegis_mapper_instance

    if _aegis_mapper_instance is None:
        _aegis_mapper_instance = AegisMapper(mappings_dir=mappings_dir)
        logger.info("Initialized AegisMapper singleton")

    return _aegis_mapper_instance
