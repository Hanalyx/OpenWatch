"""
Framework metadata service for discovering available compliance frameworks and variables.

Provides methods to query MongoDB for framework metadata, variable definitions,
and validation logic for variable values.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from motor.motor_asyncio import AsyncIOMotorDatabase

from ..models.scan_config_models import (
    FrameworkMetadata,
    FrameworkVersion,
    ScanTargetType,
    VariableConstraint,
    VariableDefinition,
)

logger = logging.getLogger(__name__)


class FrameworkMetadataService:
    """
    Service for discovering and querying compliance framework metadata.

    Provides methods to:
    - List available frameworks and versions
    - Get variable definitions for a framework/version
    - Validate variable values against constraints
    - Query framework statistics
    """

    def __init__(self, db: AsyncIOMotorDatabase):
        """
        Initialize framework metadata service.

        Args:
            db: MongoDB database instance
        """
        self.db = db
        self.collection = db.compliance_rules

    async def list_frameworks(self) -> List[FrameworkMetadata]:
        """
        List all available compliance frameworks with metadata.

        Queries compliance_rules collection and aggregates framework information.

        Returns:
            List of FrameworkMetadata objects
        """
        logger.info("Listing available frameworks")

        # Get all rules with frameworks field
        all_rules = await self.collection.find({"frameworks": {"$exists": True, "$ne": {}}}, {"frameworks": 1}).to_list(
            length=None
        )

        # Parse nested frameworks structure
        framework_data = {}
        for rule in all_rules:
            frameworks_obj = rule.get("frameworks", {})

            for fw_name, fw_versions in frameworks_obj.items():
                if not isinstance(fw_versions, dict):
                    continue

                if fw_name not in framework_data:
                    framework_data[fw_name] = {"versions": set(), "rule_count": 0}

                # Add versions from this framework
                framework_data[fw_name]["versions"].update(fw_versions.keys())
                framework_data[fw_name]["rule_count"] += 1

        # Build framework metadata list
        frameworks = []
        for fw_name, fw_info in sorted(framework_data.items()):
            # Get variable count (placeholder for now)
            var_count = 0  # TODO: Extract from XCCDF variables when available

            # Create metadata
            metadata = FrameworkMetadata(
                framework=fw_name,
                display_name=self._get_display_name(fw_name),
                versions=sorted(fw_info["versions"]),
                description=self._get_description(fw_name),
                rule_count=fw_info["rule_count"],
                variable_count=var_count,
            )

            frameworks.append(metadata)

        logger.info(f"Found {len(frameworks)} frameworks from nested structure")
        return frameworks

    async def get_framework_details(self, framework: str, version: str) -> FrameworkVersion:
        """
        Get detailed information about a specific framework version.

        Args:
            framework: Framework identifier
            version: Framework version

        Returns:
            FrameworkVersion with complete metadata

        Raises:
            ValueError: Framework/version not found
        """
        logger.info(f"Getting details for {framework}/{version}")

        # Count rules
        rule_count = await self.collection.count_documents({"framework": framework, "framework_version": version})

        if rule_count == 0:
            raise ValueError(f"Framework {framework}/{version} not found")

        # Get variables
        variables = await self.get_variables(framework, version)

        # Get categories
        categories = await self._get_categories(framework, version)

        # Get supported target types
        target_types = await self._get_target_types(framework, version)

        framework_version = FrameworkVersion(
            framework=framework,
            version=version,
            display_name=f"{self._get_display_name(framework)} {version}",
            description=self._get_description(framework),
            rule_count=rule_count,
            variable_count=len(variables),
            variables=variables,
            categories=categories,
            target_types=target_types,
        )

        return framework_version

    async def get_variables(self, framework: str, version: str) -> List[VariableDefinition]:
        """
        Get all variable definitions for a framework/version.

        Queries rules with xccdf_variables field, extracts and deduplicates
        variables, and returns sorted list.

        Args:
            framework: Framework identifier
            version: Framework version

        Returns:
            List of VariableDefinition objects
        """
        logger.info(f"Getting variables for {framework}/{version}")

        # Query rules with variables
        query = {
            "framework": framework,
            "framework_version": version,
            "xccdf_variables": {"$exists": True, "$ne": {}},
        }

        rules = await self.collection.find(query).to_list(length=None)

        # Extract and deduplicate variables
        variables_dict = {}

        for rule in rules:
            xccdf_vars = rule.get("xccdf_variables", {})

            for var_id, var_def in xccdf_vars.items():
                if var_id not in variables_dict:
                    # Convert to VariableDefinition
                    var_definition = self._parse_variable_definition(var_id, var_def)
                    variables_dict[var_id] = var_definition

        # Convert to sorted list
        variables = sorted(variables_dict.values(), key=lambda v: (v.category or "", v.title))

        logger.info(f"Found {len(variables)} variables for {framework}/{version}")
        return variables

    async def validate_variable_value(self, variable_def: VariableDefinition, value: Any) -> Tuple[bool, Optional[str]]:
        """
        Validate a variable value against its definition and constraints.

        Args:
            variable_def: Variable definition with constraints
            value: Value to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Type validation
        valid, error = self._validate_type(variable_def.type, value)
        if not valid:
            return False, error

        # Constraint validation
        if variable_def.constraints:
            valid, error = self._validate_constraints(variable_def.constraints, value, variable_def.type)
            if not valid:
                return False, error

        return True, None

    async def validate_variables(
        self, framework: str, version: str, variables: Dict[str, Any]
    ) -> Tuple[bool, Dict[str, str]]:
        """
        Validate multiple variable values.

        Args:
            framework: Framework identifier
            version: Framework version
            variables: Variable ID -> value mapping

        Returns:
            Tuple of (all_valid, error_dict)
        """
        # Get variable definitions
        var_defs = await self.get_variables(framework, version)
        var_defs_dict = {v.id: v for v in var_defs}

        errors = {}
        all_valid = True

        for var_id, value in variables.items():
            # Check if variable exists
            if var_id not in var_defs_dict:
                errors[var_id] = f"Unknown variable: {var_id}"
                all_valid = False
                continue

            # Validate value
            var_def = var_defs_dict[var_id]
            valid, error = await self.validate_variable_value(var_def, value)

            if not valid:
                errors[var_id] = error
                all_valid = False

        return all_valid, errors

    # Private helper methods

    def _get_display_name(self, framework: str) -> str:
        """Get human-readable framework name."""
        display_names = {
            "nist": "NIST 800-53",
            "cis": "CIS Controls",
            "iso27001": "ISO 27001",
            "pci": "PCI-DSS",
            "pci-dss": "PCI-DSS",
            "stig": "STIG",
            "hipaa": "HIPAA",
            "soc2": "SOC 2",
            "gdpr": "GDPR",
            "fedramp": "FedRAMP",
        }
        return display_names.get(framework, framework.upper() if framework else "Unknown")

    def _get_description(self, framework: str) -> str:
        """Get framework description."""
        descriptions = {
            "nist": "NIST Special Publication 800-53 - Security and Privacy Controls",
            "cis": "CIS Controls - Industry consensus security configuration baselines",
            "iso27001": "ISO/IEC 27001 Information Security Management",
            "pci": "Payment Card Industry Data Security Standard",
            "pci-dss": "Payment Card Industry Data Security Standard",
            "stig": "Security Technical Implementation Guides - DoD security hardening",
            "hipaa": "Health Insurance Portability and Accountability Act",
            "soc2": "SOC 2 Trust Services Criteria",
            "gdpr": "General Data Protection Regulation",
            "fedramp": "Federal Risk and Authorization Management Program",
        }
        return descriptions.get(framework, f"{framework} compliance framework")

    async def _count_variables(self, framework: str) -> int:
        """Count unique variables for a framework."""
        pipeline = [
            {"$match": {"framework": framework, "xccdf_variables": {"$exists": True}}},
            {"$project": {"vars": {"$objectToArray": "$xccdf_variables"}}},
            {"$unwind": "$vars"},
            {"$group": {"_id": "$vars.k"}},
            {"$count": "total"},
        ]

        result = await self.collection.aggregate(pipeline).to_list(length=1)
        return result[0]["total"] if result else 0

    async def _get_categories(self, framework: str, version: str) -> List[str]:
        """Get distinct rule categories."""
        categories = await self.collection.distinct("category", {"framework": framework, "framework_version": version})
        return sorted([c for c in categories if c])

    async def _get_target_types(self, framework: str, version: str) -> List[ScanTargetType]:
        """Get supported target types for framework."""
        # Query scanner_type field
        scanner_types = await self.collection.distinct(
            "scanner_type", {"framework": framework, "framework_version": version}
        )

        # Map scanner types to target types
        target_types = set()

        for scanner_type in scanner_types:
            if scanner_type == "oscap":
                target_types.add(ScanTargetType.SSH_HOST)
                target_types.add(ScanTargetType.LOCAL)
            elif scanner_type == "kubernetes":
                target_types.add(ScanTargetType.KUBERNETES)
            elif scanner_type == "aws_api":
                target_types.add(ScanTargetType.AWS_ACCOUNT)
            elif scanner_type == "azure_api":
                target_types.add(ScanTargetType.AZURE_SUBSCRIPTION)
            elif scanner_type == "gcp_api":
                target_types.add(ScanTargetType.GCP_PROJECT)

        return sorted(list(target_types), key=lambda t: t.value)

    def _parse_variable_definition(self, var_id: str, var_def: Dict[str, Any]) -> VariableDefinition:
        """
        Parse variable definition from MongoDB document.

        Args:
            var_id: Variable identifier
            var_def: Variable definition dict from xccdf_variables

        Returns:
            VariableDefinition object
        """
        # Extract basic fields
        title = var_def.get("title", var_id)
        description = var_def.get("description", "")
        var_type = var_def.get("type", "string")
        default = var_def.get("default")
        interactive = var_def.get("interactive", True)

        # Extract constraints
        constraints = None
        if any(k in var_def for k in ["lower_bound", "upper_bound", "choices", "match"]):
            constraints = VariableConstraint(
                lower_bound=var_def.get("lower_bound"),
                upper_bound=var_def.get("upper_bound"),
                choices=var_def.get("choices"),
                match=var_def.get("match"),
            )

        # Infer category from variable ID
        category = self._infer_category(var_id)

        return VariableDefinition(
            id=var_id,
            title=title,
            description=description,
            type=var_type,
            default=default,
            constraints=constraints,
            interactive=interactive,
            category=category,
        )

    def _infer_category(self, var_id: str) -> Optional[str]:
        """Infer variable category from ID."""
        if "password" in var_id or "auth" in var_id:
            return "Authentication"
        elif "account" in var_id or "user" in var_id:
            return "Access Control"
        elif "audit" in var_id or "log" in var_id:
            return "Auditing"
        elif "firewall" in var_id or "network" in var_id:
            return "Network"
        elif "crypto" in var_id or "encrypt" in var_id:
            return "Cryptography"
        elif "timeout" in var_id or "tmout" in var_id:
            return "Session Management"
        elif "banner" in var_id:
            return "System Hardening"
        return "General"

    def _validate_type(self, var_type: str, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate value matches expected type."""
        if var_type == "number":
            try:
                float(str(value))
                return True, None
            except (ValueError, TypeError):
                return False, f"Value must be a number, got: {type(value).__name__}"

        elif var_type == "boolean":
            if isinstance(value, bool):
                return True, None
            # Accept string representations
            if isinstance(value, str) and value.lower() in ["true", "false"]:
                return True, None
            return False, f"Value must be boolean (true/false), got: {value}"

        elif var_type == "string":
            if isinstance(value, str):
                return True, None
            return False, f"Value must be a string, got: {type(value).__name__}"

        return True, None

    def _validate_constraints(
        self, constraints: VariableConstraint, value: Any, var_type: str
    ) -> Tuple[bool, Optional[str]]:
        """Validate value against constraints."""

        # Range constraints (numbers)
        if var_type == "number":
            num_value = float(str(value))

            if constraints.lower_bound is not None:
                if num_value < constraints.lower_bound:
                    return (
                        False,
                        f"Value {num_value} is below lower bound {constraints.lower_bound}",
                    )

            if constraints.upper_bound is not None:
                if num_value > constraints.upper_bound:
                    return (
                        False,
                        f"Value {num_value} exceeds upper bound {constraints.upper_bound}",
                    )

        # Choice constraints
        if constraints.choices is not None:
            if str(value) not in constraints.choices:
                return (
                    False,
                    f"Value '{value}' not in allowed choices: {', '.join(constraints.choices)}",
                )

        # Pattern constraint (regex)
        if constraints.match is not None:
            try:
                pattern = re.compile(constraints.match)
                if not pattern.match(str(value)):
                    return (
                        False,
                        f"Value '{value}' does not match required pattern: {constraints.match}",
                    )
            except re.error as e:
                logger.error(f"Invalid regex pattern {constraints.match}: {e}")
                return False, f"Invalid constraint pattern"

        return True, None
