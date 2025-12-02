"""
Content Transformer for OpenWatch

This module provides transformation services to convert parsed compliance content
into MongoDB ComplianceRule documents. It handles:
- Rule ID generation (OpenWatch format)
- Metadata normalization
- Framework mapping transformation
- Platform implementation generation
- Check and fix content transformation

The transformer preserves all compliance-relevant information while adapting
the structure to OpenWatch's internal representation optimized for:
- Efficient querying by framework, severity, category
- Platform-specific implementation details
- Remediation guidance and automation

Security Considerations:
- Input validation on all parsed content
- Safe string handling for all text fields
- No shell command construction from user input

Usage:
    from backend.app.services.content.transformation import MongoDBTransformer

    transformer = MongoDBTransformer()
    result = transformer.transform(parsed_content)
    for rule in result.rules:
        # Each rule is ready for MongoDB insertion
        await collection.insert_one(rule)
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.app.models.mongo_models import FrameworkVersions, PlatformImplementation

from ..exceptions import ContentTransformationError  # noqa: F401
from ..models import ContentSeverity, ParsedContent, ParsedRule

logger = logging.getLogger(__name__)


# Platform detection patterns for content analysis
# Used to identify applicable platforms from rule text content
PLATFORM_PATTERNS: Dict[str, List[str]] = {
    "rhel": [r"red\s*hat", r"rhel", r"centos", r"rocky", r"alma"],
    "ubuntu": [r"ubuntu", r"debian"],
    "windows": [r"windows", r"microsoft"],
    "suse": [r"suse", r"opensuse", r"sles"],
}


# Version extraction patterns for each platform family
VERSION_PATTERNS: Dict[str, str] = {
    "rhel": r"(?:rhel|red\s*hat).*?(\d+(?:\.\d+)?)",
    "ubuntu": r"ubuntu.*?(\d+\.\d+)",
    "windows": r"windows.*?(\d+(?:\.\d+)?)",
    "suse": r"suse.*?(\d+(?:\.\d+)?)",
}


# Default platform versions when specific versions cannot be detected
DEFAULT_PLATFORM_VERSIONS: Dict[str, List[str]] = {
    "rhel": ["8", "9"],
    "ubuntu": ["20.04", "22.04", "24.04"],
    "windows": ["10", "11"],
    "suse": ["15"],
}


@dataclass
class TransformationResult:
    """
    Result of a content transformation operation.

    Contains the transformed rules and statistics about the transformation.

    Attributes:
        rules: List of transformed rule dictionaries ready for MongoDB
        success_count: Number of successfully transformed rules
        error_count: Number of rules that failed transformation
        errors: List of error details for failed rules
        warnings: List of non-fatal warnings
        source_file: Source file path (if available)
        transformed_at: Timestamp of transformation
    """

    rules: List[Dict[str, Any]] = field(default_factory=list)
    success_count: int = 0
    error_count: int = 0
    errors: List[Dict[str, str]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    source_file: str = ""
    transformed_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for JSON serialization."""
        return {
            "success_count": self.success_count,
            "error_count": self.error_count,
            "total_rules": len(self.rules),
            "errors": self.errors,
            "warnings": self.warnings,
            "source_file": self.source_file,
            "transformed_at": self.transformed_at.isoformat(),
        }


class MongoDBTransformer:
    """
    Transformer for converting ParsedContent to MongoDB ComplianceRule format.

    This class handles the transformation of parsed SCAP/XCCDF content into
    the MongoDB document format used by OpenWatch's ComplianceRule collection.
    It generates OpenWatch rule IDs, normalizes metadata, and creates
    platform-specific implementation details.

    Attributes:
        transformed_count: Counter for successfully transformed rules
        errors: List of transformation errors
        warnings: List of non-fatal warnings

    Example:
        >>> from backend.app.services.content.parsers import SCAPParser
        >>> parser = SCAPParser()
        >>> content = parser.parse("/path/to/benchmark.xml")
        >>>
        >>> transformer = MongoDBTransformer()
        >>> result = transformer.transform(content)
        >>> print(f"Transformed {result.success_count} rules")
    """

    def __init__(self) -> None:
        """Initialize the MongoDB transformer."""
        self.transformed_count: int = 0
        self.errors: List[Dict[str, str]] = []
        self.warnings: List[str] = []

    def transform(self, parsed_content: ParsedContent) -> TransformationResult:
        """
        Transform parsed content to MongoDB ComplianceRule format.

        This is the main entry point for transformation. It processes all
        rules from the parsed content and returns a TransformationResult
        containing the transformed rules and statistics.

        Args:
            parsed_content: ParsedContent object from a parser.

        Returns:
            TransformationResult with transformed rules and statistics.

        Raises:
            ContentTransformationError: If transformation fails critically.
        """
        # Reset state for new transformation
        self._reset_state()

        logger.info(
            "Starting transformation of %d rules from %s",
            parsed_content.rule_count,
            parsed_content.source_file or "bytes",
        )

        # Build file info for provenance tracking
        file_info = {
            "source_file": parsed_content.source_file,
            "source_hash": parsed_content.metadata.get("file_hash", ""),
            "parsed_at": parsed_content.parse_timestamp.isoformat(),
        }

        transformed_rules: List[Dict[str, Any]] = []

        for rule in parsed_content.rules:
            try:
                transformed = self._transform_rule(rule, file_info)
                if transformed:
                    transformed_rules.append(transformed)
                    self.transformed_count += 1
            except Exception as e:
                logger.error("Failed to transform rule %s: %s", rule.rule_id, str(e))
                self.errors.append(
                    {
                        "rule_id": rule.rule_id,
                        "error": str(e),
                    }
                )

        logger.info(
            "Successfully transformed %d rules (%d errors)",
            self.transformed_count,
            len(self.errors),
        )

        return TransformationResult(
            rules=transformed_rules,
            success_count=self.transformed_count,
            error_count=len(self.errors),
            errors=self.errors.copy(),
            warnings=self.warnings.copy(),
            source_file=parsed_content.source_file,
        )

    def _reset_state(self) -> None:
        """Reset transformer state for a new transformation."""
        self.transformed_count = 0
        self.errors.clear()
        self.warnings.clear()

    def _transform_rule(
        self,
        parsed_rule: ParsedRule,
        file_info: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Transform a single ParsedRule to MongoDB format.

        Args:
            parsed_rule: The ParsedRule to transform.
            file_info: Source file information for provenance.

        Returns:
            Dictionary ready for MongoDB insertion.
        """
        # Generate OpenWatch rule ID
        openwatch_id = self._generate_openwatch_id(parsed_rule.rule_id)

        # Extract category from metadata or determine from content
        category = parsed_rule.metadata.get("category", "system")
        if not category or category == "system":
            category = self._determine_category(parsed_rule)

        # Build the MongoDB document
        rule: Dict[str, Any] = {
            "rule_id": openwatch_id,
            "scap_rule_id": parsed_rule.rule_id,
            "metadata": self._transform_metadata(parsed_rule),
            "abstract": False,
            "severity": self._normalize_severity(parsed_rule.severity),
            "category": category,
            "security_function": self._determine_security_function(category),
            "tags": parsed_rule.metadata.get("tags", []),
            "frameworks": self._transform_frameworks(parsed_rule),
            "platform_implementations": self._generate_platform_implementations(parsed_rule),
            "check_type": self._determine_check_type(parsed_rule),
            "check_content": self._transform_check_content(parsed_rule),
            "fix_available": bool(parsed_rule.fix_content),
            "fix_content": self._transform_fix_content(parsed_rule),
            "remediation_complexity": self._assess_complexity(parsed_rule),
            "remediation_risk": self._assess_risk(parsed_rule),
            "source_file": Path(file_info["source_file"]).name if file_info["source_file"] else "",
            "source_hash": file_info["source_hash"],
            "version": "1.0.0",
            "imported_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "dependencies": self._extract_dependencies(parsed_rule),
        }

        return rule

    def _generate_openwatch_id(self, scap_id: str) -> str:
        """
        Generate OpenWatch rule ID from SCAP rule ID.

        Converts SCAP IDs like 'xccdf_org.ssgproject.content_rule_accounts_password_minlen'
        to OpenWatch IDs like 'ow-accounts-password-minlen'.

        Args:
            scap_id: Original SCAP rule ID.

        Returns:
            OpenWatch-formatted rule ID.
        """
        # Remove namespace prefix (everything before last underscore section)
        parts = scap_id.split("_")

        # Find the meaningful part (usually after 'rule_')
        rule_idx = -1
        for i, part in enumerate(parts):
            if part == "rule":
                rule_idx = i
                break

        if rule_idx >= 0 and rule_idx < len(parts) - 1:
            # Join parts after 'rule_'
            base_id = "_".join(parts[rule_idx + 1 :])
        else:
            # Fallback to last part or full ID
            base_id = parts[-1] if len(parts) > 1 else scap_id

        # Clean up the ID: lowercase, alphanumeric and underscores only
        clean_id = re.sub(r"[^a-z0-9_]", "_", base_id.lower())
        clean_id = re.sub(r"_+", "_", clean_id)  # Collapse multiple underscores
        clean_id = clean_id.strip("_")

        # Ensure it starts with ow-
        if not clean_id.startswith("ow_"):
            clean_id = f"ow_{clean_id}"

        # Replace underscores with hyphens for URL-friendliness
        clean_id = clean_id.replace("_", "-")

        return clean_id

    def _transform_metadata(self, parsed_rule: ParsedRule) -> Dict[str, Any]:
        """
        Transform rule metadata to OpenWatch format.

        Args:
            parsed_rule: The ParsedRule to extract metadata from.

        Returns:
            Metadata dictionary in OpenWatch format.
        """
        return {
            "name": parsed_rule.title.strip() or "Unnamed Rule",
            "description": parsed_rule.description.strip() or "No description available",
            "rationale": parsed_rule.rationale.strip(),
            "warning": parsed_rule.metadata.get("warning", ""),
            "source": "SCAP",
            "scap_original_id": parsed_rule.rule_id,
            "identifiers": parsed_rule.metadata.get("identifiers", {}),
            "references": parsed_rule.references,
            "severity_justification": self._generate_severity_justification(parsed_rule),
        }

    def _normalize_severity(self, severity: ContentSeverity) -> str:
        """
        Normalize ContentSeverity to string for MongoDB.

        Args:
            severity: ContentSeverity enum value.

        Returns:
            Severity string (critical, high, medium, low, info).
        """
        severity_map = {
            ContentSeverity.CRITICAL: "critical",
            ContentSeverity.HIGH: "high",
            ContentSeverity.MEDIUM: "medium",
            ContentSeverity.LOW: "low",
            ContentSeverity.INFO: "info",
            ContentSeverity.UNKNOWN: "medium",  # Default unknown to medium
        }
        return severity_map.get(severity, "medium")

    def _determine_category(self, parsed_rule: ParsedRule) -> str:
        """
        Determine rule category from content analysis.

        Args:
            parsed_rule: The ParsedRule to analyze.

        Returns:
            Category string.
        """
        combined_text = (
            f"{parsed_rule.rule_id} {parsed_rule.title} {parsed_rule.description}".lower()
        )

        # Category patterns (priority order)
        category_patterns = {
            "authentication": ["auth", "login", "password", "pam", "sudo", "su"],
            "access_control": ["permission", "ownership", "acl", "rbac", "selinux"],
            "audit": ["audit", "log", "rsyslog", "journald"],
            "network": ["firewall", "iptables", "tcp", "udp", "port", "network"],
            "crypto": ["crypto", "encrypt", "certificate", "tls", "ssl", "key"],
            "kernel": ["kernel", "sysctl", "module", "grub"],
            "service": ["service", "daemon", "systemd", "xinetd"],
            "filesystem": ["mount", "partition", "filesystem", "disk"],
            "package": ["package", "rpm", "yum", "dnf", "update"],
            "system": ["system", "boot", "init", "cron"],
        }

        for category, keywords in category_patterns.items():
            for keyword in keywords:
                if keyword in combined_text:
                    return category

        return "system"

    def _determine_security_function(self, category: str) -> str:
        """
        Determine high-level security function from category.

        Args:
            category: Rule category.

        Returns:
            Security function string.
        """
        function_map = {
            "authentication": "identity_management",
            "access_control": "access_management",
            "audit": "security_monitoring",
            "network": "network_protection",
            "crypto": "data_encryption",
            "kernel": "system_hardening",
            "service": "service_management",
            "filesystem": "data_protection",
            "package": "vulnerability_management",
            "system": "system_configuration",
        }
        return function_map.get(category, "system_configuration")

    def _transform_frameworks(self, parsed_rule: ParsedRule) -> FrameworkVersions:
        """
        Transform framework references to FrameworkVersions model.

        Args:
            parsed_rule: The ParsedRule with framework references.

        Returns:
            FrameworkVersions object.
        """
        frameworks = parsed_rule.metadata.get("frameworks", {})

        return FrameworkVersions(
            nist=frameworks.get("nist", {}),
            cis=frameworks.get("cis", {}),
            stig=frameworks.get("stig", {}),
            pci_dss=frameworks.get("pci_dss", {}),
            iso27001=frameworks.get("iso27001", {}),
            hipaa=frameworks.get("hipaa", {}),
        )

    def _generate_platform_implementations(
        self,
        parsed_rule: ParsedRule,
    ) -> Dict[str, PlatformImplementation]:
        """
        Generate platform implementations from rule content.

        Analyzes the rule to determine applicable platforms and generates
        platform-specific implementation details.

        Args:
            parsed_rule: The ParsedRule to analyze.

        Returns:
            Dictionary mapping platform names to PlatformImplementation objects.
        """
        implementations: Dict[str, PlatformImplementation] = {}

        # Get platforms from parsed rule
        explicit_platforms = set(parsed_rule.platforms)

        # Detect platforms from content
        detected_platforms = self._detect_platforms_from_content(parsed_rule)

        # Combine platform sources
        all_platforms = explicit_platforms.union(set(detected_platforms.keys()))

        for platform_id in all_platforms:
            platform_info = self._parse_platform_id(platform_id)
            if platform_info:
                platform_name, versions = platform_info
                impl = self._create_platform_implementation(
                    platform_name,
                    versions,
                    parsed_rule,
                )
                if impl:
                    implementations[platform_name] = impl

        # Create generic implementations if no platforms detected
        if not implementations:
            implementations = self._create_generic_implementations(parsed_rule)

        return implementations

    def _detect_platforms_from_content(
        self,
        parsed_rule: ParsedRule,
    ) -> Dict[str, List[str]]:
        """
        Detect platforms from rule content text.

        Args:
            parsed_rule: The ParsedRule to analyze.

        Returns:
            Dictionary mapping platform names to version lists.
        """
        platforms: Dict[str, List[str]] = {}

        combined_text = (
            f"{parsed_rule.rule_id} {parsed_rule.title} "
            f"{parsed_rule.description} {parsed_rule.rationale}"
        ).lower()

        for platform, patterns in PLATFORM_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    # Try to extract version
                    version_pattern = VERSION_PATTERNS.get(platform)
                    if version_pattern:
                        version_matches = re.findall(
                            version_pattern,
                            combined_text,
                            re.IGNORECASE,
                        )
                        versions = [v for v in version_matches if v]
                    else:
                        versions = []

                    if not versions:
                        versions = DEFAULT_PLATFORM_VERSIONS.get(platform, ["latest"])

                    platforms[platform] = versions
                    break

        return platforms

    def _parse_platform_id(self, platform_id: str) -> Optional[Tuple[str, List[str]]]:
        """
        Parse SCAP platform ID to platform name and versions.

        Args:
            platform_id: SCAP platform identifier (e.g., CPE ID).

        Returns:
            Tuple of (platform_name, versions) or None if not recognized.
        """
        platform_id_lower = platform_id.lower()

        # RHEL patterns
        if "rhel" in platform_id_lower or "red_hat" in platform_id_lower:
            version_match = re.search(r"(\d+(?:\.\d+)?)", platform_id_lower)
            version = version_match.group(1) if version_match else "8"
            return "rhel", [version]

        # Ubuntu patterns
        if "ubuntu" in platform_id_lower:
            version_match = re.search(r"(\d+\.\d+)", platform_id_lower)
            version = version_match.group(1) if version_match else "22.04"
            return "ubuntu", [version]

        # Windows patterns
        if "windows" in platform_id_lower:
            version_match = re.search(r"(\d+)", platform_id_lower)
            version = version_match.group(1) if version_match else "10"
            return "windows", [version]

        return None

    def _create_platform_implementation(
        self,
        platform: str,
        versions: List[str],
        parsed_rule: ParsedRule,
    ) -> PlatformImplementation:
        """
        Create a PlatformImplementation for a specific platform.

        Args:
            platform: Platform name (rhel, ubuntu, etc.)
            versions: List of applicable versions.
            parsed_rule: The source ParsedRule.

        Returns:
            PlatformImplementation object.
        """
        impl = PlatformImplementation(versions=versions)

        # Generate check command
        check_command = self._generate_check_command(platform, parsed_rule)
        if check_command:
            impl.check_command = check_command

        # Determine check method
        impl.check_method = self._determine_check_method(parsed_rule)

        # Extract configuration files
        config_files = self._extract_config_files(parsed_rule)
        if config_files:
            impl.config_files = config_files

        # Generate enable/fix command placeholder
        impl.enable_command = "# Platform-specific remediation command needed"

        # Generate validation command (same as check for now)
        impl.validation_command = check_command

        # Extract service dependencies
        dependencies = self._extract_service_dependencies(parsed_rule)
        if dependencies:
            impl.service_dependencies = dependencies

        return impl

    def _create_generic_implementations(
        self,
        parsed_rule: ParsedRule,
    ) -> Dict[str, PlatformImplementation]:
        """
        Create generic platform implementations when no specific platform detected.

        Args:
            parsed_rule: The source ParsedRule.

        Returns:
            Dictionary of generic platform implementations.
        """
        implementations: Dict[str, PlatformImplementation] = {}

        for platform, versions in DEFAULT_PLATFORM_VERSIONS.items():
            if platform in ["rhel", "ubuntu"]:  # Only Linux by default
                impl = self._create_platform_implementation(
                    platform,
                    versions,
                    parsed_rule,
                )
                implementations[platform] = impl

        return implementations

    def _generate_check_command(
        self,
        platform: str,
        parsed_rule: ParsedRule,
    ) -> Optional[str]:
        """
        Generate a check command for the platform.

        This is a basic implementation that generates common check commands
        based on rule content patterns.

        Args:
            platform: Platform name.
            parsed_rule: The source ParsedRule.

        Returns:
            Check command string or None.
        """
        rule_id = parsed_rule.rule_id.lower()

        # SSH-related checks
        if "sshd" in rule_id or "ssh" in rule_id:
            return "grep -E '^(PermitRootLogin|PasswordAuthentication)' /etc/ssh/sshd_config"

        # Audit-related checks
        if "audit" in rule_id:
            return "auditctl -l | head -20"

        # Firewall checks
        if "firewall" in rule_id:
            if platform == "rhel":
                return "firewall-cmd --list-all 2>/dev/null || iptables -L -n"
            return "ufw status verbose 2>/dev/null || iptables -L -n"

        # Generic placeholder
        return "# Platform-specific check command needed"

    def _determine_check_method(self, parsed_rule: ParsedRule) -> str:
        """
        Determine the check method from rule content.

        Args:
            parsed_rule: The source ParsedRule.

        Returns:
            Check method string (file, systemd, package, command).
        """
        combined_text = (
            f"{parsed_rule.rule_id} {parsed_rule.title} {parsed_rule.description}"
        ).lower()

        if "file" in combined_text or "config" in combined_text:
            return "file"
        if "service" in combined_text or "systemd" in combined_text:
            return "systemd"
        if "package" in combined_text:
            return "package"

        return "command"

    def _extract_config_files(self, parsed_rule: ParsedRule) -> List[str]:
        """
        Extract configuration file paths from rule content.

        Args:
            parsed_rule: The source ParsedRule.

        Returns:
            List of configuration file paths.
        """
        config_files: List[str] = []

        file_patterns = [
            r"/etc/[^\s]+\.conf?",
            r"/etc/[^\s]+/[^\s]+\.conf?",
            r"/etc/ssh/[^\s]+",
            r"/etc/audit/[^\s]+",
            r"/etc/security/[^\s]+",
            r"/etc/pam\.d/[^\s]+",
        ]

        text_content = f"{parsed_rule.description} {parsed_rule.rationale}"

        for pattern in file_patterns:
            matches = re.findall(pattern, text_content)
            config_files.extend(matches)

        return sorted(list(set(config_files)))

    def _extract_service_dependencies(self, parsed_rule: ParsedRule) -> List[str]:
        """
        Extract service dependencies from rule content.

        Args:
            parsed_rule: The source ParsedRule.

        Returns:
            List of service names.
        """
        dependencies: List[str] = []

        service_patterns = [
            "openssh-server",
            "auditd",
            "rsyslog",
            "firewalld",
            "iptables",
            "chrony",
            "ntp",
        ]

        text_content = f"{parsed_rule.description} {parsed_rule.rationale}".lower()

        for pattern in service_patterns:
            if pattern in text_content:
                dependencies.append(pattern)

        return list(set(dependencies))

    def _determine_check_type(self, parsed_rule: ParsedRule) -> str:
        """
        Determine the check type from rule content.

        Args:
            parsed_rule: The source ParsedRule.

        Returns:
            Check type string (oval, script, command, file, service, package, kernel).
        """
        check_info = parsed_rule.metadata.get("check", {})
        system = (check_info.get("system") or "").lower()

        # Map SCAP check systems to OpenWatch check types
        if "oval" in system:
            return "oval"
        if "ocil" in system:
            return "script"

        # Determine from content
        combined_text = f"{parsed_rule.title} {parsed_rule.description}".lower()

        if "file" in combined_text or "config" in combined_text:
            return "file"
        if "service" in combined_text or "daemon" in combined_text:
            return "service"
        if "package" in combined_text or "rpm" in combined_text:
            return "package"
        if "kernel" in combined_text or "sysctl" in combined_text:
            return "kernel"

        return "script"

    def _transform_check_content(self, parsed_rule: ParsedRule) -> Dict[str, Any]:
        """
        Transform check content to OpenWatch format.

        Args:
            parsed_rule: The source ParsedRule.

        Returns:
            Check content dictionary.
        """
        check_info = parsed_rule.metadata.get("check", {})
        system = (check_info.get("system") or "").lower()

        check_content: Dict[str, Any] = {
            "check_type": "command",
            "oval_reference": None,
            "ocil_reference": None,
        }

        if "oval" in system:
            check_content["check_type"] = "oval"
            check_content["oval_reference"] = {
                "system": check_info.get("system", ""),
                "href": check_info.get("href", ""),
                "name": check_info.get("name", ""),
            }
        elif "ocil" in system:
            check_content["check_type"] = "script"
            check_content["ocil_reference"] = {
                "system": check_info.get("system", ""),
                "href": check_info.get("href", ""),
                "name": check_info.get("name", ""),
            }

        return check_content

    def _transform_fix_content(
        self,
        parsed_rule: ParsedRule,
    ) -> Optional[Dict[str, Any]]:
        """
        Transform fix content to OpenWatch format.

        Args:
            parsed_rule: The source ParsedRule.

        Returns:
            Fix content dictionary or None if no fix available.
        """
        fix_info = parsed_rule.metadata.get("fix", {})

        if not fix_info.get("available"):
            return None

        fix_content: Dict[str, Any] = {}

        fixes = fix_info.get("fixes", [])
        for fix_item in fixes:
            system = (fix_item.get("system") or "").lower()
            content = fix_item.get("content", "")

            if "bash" in system or "shell" in system:
                fix_content["shell"] = {
                    "script": content,
                    "requires_root": True,
                    "complexity": fix_item.get("complexity", "low"),
                    "disruption": fix_item.get("disruption", "low"),
                    "reboot": fix_item.get("reboot", False),
                }
            elif "ansible" in system:
                fix_content["ansible"] = {
                    "content": content,
                    "complexity": fix_item.get("complexity", "low"),
                }

        return fix_content if fix_content else None

    def _assess_complexity(self, parsed_rule: ParsedRule) -> str:
        """
        Assess remediation complexity.

        Args:
            parsed_rule: The source ParsedRule.

        Returns:
            Complexity string (high, medium, low).
        """
        fix_info = parsed_rule.metadata.get("fix", {})
        fixes = fix_info.get("fixes", [])

        for fix_item in fixes:
            complexity = fix_item.get("complexity", "")
            if complexity in ["high", "medium", "low"]:
                return complexity

        # Assess from content
        combined_text = f"{parsed_rule.description} {parsed_rule.rationale}".lower()

        if "kernel" in combined_text or "reboot" in combined_text:
            return "high"
        if "service" in combined_text or "config" in combined_text:
            return "medium"

        return "low"

    def _assess_risk(self, parsed_rule: ParsedRule) -> str:
        """
        Assess remediation risk.

        Args:
            parsed_rule: The source ParsedRule.

        Returns:
            Risk string (high, medium, low).
        """
        fix_info = parsed_rule.metadata.get("fix", {})
        fixes = fix_info.get("fixes", [])

        for fix_item in fixes:
            disruption = fix_item.get("disruption", "")
            if disruption in ["high", "medium", "low"]:
                return disruption

        # Default based on severity
        if parsed_rule.severity in [ContentSeverity.HIGH, ContentSeverity.CRITICAL]:
            return "medium"

        return "low"

    def _extract_dependencies(
        self,
        parsed_rule: ParsedRule,
    ) -> Dict[str, List[str]]:
        """
        Extract rule dependencies.

        Args:
            parsed_rule: The source ParsedRule.

        Returns:
            Dependencies dictionary with requires, conflicts, related lists.
        """
        return {
            "requires": [],
            "conflicts": [],
            "related": [],
        }

    def _generate_severity_justification(self, parsed_rule: ParsedRule) -> str:
        """
        Generate severity justification text.

        Args:
            parsed_rule: The source ParsedRule.

        Returns:
            Justification string.
        """
        severity = self._normalize_severity(parsed_rule.severity)
        category = parsed_rule.metadata.get("category", "system")

        justifications = {
            "critical": f"Critical {category} security control that directly impacts system security",
            "high": f"High-impact {category} control that significantly affects security posture",
            "medium": f"Important {category} control that enhances security configuration",
            "low": f"Recommended {category} setting that provides additional security hardening",
            "info": f"Informational {category} check for compliance visibility",
        }

        return justifications.get(severity, f"Standard {category} security configuration")
