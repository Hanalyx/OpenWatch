"""
SCAP to MongoDB Transformation Service for OpenWatch
Transforms parsed SCAP rules into OpenWatch ComplianceRule documents
"""

import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.app.models.mongo_models import FrameworkVersions, PlatformImplementation

logger = logging.getLogger(__name__)


class SCAPTransformationService:
    """Service for transforming SCAP rules to MongoDB documents"""

    # Platform detection patterns
    PLATFORM_PATTERNS = {
        "rhel": [r"red\s*hat", r"rhel", r"centos", r"rocky", r"alma"],
        "ubuntu": [r"ubuntu", r"debian"],
        "windows": [r"windows", r"microsoft"],
        "suse": [r"suse", r"opensuse", r"sles"],
    }

    # Version extraction patterns
    VERSION_PATTERNS = {
        "rhel": r"(?:rhel|red\s*hat).*?(\d+(?:\.\d+)?)",
        "ubuntu": r"ubuntu.*?(\d+\.\d+)",
        "windows": r"windows.*?(\d+(?:\.\d+)?)",
        "suse": r"suse.*?(\d+(?:\.\d+)?)",
    }

    def __init__(self):
        self.transformed_count = 0
        self.errors = []
        self.warnings = []

    def transform_rules(self, parsed_scap: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Transform parsed SCAP rules to OpenWatch format"""
        logger.info(f"Starting transformation of {len(parsed_scap['rules'])} SCAP rules")

        transformed_rules = []
        file_info = {
            "source_file": parsed_scap["file_path"],
            "source_hash": parsed_scap["file_hash"],
            "parsed_at": parsed_scap["parsed_at"],
        }

        for rule in parsed_scap["rules"]:
            try:
                transformed = self._transform_single_rule(rule, file_info)
                if transformed:
                    transformed_rules.append(transformed)
                    self.transformed_count += 1
            except Exception as e:
                logger.error(f"Failed to transform rule {rule.get('scap_rule_id')}: {str(e)}")
                self.errors.append({"rule_id": rule.get("scap_rule_id"), "error": str(e)})

        logger.info(f"Successfully transformed {len(transformed_rules)} rules")
        return transformed_rules

    def _transform_single_rule(self, scap_rule: Dict[str, Any], file_info: Dict[str, Any]) -> Dict[str, Any]:
        """Transform a single SCAP rule to OpenWatch format"""
        scap_id = scap_rule["scap_rule_id"]

        # Generate OpenWatch rule ID
        openwatch_id = self._generate_openwatch_id(scap_id)

        # Create base rule structure
        rule = {
            "rule_id": openwatch_id,
            "scap_rule_id": scap_id,
            "metadata": self._transform_metadata(scap_rule),
            "abstract": False,
            "severity": self._normalize_severity(scap_rule.get("severity")),
            "category": scap_rule.get("category", "system"),
            "security_function": scap_rule.get("security_function", "system_configuration"),
            "tags": scap_rule.get("tags", []),
            "frameworks": self._transform_frameworks(scap_rule.get("frameworks", {})),
            "platform_implementations": self._generate_platform_implementations(scap_rule),
            "check_type": self._determine_check_type(scap_rule),
            "check_content": self._transform_check_content(scap_rule.get("check", {})),
            "fix_available": scap_rule.get("fix", {}).get("available", False),
            "fix_content": self._transform_fix_content(scap_rule.get("fix", {})),
            "remediation_complexity": self._assess_complexity(scap_rule),
            "remediation_risk": self._assess_risk(scap_rule),
            "source_file": Path(file_info["source_file"]).name,
            "source_hash": file_info["source_hash"],
            "version": "1.0.0",
            "imported_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }

        # Add dependencies if available
        rule["dependencies"] = self._extract_dependencies(scap_rule)

        return rule

    def _generate_openwatch_id(self, scap_id: str) -> str:
        """Generate OpenWatch rule ID from SCAP ID"""
        # Remove namespace prefix
        base_id = scap_id.split("_")[-1] if "_" in scap_id else scap_id

        # Clean up the ID
        clean_id = re.sub(r"[^a-z0-9_]", "_", base_id.lower())
        clean_id = re.sub(r"_+", "_", clean_id)
        clean_id = clean_id.strip("_")

        # Ensure it starts with ow-
        if not clean_id.startswith("ow_"):
            clean_id = f"ow_{clean_id}"

        # Replace underscores with hyphens for consistency
        clean_id = clean_id.replace("_", "-")

        return clean_id

    def _transform_metadata(self, scap_rule: Dict[str, Any]) -> Dict[str, Any]:
        """Transform SCAP metadata to OpenWatch format"""
        scap_metadata = scap_rule.get("metadata", {})

        return {
            "name": (scap_metadata.get("title") or "").strip() or "Unnamed Rule",
            "description": (scap_metadata.get("description") or "").strip() or "No description available",
            "rationale": (scap_metadata.get("rationale") or "").strip(),
            "warning": (scap_metadata.get("warning") or "").strip(),
            "source": "SCAP",
            "scap_original_id": scap_rule["scap_rule_id"],
            "identifiers": scap_rule.get("identifiers", {}),
            "references": scap_rule.get("references", {}),
            "severity_justification": self._generate_severity_justification(scap_rule),
        }

    def _normalize_severity(self, severity: Optional[str]) -> str:
        """Normalize severity to OpenWatch standard"""
        if not severity:
            return "medium"

        severity = str(severity).lower().strip()

        severity_map = {
            "info": "info",
            "low": "low",
            "medium": "medium",
            "high": "high",
            "critical": "critical",
            "unknown": "medium",
        }

        return severity_map.get(severity, "medium")

    def _transform_frameworks(self, frameworks: Dict[str, Any]) -> FrameworkVersions:
        """Transform framework mappings to OpenWatch format"""
        return FrameworkVersions(
            nist=frameworks.get("nist", {}),
            cis=frameworks.get("cis", {}),
            stig=frameworks.get("stig", {}),
            pci_dss=frameworks.get("pci_dss", {}),
            iso27001=frameworks.get("iso27001", {}),
            hipaa=frameworks.get("hipaa", {}),
        )

    def _generate_platform_implementations(self, scap_rule: Dict[str, Any]) -> Dict[str, PlatformImplementation]:
        """Generate platform implementations based on SCAP content"""
        implementations = {}

        # Extract platform information from SCAP platforms
        platforms = scap_rule.get("platform", [])
        detected_platforms = self._detect_platforms_from_content(scap_rule)

        # Combine platform sources
        all_platforms = set(platforms + list(detected_platforms.keys()))

        for platform_id in all_platforms:
            platform_info = self._parse_platform_id(platform_id)
            if platform_info:
                platform_name, versions = platform_info

                # Generate implementation based on rule content
                impl = self._generate_platform_implementation(platform_name, versions, scap_rule)

                if impl:
                    implementations[platform_name] = impl

        # If no platforms detected, create generic implementations
        if not implementations:
            implementations = self._create_generic_implementations(scap_rule)

        return implementations

    def _detect_platforms_from_content(self, scap_rule: Dict[str, Any]) -> Dict[str, List[str]]:
        """Detect platforms from rule content"""
        platforms = {}

        # Combine all text content
        text_content = []
        metadata = scap_rule.get("metadata", {})
        text_content.extend(
            [
                metadata.get("title") or "",
                metadata.get("description") or "",
                metadata.get("rationale") or "",
                scap_rule.get("scap_rule_id") or "",
            ]
        )

        combined_text = " ".join(str(item) for item in text_content).lower()

        # Check for platform patterns
        for platform, patterns in self.PLATFORM_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    # Try to extract version
                    version_pattern = self.VERSION_PATTERNS.get(platform)
                    if version_pattern:
                        version_matches = re.findall(version_pattern, combined_text, re.IGNORECASE)
                        versions = [v for v in version_matches if v]
                    else:
                        versions = []

                    if not versions:
                        # Default versions for each platform
                        default_versions = {
                            "rhel": ["8", "9"],
                            "ubuntu": ["20.04", "22.04", "24.04"],
                            "windows": ["10", "11"],
                            "suse": ["15"],
                        }
                        versions = default_versions.get(platform, ["latest"])

                    platforms[platform] = versions
                    break

        return platforms

    def _parse_platform_id(self, platform_id: str) -> Optional[Tuple[str, List[str]]]:
        """Parse SCAP platform ID to platform name and versions"""
        platform_id = platform_id.lower()

        # RHEL patterns
        if "rhel" in platform_id or "red_hat" in platform_id:
            version_match = re.search(r"(\d+(?:\.\d+)?)", platform_id)
            version = version_match.group(1) if version_match else "8"
            return "rhel", [version]

        # Ubuntu patterns
        elif "ubuntu" in platform_id:
            version_match = re.search(r"(\d+\.\d+)", platform_id)
            version = version_match.group(1) if version_match else "22.04"
            return "ubuntu", [version]

        # Windows patterns
        elif "windows" in platform_id:
            version_match = re.search(r"(\d+)", platform_id)
            version = version_match.group(1) if version_match else "10"
            return "windows", [version]

        return None

    def _generate_platform_implementation(
        self, platform: str, versions: List[str], scap_rule: Dict[str, Any]
    ) -> PlatformImplementation:
        """Generate platform implementation from SCAP rule"""
        scap_rule.get("check", {})
        scap_rule.get("fix", {})

        # Base implementation
        impl = PlatformImplementation(versions=versions)

        # Generate check command based on rule content
        check_command = self._generate_check_command(platform, scap_rule)
        if check_command:
            impl.check_command = check_command

        # Determine check method
        impl.check_method = self._determine_check_method(scap_rule)

        # Extract configuration files
        config_files = self._extract_config_files(scap_rule)
        if config_files:
            impl.config_files = config_files

        # Generate enable/fix command
        enable_command = self._generate_enable_command(platform, scap_rule)
        if enable_command:
            impl.enable_command = enable_command

        # Generate validation command
        validation_command = self._generate_validation_command(platform, scap_rule)
        if validation_command:
            impl.validation_command = validation_command

        # Extract service dependencies
        dependencies = self._extract_service_dependencies(scap_rule)
        if dependencies:
            impl.service_dependencies = dependencies

        return impl

    def _create_generic_implementations(self, scap_rule: Dict[str, Any]) -> Dict[str, PlatformImplementation]:
        """Create generic platform implementations"""
        implementations = {}

        # Default platforms
        default_platforms = {"rhel": ["8", "9"], "ubuntu": ["20.04", "22.04", "24.04"]}

        for platform, versions in default_platforms.items():
            impl = self._generate_platform_implementation(platform, versions, scap_rule)
            implementations[platform] = impl

        return implementations

    def _determine_check_type(self, scap_rule: Dict[str, Any]) -> str:
        """Determine check type from SCAP rule"""
        check = scap_rule.get("check", {})
        system = (check.get("system") or "").lower()

        # Map SCAP check systems to OpenWatch check types
        if "oval" in system:
            return "oval"
        elif "ocil" in system:
            return "script"
        elif "compliance" in system:
            return "command"
        else:
            # Determine from content
            content = scap_rule.get("metadata", {})
            combined_text = f"{content.get('title') or ''} {content.get('description') or ''}".lower()

            if "file" in combined_text or "config" in combined_text:
                return "file"
            elif "service" in combined_text or "daemon" in combined_text:
                return "service"
            elif "package" in combined_text or "rpm" in combined_text:
                return "package"
            elif "kernel" in combined_text or "sysctl" in combined_text:
                return "kernel"
            else:
                return "script"

    def _transform_check_content(self, check: Dict[str, Any]) -> Dict[str, Any]:
        """Transform SCAP check content to OpenWatch format"""
        check_content = {
            "check_type": "command",
            "oval_reference": None,
            "ocil_reference": None,
        }

        system = (check.get("system") or "").lower()
        content = check.get("content", {})

        if "oval" in system:
            check_content["check_type"] = "oval"
            check_content["oval_reference"] = {
                "system": check.get("system", ""),
                "href": content.get("href", ""),
                "name": content.get("name", ""),
            }
        elif "ocil" in system:
            check_content["check_type"] = "script"
            check_content["ocil_reference"] = {
                "system": check.get("system", ""),
                "href": content.get("href", ""),
                "name": content.get("name", ""),
            }
        else:
            check_content["check_type"] = "command"

        return check_content

    def _transform_fix_content(self, fix: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Transform SCAP fix content to OpenWatch format"""
        if not fix.get("available"):
            return None

        fix_content = {}
        fixes = fix.get("fixes", [])

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
            elif "puppet" in system:
                fix_content["puppet"] = {
                    "content": content,
                    "complexity": fix_item.get("complexity", "low"),
                }

        return fix_content if fix_content else None

    def _generate_check_command(self, platform: str, scap_rule: Dict[str, Any]) -> Optional[str]:
        """Generate check command for platform"""
        # This would contain platform-specific logic
        # For now, return a generic placeholder
        rule_id = scap_rule.get("scap_rule_id", "")

        if "sshd" in rule_id.lower():
            return "grep '^PermitRootLogin no' /etc/ssh/sshd_config"
        elif "audit" in rule_id.lower():
            return "auditctl -l | grep -E '(syscall|file)'"
        elif "firewall" in rule_id.lower():
            if platform == "rhel":
                return "firewall-cmd --list-all"
            else:
                return "ufw status verbose"
        else:
            return "# Platform-specific check command needed"

    def _determine_check_method(self, scap_rule: Dict[str, Any]) -> str:
        """Determine check method from rule content"""
        rule_id = scap_rule.get("scap_rule_id") or ""
        metadata = scap_rule.get("metadata", {})
        combined_text = f"{rule_id} {metadata.get('title') or ''} {metadata.get('description') or ''}".lower()

        if "file" in combined_text or "config" in combined_text:
            return "file"
        elif "service" in combined_text or "systemd" in combined_text:
            return "systemd"
        elif "package" in combined_text:
            return "package"
        elif "command" in combined_text:
            return "command"
        else:
            return "command"

    def _extract_config_files(self, scap_rule: Dict[str, Any]) -> List[str]:
        """Extract configuration files from rule content"""
        config_files = []

        # Common file paths patterns
        file_patterns = [
            r"/etc/[^\s]+\.conf?",
            r"/etc/[^\s]+/[^\s]+\.conf?",
            r"/etc/ssh/[^\s]+",
            r"/etc/audit/[^\s]+",
            r"/etc/security/[^\s]+",
            r"/etc/pam\.d/[^\s]+",
            r"/etc/systemd/[^\s]+",
            r"/proc/sys/[^\s]+",
            r"/sys/[^\s]+",
        ]

        # Search in all text content
        metadata = scap_rule.get("metadata", {})
        text_content = f"{metadata.get('description', '')} {metadata.get('rationale', '')}"

        for pattern in file_patterns:
            matches = re.findall(pattern, text_content)
            config_files.extend(matches)

        # Remove duplicates and sort
        return sorted(list(set(config_files)))

    def _generate_enable_command(self, platform: str, scap_rule: Dict[str, Any]) -> Optional[str]:
        """Generate enable/fix command for platform"""
        # This would contain remediation logic
        return "# Platform-specific remediation command needed"

    def _generate_validation_command(self, platform: str, scap_rule: Dict[str, Any]) -> Optional[str]:
        """Generate validation command for platform"""
        # Use the same as check command for now
        return self._generate_check_command(platform, scap_rule)

    def _extract_service_dependencies(self, scap_rule: Dict[str, Any]) -> List[str]:
        """Extract service dependencies from rule content"""
        dependencies = []

        # Common service patterns
        service_patterns = [
            r"openssh-server",
            r"auditd",
            r"rsyslog",
            r"firewalld",
            r"iptables",
            r"systemd",
            r"chrony",
            r"ntp",
        ]

        metadata = scap_rule.get("metadata", {})
        text_content = f"{metadata.get('description') or ''} {metadata.get('rationale') or ''}".lower()

        for pattern in service_patterns:
            if pattern in text_content:
                dependencies.append(pattern)

        return list(set(dependencies))

    def _extract_dependencies(self, scap_rule: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract rule dependencies"""
        return {"requires": [], "conflicts": [], "related": []}

    def _assess_complexity(self, scap_rule: Dict[str, Any]) -> str:
        """Assess remediation complexity"""
        fix = scap_rule.get("fix", {})
        fixes = fix.get("fixes", [])

        for fix_item in fixes:
            complexity = fix_item.get("complexity", "medium")
            if complexity in ["high", "medium", "low"]:
                return complexity

        # Assess based on content
        metadata = scap_rule.get("metadata", {})
        combined_text = f"{metadata.get('description') or ''} {metadata.get('rationale') or ''}".lower()

        if "kernel" in combined_text or "reboot" in combined_text:
            return "high"
        elif "service" in combined_text or "config" in combined_text:
            return "medium"
        else:
            return "low"

    def _assess_risk(self, scap_rule: Dict[str, Any]) -> str:
        """Assess remediation risk"""
        fix = scap_rule.get("fix", {})
        fixes = fix.get("fixes", [])

        for fix_item in fixes:
            disruption = fix_item.get("disruption", "low")
            if disruption in ["high", "medium", "low"]:
                return disruption

        # Assess based on severity and content
        severity = scap_rule.get("severity", "medium")
        if severity in ["high", "critical"]:
            return "medium"  # High severity issues might have medium risk fixes
        else:
            return "low"

    def _generate_severity_justification(self, scap_rule: Dict[str, Any]) -> str:
        """Generate severity justification"""
        severity = scap_rule.get("severity", "medium")
        category = scap_rule.get("category", "system")

        justifications = {
            "critical": f"Critical {category} security control that directly impacts system security",
            "high": f"High-impact {category} control that significantly affects security posture",
            "medium": f"Important {category} control that enhances security configuration",
            "low": f"Recommended {category} setting that provides additional security hardening",
            "info": f"Informational {category} check for compliance visibility",
        }

        return justifications.get(severity, f"Standard {category} security configuration")
