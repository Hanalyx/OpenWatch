"""
Smart Group Validation Service

Provides intelligent validation for host-group assignments, ensuring compatibility
between hosts, groups, and SCAP content. Uses machine learning-inspired scoring
and rule-based validation to prevent misconfigurations.
"""

import json
import logging
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from ..database import Host, HostGroup, HostGroupMembership, ScapContent
from ..models.error_models import ErrorCategory, ErrorSeverity
from .system_info_sanitization import SystemInfoSanitizationService

logger = logging.getLogger(__name__)


# Define ValidationError as a simple exception class
class ValidationError(Exception):
    def __init__(
        self,
        message: str,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.severity = severity
        self.context = context


class OSFamily:
    """OS family constants"""

    RHEL = "rhel"
    CENTOS = "centos"
    FEDORA = "fedora"
    UBUNTU = "ubuntu"
    DEBIAN = "debian"
    SUSE = "suse"
    OPENSUSE = "opensuse"
    WINDOWS = "windows"
    WINDOWS_SERVER = "windows_server"
    MACOS = "macos"
    FREEBSD = "freebsd"
    OPENBSD = "openbsd"
    SOLARIS = "solaris"

    # OS family groupings for compatibility
    RHEL_FAMILY = {RHEL, CENTOS, FEDORA}
    DEBIAN_FAMILY = {UBUNTU, DEBIAN}
    SUSE_FAMILY = {SUSE, OPENSUSE}
    WINDOWS_FAMILY = {WINDOWS, WINDOWS_SERVER}
    BSD_FAMILY = {FREEBSD, OPENBSD}


class GroupValidationService:
    """Service for intelligent group validation and compatibility checking"""

    def __init__(self, db: Session):
        self.db = db
        self.sanitization_service = SystemInfoSanitizationService()
        self.cache_duration = timedelta(hours=24)  # Cache compatibility results for 24 hours

    def validate_host_group_compatibility(
        self, host_ids: List[str], group_id: int, user_role: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Validate compatibility between hosts and a group

        Returns detailed validation results including:
        - Compatible hosts
        - Incompatible hosts with reasons
        - Suggestions for alternative groups
        - Overall compatibility score
        """
        group = self.db.query(HostGroup).filter(HostGroup.id == group_id).first()
        if not group:
            raise ValidationError(
                message=f"Group {group_id} not found",
                category=ErrorCategory.RESOURCE,
                severity=ErrorSeverity.ERROR,
                context={"group_id": group_id},
            )

        hosts = self.db.query(Host).filter(Host.id.in_(host_ids)).all()
        if not hosts:
            raise ValidationError(
                message="No hosts found",
                category=ErrorCategory.RESOURCE,
                severity=ErrorSeverity.ERROR,
                context={"host_ids": host_ids},
            )

        # Create typed collections for result dict
        compatible_hosts: List[Dict[str, Any]] = []
        incompatible_hosts: List[Dict[str, Any]] = []
        warnings_list: List[str] = []
        suggestions_dict: Dict[str, Any] = {}
        summary: Dict[str, Any] = {
            "total_hosts": len(hosts),
            "compatible_count": 0,
            "incompatible_count": 0,
            "compatibility_score": 0.0,
        }

        results: Dict[str, Any] = {
            "group": {
                "id": group.id,
                "name": group.name,
                "os_family": group.os_family,
                "os_version_pattern": group.os_version_pattern,
                "compliance_framework": group.compliance_framework,
                "scap_content_id": group.scap_content_id,
            },
            "compatible": compatible_hosts,
            "incompatible": incompatible_hosts,
            "warnings": warnings_list,
            "suggestions": suggestions_dict,
            "summary": summary,
        }

        # Check each host
        for host in hosts:
            compatibility = self._check_host_compatibility(host, group, user_role)

            host_info = {
                "id": str(host.id),
                "hostname": host.hostname,
                "os": host.operating_system,
                "os_family": host.os_family,
                "os_version": host.os_version,
                "architecture": host.architecture,
                "compatibility_score": compatibility["score"],
                "validation_details": compatibility["details"],
            }

            if compatibility["is_compatible"]:
                compatible_hosts.append(host_info)
                summary["compatible_count"] += 1
            else:
                host_info["reasons"] = compatibility["reasons"]
                incompatible_hosts.append(host_info)
                summary["incompatible_count"] += 1

                # Generate suggestions for incompatible hosts
                suggestions = self._generate_group_suggestions(host)
                if suggestions:
                    suggestions_dict[str(host.id)] = suggestions

            # Add warnings if any
            if compatibility.get("warnings"):
                warnings_list.extend(compatibility["warnings"])

        # Calculate overall compatibility score
        if hosts:
            total_score = sum(h["compatibility_score"] for h in compatible_hosts + incompatible_hosts)
            summary["compatibility_score"] = total_score / len(hosts)

        # Cache the results
        self._cache_compatibility_results(host_ids, group_id, results)

        return results

    def _check_host_compatibility(
        self, host: Host, group: HostGroup, user_role: Optional[str] = None
    ) -> Dict[str, Any]:
        """Check compatibility between a host and a group"""
        # Create typed collections for compatibility dict
        reasons: List[str] = []
        compat_warnings: List[str] = []
        details: Dict[str, Any] = {}

        compatibility: Dict[str, Any] = {
            "is_compatible": True,
            "score": 100.0,
            "reasons": reasons,
            "warnings": compat_warnings,
            "details": details,
        }

        # Detect OS information if not available
        if not host.os_family or not host.os_version:
            self._detect_host_os_info(host)

        # Check OS family compatibility
        if group.os_family:
            os_check = self._check_os_family_compatibility(host, group)
            details["os_family"] = os_check
            if not os_check["compatible"]:
                compatibility["is_compatible"] = False
                reasons.append(os_check["reason"])
                compatibility["score"] *= 0.0  # Complete mismatch
            else:
                compatibility["score"] *= os_check["score"]

        # Check OS version compatibility
        if group.os_version_pattern:
            version_check = self._check_os_version_compatibility(host, group)
            details["os_version"] = version_check
            if not version_check["compatible"]:
                compatibility["is_compatible"] = False
                reasons.append(version_check["reason"])
                compatibility["score"] *= 0.2  # Severe penalty
            else:
                compatibility["score"] *= version_check["score"]

        # Check architecture compatibility
        if group.architecture:
            arch_check = self._check_architecture_compatibility(host, group)
            details["architecture"] = arch_check
            if not arch_check["compatible"]:
                compat_warnings.append(arch_check["reason"])
                compatibility["score"] *= 0.8  # Minor penalty

        # Check SCAP content compatibility
        if group.scap_content_id:
            scap_check = self._check_scap_content_compatibility(host, group)
            details["scap_content"] = scap_check
            if not scap_check["compatible"]:
                compatibility["is_compatible"] = False
                reasons.append(scap_check["reason"])
                compatibility["score"] *= 0.1  # Severe penalty
            else:
                compatibility["score"] *= scap_check["score"]

        # Apply custom validation rules if any
        if group.validation_rules:
            custom_check = self._apply_custom_validation_rules(host, group)
            details["custom_rules"] = custom_check
            for rule_result in custom_check:
                if rule_result["severity"] == "error" and not rule_result["passed"]:
                    compatibility["is_compatible"] = False
                    reasons.append(rule_result["message"])
                    compatibility["score"] *= 0.5
                elif rule_result["severity"] == "warning" and not rule_result["passed"]:
                    compat_warnings.append(rule_result["message"])
                    compatibility["score"] *= 0.9

        return compatibility

    def _check_os_family_compatibility(self, host: Host, group: HostGroup) -> Dict[str, Any]:
        """Check if host OS family matches group requirements"""
        result = {"compatible": True, "score": 1.0, "reason": ""}

        if not host.os_family:
            result["compatible"] = False
            result["score"] = 0.0
            result["reason"] = f"Host {host.hostname} OS family not detected"
            return result

        # Direct match
        if host.os_family == group.os_family:
            result["score"] = 1.0
            return result

        # Check OS family groupings (e.g., RHEL and CentOS are compatible)
        host_family_groups = []
        group_family_groups = []

        for family_name, family_members in [
            ("RHEL_FAMILY", OSFamily.RHEL_FAMILY),
            ("DEBIAN_FAMILY", OSFamily.DEBIAN_FAMILY),
            ("SUSE_FAMILY", OSFamily.SUSE_FAMILY),
            ("WINDOWS_FAMILY", OSFamily.WINDOWS_FAMILY),
            ("BSD_FAMILY", OSFamily.BSD_FAMILY),
        ]:
            if host.os_family in family_members:
                host_family_groups.append(family_name)
            if group.os_family in family_members:
                group_family_groups.append(family_name)

        # Check if they belong to the same family group
        if set(host_family_groups) & set(group_family_groups):
            result["score"] = 0.9  # High compatibility within same family
            return result

        # No compatibility
        result["compatible"] = False
        result["score"] = 0.0
        result["reason"] = f"Host OS {host.os_family} incompatible with group requirement {group.os_family}"

        return result

    def _check_os_version_compatibility(self, host: Host, group: HostGroup) -> Dict[str, Any]:
        """Check if host OS version matches group pattern"""
        result = {"compatible": True, "score": 1.0, "reason": ""}

        if not host.os_version:
            result["compatible"] = False
            result["score"] = 0.0
            result["reason"] = f"Host {host.hostname} OS version not detected"
            return result

        try:
            # Convert pattern to regex
            pattern = group.os_version_pattern.replace("*", ".*").replace("?", ".")
            os_version_str = str(host.os_version) if host.os_version else ""
            if re.match(f"^{pattern}$", os_version_str, re.IGNORECASE):
                result["score"] = 1.0
            else:
                result["compatible"] = False
                result["score"] = 0.0
                result["reason"] = f"Host OS version {host.os_version} doesn't match pattern {group.os_version_pattern}"
        except Exception as e:
            logger.warning(f"Invalid version pattern {group.os_version_pattern}: {e}")
            result["compatible"] = False
            result["score"] = 0.0
            result["reason"] = f"Invalid version pattern: {group.os_version_pattern}"

        return result

    def _check_architecture_compatibility(self, host: Host, group: HostGroup) -> Dict[str, Any]:
        """Check if host architecture matches group requirements"""
        result = {"compatible": True, "score": 1.0, "reason": ""}

        if not host.architecture:
            result["score"] = 0.8  # Minor penalty
            result["reason"] = f"Host {host.hostname} architecture not detected"
            return result

        # Normalize architectures
        host_arch = host.architecture.lower()
        group_arch = group.architecture.lower()

        # Direct match
        if host_arch == group_arch:
            return result

        # Check compatible architectures
        arch_compatibility = {
            "x86_64": ["amd64", "x64"],
            "amd64": ["x86_64", "x64"],
            "x64": ["x86_64", "amd64"],
            "i386": ["i686", "x86"],
            "i686": ["i386", "x86"],
            "aarch64": ["arm64"],
            "arm64": ["aarch64"],
        }

        compatible_archs = arch_compatibility.get(host_arch, [])
        if group_arch in compatible_archs:
            result["score"] = 0.95
            return result

        # Not compatible
        result["compatible"] = False
        result["score"] = 0.0
        result["reason"] = (
            f"Host architecture {host.architecture} incompatible with group requirement {group.architecture}"
        )

        return result

    def _check_scap_content_compatibility(self, host: Host, group: HostGroup) -> Dict[str, Any]:
        """Check if SCAP content is compatible with host"""
        result = {"compatible": True, "score": 1.0, "reason": ""}

        # Get SCAP content
        scap_content = self.db.query(ScapContent).filter(ScapContent.id == group.scap_content_id).first()

        if not scap_content:
            result["compatible"] = False
            result["score"] = 0.0
            result["reason"] = "SCAP content not found"
            return result

        # Check OS family compatibility
        if scap_content.os_family:
            if host.os_family != scap_content.os_family:
                # Check if they're in the same family group
                compatible = False
                for family_members in [
                    OSFamily.RHEL_FAMILY,
                    OSFamily.DEBIAN_FAMILY,
                    OSFamily.SUSE_FAMILY,
                    OSFamily.WINDOWS_FAMILY,
                    OSFamily.BSD_FAMILY,
                ]:
                    if host.os_family in family_members and scap_content.os_family in family_members:
                        compatible = True
                        result["score"] = 0.9
                        break

                if not compatible:
                    result["compatible"] = False
                    result["score"] = 0.0
                    result["reason"] = (
                        f"SCAP content for {scap_content.os_family} incompatible with host OS {host.os_family}"
                    )
                    return result

        # Check OS version compatibility
        if scap_content.os_version and host.os_version:
            content_version = scap_content.os_version.split(".")[0]  # Major version
            host_version = host.os_version.split(".")[0]

            if content_version != host_version:
                # Check if it's a minor version difference
                try:
                    content_major = int(content_version)
                    host_major = int(host_version)

                    if abs(content_major - host_major) > 1:
                        result["compatible"] = False
                        result["score"] = 0.0
                        result["reason"] = (
                            f"SCAP content for version {scap_content.os_version} incompatible with host version {host.os_version}"
                        )
                    else:
                        result["score"] = 0.7  # Penalty for version mismatch
                except Exception:
                    pass

        return result

    def _apply_custom_validation_rules(self, host: Host, group: HostGroup) -> List[Dict[str, Any]]:
        """Apply custom validation rules defined for the group"""
        results: List[Dict[str, Any]] = []

        if not group.validation_rules:
            return results

        try:
            rules_data: List[Dict[str, Any]] = (
                json.loads(group.validation_rules)
                if isinstance(group.validation_rules, str)
                else list(group.validation_rules) if group.validation_rules else []
            )
        except Exception:
            logger.error(f"Failed to parse validation rules for group {group.id}")
            return results

        for rule in rules_data:
            rule_result = {
                "rule_name": rule.get("name", "Unknown"),
                "passed": True,
                "message": "",
                "severity": rule.get("severity", "warning"),
            }

            try:
                # Evaluate rule based on type
                rule_type = rule.get("type")
                expression = rule.get("expression", "")

                if rule_type == "regex":
                    field = rule.get("field", "hostname")
                    value = getattr(host, field, "")
                    if not re.match(expression, str(value)):
                        rule_result["passed"] = False
                        rule_result["message"] = rule.get("error_message", f"Field {field} doesn't match pattern")

                elif rule_type == "range":
                    field = rule.get("field", "")
                    value = getattr(host, field, None) if field else None
                    min_val = rule.get("min")
                    max_val = rule.get("max")

                    if value is not None:
                        if min_val is not None and value < min_val:
                            rule_result["passed"] = False
                            rule_result["message"] = rule.get("error_message", f"{field} below minimum")
                        elif max_val is not None and value > max_val:
                            rule_result["passed"] = False
                            rule_result["message"] = rule.get("error_message", f"{field} above maximum")

                elif rule_type == "custom":
                    # For complex custom rules, we'd evaluate them here
                    # For now, just log that we encountered a custom rule
                    logger.info(f"Custom rule {rule.get('name')} for group {group.id}")

            except Exception as e:
                logger.error(f"Failed to evaluate rule {rule.get('name')}: {e}")
                rule_result["passed"] = False
                rule_result["message"] = "Rule evaluation failed"

            results.append(rule_result)

        return results

    def _detect_host_os_info(self, host: Host) -> None:
        """Detect and update host OS information"""
        if not host.operating_system:
            return

        os_string = host.operating_system.lower()

        # Detect OS family
        os_family_patterns = {
            OSFamily.RHEL: r"red\s*hat|rhel",
            OSFamily.CENTOS: r"centos",
            OSFamily.FEDORA: r"fedora",
            OSFamily.UBUNTU: r"ubuntu",
            OSFamily.DEBIAN: r"debian",
            OSFamily.SUSE: r"suse\s*linux\s*enterprise|sles",
            OSFamily.OPENSUSE: r"opensuse",
            OSFamily.WINDOWS: r"windows\s*(?!server)",
            OSFamily.WINDOWS_SERVER: r"windows\s*server",
            OSFamily.MACOS: r"mac\s*os|darwin",
            OSFamily.FREEBSD: r"freebsd",
            OSFamily.OPENBSD: r"openbsd",
            OSFamily.SOLARIS: r"solaris|sunos",
        }

        for family, pattern in os_family_patterns.items():
            if re.search(pattern, os_string):
                host.os_family = family
                break

        # Detect OS version
        version_match = re.search(r"(\d+\.?\d*)", os_string)
        if version_match:
            host.os_version = version_match.group(1)

        # Detect architecture if present
        arch_patterns = {
            "x86_64": r"x86_64|x64|amd64",
            "i386": r"i[3-6]86|x86(?!_64)",
            "aarch64": r"aarch64|arm64",
            "ppc64le": r"ppc64le|powerpc64le",
        }

        for arch, pattern in arch_patterns.items():
            if re.search(pattern, os_string):
                host.architecture = arch
                break

        # Update last OS detection time
        host.last_os_detection = datetime.utcnow()

        # Commit changes
        self.db.add(host)
        self.db.commit()

    def _generate_group_suggestions(self, host: Host) -> List[Dict[str, Any]]:
        """Generate group suggestions for an incompatible host"""
        suggestions = []

        # Find groups with matching OS family
        matching_groups = self.db.query(HostGroup).filter(HostGroup.os_family == host.os_family).all()

        for group in matching_groups:
            # Calculate compatibility score
            compatibility = self._check_host_compatibility(host, group)

            if compatibility["is_compatible"]:
                suggestions.append(
                    {
                        "group_id": group.id,
                        "group_name": group.name,
                        "compatibility_score": compatibility["score"],
                        "compliance_framework": group.compliance_framework,
                        "reason": f"Compatible {host.os_family} group",
                    }
                )

        # Sort by compatibility score
        suggestions.sort(key=lambda x: x["compatibility_score"], reverse=True)

        # Return top 3 suggestions
        return suggestions[:3]

    def _cache_compatibility_results(self, host_ids: List[str], group_id: int, results: Dict[str, Any]) -> None:
        """Cache compatibility results for performance"""
        # This would be implemented with Redis or similar caching solution
        # For now, we'll just log that we would cache the results
        logger.info(f"Would cache compatibility results for {len(host_ids)} hosts with group {group_id}")

    def create_smart_group_from_hosts(
        self,
        host_ids: List[str],
        group_name: str,
        description: Optional[str] = None,
        created_by: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Create a smart group automatically based on host characteristics

        Analyzes the selected hosts and creates a group with appropriate
        validation rules and SCAP content assignments
        """
        hosts = self.db.query(Host).filter(Host.id.in_(host_ids)).all()
        if not hosts:
            raise ValidationError(
                message="No hosts found",
                category=ErrorCategory.RESOURCE,
                severity=ErrorSeverity.ERROR,
                context={"host_ids": host_ids},
            )

        # Detect common characteristics
        os_families: Dict[str, int] = {}
        os_versions: Dict[str, int] = {}
        architectures: Dict[str, int] = {}

        for host in hosts:
            if not host.os_family:
                self._detect_host_os_info(host)

            if host.os_family:
                os_family_key = str(host.os_family)
                os_families[os_family_key] = os_families.get(os_family_key, 0) + 1
            if host.os_version:
                os_version_key = str(host.os_version)
                os_versions[os_version_key] = os_versions.get(os_version_key, 0) + 1
            if host.architecture:
                arch_key = str(host.architecture)
                architectures[arch_key] = architectures.get(arch_key, 0) + 1

        # Determine group characteristics
        recommendations: Dict[str, Any] = {}
        characteristics: Dict[str, Any] = {
            "os_families": os_families,
            "os_versions": os_versions,
            "architectures": architectures,
        }

        result: Dict[str, Any] = {
            "hosts_analyzed": len(hosts),
            "characteristics": characteristics,
            "recommendations": recommendations,
        }

        # Check if hosts are homogeneous
        if len(os_families) == 1:
            # Homogeneous OS family
            os_family = list(os_families.keys())[0]
            recommendations["os_family"] = os_family

            # Check version pattern
            if os_versions:
                versions = list(os_versions.keys())
                if len(versions) == 1:
                    recommendations["os_version_pattern"] = versions[0]
                else:
                    # Find common version pattern
                    common_prefix = self._find_common_version_pattern(versions)
                    if common_prefix:
                        recommendations["os_version_pattern"] = f"{common_prefix}*"

            # Recommend SCAP content
            scap_content = self._find_matching_scap_content(os_family, recommendations.get("os_version_pattern"))
            if scap_content:
                recommendations["scap_content"] = {
                    "id": scap_content.id,
                    "name": scap_content.name,
                    "compliance_framework": scap_content.compliance_framework,
                }
        else:
            # Mixed OS families
            split_suggestions: List[Dict[str, Any]] = []
            for os_family in os_families.keys():
                family_hosts = [h for h in hosts if h.os_family == os_family]
                split_suggestions.append(
                    {
                        "os_family": os_family,
                        "host_count": len(family_hosts),
                        "suggested_name": f"{group_name} - {os_family}",
                    }
                )
            result["warnings"] = [
                f"Mixed OS families detected: {', '.join(os_families.keys())}",
                "Consider creating separate groups for each OS family",
            ]
            result["split_suggestions"] = split_suggestions

        return result

    def _find_common_version_pattern(self, versions: List[str]) -> Optional[str]:
        """Find common version pattern from a list of versions"""
        if not versions:
            return None

        # Split versions into components
        version_parts = []
        for version in versions:
            parts = version.split(".")
            version_parts.append(parts)

        # Find common prefix
        common_parts = []
        for i in range(min(len(parts) for parts in version_parts)):
            part_values = [parts[i] for parts in version_parts]
            if len(set(part_values)) == 1:
                common_parts.append(part_values[0])
            else:
                break

        return ".".join(common_parts) if common_parts else None

    def _find_matching_scap_content(
        self, os_family: str, os_version_pattern: Optional[str] = None
    ) -> Optional[ScapContent]:
        """Find SCAP content matching OS characteristics"""
        query = self.db.query(ScapContent).filter(ScapContent.os_family == os_family)

        if os_version_pattern:
            # Try to find exact version match first
            version = os_version_pattern.replace("*", "")
            content = query.filter(ScapContent.os_version.like(f"{version}%")).first()

            if content:
                return content

        # Return any content for the OS family
        return query.first()

    def get_group_compatibility_report(self, group_id: int) -> Dict[str, Any]:
        """Generate a comprehensive compatibility report for a group"""
        group = self.db.query(HostGroup).filter(HostGroup.id == group_id).first()
        if not group:
            raise ValidationError(
                message=f"Group {group_id} not found",
                category=ErrorCategory.RESOURCE,
                severity=ErrorSeverity.ERROR,
                context={"group_id": group_id},
            )

        # Get all hosts in the group
        memberships = self.db.query(HostGroupMembership).filter(HostGroupMembership.group_id == group_id).all()

        # Create typed collections for type safety
        hosts_list: List[Dict[str, Any]] = []
        issues_list: List[str] = []
        recommendations_list: List[Dict[str, Any]] = []
        statistics: Dict[str, int] = {
            "total_hosts": len(memberships),
            "fully_compatible": 0,
            "partially_compatible": 0,
            "incompatible": 0,
        }

        report: Dict[str, Any] = {
            "group": {
                "id": group.id,
                "name": group.name,
                "description": group.description,
                "os_family": group.os_family,
                "os_version_pattern": group.os_version_pattern,
                "compliance_framework": group.compliance_framework,
            },
            "statistics": statistics,
            "hosts": hosts_list,
            "issues": issues_list,
            "recommendations": recommendations_list,
        }

        # Check each host
        for membership in memberships:
            host = self.db.query(Host).filter(Host.id == membership.host_id).first()
            if not host:
                continue

            compatibility = self._check_host_compatibility(host, group)

            host_report = {
                "id": str(host.id),
                "hostname": host.hostname,
                "os": host.operating_system,
                "compatibility_score": compatibility["score"],
                "is_compatible": compatibility["is_compatible"],
                "issues": compatibility.get("reasons", []),
                "warnings": compatibility.get("warnings", []),
            }

            hosts_list.append(host_report)

            # Update statistics
            if compatibility["score"] >= 95:
                statistics["fully_compatible"] += 1
            elif compatibility["score"] >= 70:
                statistics["partially_compatible"] += 1
            else:
                statistics["incompatible"] += 1

            # Collect issues
            issues_list.extend(compatibility.get("reasons", []))

        # Generate recommendations
        if statistics["incompatible"] > 0:
            recommendations_list.append(
                {
                    "type": "warning",
                    "message": f"{statistics['incompatible']} hosts are incompatible with this group",
                    "action": "Review group requirements or remove incompatible hosts",
                }
            )

        if statistics["partially_compatible"] > statistics["fully_compatible"]:
            recommendations_list.append(
                {
                    "type": "info",
                    "message": "Most hosts are only partially compatible",
                    "action": "Consider relaxing group requirements or creating sub-groups",
                }
            )

        return report
