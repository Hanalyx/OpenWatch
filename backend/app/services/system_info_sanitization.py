"""
System Information Sanitization Service - Security Fix 5

Prevents reconnaissance attacks by sanitizing system information exposure.
Only exposes compliance-necessary data while blocking technical details that
could be used for system fingerprinting and attack reconnaissance.

Integrates with existing Security Fix 2 error sanitization infrastructure.
"""

import hashlib
import json
import logging
import re
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Tuple

from ..models.system_models import (
    ComplianceSystemInfo,
    SanitizedSystemValidation,
    SystemInfoAuditEvent,
    SystemInfoFilter,
    SystemInfoLevel,
    SystemInfoMetadata,
    SystemInfoSanitizationContext,
    SystemReconnaissancePattern,
)

logger = logging.getLogger(__name__)

# Lazy import to avoid cyclic dependency


class ReconnaissanceDetectionLevel(str, Enum):
    """Levels of reconnaissance detection sensitivity"""

    STRICT = "strict"  # Block all technical details
    MODERATE = "moderate"  # Allow some operational info
    PERMISSIVE = "permissive"  # Allow more technical details


class SystemInfoSanitizationService:
    """
    Service to sanitize system information and prevent reconnaissance attacks.

    Key Features:
    1. System Information Filtering - Remove detailed OS/package information
    2. Network Configuration Sanitization - Eliminate internal topology details
    3. Service Discovery Prevention - Block running service enumeration
    4. Compliance Information Protection - Safe exposure of only necessary data
    5. Integration with Error Sanitization - Build on existing infrastructure
    """

    # Reconnaissance patterns that indicate system fingerprinting attempts
    RECONNAISSANCE_PATTERNS = [
        SystemReconnaissancePattern(
            pattern_id="os_version_detailed",
            description="Detailed OS version information",
            regex_pattern=r'VERSION_ID\s*=\s*["\'][^"\']+["\']',
            severity="high",
        ),
        SystemReconnaissancePattern(
            pattern_id="kernel_version_full",
            description="Full kernel version with build info",
            regex_pattern=r"Linux\s+[\w\-\.]+\s+[\d\.\-\w]+\s+#\d+",
            severity="high",
        ),
        SystemReconnaissancePattern(
            pattern_id="package_enumeration",
            description="Package version enumeration",
            regex_pattern=r"(rpm|dpkg|yum|apt)\s+(list|query|show)",
            severity="medium",
        ),
        SystemReconnaissancePattern(
            pattern_id="network_interfaces",
            description="Network interface configuration",
            regex_pattern=r"(eth\d+|wlan\d+|enp\d+s\d+):\s+.*inet\s+[\d\.]+",
            severity="high",
        ),
        SystemReconnaissancePattern(
            pattern_id="running_services",
            description="Running service enumeration",
            regex_pattern=r"systemctl\s+(status|list-units|show)",
            severity="medium",
        ),
        SystemReconnaissancePattern(
            pattern_id="system_architecture",
            description="Detailed system architecture info",
            regex_pattern=r"Architecture:\s+x86_64|aarch64|armv7l",
            severity="low",
        ),
        SystemReconnaissancePattern(
            pattern_id="hostname_disclosure",
            description="Internal hostname disclosure",
            regex_pattern=r"hostname:\s+[\w\-\.]+\.internal|\.local|\.corp",
            severity="medium",
        ),
    ]

    # Safe system information patterns (allowed for compliance)
    COMPLIANCE_SAFE_PATTERNS = [
        r"Linux",  # Generic OS family
        r"Windows",  # Generic OS family
        r"Unix",  # Generic OS family
        r"compliance",  # Compliance-related terms
        r"security",  # Security-related terms
        r"available",  # Resource availability (generic)
        r"enabled",  # Service status (generic)
        r"disabled",  # Service status (generic)
    ]

    # System information fields to always sanitize
    SENSITIVE_SYSTEM_FIELDS = [
        "system_details",  # Full uname output
        "detailed_os_info",  # /etc/os-release content
        "kernel_version",  # Specific kernel version
        "installed_packages",  # Package list
        "network_configuration",  # Network topology
        "running_services",  # Service enumeration
        "hostname",  # Internal hostnames
        "ip_address",  # Internal IP addresses
        "mac_address",  # MAC addresses
        "cpu_info",  # CPU model/version
        "memory_info",  # Detailed memory info
        "disk_info",  # Disk configuration
        "mount_points",  # Filesystem mounts
        "environment_vars",  # Environment variables
        "process_list",  # Running processes
        "open_ports",  # Network ports
        "firewall_rules",  # Security configuration
        "users_list",  # System users
        "groups_list",  # System groups
        "cron_jobs",  # Scheduled tasks
        "ssh_config",  # SSH configuration
        "certificates",  # SSL/TLS certificates
        "keys_info",  # Cryptographic keys
    ]

    def __init__(self):
        self.detection_level = ReconnaissanceDetectionLevel.STRICT
        self.audit_events: List[SystemInfoAuditEvent] = []
        self._error_sanitization_service = None

    def _get_error_sanitization_service(self):
        """Lazy load error sanitization service to avoid cyclic import."""
        if self._error_sanitization_service is None:
            from .error_sanitization import get_error_sanitization_service

            self._error_sanitization_service = get_error_sanitization_service()
        return self._error_sanitization_service

    def sanitize_system_information(
        self, raw_system_info: Dict[str, Any], context: SystemInfoSanitizationContext
    ) -> Tuple[Dict[str, Any], SystemInfoMetadata]:
        """
        Main sanitization method - removes sensitive system information
        while preserving compliance-necessary data.

        Args:
            raw_system_info: Raw system information collected
            context: Sanitization context with user/access info

        Returns:
            Tuple of (sanitized_info, metadata)
        """
        try:
            # Determine appropriate access level
            access_level = self._determine_access_level(context)

            # Create filter based on access level
            info_filter = self._create_system_filter(access_level)

            # Detect reconnaissance patterns
            reconnaissance_detected, triggered_patterns = self._detect_reconnaissance_patterns(
                raw_system_info
            )

            # Apply sanitization based on access level
            if access_level == SystemInfoLevel.ADMIN and not reconnaissance_detected:
                sanitized_info = self._sanitize_for_admin(raw_system_info, info_filter)
            elif access_level == SystemInfoLevel.OPERATIONAL:
                sanitized_info = self._sanitize_for_operational(raw_system_info, info_filter)
            elif access_level == SystemInfoLevel.COMPLIANCE:
                sanitized_info = self._sanitize_for_compliance(raw_system_info, info_filter)
            else:
                # Default to basic (most restrictive)
                sanitized_info = self._sanitize_for_basic(raw_system_info, info_filter)

            # Create metadata
            metadata = SystemInfoMetadata(
                collection_timestamp=datetime.utcnow(),
                collection_method="ssh_command",
                sanitization_applied=True,
                sanitization_level=access_level,
                admin_access_used=(access_level == SystemInfoLevel.ADMIN),
                reconnaissance_filtered=reconnaissance_detected,
            )

            # Audit the access
            self._audit_system_info_access(
                context, access_level, reconnaissance_detected, triggered_patterns
            )

            # Log security event
            logger.info(
                f"System info sanitized: level={access_level.value}, "
                f"user={context.user_id}, reconnaissance={reconnaissance_detected}"
            )

            return sanitized_info, metadata

        except Exception as e:
            logger.error(f"System information sanitization failed: {e}")
            # Return minimal safe info on error
            return self._create_minimal_safe_info(), self._create_error_metadata()

    def create_compliance_system_info(
        self, raw_info: Dict[str, Any], context: SystemInfoSanitizationContext
    ) -> ComplianceSystemInfo:
        """Create compliance-safe system information object"""

        sanitized_info, metadata = self.sanitize_system_information(raw_info, context)

        # Extract safe OS family
        os_family = self._extract_safe_os_family(sanitized_info.get("system_details", ""))

        # Extract compliance-relevant information only
        compliance_info = {
            "scan_capability": sanitized_info.get("scan_capability", "unknown"),
            "compliance_tools_available": sanitized_info.get("compliance_tools", False),
            "security_features_enabled": sanitized_info.get("security_features", {}),
            "last_validation": metadata.collection_timestamp.isoformat(),
        }

        return ComplianceSystemInfo(
            os_family=os_family,
            compliance_relevant_info=compliance_info,
            last_updated=metadata.collection_timestamp,
            info_level=SystemInfoLevel.COMPLIANCE,
        )

    def create_sanitized_validation_result(
        self,
        raw_system_info: Dict[str, Any],
        can_proceed: bool,
        context: SystemInfoSanitizationContext,
    ) -> SanitizedSystemValidation:
        """Create sanitized validation result for API responses"""

        compliance_info = self.create_compliance_system_info(raw_system_info, context)

        # Determine system compatibility based on safe criteria
        system_compatible = self._assess_system_compatibility(raw_system_info)

        metadata = SystemInfoMetadata(
            collection_timestamp=datetime.utcnow(),
            sanitization_applied=True,
            sanitization_level=context.access_level,
            admin_access_used=context.is_admin,
            reconnaissance_filtered=True,
        )

        return SanitizedSystemValidation(
            can_proceed=can_proceed,
            system_compatible=system_compatible,
            compliance_info=compliance_info,
            validation_timestamp=datetime.utcnow(),
            metadata=metadata,
        )

    def integrate_with_error_sanitization(
        self, error_data: Dict[str, Any], context: SystemInfoSanitizationContext
    ) -> Dict[str, Any]:
        """
        Integrate system information sanitization with existing error sanitization.
        This extends Security Fix 2 error sanitization to handle system info.
        """
        try:
            # Create a copy to avoid modifying original
            sanitized_data = error_data.copy()

            # First apply system-specific sanitization if system_info exists
            if "system_info" in error_data:
                sanitized_system_info, metadata = self.sanitize_system_information(
                    error_data["system_info"], context
                )
                sanitized_data["system_info"] = sanitized_system_info

            # Apply existing error sanitization patterns
            sanitized_error = self._get_error_sanitization_service().sanitize_error(
                sanitized_data, user_id=context.user_id, source_ip=context.source_ip
            )

            # Convert to dict and ensure system_info is preserved
            result = sanitized_error.dict()
            if "system_info" in sanitized_data:
                result["system_info"] = sanitized_data["system_info"]

            return result

        except Exception as e:
            logger.error(f"Integrated sanitization failed: {e}")
            # Fallback - create basic sanitized response with system_info if it existed
            fallback_result = (
                self._get_error_sanitization_service()
                .sanitize_error(error_data, user_id=context.user_id, source_ip=context.source_ip)
                .dict()
            )

            # Add minimal system info if it was in original
            if "system_info" in error_data:
                fallback_result["system_info"] = {
                    "sanitization_error": True,
                    "access_level": "basic",
                }

            return fallback_result

    def _determine_access_level(self, context: SystemInfoSanitizationContext) -> SystemInfoLevel:
        """Determine appropriate system information access level"""

        # Admin users get full access (if not reconnaissance)
        if context.is_admin and context.user_role in ["SUPER_ADMIN", "SECURITY_ADMIN"]:
            return SystemInfoLevel.ADMIN

        # Operational users get operational info
        if context.user_role in ["SYSTEM_ADMIN", "SCAN_OPERATOR"]:
            return SystemInfoLevel.OPERATIONAL

        # Compliance users get compliance info
        if context.compliance_only or context.user_role in ["COMPLIANCE_OFFICER"]:
            return SystemInfoLevel.COMPLIANCE

        # Default to basic (most restrictive)
        return SystemInfoLevel.BASIC

    def _create_system_filter(self, access_level: SystemInfoLevel) -> SystemInfoFilter:
        """Create system information filter based on access level"""

        if access_level == SystemInfoLevel.ADMIN:
            return SystemInfoFilter(
                allow_os_version=True,
                allow_kernel_info=True,
                allow_package_info=True,
                allow_network_config=True,
                allow_service_info=True,
                allow_detailed_errors=True,
                sanitization_level=access_level,
            )
        elif access_level == SystemInfoLevel.OPERATIONAL:
            return SystemInfoFilter(
                allow_os_version=False,  # Generic OS family only
                allow_kernel_info=False,
                allow_package_info=False,
                allow_network_config=False,
                allow_service_info=True,  # Service status only
                allow_detailed_errors=False,
                sanitization_level=access_level,
            )
        elif access_level == SystemInfoLevel.COMPLIANCE:
            return SystemInfoFilter(
                allow_os_version=False,
                allow_kernel_info=False,
                allow_package_info=False,
                allow_network_config=False,
                allow_service_info=False,
                allow_detailed_errors=False,
                sanitization_level=access_level,
            )
        else:
            # Basic - most restrictive
            return SystemInfoFilter(sanitization_level=access_level)

    def _detect_reconnaissance_patterns(
        self, system_info: Dict[str, Any]
    ) -> Tuple[bool, List[str]]:
        """Detect potential reconnaissance patterns in system information"""

        triggered_patterns = []

        # Convert system info to searchable text
        system_text = json.dumps(system_info, default=str).lower()

        for pattern in self.RECONNAISSANCE_PATTERNS:
            if re.search(pattern.regex_pattern, system_text, re.IGNORECASE):
                triggered_patterns.append(pattern.pattern_id)
                logger.warning(
                    f"Reconnaissance pattern detected: {pattern.pattern_id} - {pattern.description}"
                )

        reconnaissance_detected = len(triggered_patterns) > 0

        if reconnaissance_detected:
            # Log as a warning with security context (since security_warning doesn't exist)
            security_logger = logging.getLogger("security_audit")
            security_logger.warning(
                f"System reconnaissance detected: {len(triggered_patterns)} patterns triggered",
                extra={
                    "patterns": triggered_patterns,
                    "system_info_keys": list(system_info.keys()),
                },
            )
            logger.warning(f"Reconnaissance patterns detected: {triggered_patterns}")

        return reconnaissance_detected, triggered_patterns

    def _sanitize_for_admin(
        self, raw_info: Dict[str, Any], info_filter: SystemInfoFilter
    ) -> Dict[str, Any]:
        """Sanitize system information for admin access (full details)"""

        # Admins get full access but with audit logging
        return {
            "system_details": raw_info.get("system_details", ""),
            "os_info": raw_info.get("os_info", {}),
            "kernel_info": raw_info.get("kernel_info", {}),
            "service_status": raw_info.get("service_status", {}),
            "resource_info": raw_info.get("resource_info", {}),
            "network_info": raw_info.get("network_info", {}),
            "security_info": raw_info.get("security_info", {}),
            "compliance_status": raw_info.get("compliance_status", {}),
            "access_level": "admin",
        }

    def _sanitize_for_operational(
        self, raw_info: Dict[str, Any], info_filter: SystemInfoFilter
    ) -> Dict[str, Any]:
        """Sanitize system information for operational access"""

        return {
            "os_family": self._extract_safe_os_family(raw_info.get("system_details", "")),
            "service_status": self._sanitize_service_status(raw_info.get("service_status", {})),
            "resource_availability": self._sanitize_resource_info(
                raw_info.get("resource_info", {})
            ),
            "compliance_status": raw_info.get("compliance_status", {}),
            "access_level": "operational",
        }

    def _sanitize_for_compliance(
        self, raw_info: Dict[str, Any], info_filter: SystemInfoFilter
    ) -> Dict[str, Any]:
        """Sanitize system information for compliance access"""

        return {
            "os_family": self._extract_safe_os_family(raw_info.get("system_details", "")),
            "compliance_status": raw_info.get("compliance_status", {}),
            "scan_capability": self._assess_scan_capability(raw_info),
            "security_features": self._extract_safe_security_features(raw_info),
            "access_level": "compliance",
        }

    def _sanitize_for_basic(
        self, raw_info: Dict[str, Any], info_filter: SystemInfoFilter
    ) -> Dict[str, Any]:
        """Sanitize system information for basic access (most restrictive)"""

        return {
            "system_compatible": self._assess_system_compatibility(raw_info),
            "scan_supported": True,  # Generic capability indication
            "access_level": "basic",
        }

    def _extract_safe_os_family(self, system_details: str) -> str:
        """Extract safe, generic OS family information"""

        system_details_lower = system_details.lower()

        if "linux" in system_details_lower:
            return "Linux"
        elif "windows" in system_details_lower:
            return "Windows"
        elif "darwin" in system_details_lower or "macos" in system_details_lower:
            return "macOS"
        elif (
            "freebsd" in system_details_lower
            or "openbsd" in system_details_lower
            or "netbsd" in system_details_lower
            or "unix" in system_details_lower
        ):
            return "Unix"
        else:
            return "Unknown"

    def _sanitize_service_status(self, service_status: Dict[str, Any]) -> Dict[str, str]:
        """Sanitize service status information"""

        sanitized = {}
        for service, status in service_status.items():
            # Only expose generic status, not detailed info
            if isinstance(status, str):
                if "active" in status.lower() or "running" in status.lower():
                    sanitized[service] = "enabled"
                elif "inactive" in status.lower() or "stopped" in status.lower():
                    sanitized[service] = "disabled"
                else:
                    sanitized[service] = "unknown"
            else:
                sanitized[service] = "unknown"

        return sanitized

    def _sanitize_resource_info(self, resource_info: Dict[str, Any]) -> Dict[str, str]:
        """Sanitize resource availability information"""

        sanitized = {}

        # Disk space - convert to availability categories
        if "disk_space" in resource_info:
            disk_mb = resource_info.get("disk_space", 0)
            if disk_mb > 1000:
                sanitized["disk_space"] = "adequate"
            elif disk_mb > 500:
                sanitized["disk_space"] = "limited"
            else:
                sanitized["disk_space"] = "insufficient"

        # Memory - convert to availability categories
        if "memory" in resource_info:
            memory_mb = resource_info.get("memory", 0)
            if memory_mb > 1024:
                sanitized["memory"] = "adequate"
            elif memory_mb > 512:
                sanitized["memory"] = "limited"
            else:
                sanitized["memory"] = "insufficient"

        return sanitized

    def _assess_scan_capability(self, raw_info: Dict[str, Any]) -> str:
        """Assess scanning capability without exposing technical details"""

        # Look for indicators of scan capability
        system_details = raw_info.get("system_details", "").lower()

        if "linux" in system_details:
            return "linux_compatible"
        elif "windows" in system_details:
            return "windows_compatible"
        else:
            return "compatibility_unknown"

    def _extract_safe_security_features(self, raw_info: Dict[str, Any]) -> Dict[str, bool]:
        """Extract safe security feature information"""

        return {
            "security_scanning_supported": True,  # Generic capability
            "compliance_tools_available": raw_info.get("openscap_available", False),
            "secure_connection_available": raw_info.get("ssh_available", True),
        }

    def _assess_system_compatibility(self, raw_info: Dict[str, Any]) -> bool:
        """Assess system compatibility for scanning without exposing details"""

        # Basic compatibility check based on safe criteria
        system_details = raw_info.get("system_details", "")

        # Compatible if we can identify it as a known OS family
        safe_families = ["linux", "windows", "unix", "darwin"]
        return any(family in system_details.lower() for family in safe_families)

    def _audit_system_info_access(
        self,
        context: SystemInfoSanitizationContext,
        granted_level: SystemInfoLevel,
        reconnaissance_detected: bool,
        triggered_patterns: List[str],
    ):
        """Audit system information access for security monitoring"""

        audit_event = SystemInfoAuditEvent(
            event_id=hashlib.sha256(f"{context.user_id}{datetime.utcnow()}".encode()).hexdigest(),
            user_id=context.user_id,
            source_ip=context.source_ip,
            requested_level=context.access_level,
            granted_level=granted_level,
            admin_access=context.is_admin,
            reconnaissance_detected=reconnaissance_detected,
            patterns_triggered=triggered_patterns,
            sanitization_applied=True,
        )

        self.audit_events.append(audit_event)

        # Log to security audit system
        security_logger = logging.getLogger("security_audit")
        security_logger.info(
            f"System Info Access: user={context.user_id}, level={granted_level.value}, "
            f"reconnaissance={reconnaissance_detected}",
            extra={
                "event_type": "system_info_access",
                "user_id": context.user_id,
                "source_ip": context.source_ip,
                "access_level": granted_level.value,
                "reconnaissance_detected": reconnaissance_detected,
                "patterns_triggered": triggered_patterns,
            },
        )

    def _create_minimal_safe_info(self) -> Dict[str, Any]:
        """Create minimal safe system information for error cases"""
        return {
            "system_compatible": True,
            "scan_supported": True,
            "access_level": "basic",
            "error_recovery": True,
        }

    def _create_error_metadata(self) -> SystemInfoMetadata:
        """Create metadata for error cases"""
        return SystemInfoMetadata(
            collection_timestamp=datetime.utcnow(),
            collection_method="error_fallback",
            sanitization_applied=True,
            sanitization_level=SystemInfoLevel.BASIC,
            admin_access_used=False,
            reconnaissance_filtered=True,
        )

    def get_audit_summary(self) -> Dict[str, Any]:
        """Get summary of system information access audit events"""

        total_events = len(self.audit_events)
        reconnaissance_events = sum(1 for e in self.audit_events if e.reconnaissance_detected)
        admin_events = sum(1 for e in self.audit_events if e.admin_access)

        return {
            "total_access_events": total_events,
            "reconnaissance_detected_events": reconnaissance_events,
            "admin_access_events": admin_events,
            "reconnaissance_rate": reconnaissance_events / max(total_events, 1),
            "last_24h_events": sum(
                1 for e in self.audit_events if e.timestamp > datetime.utcnow() - timedelta(days=1)
            ),
        }


# Global instance for dependency injection
_system_sanitization_service = None


def get_system_info_sanitization_service() -> SystemInfoSanitizationService:
    """Get or create the global system information sanitization service"""
    global _system_sanitization_service
    if _system_sanitization_service is None:
        _system_sanitization_service = SystemInfoSanitizationService()
    return _system_sanitization_service
