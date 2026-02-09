"""
ORSA v2.0 Interface Specification

OpenWatch Remediation System Adapter - the standard interface that all compliance
scanning and remediation plugins must implement to integrate with OpenWatch.

ORSA v2.0 provides:
- Generalized plugin interface (not Aegis-specific)
- Embedded library support (not just HTTP API)
- License-aware remediation
- Capability-based implementation selection
- Independent update mechanism

Usage:
    from app.services.plugins.orsa import ORSAPlugin, Capability, PluginInfo

    class MyCompliancePlugin(ORSAPlugin):
        async def get_info(self) -> PluginInfo:
            return PluginInfo(
                plugin_id="my-plugin",
                name="My Compliance Plugin",
                version="1.0.0",
                ...
            )

        async def check(self, host_id: str, ...) -> List[CheckResult]:
            # Execute compliance checks
            pass

Version: 2.0.0
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class Capability(str, Enum):
    """Plugin capabilities advertised to OpenWatch."""

    COMPLIANCE_CHECK = "compliance_check"  # Can check compliance status
    REMEDIATION = "remediation"  # Can remediate failures
    ROLLBACK = "rollback"  # Can rollback remediations
    CAPABILITY_DETECTION = "capability_detect"  # Can detect host capabilities
    DRY_RUN = "dry_run"  # Supports dry-run mode
    PARALLEL_EXECUTION = "parallel_exec"  # Supports parallel rule execution
    FRAMEWORK_MAPPING = "framework_map"  # Has framework mappings


@dataclass
class PluginInfo:
    """
    Plugin metadata and capabilities.

    Returned by ORSAPlugin.get_info() to advertise plugin capabilities
    and supported scope to OpenWatch.
    """

    plugin_id: str
    name: str
    version: str
    description: str
    vendor: str

    # Capabilities
    capabilities: List[Capability]

    # Supported scope
    supported_platforms: List[str]  # ["rhel8", "rhel9", "ubuntu22"]
    supported_frameworks: List[str]  # ["nist_800_53_r5", "cis", "stig"]

    # Update info
    update_url: Optional[str] = None
    latest_version: Optional[str] = None
    update_available: bool = False

    # Metadata
    documentation_url: Optional[str] = None
    license_type: str = "proprietary"  # "open_source", "proprietary", "commercial"
    requires_license: bool = False  # Requires OpenWatch+ for full functionality

    # ORSA version compatibility
    orsa_version: str = "2.0.0"


@dataclass
class CanonicalRule:
    """
    Canonical compliance rule definition.

    Represents a single compliance rule with all its metadata, framework references,
    platform support, and implementation details.
    """

    id: str  # aegis.ssh.root_login_disabled
    title: str
    description: str
    rationale: str
    severity: str  # critical, high, medium, low
    category: str  # access-control, audit, filesystem, etc.
    tags: List[str] = field(default_factory=list)

    # Framework references
    references: Dict[str, Any] = field(default_factory=dict)
    # Example:
    # {
    #   "nist_800_53": ["AC-6(2)", "AC-17(2)"],
    #   "cis": {"rhel9_v2": {"section": "5.1.20", "level": "L1"}},
    #   "stig": {"rhel9_v2r7": {"vuln_id": "V-230296"}}
    # }

    # Platform support
    platforms: List[Dict[str, Any]] = field(default_factory=list)
    # Example: [{"family": "rhel", "min_version": 8}]

    # Implementations (capability-gated)
    implementations: List[Dict[str, Any]] = field(default_factory=list)
    # Example: [{"when": "sshd_config_d", "check": {...}, "remediation": {...}}]

    # Dependencies
    depends_on: List[str] = field(default_factory=list)
    conflicts_with: List[str] = field(default_factory=list)


@dataclass
class HostMetadata:
    """
    Host metadata for exception matching.

    ORSA plugins emit this metadata so OpenWatch can match exception rules
    based on host attributes (role, tags, environment).
    """

    hostname: str
    platform_family: str  # rhel, ubuntu, debian
    platform_version: str  # 8, 9, 22.04
    role: Optional[str] = None  # bastion, web, db, etc.
    environment: Optional[str] = None  # prod, staging, dev
    tags: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)  # detected capabilities


@dataclass
class CheckResult:
    """
    Result of a single compliance check.

    Returned by ORSAPlugin.check() for each evaluated rule.
    """

    rule_id: str
    title: str
    severity: str
    category: str

    # Result
    passed: bool
    detail: str

    # Values
    actual_value: Optional[Any] = None
    expected_value: Optional[Any] = None

    # Execution metadata
    implementation_used: Optional[str] = None  # Which capability gate was used
    check_method: Optional[str] = None  # config_value, file_permission, etc.
    check_duration_ms: Optional[int] = None

    # Framework references (for reporting)
    framework_refs: Dict[str, Any] = field(default_factory=dict)

    # Host metadata for exception matching (OpenWatch applies exception overlay)
    host_metadata: Optional[HostMetadata] = None


@dataclass
class RemediationStepResult:
    """Result of a single remediation step."""

    step_index: int
    mechanism: str  # config_set, service_enabled, etc.
    success: bool
    detail: str

    # State tracking
    pre_state: Optional[Dict[str, Any]] = None
    post_state: Optional[Dict[str, Any]] = None

    # Verification
    verified: bool = False
    verification_detail: Optional[str] = None


@dataclass
class RemediationResult:
    """
    Result of remediating a single rule.

    Returned by ORSAPlugin.remediate() for each rule.
    """

    rule_id: str
    title: str
    severity: str

    # Result
    success: bool
    changes_made: bool
    detail: str

    # Step results
    step_results: List[RemediationStepResult] = field(default_factory=list)

    # Rollback support
    rollback_available: bool = False
    rollback_data: Optional[Dict[str, Any]] = None

    # Execution metadata
    dry_run: bool = True
    duration_ms: Optional[int] = None
    reboot_required: bool = False


@dataclass
class RollbackResult:
    """Result of rolling back a remediation job."""

    job_id: str
    success: bool
    detail: str

    # Per-rule rollback results
    rule_results: List[Dict[str, Any]] = field(default_factory=list)

    # Execution metadata
    duration_ms: Optional[int] = None


@dataclass
class HostCapabilities:
    """
    Detected capabilities of a target host.

    Returned by ORSAPlugin.detect_capabilities() to inform which
    implementation to use for each rule.
    """

    platform_family: str  # rhel, ubuntu, debian
    platform_version: str  # 9.3, 22.04

    # Detected capabilities
    capabilities: List[str]  # ["sshd_config_d", "authselect", "firewalld"]

    # Detection timestamp
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ORSAPlugin(ABC):
    """
    Abstract base class for ORSA-compliant plugins.

    All compliance scanning and remediation plugins must implement this interface
    to integrate with the OpenWatch Compliance OS.

    Free Tier vs OpenWatch+:
        - get_info(), get_capabilities(), get_rules(): Always free
        - detect_capabilities(), check(): Always free (core scanning)
        - remediate(), rollback(): Requires OpenWatch+ license

    Example:
        class AegisPlugin(ORSAPlugin):
            async def get_info(self) -> PluginInfo:
                return PluginInfo(
                    plugin_id="aegis",
                    name="Aegis Compliance Engine",
                    version="0.1.0",
                    description="SSH-based compliance scanning",
                    vendor="Hanalyx",
                    capabilities=[
                        Capability.COMPLIANCE_CHECK,
                        Capability.REMEDIATION,
                        Capability.ROLLBACK,
                        Capability.FRAMEWORK_MAPPING,
                    ],
                    supported_platforms=["rhel8", "rhel9"],
                    supported_frameworks=["cis", "stig", "nist_800_53"],
                )
    """

    @abstractmethod
    async def get_info(self) -> PluginInfo:
        """
        Get plugin metadata and capabilities.

        Returns:
            PluginInfo with plugin details, version, and supported scope.
        """
        pass

    @abstractmethod
    async def get_capabilities(self) -> List[Capability]:
        """
        Get list of plugin capabilities.

        Returns:
            List of Capability enums supported by this plugin.
        """
        pass

    @abstractmethod
    async def get_rules(
        self,
        platform: Optional[str] = None,
        framework: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> List[CanonicalRule]:
        """
        Get available compliance rules.

        Args:
            platform: Filter by platform (rhel8, ubuntu22, etc.)
            framework: Filter by framework (nist_800_53, cis, stig)
            category: Filter by category (access-control, audit, etc.)
            severity: Filter by severity (critical, high, medium, low)
            tags: Filter by tags

        Returns:
            List of CanonicalRule matching filters.
        """
        pass

    @abstractmethod
    async def detect_capabilities(
        self,
        host_id: str,
    ) -> HostCapabilities:
        """
        Detect capabilities of target host.

        This is used to select the appropriate implementation for each rule.

        Args:
            host_id: OpenWatch host ID

        Returns:
            HostCapabilities with detected platform and capabilities.
        """
        pass

    @abstractmethod
    async def check(
        self,
        host_id: str,
        rule_ids: Optional[List[str]] = None,
        framework: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[CheckResult]:
        """
        Execute compliance checks on target host.

        This is the core scanning functionality. Always available without license.

        Args:
            host_id: OpenWatch host ID
            rule_ids: Specific rules to check (optional, defaults to all)
            framework: Filter rules by framework
            category: Filter rules by category
            severity: Filter rules by minimum severity

        Returns:
            List of CheckResult for each evaluated rule.
        """
        pass

    @abstractmethod
    async def remediate(
        self,
        host_id: str,
        rule_ids: List[str],
        dry_run: bool = True,
        framework: Optional[str] = None,
    ) -> List[RemediationResult]:
        """
        Execute remediation on target host.

        This is the remediation functionality. Requires OpenWatch+ license.

        Args:
            host_id: OpenWatch host ID
            rule_ids: Rules to remediate (failed checks)
            dry_run: If True, simulate remediation without making changes
            framework: Framework context for framework-specific values

        Returns:
            List of RemediationResult for each rule.

        Raises:
            LicenseRequiredError: If OpenWatch+ license not active
        """
        pass

    @abstractmethod
    async def rollback(
        self,
        host_id: str,
        job_id: str,
    ) -> RollbackResult:
        """
        Rollback a previous remediation job.

        Args:
            host_id: OpenWatch host ID
            job_id: Remediation job ID to rollback

        Returns:
            RollbackResult with rollback status.

        Raises:
            LicenseRequiredError: If OpenWatch+ license not active
            RollbackNotAvailableError: If job has no rollback data
        """
        pass

    # Optional methods with default implementations

    async def health_check(self) -> Dict[str, Any]:
        """
        Check plugin health status.

        Returns:
            Dict with health status information.
        """
        return {
            "healthy": True,
            "message": "Plugin operational",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def get_framework_mappings(
        self,
        framework: str,
        version: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Get framework mapping data.

        Args:
            framework: Framework ID (nist_800_53, cis_rhel9, stig_rhel9)
            version: Framework version (optional)

        Returns:
            Framework mapping data or None if not available.
        """
        return None

    async def validate_rules(self) -> Dict[str, Any]:
        """
        Validate all rules against schema.

        Returns:
            Validation results with any errors.
        """
        return {"valid": True, "errors": []}


__all__ = [
    # Enums
    "Capability",
    # Dataclasses
    "PluginInfo",
    "CanonicalRule",
    "HostMetadata",
    "CheckResult",
    "RemediationStepResult",
    "RemediationResult",
    "RollbackResult",
    "HostCapabilities",
    # Abstract class
    "ORSAPlugin",
]
