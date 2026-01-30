"""
Pydantic Models for SCAP Scanning API

This module contains all request and response models used by the scanning API.
Models are organized into categories based on their use case.

Architecture Notes:
    - ComplianceScanRequest/Response: PRIMARY models for database-agnostic scanning
    - ScanRequest and related models: LEGACY models requiring scap_content table
    - All models follow CLAUDE.md best practices with comprehensive docstrings

Security Notes:
    - All string fields have appropriate length limits to prevent DoS
    - Field descriptions avoid exposing implementation details
    - UUID fields use str type for JSON serialization compatibility
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, model_validator

from app.services.engine import RecommendedScanProfile

# =============================================================================
# COMPLIANCE SCAN MODELS (PRIMARY - database-agnostic)
# =============================================================================
# These models use the compliance rule repository, abstracting the underlying
# document store. Use these for all new implementations.


class ComplianceScanRequest(BaseModel):
    """
    Request model for rule-based compliance scanning.

    This is the PRIMARY model for creating scans. It uses compliance rules
    from the rule repository (document store) rather than SCAP content files.

    Platform Detection:
        Platform is auto-detected using the following priority:
        1. Host's persisted platform_identifier (from OS discovery)
        2. Computed from host's os_family + os_version
        3. Provided platform/platform_version parameters
        4. JIT (Just-In-Time) detection via SSH if needed

    Example:
        >>> request = ComplianceScanRequest(
        ...     host_id="550e8400-e29b-41d4-a716-446655440000",
        ...     framework="nist_800_53",
        ...     severity_filter=["high", "critical"]
        ... )
    """

    host_id: str = Field(
        ...,
        description="UUID of the target host",
        min_length=1,
    )
    hostname: Optional[str] = Field(
        None,
        description="Hostname or IP address (auto-resolved from host_id if not provided)",
    )
    platform: Optional[str] = Field(
        None,
        description="Target platform (rhel, ubuntu, etc.) - auto-detected if not provided",
    )
    platform_version: Optional[str] = Field(
        None,
        description="Platform version (8, 22.04, etc.) - auto-detected if not provided",
    )
    framework: Optional[str] = Field(
        None,
        description="Compliance framework filter (nist_800_53, cis, stig, pci_dss)",
    )
    severity_filter: Optional[List[str]] = Field(
        None,
        description="Filter rules by severity levels (critical, high, medium, low)",
    )
    rule_ids: Optional[List[str]] = Field(
        None,
        description="Specific rule IDs to scan (from rule selection wizard)",
    )
    connection_params: Optional[Dict[str, Any]] = Field(
        None,
        description="SSH connection parameters (uses host credentials if not provided)",
    )
    include_enrichment: bool = Field(
        True,
        description="Include result enrichment with remediation guidance",
    )
    generate_report: bool = Field(
        True,
        description="Generate compliance framework report",
    )
    name: Optional[str] = Field(
        None,
        description="Custom scan name (auto-generated if not provided)",
    )


class ComplianceScanResponse(BaseModel):
    """
    Response model for compliance scan creation.

    Contains scan identification, status, and result summary information.
    """

    success: bool = Field(..., description="Whether the scan completed successfully")
    scan_id: str = Field(..., description="UUID of the created scan")
    host_id: str = Field(..., description="UUID of the scanned host")
    scan_started: str = Field(..., description="ISO 8601 timestamp of scan start")
    scan_completed: Optional[str] = Field(None, description="ISO 8601 timestamp of scan completion")
    rules_evaluated: int = Field(..., description="Number of rules evaluated")
    platform: str = Field(..., description="Detected/used platform identifier")
    framework: Optional[str] = Field(None, description="Compliance framework used")
    results_summary: Dict[str, Any] = Field(
        default_factory=dict,
        description="Summary of scan results (pass/fail counts, score)",
    )
    enrichment_data: Optional[Dict[str, Any]] = Field(
        None, description="Enrichment data if include_enrichment was True"
    )
    compliance_report: Optional[Dict[str, Any]] = Field(
        None, description="Compliance report if generate_report was True"
    )
    result_files: Dict[str, str] = Field(
        default_factory=dict,
        description="Paths to result files (xml_results, html_report)",
    )


# =============================================================================
# AVAILABLE RULES RESPONSE MODELS
# =============================================================================
# These models support the /api/scans/rules/available endpoint for retrieving
# compliance rules from the rule repository.


class RuleSummary(BaseModel):
    """
    Summary information for a single compliance rule.

    This model provides essential rule metadata without the full implementation
    details, suitable for rule selection interfaces and listings.
    """

    rule_id: str = Field(..., description="Unique rule identifier (XCCDF format)")
    name: str = Field(..., description="Human-readable rule name")
    description: str = Field(..., description="Brief description of the rule")
    severity: str = Field(..., description="Severity level (critical, high, medium, low)")
    category: Optional[str] = Field(None, description="Rule category/group")
    frameworks: List[str] = Field(
        default_factory=list,
        description="Compliance frameworks this rule maps to (NIST, CIS, STIG)",
    )
    platforms: List[str] = Field(
        default_factory=list,
        description="Supported platform identifiers (rhel8, ubuntu2204, etc.)",
    )


class PlatformResolution(BaseModel):
    """
    Details about how the effective platform was resolved.

    Platform resolution follows a priority order:
    1. Host database (platform_identifier column)
    2. Computed from os_family + os_version
    3. Query parameter from request
    4. Default fallback
    """

    platform: str = Field(..., description="Resolved platform identifier")
    platform_version: Optional[str] = Field(None, description="Resolved platform version")
    source: str = Field(
        ...,
        description="Resolution source: host_database, computed, query_parameter, or default",
    )


class AvailableRulesResponse(BaseModel):
    """
    Response model for the available rules endpoint.

    Contains a paginated list of compliance rules matching the specified
    platform and framework criteria, along with filter and resolution metadata.
    """

    success: bool = Field(..., description="Whether the query was successful")
    total_rules_available: int = Field(..., description="Total count of matching rules")
    rules_sample: List[RuleSummary] = Field(
        default_factory=list,
        description="Sample of matching rules (paginated)",
    )
    filters_applied: Dict[str, Optional[str]] = Field(
        default_factory=dict,
        description="Filters that were applied to the query",
    )
    resolved_platform: PlatformResolution = Field(
        ...,
        description="Details about platform resolution",
    )
    page: int = Field(1, description="Current page number (1-indexed)")
    page_size: int = Field(50, description="Number of rules per page")


# =============================================================================
# SCANNER HEALTH RESPONSE MODELS
# =============================================================================
# These models support the /api/scans/scanner/health endpoint for checking
# scanner service status and component health.


class ComponentHealth(BaseModel):
    """
    Health status for a single scanner component.

    Each component reports its initialization state and any relevant
    statistics or configuration information.
    """

    status: str = Field(
        ...,
        description="Component status: initialized, not_initialized, error, degraded",
    )
    details: Optional[Dict[str, Any]] = Field(
        None,
        description="Additional component-specific details",
    )


class ScannerCapabilities(BaseModel):
    """
    Capabilities supported by the compliance scanner.

    Documents the features available in the current scanner configuration.
    """

    platform_aware_scanning: bool = Field(True, description="Scanner supports platform-specific rule selection")
    rule_inheritance_resolution: bool = Field(True, description="Scanner resolves rule inheritance hierarchies")
    result_enrichment: bool = Field(True, description="Scanner can enrich results with intelligence data")
    compliance_reporting: bool = Field(True, description="Scanner generates compliance framework reports")
    supported_platforms: List[str] = Field(
        default_factory=list,
        description="List of supported platform identifiers",
    )
    supported_frameworks: List[str] = Field(
        default_factory=list,
        description="List of supported compliance frameworks",
    )


class ScannerHealthResponse(BaseModel):
    """
    Response model for the scanner health endpoint.

    Provides comprehensive health status for all scanner components
    and overall system capabilities.
    """

    status: str = Field(
        ...,
        description="Overall scanner status: healthy, degraded, or error",
    )
    components: Dict[str, ComponentHealth] = Field(
        default_factory=dict,
        description="Health status of individual components",
    )
    capabilities: ScannerCapabilities = Field(
        ...,
        description="Scanner feature capabilities",
    )
    timestamp: str = Field(
        ...,
        description="ISO 8601 timestamp of health check",
    )


# =============================================================================
# LEGACY SCAP CONTENT MODELS (require scap_content table)
# =============================================================================
# These models are used by deprecated endpoints that rely on SCAP content files.
# For new implementations, use ComplianceScanRequest above.


class ScanRequest(BaseModel):
    """
    Request model for creating a new SCAP scan (LEGACY).

    DEPRECATION: This model requires content_id referencing scap_content table.
    Use ComplianceScanRequest instead, which uses the compliance rule repository.
    """

    name: str = Field(..., description="Human-readable name for the scan")
    host_id: str = Field(..., description="UUID of the target host")
    content_id: int = Field(
        ...,
        description="ID of the SCAP content to use (LEGACY: references scap_content table)",
    )
    profile_id: str = Field(..., description="XCCDF profile ID to apply")
    scan_options: Optional[Dict[str, Any]] = Field(
        default_factory=dict, description="Additional scan configuration options"
    )


class ScanUpdate(BaseModel):
    """Request model for updating scan status (internal use)."""

    status: Optional[str] = Field(None, description="New scan status")
    progress: Optional[int] = Field(None, ge=0, le=100, description="Progress percentage")
    error_message: Optional[str] = Field(None, description="Error message if scan failed")


class RuleRescanRequest(BaseModel):
    """
    Request model for rescanning a specific rule (DISABLED).

    This feature is no longer supported. MongoDB-based scans should
    create a new full scan rather than rescanning individual rules.
    """

    rule_id: str = Field(..., description="XCCDF rule ID to rescan (DISABLED)")
    name: Optional[str] = Field(None, description="Optional name for the rescan")


class VerificationScanRequest(BaseModel):
    """
    Request model for post-remediation verification scan (LEGACY).

    DEPRECATION: This model requires content_id referencing scap_content table.
    For compliance scanning, use POST /api/scans/ instead.
    """

    host_id: str = Field(..., description="UUID of the target host")
    content_id: int = Field(
        ...,
        description="ID of the SCAP content to use (LEGACY: references scap_content table)",
    )
    profile_id: str = Field(..., description="XCCDF profile ID to apply")
    original_scan_id: Optional[str] = Field(None, description="ID of the original failed scan")
    remediation_job_id: Optional[str] = Field(None, description="AEGIS remediation job ID")
    name: Optional[str] = Field(None, description="Optional scan name")


class ValidationRequest(BaseModel):
    """
    Request model for pre-flight scan validation.

    Supports two validation modes:
    1. Legacy SCAP content: Requires content_id and profile_id
    2. Compliance scanning: Requires platform, platform_version, and framework

    At least one mode's required fields must be provided.
    """

    host_id: str = Field(..., description="UUID of the target host")

    # Legacy SCAP content fields (optional for compliance mode)
    content_id: Optional[int] = Field(
        None,
        description="ID of the SCAP content to validate (LEGACY: references scap_content table)",
    )
    profile_id: Optional[str] = Field(None, description="XCCDF profile ID to validate (LEGACY)")

    # Compliance scanning fields (optional for legacy mode)
    platform: Optional[str] = Field(None, description="Target platform (e.g., 'rhel', 'ubuntu')")
    platform_version: Optional[str] = Field(None, description="Platform version (e.g., '8', '9', '22.04')")
    framework: Optional[str] = Field(
        None,
        description="Compliance framework (e.g., 'nist_800_53', 'cis', 'disa_stig')",
    )

    @model_validator(mode="after")
    def validate_request_mode(self) -> "ValidationRequest":
        """Ensure either legacy or compliance fields are provided."""
        has_legacy = self.content_id is not None and self.profile_id is not None
        has_compliance = self.platform is not None and self.platform_version is not None and self.framework is not None

        if not has_legacy and not has_compliance:
            raise ValueError(
                "Either legacy fields (content_id, profile_id) or "
                "compliance fields (platform, platform_version, framework) must be provided"
            )
        return self


class AutomatedFixRequest(BaseModel):
    """Request model for applying an automated fix to a host."""

    fix_id: str = Field(..., description="ID of the automated fix to apply")
    host_id: str = Field(..., description="UUID of the target host")
    validate_after: bool = Field(True, description="Run validation scan after fix")


class QuickScanRequest(BaseModel):
    """Request model for quick scan with intelligent defaults."""

    template_id: Optional[str] = Field("auto", description="Profile template ID or 'auto' for intelligent selection")
    priority: Optional[str] = Field("normal", description="Scan priority: low, normal, high")
    name: Optional[str] = Field(None, description="Optional scan name")
    email_notify: bool = Field(False, description="Send email notification on completion")


class QuickScanResponse(BaseModel):
    """Response model for quick scan creation."""

    id: str = Field(..., description="UUID of the created scan")
    message: str = Field(..., description="Status message")
    status: str = Field(..., description="Current scan status")
    suggested_profile: RecommendedScanProfile = Field(..., description="Profile recommendation details")
    estimated_completion: Optional[float] = Field(None, description="Estimated completion timestamp")


class BulkScanRequest(BaseModel):
    """Request model for bulk scanning multiple hosts."""

    host_ids: List[str] = Field(..., min_length=1, description="List of host UUIDs to scan")
    template_id: Optional[str] = Field("auto", description="Profile template ID or 'auto'")
    priority: Optional[str] = Field("normal", description="Scan priority for all hosts")
    name_prefix: Optional[str] = Field("Bulk Scan", description="Prefix for scan names")
    stagger_delay: int = Field(30, ge=0, le=300, description="Seconds between scan starts (0-300)")


class BulkScanResponse(BaseModel):
    """Response model for bulk scan session creation."""

    session_id: str = Field(..., description="UUID of the bulk scan session")
    message: str = Field(..., description="Status message")
    total_hosts: int = Field(..., ge=0, description="Number of hosts in the session")
    estimated_completion: float = Field(..., description="Estimated completion timestamp")
    scan_ids: List[str] = Field(..., description="List of individual scan UUIDs")


# =============================================================================
# PUBLIC API EXPORTS
# =============================================================================

__all__ = [
    # Compliance scan models (PRIMARY)
    "ComplianceScanRequest",
    "ComplianceScanResponse",
    # Available rules models
    "RuleSummary",
    "PlatformResolution",
    "AvailableRulesResponse",
    # Scanner health models
    "ComponentHealth",
    "ScannerCapabilities",
    "ScannerHealthResponse",
    # Legacy SCAP models
    "ScanRequest",
    "ScanUpdate",
    "RuleRescanRequest",
    "VerificationScanRequest",
    "ValidationRequest",
    "AutomatedFixRequest",
    "QuickScanRequest",
    "QuickScanResponse",
    "BulkScanRequest",
    "BulkScanResponse",
]
