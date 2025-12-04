"""
Host Management Pydantic Models

This module contains all Pydantic models for the hosts package,
including request/response models for CRUD operations and discovery endpoints.

Model Categories:
    - Host CRUD Models: Host, HostCreate, HostUpdate, OSDiscoveryResponse
    - Basic Discovery Models: HostDiscoveryResponse, BulkDiscoveryRequest/Response
    - Network Discovery Models: NetworkDiscoveryResponse, NetworkSecurityAssessment, etc.
    - Security Discovery Models: SecurityDiscoveryResponse, etc.
    - Compliance Discovery Models: ComplianceDiscoveryResponse, etc.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# =============================================================================
# HOST CRUD MODELS
# =============================================================================


class Host(BaseModel):
    """Response model for host information."""

    id: Optional[str] = None
    hostname: str
    ip_address: str
    display_name: Optional[str] = None
    operating_system: str
    status: str = "offline"
    # OS detection fields for platform auto-detection
    os_family: Optional[str] = None
    os_version: Optional[str] = None
    platform_identifier: Optional[str] = None
    port: Optional[int] = 22
    username: Optional[str] = None
    auth_method: Optional[str] = None
    last_scan: Optional[str] = None
    last_check: Optional[str] = None
    compliance_score: Optional[float] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    ssh_key_fingerprint: Optional[str] = None
    ssh_key_type: Optional[str] = None
    ssh_key_bits: Optional[int] = None
    ssh_key_comment: Optional[str] = None

    # Host monitoring fields
    response_time_ms: Optional[int] = None
    check_priority: Optional[int] = None
    ping_consecutive_failures: Optional[int] = None
    ssh_consecutive_failures: Optional[int] = None
    privilege_consecutive_failures: Optional[int] = None
    ping_consecutive_successes: Optional[int] = None
    ssh_consecutive_successes: Optional[int] = None
    privilege_consecutive_successes: Optional[int] = None

    # Latest scan information
    latest_scan_id: Optional[str] = None
    latest_scan_name: Optional[str] = None
    scan_status: Optional[str] = None
    scan_progress: Optional[int] = None
    failed_rules: Optional[int] = None
    passed_rules: Optional[int] = None

    # Failed rule counts by severity
    critical_issues: Optional[int] = None
    high_issues: Optional[int] = None
    medium_issues: Optional[int] = None
    low_issues: Optional[int] = None
    total_rules: Optional[int] = None

    # Per-severity pass/fail breakdown for accurate compliance visualization
    # NIST SP 800-137 Continuous Monitoring granular tracking
    critical_passed: Optional[int] = None
    critical_failed: Optional[int] = None
    high_passed: Optional[int] = None
    high_failed: Optional[int] = None
    medium_passed: Optional[int] = None
    medium_failed: Optional[int] = None
    low_passed: Optional[int] = None
    low_failed: Optional[int] = None

    # Group information
    group_id: Optional[int] = None
    group_name: Optional[str] = None
    group_description: Optional[str] = None
    group_color: Optional[str] = None


class HostCreate(BaseModel):
    """Request model for creating a new host."""

    hostname: str
    ip_address: str
    display_name: Optional[str] = None
    operating_system: str
    port: Optional[int] = 22
    username: Optional[str] = None
    auth_method: Optional[str] = Field("ssh_key", pattern="^(password|ssh_key|system_default)$")
    ssh_key: Optional[str] = None
    password: Optional[str] = None
    environment: Optional[str] = "production"
    tags: Optional[List[str]] = []
    owner: Optional[str] = None


class HostUpdate(BaseModel):
    """Request model for updating an existing host."""

    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    display_name: Optional[str] = None
    operating_system: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    auth_method: Optional[str] = Field(None, pattern="^(password|ssh_key|system_default)$")
    ssh_key: Optional[str] = None
    password: Optional[str] = None
    environment: Optional[str] = None
    tags: Optional[List[str]] = None
    owner: Optional[str] = None
    description: Optional[str] = None  # Allow description updates


class OSDiscoveryResponse(BaseModel):
    """
    Response model for OS discovery operations.

    Contains the discovered OS information and task status for async operations.
    Used by both immediate discovery results and task status checks.
    """

    host_id: str = Field(..., description="UUID of the host")
    task_id: Optional[str] = Field(None, description="Celery task ID for async tracking")
    status: str = Field(..., description="Discovery status: queued, in_progress, completed, failed")
    os_family: Optional[str] = Field(None, description="Detected OS family (rhel, ubuntu, debian)")
    os_version: Optional[str] = Field(None, description="Detected OS version (9.3, 22.04)")
    platform_identifier: Optional[str] = Field(
        None, description="Normalized platform ID for OVAL selection (rhel9, ubuntu2204)"
    )
    architecture: Optional[str] = Field(None, description="CPU architecture (x86_64, aarch64)")
    discovered_at: Optional[str] = Field(None, description="ISO timestamp of discovery")
    error: Optional[str] = Field(None, description="Error message if discovery failed")


# =============================================================================
# BASIC DISCOVERY MODELS
# =============================================================================


class HostDiscoveryResponse(BaseModel):
    """Response model for basic host discovery operations."""

    host_id: str
    hostname: str
    discovery_status: str
    discovered_info: Dict[str, Any]
    timestamp: datetime


class BulkDiscoveryRequest(BaseModel):
    """Request model for bulk host discovery."""

    host_ids: List[str]
    discovery_types: List[str] = ["basic_system"]  # For future extension


class BulkDiscoveryResponse(BaseModel):
    """Response model for bulk discovery operations."""

    total_hosts: int
    discovery_initiated: List[str]
    discovery_failed: List[Dict[str, str]]
    estimated_completion: datetime


# =============================================================================
# NETWORK DISCOVERY MODELS
# =============================================================================


class NetworkDiscoveryResponse(BaseModel):
    """Response model for network discovery results."""

    network_interfaces: Dict[str, Any]
    routing_table: List[Dict[str, Any]]
    dns_configuration: Dict[str, Any]
    ntp_configuration: Dict[str, Any]
    network_services: Dict[str, Any]
    connectivity_tests: Dict[str, Any]
    network_security: Dict[str, Any]
    discovery_timestamp: str
    discovery_success: bool
    discovery_errors: List[str]


class BulkNetworkDiscoveryRequest(BaseModel):
    """Request model for bulk network discovery."""

    host_ids: List[str]


class BulkNetworkDiscoveryResponse(BaseModel):
    """Response model for bulk network discovery results."""

    total_hosts: int
    successful_discoveries: int
    failed_discoveries: int
    results: Dict[str, NetworkDiscoveryResponse]
    errors: Dict[str, str]


class NetworkTopologyMap(BaseModel):
    """Response model for network topology map."""

    hosts: List[Dict[str, Any]]
    network_segments: List[Dict[str, Any]]
    connectivity_matrix: Dict[str, Dict[str, bool]]
    network_summary: Dict[str, Any]


class NetworkSecurityAssessment(BaseModel):
    """Response model for network security assessment."""

    host_id: str
    hostname: str
    security_score: float  # 0.0 to 1.0
    open_ports: List[Dict[str, Any]]
    risky_services: List[str]
    firewall_status: str
    hardening_recommendations: List[str]
    network_vulnerabilities: List[str]


# =============================================================================
# SECURITY DISCOVERY MODELS
# =============================================================================


class SecurityDiscoveryResponse(BaseModel):
    """Response model for security discovery results."""

    package_managers: Dict[str, Any]
    service_manager: str
    selinux_status: Any
    apparmor_status: Any
    firewall_services: Dict[str, Any]
    security_tools: List[str]
    discovery_timestamp: str
    discovery_success: bool
    discovery_errors: List[str]


class BulkSecurityDiscoveryRequest(BaseModel):
    """Request model for bulk security discovery."""

    host_ids: List[str]


class BulkSecurityDiscoveryResponse(BaseModel):
    """Response model for bulk security discovery results."""

    total_hosts: int
    successful_discoveries: int
    failed_discoveries: int
    results: Dict[str, SecurityDiscoveryResponse]
    errors: Dict[str, str]


# =============================================================================
# COMPLIANCE DISCOVERY MODELS
# =============================================================================


class ComplianceDiscoveryResponse(BaseModel):
    """Response model for compliance discovery results."""

    python_environments: Dict[str, Any]
    openscap_tools: Dict[str, Any]
    privilege_escalation: Dict[str, Any]
    compliance_scanners: Dict[str, Any]
    filesystem_capabilities: Dict[str, Any]
    audit_tools: Dict[str, Any]
    compliance_frameworks: List[str]
    discovery_timestamp: str
    discovery_success: bool
    discovery_errors: List[str]


class BulkComplianceDiscoveryRequest(BaseModel):
    """Request model for bulk compliance discovery operations."""

    host_ids: List[str]


class BulkComplianceDiscoveryResponse(BaseModel):
    """Response model for bulk compliance discovery results."""

    total_hosts: int
    successful_discoveries: int
    failed_discoveries: int
    results: Dict[str, ComplianceDiscoveryResponse]
    errors: Dict[str, str]


class ComplianceCapabilityAssessment(BaseModel):
    """Model for compliance capability assessment results."""

    host_id: str
    hostname: str
    overall_compliance_readiness: str  # ready, partial, not_ready
    scap_capability: str  # full, limited, none
    python_capability: str  # available, limited, none
    privilege_escalation: str  # available, limited, none
    audit_capability: str  # full, partial, none
    recommended_frameworks: List[str]
    missing_tools: List[str]
    readiness_score: float  # 0.0 to 1.0
