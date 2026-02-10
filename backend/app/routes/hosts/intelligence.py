"""
Host Server Intelligence API

Endpoints for retrieving server intelligence data:
- Installed packages
- Running services
- System information

Part of OpenWatch OS Transformation - Server Intelligence.
"""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.rbac import Permission, require_permission

from .helpers import validate_host_uuid

logger = logging.getLogger(__name__)


# =============================================================================
# Pydantic Models
# =============================================================================


class PackageResponse(BaseModel):
    """Response model for a single package."""

    name: str
    version: Optional[str] = None
    release: Optional[str] = None
    arch: Optional[str] = None
    source_repo: Optional[str] = None
    installed_at: Optional[str] = None
    collected_at: Optional[str] = None


class PackagesListResponse(BaseModel):
    """Response model for paginated packages list."""

    items: List[PackageResponse]
    total: int
    limit: int
    offset: int


class ServiceResponse(BaseModel):
    """Response model for a single service."""

    name: str
    display_name: Optional[str] = None
    status: Optional[str] = None
    enabled: Optional[bool] = None
    service_type: Optional[str] = None
    run_as_user: Optional[str] = None
    listening_ports: Optional[List[Dict[str, Any]]] = None
    collected_at: Optional[str] = None


class ServicesListResponse(BaseModel):
    """Response model for paginated services list."""

    items: List[ServiceResponse]
    total: int
    limit: int
    offset: int


class SystemInfoResponse(BaseModel):
    """Response model for host system information."""

    os_name: Optional[str] = None
    os_version: Optional[str] = None
    os_version_full: Optional[str] = None
    os_pretty_name: Optional[str] = None
    os_id: Optional[str] = None
    os_id_like: Optional[str] = None
    kernel_version: Optional[str] = None
    kernel_release: Optional[str] = None
    kernel_name: Optional[str] = None
    architecture: Optional[str] = None
    cpu_model: Optional[str] = None
    cpu_cores: Optional[int] = None
    cpu_threads: Optional[int] = None
    memory_total_mb: Optional[int] = None
    memory_available_mb: Optional[int] = None
    swap_total_mb: Optional[int] = None
    disk_total_gb: Optional[float] = None
    disk_used_gb: Optional[float] = None
    disk_free_gb: Optional[float] = None
    selinux_status: Optional[str] = None
    selinux_mode: Optional[str] = None
    firewall_status: Optional[str] = None
    firewall_service: Optional[str] = None
    hostname: Optional[str] = None
    fqdn: Optional[str] = None
    primary_ip: Optional[str] = None
    uptime_seconds: Optional[int] = None
    boot_time: Optional[str] = None
    collected_at: Optional[str] = None
    updated_at: Optional[str] = None


class ServerIntelligenceSummary(BaseModel):
    """Summary of server intelligence data for a host."""

    host_id: str
    system_info_collected: bool
    packages_count: int
    services_count: int
    running_services_count: int
    listening_ports_count: int
    users_count: int = 0
    sudo_users_count: int = 0
    network_interfaces_count: int = 0
    firewall_rules_count: int = 0
    routes_count: int = 0
    audit_events_count: int = 0
    last_collected_at: Optional[str] = None


class UserResponse(BaseModel):
    """Response model for a single user account."""

    username: str
    uid: Optional[int] = None
    gid: Optional[int] = None
    groups: Optional[List[str]] = None
    home_dir: Optional[str] = None
    shell: Optional[str] = None
    gecos: Optional[str] = None
    is_system_account: Optional[bool] = None
    is_locked: Optional[bool] = None
    has_password: Optional[bool] = None
    password_last_changed: Optional[str] = None
    password_expires: Optional[str] = None
    password_max_days: Optional[int] = None
    password_warn_days: Optional[int] = None
    last_login: Optional[str] = None
    last_login_ip: Optional[str] = None
    ssh_keys_count: Optional[int] = None
    ssh_key_types: Optional[List[str]] = None
    sudo_rules: Optional[List[str]] = None
    has_sudo_all: Optional[bool] = None
    has_sudo_nopasswd: Optional[bool] = None
    collected_at: Optional[str] = None


class UsersListResponse(BaseModel):
    """Response model for paginated users list."""

    items: List[UserResponse]
    total: int
    limit: int
    offset: int


class NetworkInterfaceResponse(BaseModel):
    """Response model for a network interface."""

    interface_name: str
    mac_address: Optional[str] = None
    ip_addresses: Optional[List[Dict[str, Any]]] = None
    is_up: Optional[bool] = None
    mtu: Optional[int] = None
    speed_mbps: Optional[int] = None
    interface_type: Optional[str] = None
    collected_at: Optional[str] = None


class NetworkListResponse(BaseModel):
    """Response model for paginated network interfaces list."""

    items: List[NetworkInterfaceResponse]
    total: int
    limit: int
    offset: int


class FirewallRuleResponse(BaseModel):
    """Response model for a firewall rule."""

    firewall_type: Optional[str] = None
    chain: Optional[str] = None
    rule_number: Optional[int] = None
    protocol: Optional[str] = None
    source: Optional[str] = None
    destination: Optional[str] = None
    port: Optional[str] = None
    action: Optional[str] = None
    interface_in: Optional[str] = None
    interface_out: Optional[str] = None
    state: Optional[str] = None
    comment: Optional[str] = None
    raw_rule: Optional[str] = None
    collected_at: Optional[str] = None


class FirewallListResponse(BaseModel):
    """Response model for paginated firewall rules list."""

    items: List[FirewallRuleResponse]
    total: int
    limit: int
    offset: int


class RouteResponse(BaseModel):
    """Response model for a network route."""

    destination: str
    gateway: Optional[str] = None
    interface: Optional[str] = None
    metric: Optional[int] = None
    scope: Optional[str] = None
    route_type: Optional[str] = None
    protocol: Optional[str] = None
    is_default: Optional[bool] = None
    collected_at: Optional[str] = None


class RoutesListResponse(BaseModel):
    """Response model for paginated routes list."""

    items: List[RouteResponse]
    total: int
    limit: int
    offset: int


class AuditEventResponse(BaseModel):
    """Response model for a security audit event."""

    event_type: str
    event_timestamp: str
    username: Optional[str] = None
    source_ip: Optional[str] = None
    action: Optional[str] = None
    target: Optional[str] = None
    result: Optional[str] = None
    raw_message: Optional[str] = None
    source_process: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    collected_at: Optional[str] = None


class AuditEventsListResponse(BaseModel):
    """Response model for paginated audit events list."""

    items: List[AuditEventResponse]
    total: int
    limit: int
    offset: int


class MetricsResponse(BaseModel):
    """Response model for resource metrics snapshot."""

    collected_at: Optional[str] = None
    cpu_usage_percent: Optional[float] = None
    load_avg_1m: Optional[float] = None
    load_avg_5m: Optional[float] = None
    load_avg_15m: Optional[float] = None
    memory_total_bytes: Optional[int] = None
    memory_used_bytes: Optional[int] = None
    memory_available_bytes: Optional[int] = None
    swap_total_bytes: Optional[int] = None
    swap_used_bytes: Optional[int] = None
    disk_total_bytes: Optional[int] = None
    disk_used_bytes: Optional[int] = None
    disk_available_bytes: Optional[int] = None
    uptime_seconds: Optional[int] = None
    process_count: Optional[int] = None


class MetricsListResponse(BaseModel):
    """Response model for paginated metrics list."""

    items: List[MetricsResponse]
    total: int
    limit: int
    offset: int


# =============================================================================
# Router
# =============================================================================

router = APIRouter(tags=["Host Intelligence"])


@router.get(
    "/{host_id}/packages",
    response_model=PackagesListResponse,
    summary="List installed packages",
    description="Get installed packages for a host with pagination and search.",
)
@require_permission(Permission.HOST_READ)
async def list_host_packages(
    host_id: str,
    search: Optional[str] = Query(None, description="Search by package name"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum items to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
) -> PackagesListResponse:
    """
    Get installed packages for a host.

    Returns paginated list of packages with optional search filter.
    """
    # Validate host exists
    host_uuid = validate_host_uuid(host_id, db)

    from app.services.system_info import SystemInfoService

    service = SystemInfoService(db)
    result = service.get_packages(host_uuid, search=search, limit=limit, offset=offset)

    return PackagesListResponse(
        items=[PackageResponse(**pkg) for pkg in result["items"]],
        total=result["total"],
        limit=result["limit"],
        offset=result["offset"],
    )


@router.get(
    "/{host_id}/services",
    response_model=ServicesListResponse,
    summary="List system services",
    description="Get running services for a host with pagination and filtering.",
)
@require_permission(Permission.HOST_READ)
async def list_host_services(
    host_id: str,
    search: Optional[str] = Query(None, description="Search by service name"),
    status: Optional[str] = Query(None, description="Filter by status (running, stopped, failed)"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum items to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
) -> ServicesListResponse:
    """
    Get services for a host.

    Returns paginated list of services with optional search and status filter.
    """
    # Validate host exists
    host_uuid = validate_host_uuid(host_id, db)

    from app.services.system_info import SystemInfoService

    service = SystemInfoService(db)
    result = service.get_services(host_uuid, search=search, status=status, limit=limit, offset=offset)

    return ServicesListResponse(
        items=[ServiceResponse(**svc) for svc in result["items"]],
        total=result["total"],
        limit=result["limit"],
        offset=result["offset"],
    )


@router.get(
    "/{host_id}/system-info",
    response_model=SystemInfoResponse,
    summary="Get system information",
    description="Get detailed system information for a host.",
)
@require_permission(Permission.HOST_READ)
async def get_host_system_info(
    host_id: str,
    db: Session = Depends(get_db),
) -> SystemInfoResponse:
    """
    Get system information for a host.

    Returns OS, hardware, security, and network information.
    """
    # Validate host exists
    host_uuid = validate_host_uuid(host_id, db)

    from app.services.system_info import SystemInfoService

    service = SystemInfoService(db)
    result = service.get_system_info(host_uuid)

    if not result:
        raise HTTPException(
            status_code=404,
            detail="System information not collected for this host. "
            "Run a compliance scan with system info collection enabled.",
        )

    return SystemInfoResponse(**result)


@router.get(
    "/{host_id}/users",
    response_model=UsersListResponse,
    summary="List user accounts",
    description="Get local user accounts for a host with pagination and filtering.",
)
@require_permission(Permission.HOST_READ)
async def list_host_users(
    host_id: str,
    search: Optional[str] = Query(None, description="Search by username or full name"),
    include_system: bool = Query(False, description="Include system accounts (UID < 1000)"),
    has_sudo: Optional[bool] = Query(None, description="Filter by sudo access"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum items to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
) -> UsersListResponse:
    """
    Get user accounts for a host.

    Returns paginated list of users with optional filtering.
    By default, system accounts (UID < 1000) are excluded.
    """
    # Validate host exists
    host_uuid = validate_host_uuid(host_id, db)

    from app.services.system_info import SystemInfoService

    service = SystemInfoService(db)
    result = service.get_users(
        host_uuid,
        search=search,
        include_system=include_system,
        has_sudo=has_sudo,
        limit=limit,
        offset=offset,
    )

    return UsersListResponse(
        items=[UserResponse(**user) for user in result["items"]],
        total=result["total"],
        limit=result["limit"],
        offset=result["offset"],
    )


@router.get(
    "/{host_id}/intelligence/summary",
    response_model=ServerIntelligenceSummary,
    summary="Get server intelligence summary",
    description="Get a summary of all server intelligence data for a host.",
)
@require_permission(Permission.HOST_READ)
async def get_server_intelligence_summary(
    host_id: str,
    db: Session = Depends(get_db),
) -> ServerIntelligenceSummary:
    """
    Get server intelligence summary for a host.

    Returns counts and status of collected server intelligence data.
    """
    from sqlalchemy import text

    # Validate host exists
    host_uuid = validate_host_uuid(host_id, db)

    # Get system info collected status
    system_info_result = db.execute(
        text("SELECT collected_at FROM host_system_info WHERE host_id = :host_id"),
        {"host_id": str(host_uuid)},
    )
    system_info_row = system_info_result.fetchone()
    system_info_collected = system_info_row is not None
    last_collected = system_info_row.collected_at if system_info_row else None

    # Get packages count
    packages_result = db.execute(
        text("SELECT COUNT(*) FROM host_packages WHERE host_id = :host_id"),
        {"host_id": str(host_uuid)},
    )
    packages_count = packages_result.scalar() or 0

    # Get services count and running count
    services_result = db.execute(
        text(
            """
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE status = 'running') as running
            FROM host_services
            WHERE host_id = :host_id
            """
        ),
        {"host_id": str(host_uuid)},
    )
    services_row = services_result.fetchone()
    services_count = services_row.total if services_row else 0
    running_services_count = services_row.running if services_row else 0

    # Get listening ports count
    ports_result = db.execute(
        text(
            """
            SELECT COUNT(*)
            FROM host_services
            WHERE host_id = :host_id
              AND listening_ports IS NOT NULL
              AND jsonb_array_length(listening_ports) > 0
            """
        ),
        {"host_id": str(host_uuid)},
    )
    listening_ports_count = ports_result.scalar() or 0

    # Get users count and sudo users count
    users_result = db.execute(
        text(
            """
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE has_sudo_all = true) as sudo_count
            FROM host_users
            WHERE host_id = :host_id
              AND (is_system_account = false OR is_system_account IS NULL)
            """
        ),
        {"host_id": str(host_uuid)},
    )
    users_row = users_result.fetchone()
    users_count = users_row.total if users_row else 0
    sudo_users_count = users_row.sudo_count if users_row else 0

    # Get network interfaces count
    network_result = db.execute(
        text("SELECT COUNT(*) FROM host_network WHERE host_id = :host_id"),
        {"host_id": str(host_uuid)},
    )
    network_interfaces_count = network_result.scalar() or 0

    # Get firewall rules count
    firewall_result = db.execute(
        text("SELECT COUNT(*) FROM host_firewall_rules WHERE host_id = :host_id"),
        {"host_id": str(host_uuid)},
    )
    firewall_rules_count = firewall_result.scalar() or 0

    # Get routes count
    routes_result = db.execute(
        text("SELECT COUNT(*) FROM host_routes WHERE host_id = :host_id"),
        {"host_id": str(host_uuid)},
    )
    routes_count = routes_result.scalar() or 0

    # Get audit events count
    audit_result = db.execute(
        text("SELECT COUNT(*) FROM host_audit_events WHERE host_id = :host_id"),
        {"host_id": str(host_uuid)},
    )
    audit_events_count = audit_result.scalar() or 0

    return ServerIntelligenceSummary(
        host_id=str(host_uuid),
        system_info_collected=system_info_collected,
        packages_count=packages_count,
        services_count=services_count,
        running_services_count=running_services_count,
        listening_ports_count=listening_ports_count,
        users_count=users_count,
        sudo_users_count=sudo_users_count,
        network_interfaces_count=network_interfaces_count,
        firewall_rules_count=firewall_rules_count,
        routes_count=routes_count,
        audit_events_count=audit_events_count,
        last_collected_at=last_collected.isoformat() if last_collected else None,
    )


@router.get(
    "/{host_id}/network",
    response_model=NetworkListResponse,
    summary="List network interfaces",
    description="Get network interfaces for a host with pagination and filtering.",
)
@require_permission(Permission.HOST_READ)
async def list_host_network(
    host_id: str,
    interface_type: Optional[str] = Query(None, description="Filter by interface type (ethernet, loopback, etc.)"),
    is_up: Optional[bool] = Query(None, description="Filter by up/down status"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum items to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
) -> NetworkListResponse:
    """
    Get network interfaces for a host.

    Returns paginated list of network interfaces with optional filtering.
    """
    # Validate host exists
    host_uuid = validate_host_uuid(host_id, db)

    from app.services.system_info import SystemInfoService

    service = SystemInfoService(db)
    result = service.get_network(host_uuid, interface_type=interface_type, is_up=is_up, limit=limit, offset=offset)

    return NetworkListResponse(
        items=[NetworkInterfaceResponse(**iface) for iface in result["items"]],
        total=result["total"],
        limit=result["limit"],
        offset=result["offset"],
    )


@router.get(
    "/{host_id}/firewall",
    response_model=FirewallListResponse,
    summary="List firewall rules",
    description="Get firewall rules for a host with pagination and filtering.",
)
@require_permission(Permission.HOST_READ)
async def list_host_firewall(
    host_id: str,
    chain: Optional[str] = Query(None, description="Filter by chain (INPUT, OUTPUT, FORWARD)"),
    action: Optional[str] = Query(None, description="Filter by action (ACCEPT, DROP, REJECT)"),
    firewall_type: Optional[str] = Query(None, description="Filter by firewall type (iptables, firewalld)"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum items to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
) -> FirewallListResponse:
    """
    Get firewall rules for a host.

    Returns paginated list of firewall rules with optional filtering.
    """
    # Validate host exists
    host_uuid = validate_host_uuid(host_id, db)

    from app.services.system_info import SystemInfoService

    service = SystemInfoService(db)
    result = service.get_firewall_rules(
        host_uuid, chain=chain, action=action, firewall_type=firewall_type, limit=limit, offset=offset
    )

    return FirewallListResponse(
        items=[FirewallRuleResponse(**rule) for rule in result["items"]],
        total=result["total"],
        limit=result["limit"],
        offset=result["offset"],
    )


@router.get(
    "/{host_id}/routes",
    response_model=RoutesListResponse,
    summary="List network routes",
    description="Get network routes for a host with pagination and filtering.",
)
@require_permission(Permission.HOST_READ)
async def list_host_routes(
    host_id: str,
    is_default: Optional[bool] = Query(None, description="Filter for default routes only"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum items to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
) -> RoutesListResponse:
    """
    Get network routes for a host.

    Returns paginated list of routes with optional filtering.
    """
    # Validate host exists
    host_uuid = validate_host_uuid(host_id, db)

    from app.services.system_info import SystemInfoService

    service = SystemInfoService(db)
    result = service.get_routes(host_uuid, is_default=is_default, limit=limit, offset=offset)

    return RoutesListResponse(
        items=[RouteResponse(**route) for route in result["items"]],
        total=result["total"],
        limit=result["limit"],
        offset=result["offset"],
    )


@router.get(
    "/{host_id}/audit-events",
    response_model=AuditEventsListResponse,
    summary="List security audit events",
    description="Get security audit events for a host with pagination and filtering.",
)
@require_permission(Permission.HOST_READ)
async def list_host_audit_events(
    host_id: str,
    event_type: Optional[str] = Query(None, description="Filter by event type (auth, sudo, service, login_failure)"),
    result_filter: Optional[str] = Query(None, alias="result", description="Filter by result (success, failure)"),
    username: Optional[str] = Query(None, description="Filter by username"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum items to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
) -> AuditEventsListResponse:
    """
    Get security audit events for a host.

    Returns paginated list of audit events with optional filtering.
    Events include authentication attempts, sudo usage, service changes, and login failures.
    """
    # Validate host exists
    host_uuid = validate_host_uuid(host_id, db)

    from app.services.system_info import SystemInfoService

    service = SystemInfoService(db)
    result = service.get_audit_events(
        host_uuid,
        event_type=event_type,
        result=result_filter,
        username=username,
        limit=limit,
        offset=offset,
    )

    return AuditEventsListResponse(
        items=[AuditEventResponse(**event) for event in result["items"]],
        total=result["total"],
        limit=result["limit"],
        offset=result["offset"],
    )


@router.get(
    "/{host_id}/metrics",
    response_model=MetricsListResponse,
    summary="List resource metrics",
    description="Get time-series resource metrics for a host with pagination and time filtering.",
)
@require_permission(Permission.HOST_READ)
async def list_host_metrics(
    host_id: str,
    hours_back: int = Query(24, ge=1, le=720, description="Hours of metrics to return (max 30 days)"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum items to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
) -> MetricsListResponse:
    """
    Get resource metrics for a host.

    Returns time-series metrics including CPU, memory, disk, and load average.
    Metrics are collected during compliance scans and stored for historical analysis.
    """
    # Validate host exists
    host_uuid = validate_host_uuid(host_id, db)

    from app.services.system_info import SystemInfoService

    service = SystemInfoService(db)
    result = service.get_metrics(
        host_uuid,
        hours_back=hours_back,
        limit=limit,
        offset=offset,
    )

    return MetricsListResponse(
        items=[MetricsResponse(**m) for m in result["items"]],
        total=result["total"],
        limit=result["limit"],
        offset=result["offset"],
    )


@router.get(
    "/{host_id}/metrics/latest",
    response_model=MetricsResponse,
    summary="Get latest resource metrics",
    description="Get the most recent resource metrics for a host.",
)
@require_permission(Permission.HOST_READ)
async def get_host_latest_metrics(
    host_id: str,
    db: Session = Depends(get_db),
) -> MetricsResponse:
    """
    Get the most recent metrics for a host.

    Returns the latest collected CPU, memory, disk, and system metrics.
    """
    # Validate host exists
    host_uuid = validate_host_uuid(host_id, db)

    from app.services.system_info import SystemInfoService

    service = SystemInfoService(db)
    result = service.get_latest_metrics(host_uuid)

    if not result:
        raise HTTPException(
            status_code=404,
            detail="No metrics collected for this host. " "Run a compliance scan with metrics collection enabled.",
        )

    return MetricsResponse(**result)


__all__ = [
    "router",
    "PackageResponse",
    "PackagesListResponse",
    "ServiceResponse",
    "ServicesListResponse",
    "SystemInfoResponse",
    "ServerIntelligenceSummary",
    "UserResponse",
    "UsersListResponse",
    "NetworkInterfaceResponse",
    "NetworkListResponse",
    "FirewallRuleResponse",
    "FirewallListResponse",
    "RouteResponse",
    "RoutesListResponse",
    "AuditEventResponse",
    "AuditEventsListResponse",
    "MetricsResponse",
    "MetricsListResponse",
]
