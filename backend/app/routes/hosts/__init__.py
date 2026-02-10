"""
Host Management API Package

This package provides the REST API for host management operations.
The package follows a modular architecture for maintainability.

Package Structure:
    hosts/
    ├── __init__.py         # This file - public API and router aggregation
    ├── models.py           # Pydantic request/response models
    ├── helpers.py          # Utility functions and validation helpers
    ├── crud.py             # Basic CRUD operations (list, get, create, update, delete)
    ├── discovery.py        # Host discovery operations (basic, network, security, compliance)
    └── intelligence.py     # Server intelligence (packages, services, system info)

Migration Status (API Standardization - Phase 3):
    Phase 3: Host Discovery Consolidation
    - hosts.py content moved to crud.py
    - host_discovery.py endpoints consolidated under /discovery/basic
    - host_network_discovery.py endpoints consolidated under /discovery/network
    - host_security_discovery.py endpoints consolidated under /discovery/security
    - host_compliance_discovery.py endpoints consolidated under /discovery/compliance

Usage:
    # Import the router in main.py
    from app.routes.hosts import router
    app.include_router(router, prefix="/api/hosts")

    # Import models directly
    from app.routes.hosts.models import Host, HostCreate

    # Import helpers
    from app.routes.hosts.helpers import validate_host_uuid

Router Organization:
    The main router aggregates all sub-routers with their endpoints:

    CRUD Router (crud.py):
        POST /validate-credentials         - Validate SSH credentials
        GET  /                             - List all hosts
        POST /                             - Create new host
        GET  /capabilities                 - Get host management capabilities
        GET  /summary                      - Get hosts summary statistics
        GET  /{host_id}                    - Get host details
        PUT  /{host_id}                    - Update host
        DELETE /{host_id}                  - Delete host
        DELETE /{host_id}/ssh-key          - Delete host SSH key
        POST /{host_id}/discover-os        - Trigger OS discovery
        GET  /{host_id}/os-info            - Get OS information

    Intelligence Router (intelligence.py):
        GET  /{host_id}/packages           - List installed packages
        GET  /{host_id}/services           - List system services
        GET  /{host_id}/system-info        - Get system information
        GET  /{host_id}/intelligence/summary - Get server intelligence summary

    Discovery Router (discovery.py):
        # Basic System Discovery
        POST /{host_id}/discovery/basic    - Discover basic system info
        POST /discovery/basic/bulk         - Bulk basic system discovery
        GET  /{host_id}/discovery/status   - Get discovery status

        # Network Discovery
        POST /{host_id}/discovery/network  - Discover network topology
        POST /discovery/network/bulk       - Bulk network discovery
        GET  /{host_id}/discovery/network/security-assessment - Network security
        POST /discovery/network/topology-map - Generate topology map
        GET  /discovery/network/capabilities - Network discovery capabilities

        # Security Discovery
        POST /{host_id}/discovery/security - Discover security infrastructure
        POST /discovery/security/bulk      - Bulk security discovery
        GET  /{host_id}/discovery/security/summary - Security summary

        # Compliance Discovery
        POST /{host_id}/discovery/compliance - Discover compliance infrastructure
        POST /discovery/compliance/bulk    - Bulk compliance discovery
        GET  /{host_id}/discovery/compliance/assessment - Compliance assessment
        GET  /discovery/compliance/frameworks - Supported frameworks
"""

from fastapi import APIRouter

# Create main router that aggregates all sub-routers
# Note: prefix="/hosts" ensures all endpoints are under /api/hosts/*
router = APIRouter(prefix="/hosts", tags=["Hosts"])

# Import sub-routers from modular files
# Using try/except for graceful fallback during migration
_modules_loaded = False

try:
    # Core host routers - use relative imports within package
    from .baselines import router as baselines_router
    from .crud import router as crud_router
    from .discovery import router as discovery_router
    from .intelligence import router as intelligence_router

    # Include all sub-routers into main router
    # Order matters for route matching - more specific routes first
    # Discovery router has specific prefixes, so include it first
    router.include_router(discovery_router)

    # Intelligence router (/{host_id}/packages, /{host_id}/services, etc.)
    router.include_router(intelligence_router)

    # Baselines endpoints (/{host_id}/baseline)
    router.include_router(baselines_router)

    # CRUD router (more generic patterns)
    router.include_router(crud_router)

    _modules_loaded = True

except ImportError as e:
    # Fall back to legacy monolithic router during migration
    import logging

    logger = logging.getLogger(__name__)
    logger.warning(f"Failed to load modular host routers, falling back to hosts_legacy.py: {e}")

    try:
        from ..hosts_legacy import router as legacy_router

        router = legacy_router
    except ImportError:
        # If even legacy fails, create empty router (should not happen in production)
        logger.error("Failed to load any host router - API will be incomplete")


# Re-export validate_ssh_key for backward compatibility and testing
# This function is used in crud.py for SSH key validation
from ...services.ssh import validate_ssh_key  # noqa: E402, F401

# Re-export helpers for convenient access - use relative imports
from .helpers import validate_host_uuid  # noqa: E402

# Re-export intelligence models
from .intelligence import (  # noqa: E402
    AuditEventResponse,
    AuditEventsListResponse,
    FirewallListResponse,
    FirewallRuleResponse,
    MetricsListResponse,
    MetricsResponse,
    NetworkInterfaceResponse,
    NetworkListResponse,
    PackageResponse,
    PackagesListResponse,
    RouteResponse,
    RoutesListResponse,
    ServerIntelligenceSummary,
    ServiceResponse,
    ServicesListResponse,
    SystemInfoResponse,
    UserResponse,
    UsersListResponse,
)

# Re-export models for convenient access - use relative imports
from .models import (  # noqa: E402
    BulkComplianceDiscoveryRequest,
    BulkComplianceDiscoveryResponse,
    BulkDiscoveryRequest,
    BulkDiscoveryResponse,
    BulkNetworkDiscoveryRequest,
    BulkNetworkDiscoveryResponse,
    BulkSecurityDiscoveryRequest,
    BulkSecurityDiscoveryResponse,
    ComplianceCapabilityAssessment,
    ComplianceDiscoveryResponse,
    Host,
    HostCreate,
    HostDiscoveryResponse,
    HostUpdate,
    NetworkDiscoveryResponse,
    NetworkSecurityAssessment,
    NetworkTopologyMap,
    OSDiscoveryResponse,
    SecurityDiscoveryResponse,
)

__all__ = [
    # Router
    "router",
    # Host models
    "Host",
    "HostCreate",
    "HostUpdate",
    "OSDiscoveryResponse",
    # Basic discovery models
    "HostDiscoveryResponse",
    "BulkDiscoveryRequest",
    "BulkDiscoveryResponse",
    # Network discovery models
    "NetworkDiscoveryResponse",
    "BulkNetworkDiscoveryRequest",
    "BulkNetworkDiscoveryResponse",
    "NetworkTopologyMap",
    "NetworkSecurityAssessment",
    # Security discovery models
    "SecurityDiscoveryResponse",
    "BulkSecurityDiscoveryRequest",
    "BulkSecurityDiscoveryResponse",
    # Compliance discovery models
    "ComplianceDiscoveryResponse",
    "BulkComplianceDiscoveryRequest",
    "BulkComplianceDiscoveryResponse",
    "ComplianceCapabilityAssessment",
    # Server intelligence models
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
    # Helpers
    "validate_host_uuid",
    # SSH validation (re-exported for backward compatibility)
    "validate_ssh_key",
]
