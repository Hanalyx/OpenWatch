"""
Host Groups API Package

Provides modular REST API for host group management and group scanning operations.
This package consolidates functionality previously split between:
- routes/host_groups.py (CRUD operations)
- routes/group_compliance.py (compliance scanning)

Package Structure:
    host_groups/
    |-- __init__.py      # This file - public API and router aggregation
    |-- models.py        # Pydantic request/response models
    |-- crud.py          # CRUD operations for host groups
    |-- scans.py         # Group scanning and compliance endpoints

Router Organization:
    The main router aggregates all sub-routers with their endpoints:

    CRUD Router (crud.py):
        GET    /                           - List all host groups
        GET    /{group_id}                 - Get specific host group
        POST   /                           - Create new host group
        PUT    /{group_id}                 - Update host group
        DELETE /{group_id}                 - Delete host group
        POST   /{group_id}/hosts           - Assign hosts to group
        DELETE /{group_id}/hosts/{host_id} - Remove host from group
        POST   /{group_id}/validate-hosts  - Validate host compatibility
        POST   /smart-create               - Create smart group
        GET    /{group_id}/compatibility-report - Get compatibility report
        POST   /{group_id}/hosts/validate  - Validate and assign hosts

    Scans Router (scans.py):
        POST   /{group_id}/scan                              - Start group scan
        GET    /{group_id}/scan-sessions                     - List scan sessions
        GET    /{group_id}/scan-sessions/{session_id}/progress - Get scan progress
        POST   /{group_id}/scan-sessions/{session_id}/cancel - Cancel scan session
        GET    /{group_id}/compliance/report                 - Get compliance report
        GET    /{group_id}/compliance/metrics                - Get compliance metrics
        GET    /{group_id}/scan-history                      - Get scan history
        POST   /{group_id}/compliance/schedule               - Schedule recurring scans

Usage:
    # Import the router in main.py
    from app.routes.host_groups import router
    app.include_router(router, prefix="/api/host-groups", tags=["Host Groups"])

    # Import models directly
    from app.routes.host_groups.models import HostGroupCreate, GroupScanRequest

Frontend Alignment:
    These endpoints align with frontend scanService.ts:
    - ScanService.startGroupScan()        -> POST /{group_id}/scan
    - ScanService.getGroupScanSessions()  -> GET /{group_id}/scan-sessions
    - ScanService.getGroupScanProgress()  -> GET /{group_id}/scan-sessions/{session_id}/progress
    - ScanService.cancelGroupScan()       -> POST /{group_id}/scan-sessions/{session_id}/cancel
"""

import logging

from fastapi import APIRouter

logger = logging.getLogger(__name__)

# Create main router that aggregates all sub-routers
router = APIRouter(prefix="/host-groups", tags=["Host Groups"])

# Import sub-routers from modular files
try:
    from app.routes.host_groups.crud import router as crud_router
    from app.routes.host_groups.scans import router as scans_router

    # Include all sub-routers into main router
    # CRUD router first (handles base group operations)
    router.include_router(crud_router)
    # Scans router second (handles scan-specific operations)
    router.include_router(scans_router)

    logger.info("Host groups modular routers loaded successfully")

except ImportError as e:
    logger.error(f"Failed to load host groups modular routers: {e}")
    raise


# Re-export models for convenient access
from app.routes.host_groups.models import (  # noqa: E402
    AssignHostsRequest,
    CancelScanResponse,
    CompatibilityValidationResponse,
    ComplianceMetricsResponse,
    GroupComplianceReportResponse,
    GroupScanHistoryResponse,
    GroupScanRequest,
    GroupScanScheduleRequest,
    GroupScanSessionResponse,
    HostGroupCreate,
    HostGroupResponse,
    HostGroupUpdate,
    IndividualScanProgress,
    ScanPriority,
    ScanProgressResponse,
    ScanSessionStatus,
    SmartGroupCreateRequest,
    ValidateHostsRequest,
)

# Re-export helper functions for Celery tasks backward compatibility
from app.routes.host_groups.scans import execute_group_compliance_scan  # noqa: E402

__all__ = [
    # Router
    "router",
    # Host group CRUD models
    "HostGroupCreate",
    "HostGroupUpdate",
    "HostGroupResponse",
    "AssignHostsRequest",
    "ValidateHostsRequest",
    "SmartGroupCreateRequest",
    "CompatibilityValidationResponse",
    # Group scan models
    "GroupScanRequest",
    "GroupScanSessionResponse",
    "ScanProgressResponse",
    "IndividualScanProgress",
    "CancelScanResponse",
    "ScanSessionStatus",
    "ScanPriority",
    # Compliance models
    "ComplianceMetricsResponse",
    "GroupScanHistoryResponse",
    "GroupScanScheduleRequest",
    "GroupComplianceReportResponse",
    # Helper functions for backward compatibility
    "execute_group_compliance_scan",
]
