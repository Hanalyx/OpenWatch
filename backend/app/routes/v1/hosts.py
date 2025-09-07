"""
OpenWatch API v1 - Host Management
Versioned host management endpoints with enhanced capabilities
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from typing import List, Optional
from pydantic import BaseModel
import logging

from ...auth import get_current_user
from ..hosts import (
    # Import existing functionality from the main hosts router
    router as hosts_router,
    # We'll re-export the same endpoints but with v1 specific enhancements
)

logger = logging.getLogger(__name__)

# Create v1 hosts router
router = APIRouter()

# Re-include all routes from the main hosts router but with v1 prefix
# This maintains backward compatibility while establishing v1 versioning
for route in hosts_router.routes:
    router.routes.append(route)


# Add v1-specific enhancements
@router.get("/capabilities")
async def get_host_management_capabilities(current_user: dict = Depends(get_current_user)):
    """
    Get host management capabilities for API v1

    Returns information about available host management features,
    limits, and supported operations in the v1 API.
    """
    return {
        "version": "v1",
        "features": {
            "bulk_import": True,
            "csv_import": True,
            "host_groups": True,
            "ssh_key_management": True,
            "remote_scanning": True,
            "monitoring": True,
        },
        "limits": {
            "max_hosts_per_request": 100,
            "bulk_import_max_size": 10000,
            "supported_os": ["linux", "unix", "rhel", "ubuntu", "debian", "centos"],
        },
        "endpoints": {
            "list_hosts": "GET /api/v1/hosts",
            "create_host": "POST /api/v1/hosts",
            "get_host": "GET /api/v1/hosts/{host_id}",
            "update_host": "PUT /api/v1/hosts/{host_id}",
            "delete_host": "DELETE /api/v1/hosts/{host_id}",
            "bulk_import": "POST /api/v1/hosts/bulk",
            "capabilities": "GET /api/v1/hosts/capabilities",
        },
    }


@router.get("/summary")
async def get_hosts_summary(current_user: dict = Depends(get_current_user)):
    """
    Get summary statistics for host management (v1 specific)

    Returns aggregate information about hosts, groups, and management status.
    """
    # This would typically query the database for actual statistics
    return {
        "total_hosts": 0,
        "active_hosts": 0,
        "groups": 0,
        "last_scan": None,
        "compliance_summary": {"compliant": 0, "non_compliant": 0, "unknown": 0},
        "os_distribution": {},
        "scan_status": {"never_scanned": 0, "recently_scanned": 0, "outdated_scans": 0},
    }
