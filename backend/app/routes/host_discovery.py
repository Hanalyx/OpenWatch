"""
Host Discovery API Routes
Endpoints for triggering and managing host discovery operations
"""

import logging
from typing import Dict, Any, List
from datetime import datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel

from ..database import get_db, Host
from ..auth import get_current_user
from ..services.host_discovery_service import HostBasicDiscoveryService
from ..rbac import check_permission

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/host-discovery", tags=["Host Discovery"])


class HostDiscoveryResponse(BaseModel):
    """Response model for host discovery operations"""

    host_id: str
    hostname: str
    discovery_status: str
    discovered_info: Dict[str, Any]
    timestamp: datetime


class BulkDiscoveryRequest(BaseModel):
    """Request model for bulk host discovery"""

    host_ids: List[str]
    discovery_types: List[str] = ["basic_system"]  # For future extension


class BulkDiscoveryResponse(BaseModel):
    """Response model for bulk discovery operations"""

    total_hosts: int
    discovery_initiated: List[str]
    discovery_failed: List[Dict[str, str]]
    estimated_completion: datetime


@router.post("/{host_id}/basic-system", response_model=HostDiscoveryResponse)
async def discover_basic_system_info(
    host_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Trigger basic system information discovery for a specific host
    """
    # Check permissions
    check_permission(current_user, "hosts:discover")

    # Validate host exists
    try:
        host_uuid = UUID(host_id)
        host = db.query(Host).filter(Host.id == host_uuid).first()
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid host ID format")

    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    # Check if host has necessary connection info
    if not host.username or not (host.ip_address or host.hostname):
        raise HTTPException(
            status_code=400,
            detail="Host missing required connection information (username, IP/hostname)",
        )

    # Initialize discovery service
    discovery_service = HostBasicDiscoveryService()

    try:
        # Perform discovery
        discovery_results = discovery_service.discover_basic_system_info(host)

        # Update host in database
        db.add(host)
        db.commit()
        db.refresh(host)

        # Determine discovery status
        if discovery_results["discovery_success"]:
            discovery_status = "completed"
        elif discovery_results["discovery_errors"]:
            discovery_status = "partial"
        else:
            discovery_status = "failed"

        return HostDiscoveryResponse(
            host_id=str(host.id),
            hostname=host.hostname,
            discovery_status=discovery_status,
            discovered_info=discovery_results,
            timestamp=discovery_results["discovery_timestamp"],
        )

    except Exception as e:
        logger.error(f"Host discovery failed for {host_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Discovery failed: {str(e)}")


@router.post("/bulk/basic-system", response_model=BulkDiscoveryResponse)
async def discover_basic_system_bulk(
    request: BulkDiscoveryRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Trigger basic system discovery for multiple hosts
    """
    # Check permissions
    check_permission(current_user, "hosts:discover")

    # Validate hosts exist
    valid_hosts = []
    invalid_hosts = []

    for host_id in request.host_ids:
        try:
            host_uuid = UUID(host_id)
            host = db.query(Host).filter(Host.id == host_uuid).first()

            if host:
                # Check connection requirements
                if host.username and (host.ip_address or host.hostname):
                    valid_hosts.append(host)
                else:
                    invalid_hosts.append(
                        {"host_id": host_id, "error": "Missing connection information"}
                    )
            else:
                invalid_hosts.append({"host_id": host_id, "error": "Host not found"})

        except ValueError:
            invalid_hosts.append(
                {"host_id": host_id, "error": "Invalid host ID format"}
            )

    if not valid_hosts:
        raise HTTPException(
            status_code=400, detail="No valid hosts found for discovery"
        )

    # Schedule background discovery for valid hosts
    initiated_hosts = []

    for host in valid_hosts:
        try:
            # Add background task for each host
            background_tasks.add_task(_execute_background_discovery, str(host.id), db)
            initiated_hosts.append(str(host.id))

        except Exception as e:
            logger.error(f"Failed to schedule discovery for host {host.id}: {str(e)}")
            invalid_hosts.append(
                {"host_id": str(host.id), "error": f"Failed to schedule: {str(e)}"}
            )

    # Estimate completion time (assume 30 seconds per host)
    estimated_completion = datetime.utcnow()
    if valid_hosts:
        estimated_completion = datetime.utcnow() + timedelta(
            seconds=len(valid_hosts) * 30
        )

    return BulkDiscoveryResponse(
        total_hosts=len(request.host_ids),
        discovery_initiated=initiated_hosts,
        discovery_failed=invalid_hosts,
        estimated_completion=estimated_completion,
    )


@router.get("/{host_id}/status")
async def get_discovery_status(
    host_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Get the current discovery status and information for a host
    """
    # Check permissions
    check_permission(current_user, "hosts:view")

    # Validate and get host
    try:
        host_uuid = UUID(host_id)
        host = db.query(Host).filter(Host.id == host_uuid).first()
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid host ID format")

    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    # Return current discovery information
    return {
        "host_id": str(host.id),
        "hostname": host.hostname,
        "os_family": host.os_family,
        "os_version": host.os_version,
        "architecture": host.architecture,
        "operating_system": host.operating_system,
        "last_discovery": host.last_os_detection,
        "discovery_complete": bool(
            host.os_family
            and host.os_family != "Unknown"
            and host.os_version
            and host.os_version != "Unknown"
            and host.architecture
            and host.architecture != "Unknown"
        ),
    }


async def _execute_background_discovery(host_id: str, db: Session):
    """
    Background task for executing host discovery
    """
    try:
        host_uuid = UUID(host_id)
        host = db.query(Host).filter(Host.id == host_uuid).first()

        if host:
            discovery_service = HostBasicDiscoveryService()
            discovery_results = discovery_service.discover_basic_system_info(host)

            # Update host in database
            db.add(host)
            db.commit()

            logger.info(f"Background discovery completed for host {host_id}")

    except Exception as e:
        logger.error(f"Background discovery failed for host {host_id}: {str(e)}")
