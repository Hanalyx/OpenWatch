"""
Host Security Discovery API Routes
Provides endpoints for discovering security infrastructure on hosts
"""

import logging
from typing import Any, Dict, List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import Host, get_db
from ..rbac import check_permission
from ..services.host_security_discovery import HostSecurityDiscoveryService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/host-security-discovery", tags=["Host Security Discovery"])


class SecurityDiscoveryResponse(BaseModel):
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
    host_ids: List[str]


class BulkSecurityDiscoveryResponse(BaseModel):
    total_hosts: int
    successful_discoveries: int
    failed_discoveries: int
    results: Dict[str, SecurityDiscoveryResponse]
    errors: Dict[str, str]


@router.post("/hosts/{host_id}/security-discovery", response_model=SecurityDiscoveryResponse)
async def discover_host_security_infrastructure(
    host_id: str, current_user=Depends(get_current_user), db: Session = Depends(get_db)
):
    """
    Discover security infrastructure and configurations on a specific host

    Args:
        host_id: UUID of the host to discover security information for

    Returns:
        SecurityDiscoveryResponse containing discovered security information
    """
    # Check permissions
    check_permission(current_user["role"], "hosts", "read")

    try:
        # Convert string UUID to UUID object
        host_uuid = UUID(host_id)

        # Get host from database
        host = db.query(Host).filter(Host.id == host_uuid).first()
        if not host:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Host with ID {host_id} not found",
            )

        # Perform security discovery
        security_service = HostSecurityDiscoveryService()
        discovery_results = security_service.discover_security_infrastructure(host)

        # Convert datetime to string for JSON serialization
        discovery_results["discovery_timestamp"] = discovery_results["discovery_timestamp"].isoformat()

        logger.info(
            f"Security discovery completed for host {host.hostname}: "
            f"Found {len(discovery_results['package_managers'])} package managers, "
            f"SELinux: {discovery_results['selinux_status']}, "
            f"AppArmor: {discovery_results['apparmor_status']}"
        )

        return SecurityDiscoveryResponse(**discovery_results)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid host ID format: {str(e)}",
        )
    except Exception as e:
        logger.error(f"Security discovery failed for host {host_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Security discovery failed: {str(e)}",
        )


@router.post("/bulk-security-discovery", response_model=BulkSecurityDiscoveryResponse)
async def bulk_discover_security_infrastructure(
    request: BulkSecurityDiscoveryRequest,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Discover security infrastructure for multiple hosts in bulk

    Args:
        request: BulkSecurityDiscoveryRequest containing list of host IDs

    Returns:
        BulkSecurityDiscoveryResponse with results for all hosts
    """
    # Check permissions
    check_permission(current_user["role"], "hosts", "read")

    if not request.host_ids:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No host IDs provided")

    if len(request.host_ids) > 50:  # Limit bulk operations
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Too many hosts requested. Maximum 50 hosts per bulk operation.",
        )

    logger.info(f"Starting bulk security discovery for {len(request.host_ids)} hosts")

    results = {}
    errors = {}
    successful_discoveries = 0
    failed_discoveries = 0

    security_service = HostSecurityDiscoveryService()

    for host_id in request.host_ids:
        try:
            # Convert string UUID to UUID object
            host_uuid = UUID(host_id)

            # Get host from database
            host = db.query(Host).filter(Host.id == host_uuid).first()
            if not host:
                errors[host_id] = f"Host with ID {host_id} not found"
                failed_discoveries += 1
                continue

            # Perform security discovery
            discovery_results = security_service.discover_security_infrastructure(host)

            # Convert datetime to string for JSON serialization
            discovery_results["discovery_timestamp"] = discovery_results["discovery_timestamp"].isoformat()

            results[host_id] = SecurityDiscoveryResponse(**discovery_results)

            if discovery_results["discovery_success"]:
                successful_discoveries += 1
            else:
                failed_discoveries += 1

        except ValueError as e:
            errors[host_id] = f"Invalid host ID format: {str(e)}"
            failed_discoveries += 1
        except Exception as e:
            logger.error(f"Security discovery failed for host {host_id}: {str(e)}")
            errors[host_id] = f"Security discovery failed: {str(e)}"
            failed_discoveries += 1

    logger.info(
        f"Bulk security discovery completed: {successful_discoveries} successful, "
        f"{failed_discoveries} failed out of {len(request.host_ids)} total hosts"
    )

    return BulkSecurityDiscoveryResponse(
        total_hosts=len(request.host_ids),
        successful_discoveries=successful_discoveries,
        failed_discoveries=failed_discoveries,
        results=results,
        errors=errors,
    )


@router.get("/hosts/{host_id}/security-summary")
async def get_host_security_summary(
    host_id: str, current_user=Depends(get_current_user), db: Session = Depends(get_db)
):
    """
    Get a quick security summary for a host without running full discovery

    Args:
        host_id: UUID of the host

    Returns:
        Security summary based on existing host data
    """
    # Check permissions
    check_permission(current_user["role"], "hosts", "read")

    try:
        # Convert string UUID to UUID object
        host_uuid = UUID(host_id)

        # Get host from database
        host = db.query(Host).filter(Host.id == host_uuid).first()
        if not host:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Host with ID {host_id} not found",
            )

        # Generate security summary based on existing host information
        summary = {
            "host_id": str(host.id),
            "hostname": host.hostname,
            "os_family": host.os_family,
            "os_version": host.os_version,
            "architecture": host.architecture,
            "last_os_detection": (host.last_os_detection.isoformat() if host.last_os_detection else None),
            "auth_method": host.auth_method,
            "security_recommendations": [],
        }

        # Add security recommendations based on OS family
        if host.os_family:
            if (
                "rhel" in host.os_family.lower()
                or "centos" in host.os_family.lower()
                or "fedora" in host.os_family.lower()
            ):
                summary["security_recommendations"].extend(
                    [
                        "Consider enabling SELinux if not already active",
                        "Ensure firewalld is configured properly",
                        "Keep system updated with dnf/yum",
                    ]
                )
            elif "ubuntu" in host.os_family.lower() or "debian" in host.os_family.lower():
                summary["security_recommendations"].extend(
                    [
                        "Consider configuring AppArmor profiles",
                        "Ensure UFW firewall is configured",
                        "Keep system updated with apt",
                    ]
                )
            elif "suse" in host.os_family.lower():
                summary["security_recommendations"].extend(
                    [
                        "Configure AppArmor or SELinux as appropriate",
                        "Ensure firewall is configured",
                        "Keep system updated with zypper",
                    ]
                )

        return summary

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid host ID format: {str(e)}",
        )
    except Exception as e:
        logger.error(f"Failed to get security summary for host {host_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get security summary: {str(e)}",
        )
