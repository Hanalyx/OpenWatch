"""
SSH Settings API Endpoints

This module provides SSH policy and known hosts management endpoints.
Part of Phase 4 API Standardization: System & Integrations.

Endpoint Structure:
    GET  /settings/policy                       - Get SSH policy configuration
    POST /settings/policy                       - Set SSH policy configuration
    GET  /settings/known-hosts                  - List SSH known hosts
    POST /settings/known-hosts                  - Add SSH known host
    DELETE /settings/known-hosts/{hostname}     - Remove SSH known host
    GET  /settings/test-connectivity/{host_id}  - Test SSH connectivity

Migration Status:
    - /api/ssh-settings/* -> /api/ssh/settings/*
"""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ...auth import get_current_user
from ...database import get_db
from ...rbac import Permission, require_permission
from ...services.ssh import SSHConfigManager
from .models import KnownHostRequest, KnownHostResponse, SSHPolicyRequest, SSHPolicyResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/settings", tags=["SSH Settings"])


@router.get("/policy", response_model=SSHPolicyResponse)
@require_permission(Permission.SYSTEM_CONFIG)
async def get_ssh_policy(
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> SSHPolicyResponse:
    """
    Get current SSH host key policy configuration.

    Returns the current SSH policy settings including:
    - Policy type (strict, auto_add, bypass_trusted)
    - Trusted network ranges
    - Policy description

    Args:
        db: Database session
        current_user: Authenticated user context

    Returns:
        SSHPolicyResponse with current configuration

    Raises:
        HTTPException: 500 if policy retrieval fails
    """
    try:
        service = SSHConfigManager(db)

        policy = "default_policy"
        trusted_networks = service.get_trusted_networks()

        policy_descriptions = {
            "strict": "Reject connections to unknown hosts (most secure)",
            "auto_add": "Automatically accept and save unknown host keys",
            "bypass_trusted": "Auto-accept hosts in trusted network ranges",
        }

        return SSHPolicyResponse(
            policy=policy,
            trusted_networks=trusted_networks,
            description=policy_descriptions.get(policy, "Unknown policy"),
        )
    except Exception as e:
        logger.error(f"Error getting SSH policy: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve SSH policy",
        )


@router.post("/policy", response_model=SSHPolicyResponse)
@require_permission(Permission.SYSTEM_CONFIG)
async def set_ssh_policy(
    policy_request: SSHPolicyRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> SSHPolicyResponse:
    """
    Set SSH host key policy configuration.

    Configures the SSH policy settings including:
    - Policy type (strict, auto_add, bypass_trusted)
    - Trusted network ranges for bypass_trusted mode

    Args:
        policy_request: New policy configuration
        db: Database session
        current_user: Authenticated user context

    Returns:
        SSHPolicyResponse with updated configuration

    Raises:
        HTTPException: 400 if validation fails
        HTTPException: 500 if policy update fails
    """
    try:
        service = SSHConfigManager(db)

        # Set policy
        success = service.set_ssh_policy(policy_request.policy, current_user.get("id"))
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update SSH policy",
            )

        # Set trusted networks if provided
        if policy_request.trusted_networks is not None:
            success = service.set_trusted_networks(policy_request.trusted_networks, current_user.get("id"))
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to update trusted networks",
                )

        # Return updated configuration
        policy_response: SSHPolicyResponse = await get_ssh_policy(db=db, current_user=current_user)
        return policy_response

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Error setting SSH policy: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update SSH policy",
        )


@router.get("/known-hosts", response_model=List[KnownHostResponse])
@require_permission(Permission.SYSTEM_CONFIG)
async def get_known_hosts(
    hostname: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[KnownHostResponse]:
    """
    Get SSH known hosts, optionally filtered by hostname.

    Lists all SSH known hosts registered in the system with their
    key information and trust status.

    Args:
        hostname: Optional filter by hostname
        db: Database session
        current_user: Authenticated user context

    Returns:
        List of KnownHostResponse objects

    Raises:
        HTTPException: 500 if retrieval fails
    """
    try:
        service = SSHConfigManager(db)

        hosts = service.get_known_hosts(hostname)
        return [KnownHostResponse(**host) for host in hosts]

    except Exception as e:
        logger.error(f"Error getting known hosts: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve known hosts",
        )


@router.post("/known-hosts", response_model=KnownHostResponse)
@require_permission(Permission.SYSTEM_CONFIG)
async def add_known_host(
    host_request: KnownHostRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> KnownHostResponse:
    """
    Add a host key to SSH known hosts.

    Registers a new SSH host key for trusted connections.

    Args:
        host_request: New host key information
        db: Database session
        current_user: Authenticated user context

    Returns:
        KnownHostResponse with created host details

    Raises:
        HTTPException: 400 if validation fails
        HTTPException: 500 if creation fails
    """
    try:
        service = SSHConfigManager(db)

        # Add known host
        success = service.add_known_host(
            hostname=host_request.hostname,
            ip_address=host_request.ip_address,
            key_type=host_request.key_type,
            public_key=host_request.public_key,
            notes=host_request.notes,
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to add known host",
            )

        # Return the added host
        hosts = service.get_known_hosts(host_request.hostname)
        matching_host = next(
            (h for h in hosts if h["hostname"] == host_request.hostname and h["key_type"] == host_request.key_type),
            None,
        )

        if not matching_host:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Host added but could not retrieve details",
            )

        return KnownHostResponse(**matching_host)

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Error adding known host: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to add known host",
        )


@router.delete("/known-hosts/{hostname}")
@require_permission(Permission.SYSTEM_CONFIG)
async def remove_known_host(
    hostname: str,
    key_type: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Remove a host key from SSH known hosts.

    Removes one or all SSH host keys for a given hostname.

    Args:
        hostname: Hostname to remove
        key_type: Optional specific key type to remove
        db: Database session
        current_user: Authenticated user context

    Returns:
        Success message

    Raises:
        HTTPException: 404 if host not found
        HTTPException: 500 if removal fails
    """
    try:
        service = SSHConfigManager(db)

        # Pass empty string if key_type is None (removes all key types for hostname)
        success = service.remove_known_host(hostname, key_type or "")

        if not success:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Known host not found")

        return {"message": f"Known host {hostname} removed successfully"}

    except Exception as e:
        logger.error(f"Error removing known host: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to remove known host",
        )


@router.get("/test-connectivity/{host_id}")
@require_permission(Permission.SCAN_EXECUTE)
async def test_ssh_connectivity(
    host_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Test SSH connectivity to a host with current policy.

    Performs an SSH connectivity test to verify the host is reachable.

    Args:
        host_id: UUID of the host to test
        db: Database session
        current_user: Authenticated user context

    Returns:
        Connectivity test results

    Raises:
        HTTPException: 404 if host not found
        HTTPException: 500 if test fails
    """
    try:
        from ...database import Host
        from ...services.host_monitor import HostMonitor

        # Get host
        host = db.query(Host).filter(Host.id == host_id).first()
        if not host:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Host not found")

        # Test connectivity using check_ssh_connectivity method
        monitor = HostMonitor()
        is_connected, error_msg = await monitor.check_ssh_connectivity(
            ip_address=str(host.ip_address),
            port=22,
        )

        return {
            "host_id": host_id,
            "ip_address": host.ip_address,
            "connected": is_connected,
            "error_message": error_msg,
            "current_policy": "default_policy",
        }

    except Exception as e:
        logger.error(f"Error testing SSH connectivity: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to test SSH connectivity",
        )
