"""
SSH Settings API Routes
Handles SSH host key policy and known hosts management
"""

import ipaddress
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, validator
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..rbac import Permission, require_permission
from ..services.unified_ssh_service import SSHConfigService

# from ..services.enhanced_audit_service import log_enhanced_ssh_event  # TODO: Create when needed

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ssh-settings", tags=["SSH Settings"])


# Pydantic models
class SSHPolicyRequest(BaseModel):
    policy: str
    trusted_networks: Optional[List[str]] = []

    @validator("policy")
    def validate_policy(cls, v):
        valid_policies = ["strict", "auto_add", "bypass_trusted"]
        if v not in valid_policies:
            raise ValueError(f"Policy must be one of: {valid_policies}")
        return v

    @validator("trusted_networks")
    def validate_networks(cls, v):
        for network in v:
            try:
                ipaddress.ip_network(network, strict=False)
            except ValueError as e:
                raise ValueError(f"Invalid network range '{network}': {e}")
        return v


class SSHPolicyResponse(BaseModel):
    policy: str
    trusted_networks: List[str]
    description: str


class KnownHostRequest(BaseModel):
    hostname: str
    ip_address: Optional[str] = None
    key_type: str
    public_key: str
    notes: Optional[str] = None

    @validator("key_type")
    def validate_key_type(cls, v):
        valid_types = ["rsa", "ecdsa", "ed25519", "dsa"]
        if v not in valid_types:
            raise ValueError(f"Key type must be one of: {valid_types}")
        return v


class KnownHostResponse(BaseModel):
    id: int
    hostname: str
    ip_address: Optional[str]
    key_type: str
    fingerprint: str
    first_seen: str
    last_verified: Optional[str]
    is_trusted: bool
    notes: Optional[str]


@router.get("/policy", response_model=SSHPolicyResponse)
@require_permission(Permission.SYSTEM_CONFIG)
async def get_ssh_policy(
    db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)
):
    """Get current SSH host key policy configuration"""
    try:
        service = SSHConfigService(db)

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
    current_user: dict = Depends(get_current_user),
):
    """Set SSH host key policy configuration"""
    try:
        service = SSHConfigService(db)

        # Set policy
        success = service.set_ssh_policy(policy_request.policy, current_user.get("id"))
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update SSH policy",
            )

        # Set trusted networks if provided
        if policy_request.trusted_networks is not None:
            success = service.set_trusted_networks(
                policy_request.trusted_networks, current_user.get("id")
            )
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to update trusted networks",
                )

        # Enhanced audit logging with dual system support
        # FIXME: Disabled - log_enhanced_ssh_event function not yet implemented
        # logger.info(f"SSH policy update: About to call enhanced audit logging")
        # logger.info(f"Current user: {current_user}")
        # logger.info(f"Policy request: {policy_request.policy}")
        # try:
        #     await log_enhanced_ssh_event(
        #         db=db,
        #         action="POLICY_UPDATED",
        #         policy_data={
        #             "policy": policy_request.policy,
        #             "trusted_networks": policy_request.trusted_networks or [],
        #             "trusted_networks_count": len(policy_request.trusted_networks or []),
        #             "change_reason": "Administrator policy update",
        #         },
        #         user_id=current_user.get("id"),
        #         username=current_user.get("username"),
        #         ip_address="172.20.0.1",
        #         new_values={
        #             "policy": policy_request.policy,
        #             "trusted_networks": policy_request.trusted_networks,
        #         },
        #     )
        #     logger.info(f"Enhanced audit logging completed successfully")
        # except Exception as audit_error:
        #     logger.warning(f"Enhanced audit logging failed for SSH policy update: {audit_error}")
        #     logger.warning(f"Error details: {type(audit_error)} - {str(audit_error)}")
        #     import traceback
        #
        #     logger.warning(f"Traceback: {traceback.format_exc()}")
        #     # Continue with operation - don't fail SSH updates due to audit issues

        # Return updated configuration
        return await get_ssh_policy(db=db, current_user=current_user)

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
    current_user: dict = Depends(get_current_user),
):
    """Get SSH known hosts, optionally filtered by hostname"""
    try:
        service = SSHConfigService(db)

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
    current_user: dict = Depends(get_current_user),
):
    """Add a host key to SSH known hosts"""
    try:
        service = SSHConfigService(db)

        success = service.add_known_host(
            hostname=host_request.hostname,
            ip_address=host_request.ip_address,
            key_type=host_request.key_type,
            public_key=host_request.public_key,
            user_id=current_user.get("id"),
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to add known host",
            )

        # Enhanced audit logging
        # FIXME: Disabled - log_enhanced_ssh_event function not yet implemented
        # try:
        #     await log_enhanced_ssh_event(
        #         db=db,
        #         action="KNOWN_HOST_ADDED",
        #         policy_data={
        #             "hostname": host_request.hostname,
        #             "ip_address": host_request.ip_address,
        #             "key_type": host_request.key_type,
        #             "action": "add_known_host",
        #         },
        #         user_id=current_user.get("id"),
        #         username=current_user.get("username"),
        #         ip_address="172.20.0.1",
        #     )
        # except Exception as audit_error:
        #     logger.warning(
        #         f"Enhanced audit logging failed for SSH known host addition: {audit_error}"
        #     )

        # Return the added host
        hosts = service.get_known_hosts(host_request.hostname)
        matching_host = next(
            (
                h
                for h in hosts
                if h["hostname"] == host_request.hostname and h["key_type"] == host_request.key_type
            ),
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
    current_user: dict = Depends(get_current_user),
):
    """Remove a host key from SSH known hosts"""
    try:
        service = SSHConfigService(db)

        success = service.remove_known_host(hostname, key_type)

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Known host not found"
            )

        # Enhanced audit logging
        # FIXME: Disabled - log_enhanced_ssh_event function not yet implemented
        # try:
        #     await log_enhanced_ssh_event(
        #         db=db,
        #         action="KNOWN_HOST_REMOVED",
        #         policy_data={
        #             "hostname": hostname,
        #             "key_type": key_type or "all_key_types",
        #             "action": "remove_known_host",
        #         },
        #         user_id=current_user.get("id"),
        #         username=current_user.get("username"),
        #         ip_address="172.20.0.1",
        #     )
        # except Exception as audit_error:
        #     logger.warning(
        #         f"Enhanced audit logging failed for SSH known host removal: {audit_error}"
        #     )

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
    current_user: dict = Depends(get_current_user),
):
    """Test SSH connectivity to a host with current policy"""
    try:
        from ..database import Host
        from ..services.host_monitor import HostMonitor

        # Get host
        host = db.query(Host).filter(Host.id == host_id).first()
        if not host:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Host not found")

        # Test connectivity
        monitor = HostMonitor()
        is_connected, error_msg = await monitor.test_ssh_connection(
            host.ip_address,
            22,  # Default SSH port
            None,  # Will use system credentials
            None,
            None,
        )

        # Enhanced audit logging
        # FIXME: Disabled - log_enhanced_ssh_event function not yet implemented
        # try:
        #     await log_enhanced_ssh_event(
        #         db=db,
        #         action="CONNECTIVITY_TEST",
        #         policy_data={
        #             "host_id": host_id,
        #             "target_ip": host.ip_address,
        #             "test_result": "SUCCESS" if is_connected else "FAILED",
        #             "error_message": error_msg,
        #             "current_policy": "default_policy",
        #         },
        #         user_id=current_user.get("id"),
        #         username=current_user.get("username"),
        #         ip_address="172.20.0.1",
        #     )
        # except Exception as audit_error:
        #     logger.warning(
        #         f"Enhanced audit logging failed for SSH connectivity test: {audit_error}"
        #     )

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
