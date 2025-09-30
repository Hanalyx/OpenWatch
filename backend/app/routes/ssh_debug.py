"""
SSH Debug Routes
Provides detailed SSH debugging capabilities for troubleshooting authentication issues
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
import logging
import json
from typing import Optional, Dict, Any

from ..database import get_db, Host
from ..auth import get_current_user
from ..rbac import require_permission, Permission
from ..services.unified_ssh_service import UnifiedSSHService
from ..services.auth_service import get_auth_service
from ..services.crypto import decrypt_credentials

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ssh-debug", tags=["SSH Debug"])


class SSHDebugRequest(BaseModel):
    host_id: str
    enable_paramiko_debug: Optional[bool] = True
    test_host_credentials: Optional[bool] = True
    test_global_credentials: Optional[bool] = True


class SSHDebugResponse(BaseModel):
    host_info: Dict[str, Any]
    host_credentials_test: Optional[Dict[str, Any]]
    global_credentials_test: Optional[Dict[str, Any]]
    ssh_policy_info: Dict[str, Any]
    recommendations: List[str]


@router.post("/test-authentication", response_model=SSHDebugResponse)
@require_permission(Permission.SYSTEM_CONFIG)
async def debug_ssh_authentication(
    request: SSHDebugRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Debug SSH authentication issues with detailed diagnostics
    """
    try:
        # Get host details
        host = db.query(Host).filter(Host.id == request.host_id).first()
        if not host:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Host not found"
            )
        
        ssh_service = UnifiedSSHService(db)
        auth_service = get_auth_service(db)
        
        # Enable debug mode if requested
        if request.enable_paramiko_debug:
            ssh_service.enable_debug_mode()
        
        response = SSHDebugResponse(
            host_info={
                "id": str(host.id),
                "hostname": host.hostname,
                "ip_address": str(host.ip_address),
                "port": host.port or 22,
                "username": host.username,
                "auth_method": host.auth_method,
                "has_encrypted_credentials": bool(host.encrypted_credentials),
                "status": host.status
            },
            host_credentials_test=None,
            global_credentials_test=None,
            ssh_policy_info={
                "current_policy": ssh_service.get_ssh_policy(),
                "trusted_networks": ssh_service.get_trusted_networks(),
                "is_host_trusted": ssh_service.is_host_in_trusted_network(host.ip_address)
            },
            recommendations=[]
        )
        
        # Test host-specific credentials
        if request.test_host_credentials and host.encrypted_credentials:
            logger.info(f"Testing host-specific credentials for {host.hostname}")
            try:
                # Decrypt host credentials
                encrypted_data = host.encrypted_credentials
                if isinstance(encrypted_data, memoryview):
                    encrypted_data = bytes(encrypted_data)
                
                decrypted_data = decrypt_credentials(encrypted_data)
                cred_data = json.loads(decrypted_data)
                
                # Validate key if present
                key_info = None
                if cred_data.get('ssh_key'):
                    validation_result = ssh_service.validate_ssh_key(cred_data['ssh_key'])
                    key_info = {
                        "valid": validation_result.is_valid,
                        "type": validation_result.key_type.value if validation_result.key_type else None,
                        "size": validation_result.key_size,
                        "security_level": validation_result.security_level.value if validation_result.security_level else None,
                        "error": validation_result.error_message
                    }
                
                # Test connection
                auth_method = "key" if cred_data.get('ssh_key') else "password"
                credential = cred_data.get('ssh_key') or cred_data.get('password')
                
                connection_result = ssh_service.connect_with_credentials(
                    hostname=host.ip_address,
                    port=host.port or 22,
                    username=cred_data.get('username', host.username),
                    auth_method=auth_method,
                    credential=credential,
                    service_name="SSH_Debug_Host_Creds",
                    timeout=15
                )
                
                response.host_credentials_test = {
                    "success": connection_result.success,
                    "auth_method": auth_method,
                    "username": cred_data.get('username', host.username),
                    "key_info": key_info,
                    "error_message": connection_result.error_message,
                    "error_type": connection_result.error_type,
                    "host_key_fingerprint": connection_result.host_key_fingerprint
                }
                
                if connection_result.connection:
                    connection_result.connection.close()
                
            except Exception as e:
                logger.error(f"Host credential test failed: {type(e).__name__}: {str(e)}")
                response.host_credentials_test = {
                    "success": False,
                    "error": f"Failed to test host credentials: {type(e).__name__}: {str(e)}"
                }
        
        # Test global/system credentials
        if request.test_global_credentials:
            logger.info(f"Testing global credentials for {host.hostname}")
            try:
                # Get global credentials
                global_creds = auth_service.resolve_credential(
                    target_id=None,
                    use_default=True
                )
                
                if global_creds:
                    # Validate key if present
                    key_info = None
                    if global_creds.private_key:
                        validation_result = ssh_service.validate_ssh_key(global_creds.private_key)
                        key_info = {
                            "valid": validation_result.is_valid,
                            "type": validation_result.key_type.value if validation_result.key_type else None,
                            "size": validation_result.key_size,
                            "security_level": validation_result.security_level.value if validation_result.security_level else None,
                            "error": validation_result.error_message,
                            "warnings": validation_result.warnings,
                            "recommendations": validation_result.recommendations
                        }
                    
                    # Test connection
                    auth_method = "key" if global_creds.private_key else "password"
                    credential = global_creds.private_key or global_creds.password
                    
                    connection_result = ssh_service.connect_with_credentials(
                        hostname=host.ip_address,
                        port=host.port or 22,
                        username=global_creds.username,
                        auth_method=auth_method,
                        credential=credential,
                        service_name="SSH_Debug_Global_Creds",
                        timeout=15
                    )
                    
                    response.global_credentials_test = {
                        "success": connection_result.success,
                        "auth_method": auth_method,
                        "username": global_creds.username,
                        "key_info": key_info,
                        "error_message": connection_result.error_message,
                        "error_type": connection_result.error_type,
                        "host_key_fingerprint": connection_result.host_key_fingerprint,
                        "source": global_creds.source
                    }
                    
                    if connection_result.connection:
                        connection_result.connection.close()
                else:
                    response.global_credentials_test = {
                        "success": False,
                        "error": "No global SSH credentials configured"
                    }
                    
            except Exception as e:
                logger.error(f"Global credential test failed: {type(e).__name__}: {str(e)}")
                response.global_credentials_test = {
                    "success": False,
                    "error": f"Failed to test global credentials: {type(e).__name__}: {str(e)}"
                }
        
        # Generate recommendations
        recommendations = []
        
        # Check if any credentials succeeded
        host_success = response.host_credentials_test and response.host_credentials_test.get("success")
        global_success = response.global_credentials_test and response.global_credentials_test.get("success")
        
        if not host_success and not global_success:
            recommendations.append("No working SSH credentials found. Please verify:")
            recommendations.append("- The SSH username is correct")
            recommendations.append("- The SSH key or password is valid")
            recommendations.append("- The target host accepts the authentication method")
            recommendations.append("- SSH service is running on the target host")
            
            # Check specific error types
            if response.host_credentials_test:
                error_type = response.host_credentials_test.get("error_type")
                if error_type == "auth_failed":
                    recommendations.append("- Ensure the SSH key is added to ~/.ssh/authorized_keys on the target")
                    recommendations.append("- Check SSH server configuration (PermitRootLogin, PubkeyAuthentication)")
                elif error_type == "key_error":
                    recommendations.append("- Verify the SSH private key format (RSA, Ed25519, etc.)")
                    recommendations.append("- Ensure the key is not corrupted")
        
        elif host_success and not global_success:
            recommendations.append("Host-specific credentials work. Global credentials may need updating.")
        
        elif not host_success and global_success:
            recommendations.append("Global credentials work. Consider using 'default' auth method for this host.")
        
        # Add SSH policy recommendations
        if response.ssh_policy_info["current_policy"] == "strict":
            recommendations.append("SSH policy is set to 'strict' - ensure known_hosts is properly configured")
        
        # Check key security if available
        if response.global_credentials_test and response.global_credentials_test.get("key_info"):
            key_info = response.global_credentials_test["key_info"]
            if key_info.get("recommendations"):
                recommendations.extend(key_info["recommendations"])
        
        response.recommendations = recommendations
        
        # Disable debug mode
        if request.enable_paramiko_debug:
            ssh_service.disable_debug_mode()
            recommendations.append("Check /tmp/paramiko_debug.log for detailed SSH protocol debugging")
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"SSH debug test failed: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"SSH debug test failed: {str(e)}"
        )


@router.get("/paramiko-log")
@require_permission(Permission.SYSTEM_CONFIG)
async def get_paramiko_debug_log(
    lines: int = 100,
    current_user: dict = Depends(get_current_user)
):
    """
    Retrieve the last N lines of the paramiko debug log
    """
    try:
        import os
        log_path = "/tmp/paramiko_debug.log"
        
        if not os.path.exists(log_path):
            return {
                "exists": False,
                "message": "No paramiko debug log found. Enable debug mode first."
            }
        
        # Read last N lines
        with open(log_path, 'r') as f:
            all_lines = f.readlines()
            last_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines
        
        return {
            "exists": True,
            "total_lines": len(all_lines),
            "returned_lines": len(last_lines),
            "log_content": ''.join(last_lines)
        }
        
    except Exception as e:
        logger.error(f"Failed to read paramiko log: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read debug log: {str(e)}"
        )