"""
Centralized Authentication API v2
Provides unified credential management endpoints that replace the inconsistent
dual-system approach with a single, consistent authentication layer.
"""

import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ...auth import get_current_user
from ...database import get_db
from ...encryption import EncryptionService
from ...rbac import Permission, require_permission
from ...services.auth_service import (
    AuthMethod,
    CentralizedAuthService,
    CredentialData,
    CredentialMetadata,
    CredentialScope,
    get_auth_service,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v2/credentials", tags=["Credentials v2"])


def get_encryption_service_from_request(request: Request) -> EncryptionService:
    """Helper function to get encryption service from app state"""
    return request.app.state.encryption_service


# Pydantic models for API
class CredentialCreateRequest(BaseModel):
    """Request model for creating credentials"""

    name: str = Field(..., description="Human-readable name for the credential")
    description: Optional[str] = Field(None, description="Optional description")
    scope: CredentialScope = Field(..., description="Credential scope")
    target_id: Optional[str] = Field(None, description="Target ID (required for host/group scope)")
    username: str = Field(..., description="SSH username")
    auth_method: AuthMethod = Field(..., description="Authentication method")
    private_key: Optional[str] = Field(None, description="SSH private key content")
    password: Optional[str] = Field(None, description="SSH password")
    private_key_passphrase: Optional[str] = Field(None, description="SSH key passphrase")
    is_default: bool = Field(False, description="Set as default for this scope")


class CredentialResponse(BaseModel):
    """Response model for credential data (without sensitive fields)"""

    id: str
    name: str
    description: Optional[str]
    scope: str
    target_id: Optional[str]
    username: str
    auth_method: str
    ssh_key_fingerprint: Optional[str]
    ssh_key_type: Optional[str]
    ssh_key_bits: Optional[int]
    ssh_key_comment: Optional[str]
    is_default: bool
    is_active: bool  # WEEK 2 FIX: Include is_active for compliance visibility
    created_at: str
    updated_at: str


class CredentialResolveResponse(BaseModel):
    """Response model for resolved credentials"""

    username: str
    auth_method: str
    has_private_key: bool
    has_password: bool
    source: str
    ssh_key_fingerprint: Optional[str]
    ssh_key_type: Optional[str]


class CredentialDataResponse(BaseModel):
    """Response model with decrypted credential data (admin only)"""

    username: str
    auth_method: str
    private_key: Optional[str]
    password: Optional[str]
    private_key_passphrase: Optional[str]
    source: str


@router.post("/", response_model=CredentialResponse)
@require_permission(Permission.SYSTEM_CREDENTIALS)
async def create_credential(
    request: CredentialCreateRequest,
    http_request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Create a new credential with unified encryption.
    All credentials use AES-256-GCM regardless of scope.
    """
    try:
        encryption_service = get_encryption_service_from_request(http_request)
        auth_service = get_auth_service(db, encryption_service)

        # Validate scope and target_id relationship
        if request.scope in [CredentialScope.HOST, CredentialScope.GROUP] and not request.target_id:
            raise HTTPException(
                status_code=400,
                detail=f"target_id is required for {request.scope.value} scope",
            )

        if request.scope == CredentialScope.SYSTEM and request.target_id:
            raise HTTPException(status_code=400, detail="target_id must be null for system scope")

        # Create credential data
        credential_data = CredentialData(
            username=request.username,
            auth_method=request.auth_method,
            private_key=request.private_key,
            password=request.password,
            private_key_passphrase=request.private_key_passphrase,
        )

        # Create metadata
        metadata = CredentialMetadata(
            name=request.name,
            description=request.description,
            scope=request.scope,
            target_id=request.target_id,
            is_default=request.is_default,
        )

        # Store credential
        # WEEK 2 MIGRATION: Convert integer user ID to UUID format
        user_id = current_user.get("id")
        if user_id and isinstance(user_id, int):
            user_id = f"00000000-0000-0000-0000-{user_id:012d}"

        credential_id = auth_service.store_credential(
            credential_data=credential_data, metadata=metadata, created_by=user_id
        )

        # Return credential metadata (no sensitive data)
        credentials_list = auth_service.list_credentials()
        created_credential = next((c for c in credentials_list if c["id"] == credential_id), None)

        if not created_credential:
            raise HTTPException(status_code=500, detail="Failed to retrieve created credential")

        return CredentialResponse(**created_credential)

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to create credential: {e}")
        raise HTTPException(status_code=500, detail="Failed to create credential")


@router.get("/", response_model=List[CredentialResponse])
@require_permission(Permission.SYSTEM_CREDENTIALS)
async def list_credentials(
    http_request: Request,
    scope: Optional[CredentialScope] = None,
    target_id: Optional[str] = None,
    include_inactive: bool = False,  # WEEK 2: Control inactive credential visibility
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    List credentials with optional filtering.
    Returns metadata only (no sensitive credential data).
    Set include_inactive=true to show deleted/inactive credentials for compliance audit.
    """
    try:
        encryption_service = get_encryption_service_from_request(http_request)
        auth_service = get_auth_service(db, encryption_service)

        # For non-admin users, filter by their created credentials
        # Note: user_id must be UUID string format, not integer
        # WEEK 2 FIX: Check role instead of is_admin (which doesn't exist in JWT)
        user_id = None
        user_role = current_user.get("role", "")
        is_admin = user_role in ["super_admin", "admin"]

        if not is_admin:
            # Convert integer user ID to UUID format (for compatibility)
            int_id = current_user.get("id")
            if int_id:
                user_id = f"00000000-0000-0000-0000-{int_id:012d}"

        # WEEK 2 FIX: Include inactive credentials only if requested (for compliance audit)
        credentials = auth_service.list_credentials(
            scope=scope,
            target_id=target_id,
            user_id=user_id,
            include_inactive=include_inactive,
        )

        return [CredentialResponse(**cred) for cred in credentials]

    except Exception as e:
        logger.error(f"Failed to list credentials: {e}")
        raise HTTPException(status_code=500, detail="Failed to list credentials")


@router.get("/resolve/{target_id}", response_model=CredentialResolveResponse)
async def resolve_credential(
    target_id: str,
    http_request: Request,
    use_default: bool = False,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Resolve effective credentials for a target using inheritance logic.
    This is the core endpoint that fixes authentication inconsistency.

    Resolution order:
    1. If use_default=True -> system default credential
    2. If target_id provided -> target-specific credential
    3. If target has no credential -> fallback to system default
    """
    try:
        encryption_service = get_encryption_service_from_request(http_request)
        auth_service = get_auth_service(db, encryption_service)

        credential = auth_service.resolve_credential(target_id=target_id, use_default=use_default)

        if not credential:
            raise HTTPException(
                status_code=404,
                detail=f"No credentials available for target {target_id}",
            )

        # Return non-sensitive credential information
        return CredentialResolveResponse(
            username=credential.username,
            auth_method=credential.auth_method.value,
            has_private_key=bool(credential.private_key),
            has_password=bool(credential.password),
            source=credential.source,
            ssh_key_fingerprint=None,  # Could add SSH metadata lookup here
            ssh_key_type=None,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to resolve credential for {target_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to resolve credential")


@router.get("/resolve/{target_id}/data", response_model=CredentialDataResponse)
@require_permission(Permission.SYSTEM_CREDENTIALS)
async def get_credential_data(
    target_id: str,
    http_request: Request,
    use_default: bool = False,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Get decrypted credential data for internal use (admin only).
    Used by scanning and monitoring services.
    """
    try:
        encryption_service = get_encryption_service_from_request(http_request)
        auth_service = get_auth_service(db, encryption_service)

        credential = auth_service.resolve_credential(target_id=target_id, use_default=use_default)

        if not credential:
            raise HTTPException(
                status_code=404,
                detail=f"No credentials available for target {target_id}",
            )

        # Return decrypted credential data
        return CredentialDataResponse(
            username=credential.username,
            auth_method=credential.auth_method.value,
            private_key=credential.private_key,
            password=credential.password,
            private_key_passphrase=credential.private_key_passphrase,
            source=credential.source,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get credential data for {target_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get credential data")


@router.get("/system/default", response_model=CredentialDataResponse)
async def get_system_default_credential(
    http_request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Get system default credential for internal use.
    Maintains compatibility with existing code.
    """
    try:
        encryption_service = get_encryption_service_from_request(http_request)
        auth_service = get_auth_service(db, encryption_service)

        credential = auth_service.resolve_credential(use_default=True)

        if not credential:
            raise HTTPException(status_code=404, detail="No system default credential configured")

        return CredentialDataResponse(
            username=credential.username,
            auth_method=credential.auth_method.value,
            private_key=credential.private_key,
            password=credential.password,
            private_key_passphrase=credential.private_key_passphrase,
            source=credential.source,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get system default credential: {e}")
        raise HTTPException(status_code=500, detail="Failed to get system default credential")


@router.post("/validate")
async def validate_credential(
    credential_data: CredentialCreateRequest,
    http_request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Validate credential format and connectivity without storing.
    """
    try:
        encryption_service = get_encryption_service_from_request(http_request)
        auth_service = get_auth_service(db, encryption_service)

        # Create credential data for validation
        cred_data = CredentialData(
            username=credential_data.username,
            auth_method=credential_data.auth_method,
            private_key=credential_data.private_key,
            password=credential_data.password,
            private_key_passphrase=credential_data.private_key_passphrase,
        )

        # Validate credential
        is_valid, error_message = auth_service.validate_credential(cred_data)

        if is_valid:
            return {"valid": True, "message": "Credential validation passed"}
        else:
            return {"valid": False, "message": error_message}

    except Exception as e:
        logger.error(f"Credential validation error: {e}")
        return {"valid": False, "message": f"Validation error: {str(e)}"}


@router.delete("/{credential_id}/")
@require_permission(Permission.SYSTEM_CREDENTIALS)
async def delete_credential(
    credential_id: str,
    http_request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Soft delete a credential by marking it inactive.
    """
    try:
        encryption_service = get_encryption_service_from_request(http_request)
        auth_service = get_auth_service(db, encryption_service)

        success = auth_service.delete_credential(credential_id)

        if success:
            return {"message": "Credential deleted successfully"}
        else:
            raise HTTPException(status_code=404, detail="Credential not found")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete credential: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete credential")
