"""
API Key Management Routes
Handles creation and management of API keys for service-to-service authentication
"""

import hashlib
import logging
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, text
from sqlalchemy.orm import Session

from ...auth import audit_logger, get_current_user
from ...database import ApiKey, get_db
from ...rbac import UserRole, check_permission

logger = logging.getLogger(__name__)
router = APIRouter()


class CreateApiKeyRequest(BaseModel):
    """Request model for creating API keys."""

    name: str = Field(..., min_length=3, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    expires_in_days: Optional[int] = Field(365, ge=1, le=1825)  # Max 5 years
    permissions: Optional[Dict[str, List[str]]] = Field(default_factory=dict)


class ApiKeyResponse(BaseModel):
    """Response model for API key data."""

    id: str
    name: str
    description: Optional[str]
    created_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    is_active: bool
    permissions: Dict[str, List[str]]
    created_by_username: str


class CreateApiKeyResponse(ApiKeyResponse):
    key: str  # Only returned on creation


def generate_api_key() -> tuple[str, str]:
    """Generate a secure API key and its hash"""
    # Generate a 32-byte random key
    raw_key = secrets.token_urlsafe(32)
    # Create a prefixed key for easy identification
    api_key = f"owk_{raw_key}"
    # Hash the key for storage
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    return api_key, key_hash


@router.post("/", response_model=CreateApiKeyResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    request: CreateApiKeyRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> CreateApiKeyResponse:
    """Create a new API key for service integration."""
    # Check permission
    check_permission(current_user["role"], "api_keys", "create")

    # Check if API key with same name exists
    existing = db.query(ApiKey).filter(and_(ApiKey.name == request.name, ApiKey.is_active.is_(True))).first()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"API key with name '{request.name}' already exists",
        )

    # Generate API key
    api_key, key_hash = generate_api_key()

    # Calculate expiration
    expires_at = None
    if request.expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=request.expires_in_days)

    # Create database entry
    db_api_key = ApiKey(
        name=request.name,
        description=request.description,
        key_hash=key_hash,
        permissions=request.permissions or {},
        created_by=current_user["id"],
        expires_at=expires_at,
        is_active=True,
    )

    db.add(db_api_key)
    db.commit()
    db.refresh(db_api_key)

    # Log the action (fire-and-forget, no return value)
    audit_logger.log_api_key_action(
        user_id=current_user["id"],
        action="API_KEY_CREATED",
        api_key_id=str(db_api_key.id),
        api_key_name=str(db_api_key.name),
        details={"expires_at": expires_at.isoformat() if expires_at else None},
    )

    logger.info(f"API key '{request.name}' created by user {current_user['username']}")

    return CreateApiKeyResponse(
        id=str(db_api_key.id),
        name=db_api_key.name,
        description=db_api_key.description,
        created_at=db_api_key.created_at,
        expires_at=db_api_key.expires_at,
        last_used_at=db_api_key.last_used_at,
        is_active=db_api_key.is_active,
        permissions=db_api_key.permissions,
        created_by_username=current_user["username"],
        key=api_key,  # Return the actual key only on creation
    )


@router.get("/", response_model=List[ApiKeyResponse])
async def list_api_keys(
    skip: int = 0,
    limit: int = 100,
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[ApiKeyResponse]:
    """List all API keys."""
    # Check permission
    check_permission(current_user["role"], "api_keys", "read")

    query = db.query(ApiKey)

    if not include_inactive:
        query = query.filter(ApiKey.is_active.is_(True))

    # If not admin, only show keys created by the user
    if current_user["role"] not in [
        UserRole.SUPER_ADMIN.value,
        UserRole.SECURITY_ADMIN.value,
    ]:
        query = query.filter(ApiKey.created_by == current_user["id"])

    api_keys = query.offset(skip).limit(limit).all()

    # Get creator usernames
    creator_ids = [key.created_by for key in api_keys]
    creators: Dict[str, str] = {}
    if creator_ids:
        creator_query = db.execute(
            text("SELECT id, username FROM users WHERE id = ANY(:ids)"),
            {"ids": creator_ids},
        )
        creators = {str(row.id): row.username for row in creator_query}

    return [
        ApiKeyResponse(
            id=str(key.id),
            name=key.name,
            description=key.description,
            created_at=key.created_at,
            expires_at=key.expires_at,
            last_used_at=key.last_used_at,
            is_active=key.is_active,
            permissions=key.permissions,
            created_by_username=creators.get(str(key.created_by), "unknown"),
        )
        for key in api_keys
    ]


@router.delete("/{api_key_id}")
async def revoke_api_key(
    api_key_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, str]:
    """Revoke an API key."""
    # Check permission
    check_permission(current_user["role"], "api_keys", "delete")

    # Get the API key
    api_key = db.query(ApiKey).filter(ApiKey.id == api_key_id).first()

    if not api_key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")

    # Check ownership (unless admin)
    if current_user["role"] not in [
        UserRole.SUPER_ADMIN.value,
        UserRole.SECURITY_ADMIN.value,
    ]:
        if str(api_key.created_by) != current_user["id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only revoke your own API keys",
            )

    # Revoke the key
    api_key.is_active = False
    db.commit()

    # Log the action (fire-and-forget, no return value)
    audit_logger.log_api_key_action(
        user_id=current_user["id"],
        action="API_KEY_REVOKED",
        api_key_id=api_key_id,
        api_key_name=str(api_key.name),
    )

    logger.info(f"API key '{api_key.name}' revoked by user {current_user['username']}")

    return {"message": "API key revoked successfully"}


@router.put("/{api_key_id}/permissions")
async def update_api_key_permissions(
    api_key_id: str,
    permissions: Dict[str, List[str]],
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, str]:
    """Update API key permissions."""
    # Check permission (only admins can update permissions)
    if current_user["role"] not in [
        UserRole.SUPER_ADMIN.value,
        UserRole.SECURITY_ADMIN.value,
    ]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can update API key permissions",
        )

    # Get the API key
    api_key = db.query(ApiKey).filter(ApiKey.id == api_key_id).first()

    if not api_key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")

    # Update permissions
    api_key.permissions = permissions
    db.commit()

    # Log the action (fire-and-forget, no return value)
    audit_logger.log_api_key_action(
        user_id=current_user["id"],
        action="API_KEY_PERMISSIONS_UPDATED",
        api_key_id=api_key_id,
        api_key_name=str(api_key.name),
        details={"new_permissions": permissions},
    )

    logger.info(f"API key '{api_key.name}' permissions updated by user {current_user['username']}")

    return {"message": "API key permissions updated successfully"}
