"""
Credential Sharing API Routes

API endpoints for sharing SSH credentials with AEGIS for remediation.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Response, status
from fastapi.security import HTTPBearer
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..utils.logging_security import sanitize_id_for_log

logger = logging.getLogger(__name__)
security = HTTPBearer(auto_error=False)

router = APIRouter(prefix="/credentials", tags=["Credential Sharing"])


def verify_aegis_signature(payload: bytes, signature: str, secret_key: str) -> bool:
    """Verify HMAC-SHA256 signature from AEGIS."""
    try:
        expected_signature = hmac.new(secret_key.encode("utf-8"), payload, hashlib.sha256).hexdigest()

        # Remove 'sha256=' prefix if present
        if signature.startswith("sha256="):
            signature = signature[7:]

        return hmac.compare_digest(expected_signature, signature)
    except Exception as e:
        logger.error(f"Signature verification failed: {e}")
        return False


def validate_aegis_request(signature: Optional[str] = Header(None, alias="X-AEGIS-Signature")) -> bool:
    """Validate incoming AEGIS request signature."""
    if not signature:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing AEGIS signature header",
        )

    # AEGIS integration secrets removed - not currently implemented
    # AEGIS integration is optional and only active when AEGIS_URL is configured
    # When AEGIS integration is activated, proper secret configuration should be added
    # via environment variables (never hardcoded)

    # For now, skip signature verification if AEGIS_URL is not configured
    aegis_url = os.environ.get("AEGIS_URL")
    if not aegis_url:
        # AEGIS not configured, skip verification
        return True

    # Note: When AEGIS is implemented, add proper signature verification here
    # using secrets from environment variables, never hardcoded values
    return True


class HostCredentialsRequest(BaseModel):
    """Request for host credentials."""

    host_ids: List[str]
    requesting_service: str = "aegis"


class SSHCredential(BaseModel):
    """SSH credential information."""

    host_id: str
    hostname: str
    username: str
    auth_method: str
    ssh_key: Optional[str] = None
    key_type: Optional[str] = None
    password: Optional[str] = None
    source: str = "openwatch"
    last_updated: str


class CredentialsResponse(BaseModel):
    """Response containing SSH credentials."""

    credentials: List[SSHCredential]
    total_count: int
    requested_count: int


@router.get("/hosts/{host_id}", response_model=SSHCredential)
async def get_host_credentials(
    host_id: str,
    db: Session = Depends(get_db),
    _: bool = Depends(validate_aegis_request),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> SSHCredential:
    """
    Get SSH credentials for a specific host (AEGIS integration).

    This endpoint allows AEGIS to retrieve SSH credentials for a host
    to perform remediation tasks.
    """
    try:
        # Get host and its credentials
        result = db.execute(
            text("""
            SELECT h.id, h.hostname, h.username, h.auth_method, h.encrypted_credentials,
                   h.updated_at
            FROM hosts h
            WHERE h.id = :host_id AND h.is_active = true
        """),
            {"host_id": host_id},
        )

        row = result.fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Host not found or inactive",
            )

        # Decrypt credentials
        ssh_key = None
        key_type = None
        password = None

        if row.encrypted_credentials:
            try:
                # Decrypt the credentials (currently using base64)
                decoded_data = base64.b64decode(row.encrypted_credentials).decode("utf-8")
                credentials_data = json.loads(decoded_data)

                ssh_key = credentials_data.get("ssh_key")
                password = credentials_data.get("password")

                # Determine key type if SSH key is present
                if ssh_key:
                    from ..services.ssh import detect_key_type

                    detected_type = detect_key_type(ssh_key)
                    key_type = detected_type.value if detected_type else None

            except Exception as e:
                logger.error(
                    f"Failed to decrypt credentials for host {sanitize_id_for_log(host_id)}: {type(e).__name__}"
                )
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to retrieve host credentials",
                )

        credential = SSHCredential(
            host_id=str(row.id),
            hostname=row.hostname,
            username=row.username or "",
            auth_method=row.auth_method or "ssh_key",
            ssh_key=ssh_key,
            key_type=key_type,
            password=password,
            source="openwatch",
            last_updated=(row.updated_at.isoformat() if row.updated_at else datetime.utcnow().isoformat()),
        )

        logger.info(f"Provided SSH credentials for host {row.hostname} to AEGIS")
        return credential

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving host credentials: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve host credentials",
        )


@router.post("/hosts/batch", response_model=CredentialsResponse)
async def get_multiple_host_credentials(
    request: HostCredentialsRequest,
    db: Session = Depends(get_db),
    _: bool = Depends(validate_aegis_request),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> CredentialsResponse:
    """
    Get SSH credentials for multiple hosts (AEGIS integration).

    Batch endpoint for retrieving SSH credentials for multiple hosts
    to perform remediation tasks efficiently.
    """
    try:
        if not request.host_ids:
            return CredentialsResponse(credentials=[], total_count=0, requested_count=0)

        # Limit batch size to prevent abuse
        if len(request.host_ids) > 100:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Maximum 100 hosts per batch request",
            )

        # Get hosts and their credentials
        placeholders = ",".join([f":host_id_{i}" for i in range(len(request.host_ids))])
        params = {f"host_id_{i}": host_id for i, host_id in enumerate(request.host_ids)}

        result = db.execute(
            text(f"""
            SELECT h.id, h.hostname, h.username, h.auth_method, h.encrypted_credentials,
                   h.updated_at
            FROM hosts h
            WHERE h.id IN ({placeholders}) AND h.is_active = true
            ORDER BY h.hostname
        """),
            params,
        )

        credentials = []
        from ..services.ssh import detect_key_type

        for row in result:
            ssh_key = None
            key_type = None
            password = None

            if row.encrypted_credentials:
                try:
                    # Decrypt the credentials (currently using base64)
                    decoded_data = base64.b64decode(row.encrypted_credentials).decode("utf-8")
                    credentials_data = json.loads(decoded_data)

                    ssh_key = credentials_data.get("ssh_key")
                    password = credentials_data.get("password")

                    # Determine key type if SSH key is present
                    if ssh_key:
                        detected_type = detect_key_type(ssh_key)
                        key_type = detected_type.value if detected_type else None

                except Exception as e:
                    logger.error(f"Failed to decrypt credentials for host {row.id}: {e}")
                    continue  # Skip this host rather than failing the entire batch

            credential = SSHCredential(
                host_id=str(row.id),
                hostname=row.hostname,
                username=row.username or "",
                auth_method=row.auth_method or "ssh_key",
                ssh_key=ssh_key,
                key_type=key_type,
                password=password,
                source="openwatch",
                last_updated=(row.updated_at.isoformat() if row.updated_at else datetime.utcnow().isoformat()),
            )

            credentials.append(credential)

        logger.info(f"Provided SSH credentials for {len(credentials)} hosts to AEGIS")

        return CredentialsResponse(
            credentials=credentials,
            total_count=len(credentials),
            requested_count=len(request.host_ids),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving batch host credentials: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve batch host credentials",
        )


@router.get("/system/default", response_model=SSHCredential)
async def get_default_system_credentials(
    response: Response,
    db: Session = Depends(get_db),
    _: bool = Depends(validate_aegis_request),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> SSHCredential:
    """
    Get default system SSH credentials (AEGIS integration).

    Retrieves the default system-wide SSH credentials that can be used
    for hosts that don't have specific credentials configured.
    """

    try:
        # WEEK 2 MIGRATION: Use CentralizedAuthService instead of system_credentials table
        from ..config import get_settings
        from ..encryption import create_encryption_service
        from ..services.auth import get_auth_service

        settings = get_settings()
        encryption_service = create_encryption_service(settings.MASTER_KEY)
        auth_service = get_auth_service(db, encryption_service)
        credential_data = auth_service.resolve_credential(use_default=True)

        if not credential_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No default system credentials configured",
            )

        # Determine key type if SSH key is present
        key_type = None
        if credential_data.private_key:
            from ..services.ssh import detect_key_type

            detected_type = detect_key_type(credential_data.private_key)
            key_type = detected_type.value if detected_type else None

        # Transform to SSHCredential response model (maintains backward compatibility)
        credential = SSHCredential(
            host_id="system-default",
            hostname="system-default",
            username=credential_data.username,
            auth_method=credential_data.auth_method.value,
            ssh_key=credential_data.private_key,
            key_type=key_type,
            password=credential_data.password,
            source="openwatch-system",
            last_updated=datetime.utcnow().isoformat(),
        )

        logger.info("Provided default system SSH credentials to AEGIS")
        return credential

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving default system credentials: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve default system credentials",
        )


@router.get("/health")
async def credentials_health_check() -> Dict[str, str]:
    """Health check endpoint for credential sharing service."""
    return {
        "status": "healthy",
        "service": "credential-sharing",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
    }
