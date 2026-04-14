"""
Admin CRUD endpoints for SSO provider management.

All endpoints require SUPER_ADMIN role.  Provider config is encrypted at
rest via EncryptionService and sensitive fields are redacted in list/get
responses.

Spec: specs/services/auth/sso-federation.spec.yaml (AC-13, AC-14)
"""

import base64
import json
import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from ...auth import get_current_user
from ...database import get_db
from ...rbac import UserRole, require_role
from ...utils.mutation_builders import DeleteBuilder, InsertBuilder, UpdateBuilder
from ...utils.query_builder import QueryBuilder

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/admin/sso",
    tags=["SSO Administration"],
)

# Redaction sentinel
REDACTED = "***REDACTED***"

# Config keys that contain sensitive values and must be redacted in responses
_SENSITIVE_CONFIG_KEYS = frozenset(
    {
        "client_secret",
        "signing_key",
        "sp_key_file",
        "sp_private_key",
        "private_key",
        "secret",
        "password",
        "token",
        "api_key",
    }
)

VALID_PROVIDER_TYPES = {"saml", "oidc"}


# ---------------------------------------------------------------------------
# Pydantic request / response schemas
# ---------------------------------------------------------------------------


class SSOProviderCreateRequest(BaseModel):
    """Request body for creating an SSO provider."""

    provider_type: str = Field(
        ...,
        pattern="^(saml|oidc)$",
        description="Provider protocol type",
    )
    name: str = Field(..., min_length=1, max_length=255)
    config: Dict[str, Any] = Field(
        ...,
        description="Provider configuration (will be encrypted at rest)",
    )
    enabled: bool = True


class SSOProviderUpdateRequest(BaseModel):
    """Request body for updating an SSO provider."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    config: Optional[Dict[str, Any]] = None
    enabled: Optional[bool] = None


class SSOProviderResponse(BaseModel):
    """Response body for an SSO provider (config secrets redacted)."""

    id: str
    provider_type: str
    name: str
    config: Dict[str, Any]
    enabled: bool
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_encryption_service(request: Request) -> Any:
    """Retrieve EncryptionService from app state."""
    if hasattr(request.app.state, "encryption_service"):
        return request.app.state.encryption_service
    from ...config import get_settings
    from ...encryption import EncryptionConfig, create_encryption_service

    settings = get_settings()
    return create_encryption_service(settings.master_key, EncryptionConfig())


def _encrypt_config(encryption_service: Any, config: Dict[str, Any]) -> str:
    """Encrypt a config dict and return a base64-encoded string for TEXT storage."""
    plaintext = json.dumps(config).encode("utf-8")
    encrypted_bytes = encryption_service.encrypt(plaintext)
    return base64.b64encode(encrypted_bytes).decode("ascii")


def _decrypt_config(encryption_service: Any, encrypted_b64: str) -> Dict[str, Any]:
    """Decrypt a base64-encoded encrypted config back to a dict."""
    encrypted_bytes = base64.b64decode(encrypted_b64)
    plaintext = encryption_service.decrypt(encrypted_bytes)
    return json.loads(plaintext.decode("utf-8"))


def _redact_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of config with sensitive values replaced by REDACTED."""
    redacted: Dict[str, Any] = {}
    for key, value in config.items():
        if key.lower() in _SENSITIVE_CONFIG_KEYS:
            redacted[key] = REDACTED
        else:
            redacted[key] = value
    return redacted


def _row_to_response(
    row: Any,
    encryption_service: Any,
) -> Dict[str, Any]:
    """Convert a DB row to an SSOProviderResponse dict with redacted config."""
    try:
        decrypted = _decrypt_config(encryption_service, row.config_encrypted)
    except Exception:
        decrypted = {"error": "unable to decrypt config"}
    return {
        "id": str(row.id),
        "provider_type": row.provider_type,
        "name": row.name,
        "config": _redact_config(decrypted),
        "enabled": row.enabled,
        "created_at": str(row.created_at) if row.created_at else None,
        "updated_at": str(row.updated_at) if row.updated_at else None,
    }


# ---------------------------------------------------------------------------
# Endpoints (AC-14: SUPER_ADMIN required)
# ---------------------------------------------------------------------------


@router.get("/providers", response_model=List[SSOProviderResponse])
@require_role([UserRole.SUPER_ADMIN])
async def list_sso_providers(
    request: Request,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """List all SSO providers with redacted config secrets (AC-13)."""
    encryption_service = _get_encryption_service(request)
    builder = QueryBuilder("sso_providers").order_by("created_at", "DESC")
    query, params = builder.build()
    result = db.execute(text(query), params)
    rows = result.fetchall()
    return [_row_to_response(row, encryption_service) for row in rows]


@router.post(
    "/providers",
    response_model=SSOProviderResponse,
    status_code=201,
)
@require_role([UserRole.SUPER_ADMIN])
async def create_sso_provider(
    body: SSOProviderCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Create a new SSO provider with encrypted config."""
    if body.provider_type not in VALID_PROVIDER_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid provider_type. Must be one of: {VALID_PROVIDER_TYPES}",
        )

    encryption_service = _get_encryption_service(request)
    encrypted_config = _encrypt_config(encryption_service, body.config)

    builder = (
        InsertBuilder("sso_providers")
        .columns("provider_type", "name", "config_encrypted", "enabled")
        .values(body.provider_type, body.name, encrypted_config, body.enabled)
        .returning(
            "id",
            "provider_type",
            "name",
            "config_encrypted",
            "enabled",
            "created_at",
            "updated_at",
        )
    )
    query, params = builder.build()
    result = db.execute(text(query), params)
    db.commit()
    row = result.fetchone()
    return _row_to_response(row, encryption_service)


@router.put("/providers/{provider_id}", response_model=SSOProviderResponse)
@require_role([UserRole.SUPER_ADMIN])
async def update_sso_provider(
    provider_id: UUID,
    body: SSOProviderUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Update an existing SSO provider."""
    encryption_service = _get_encryption_service(request)

    builder = UpdateBuilder("sso_providers")
    builder.set_if("name", body.name)
    builder.set_if("enabled", body.enabled)
    if body.config is not None:
        encrypted_config = _encrypt_config(encryption_service, body.config)
        builder.set("config_encrypted", encrypted_config)
    builder.set_raw("updated_at", "CURRENT_TIMESTAMP")
    builder.where("id = :id", str(provider_id), "id")
    builder.returning(
        "id",
        "provider_type",
        "name",
        "config_encrypted",
        "enabled",
        "created_at",
        "updated_at",
    )

    query, params = builder.build()
    result = db.execute(text(query), params)
    db.commit()
    row = result.fetchone()
    if not row:
        raise HTTPException(
            status_code=404,
            detail="SSO provider not found",
        )
    return _row_to_response(row, encryption_service)


@router.delete("/providers/{provider_id}", status_code=204)
@require_role([UserRole.SUPER_ADMIN])
async def delete_sso_provider(
    provider_id: UUID,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> None:
    """Delete an SSO provider.

    Users linked to this provider will have sso_provider_id set to NULL
    (FK ON DELETE SET NULL) but will retain their accounts.
    """
    builder = DeleteBuilder("sso_providers").where("id = :id", str(provider_id), "id").returning("id")
    query, params = builder.build()
    result = db.execute(text(query), params)
    db.commit()
    row = result.fetchone()
    if not row:
        raise HTTPException(
            status_code=404,
            detail="SSO provider not found",
        )


@router.post("/providers/{provider_id}/test")
@require_role([UserRole.SUPER_ADMIN])
async def test_sso_provider(
    provider_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Test an SSO provider configuration.

    Attempts to build the provider and generate a login URL as a basic
    connectivity check.
    """
    encryption_service = _get_encryption_service(request)

    builder = QueryBuilder("sso_providers").where("id = :id", str(provider_id), "id")
    query, params = builder.build()
    result = db.execute(text(query), params)
    row = result.fetchone()
    if not row:
        raise HTTPException(
            status_code=404,
            detail="SSO provider not found",
        )

    try:
        config = _decrypt_config(encryption_service, row.config_encrypted)
        if row.provider_type == "oidc":
            from ...services.auth.sso.oidc import OIDCProvider

            provider = OIDCProvider(config)
        elif row.provider_type == "saml":
            from ...services.auth.sso.saml import SAMLProvider

            provider = SAMLProvider(config)
        else:
            raise ValueError(f"Unknown provider type: {row.provider_type}")

        # Try to generate a login URL as a basic config validation
        test_state = "test-state-validation"
        test_url = provider.get_login_url(
            test_state,
            "https://localhost/test-callback",
        )
        return {
            "status": "ok",
            "provider_type": row.provider_type,
            "login_url_generated": bool(test_url),
        }
    except Exception as exc:
        logger.error("SSO provider test failed for %s: %s", provider_id, exc)
        return {
            "status": "error",
            "provider_type": row.provider_type,
            "error": str(exc),
        }
