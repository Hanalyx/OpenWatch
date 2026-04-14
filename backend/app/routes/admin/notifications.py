"""
Notification Channel Administration API.

CRUD endpoints for managing outbound notification channels (Slack, email,
webhook).  All endpoints require SUPER_ADMIN role.  Channel config is
encrypted at rest via EncryptionService and redacted in list responses.

Spec: specs/services/infrastructure/notification-channels.spec.yaml
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

router = APIRouter(prefix="/admin/notifications", tags=["Notification Administration"])

VALID_CHANNEL_TYPES = {"slack", "email", "webhook"}

# Redaction sentinel
REDACTED = "***REDACTED***"

# Config keys that contain sensitive values and must be redacted in responses
_SENSITIVE_CONFIG_KEYS = frozenset(
    {
        "webhook_url",
        "url",
        "secret",
        "smtp_password",
        "password",
        "api_key",
        "token",
        "private_key",
    }
)


# ---------------------------------------------------------------------------
# Pydantic request / response schemas
# ---------------------------------------------------------------------------


class ChannelCreateRequest(BaseModel):
    """Request body for creating a notification channel."""

    name: str = Field(..., min_length=1, max_length=255)
    channel_type: str = Field(..., min_length=1, max_length=16)
    config: Dict[str, Any] = Field(..., description="Channel-specific configuration")
    enabled: bool = True
    tenant_id: Optional[UUID] = None


class ChannelUpdateRequest(BaseModel):
    """Request body for updating a notification channel."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    config: Optional[Dict[str, Any]] = None
    enabled: Optional[bool] = None


class ChannelResponse(BaseModel):
    """Single channel response (config redacted)."""

    id: str
    tenant_id: Optional[str] = None
    channel_type: str
    name: str
    config: Dict[str, Any]
    enabled: bool
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class TestResultResponse(BaseModel):
    """Response from the test-send endpoint."""

    success: bool
    status_code: Optional[int] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_encryption_service(request: Request) -> Any:
    """Retrieve EncryptionService from app state."""
    if hasattr(request.app.state, "encryption_service"):
        return request.app.state.encryption_service
    # Fallback for testing
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


def _row_to_response(row: Any, encryption_service: Any) -> Dict[str, Any]:
    """Convert a DB row to a ChannelResponse dict with redacted config."""
    try:
        decrypted = _decrypt_config(encryption_service, row.config_encrypted)
    except Exception:
        decrypted = {"error": "unable to decrypt config"}
    return {
        "id": str(row.id),
        "tenant_id": str(row.tenant_id) if row.tenant_id else None,
        "channel_type": row.channel_type,
        "name": row.name,
        "config": _redact_config(decrypted),
        "enabled": row.enabled,
        "created_at": str(row.created_at) if row.created_at else None,
        "updated_at": str(row.updated_at) if row.updated_at else None,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/channels", response_model=List[ChannelResponse])
@require_role([UserRole.SUPER_ADMIN])
async def list_channels(
    request: Request,
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """List all notification channels (config values redacted).

    AC-13: GET response does not include decrypted config values.
    """
    encryption_service = _get_encryption_service(request)
    builder = QueryBuilder("notification_channels").order_by("created_at", "DESC")
    query, params = builder.build()
    result = db.execute(text(query), params)
    rows = result.fetchall()
    return [_row_to_response(row, encryption_service) for row in rows]


@router.post("/channels", response_model=ChannelResponse, status_code=201)
@require_role([UserRole.SUPER_ADMIN])
async def create_channel(
    body: ChannelCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """Create a new notification channel.

    AC-11: Requires SUPER_ADMIN role.
    Config is encrypted before storage (AC-1).
    """
    if body.channel_type not in VALID_CHANNEL_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid channel_type. Must be one of: {', '.join(sorted(VALID_CHANNEL_TYPES))}",
        )

    encryption_service = _get_encryption_service(request)
    encrypted_config = _encrypt_config(encryption_service, body.config)

    builder = (
        InsertBuilder("notification_channels")
        .columns("channel_type", "name", "config_encrypted", "enabled", "tenant_id")
        .values(body.channel_type, body.name, encrypted_config, body.enabled, body.tenant_id)
        .returning("id", "tenant_id", "channel_type", "name", "config_encrypted", "enabled", "created_at", "updated_at")
    )
    query, params = builder.build()
    result = db.execute(text(query), params)
    db.commit()
    row = result.fetchone()
    return _row_to_response(row, encryption_service)


@router.put("/channels/{channel_id}", response_model=ChannelResponse)
@require_role([UserRole.SUPER_ADMIN])
async def update_channel(
    channel_id: UUID,
    body: ChannelUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """Update an existing notification channel."""
    encryption_service = _get_encryption_service(request)

    builder = UpdateBuilder("notification_channels")
    builder.set_if("name", body.name)
    builder.set_if("enabled", body.enabled)
    if body.config is not None:
        encrypted_config = _encrypt_config(encryption_service, body.config)
        builder.set("config_encrypted", encrypted_config)
    builder.set_raw("updated_at", "CURRENT_TIMESTAMP")
    builder.where("id = :id", str(channel_id), "id")
    builder.returning(
        "id", "tenant_id", "channel_type", "name", "config_encrypted", "enabled", "created_at", "updated_at"
    )

    query, params = builder.build()
    result = db.execute(text(query), params)
    db.commit()
    row = result.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Notification channel not found")
    return _row_to_response(row, encryption_service)


@router.delete("/channels/{channel_id}", status_code=204)
@require_role([UserRole.SUPER_ADMIN])
async def delete_channel(
    channel_id: UUID,
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_user),
) -> None:
    """Delete a notification channel and its delivery history."""
    builder = DeleteBuilder("notification_channels").where("id = :id", str(channel_id), "id").returning("id")
    query, params = builder.build()
    result = db.execute(text(query), params)
    db.commit()
    if not result.fetchone():
        raise HTTPException(status_code=404, detail="Notification channel not found")
    return None


@router.post("/channels/{channel_id}/test", response_model=TestResultResponse)
@require_role([UserRole.SUPER_ADMIN])
async def test_channel(
    channel_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """Send a synthetic test alert through a channel.

    AC-12: Sends a synthetic alert and returns the delivery result.
    """
    encryption_service = _get_encryption_service(request)

    # Fetch channel
    builder = QueryBuilder("notification_channels").where("id = :id", str(channel_id), "id")
    query, params = builder.build()
    result = db.execute(text(query), params)
    row = result.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Notification channel not found")

    # Decrypt config
    try:
        config = _decrypt_config(encryption_service, row.config_encrypted)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to decrypt channel config: {exc}")

    # Build synthetic alert
    test_alert: Dict[str, Any] = {
        "type": "TEST_ALERT",
        "severity": "info",
        "title": "OpenWatch test notification",
        "detail": "This is a test alert sent from the OpenWatch notification admin panel.",
        "host_id": "00000000-0000-0000-0000-000000000000",
        "rule_id": "test-rule",
    }

    # Instantiate the correct channel
    from ...services.notifications import EmailChannel, SlackChannel, WebhookChannel

    channel_map = {
        "slack": SlackChannel,
        "email": EmailChannel,
        "webhook": WebhookChannel,
    }
    channel_cls = channel_map.get(row.channel_type)
    if not channel_cls:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown channel type: {row.channel_type}",
        )

    channel = channel_cls(config)  # type: ignore[abstract]
    delivery = await channel.send(test_alert)

    # Record delivery attempt
    delivery_builder = (
        InsertBuilder("notification_deliveries")
        .columns("channel_id", "status", "response_code", "response_body")
        .values(
            str(channel_id),
            "delivered" if delivery.success else "failed",
            delivery.status_code,
            delivery.response_body[:1000] if delivery.response_body else delivery.error,
        )
    )
    dq, dp = delivery_builder.build()
    db.execute(text(dq), dp)
    db.commit()

    return {
        "success": delivery.success,
        "status_code": delivery.status_code,
        "error": delivery.error,
    }
