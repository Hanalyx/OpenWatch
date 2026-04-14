"""
Alert Routing Rules Administration API.

CRUD endpoints for managing per-severity alert routing rules.
All endpoints require SUPER_ADMIN role.

Spec: specs/services/compliance/alert-routing.spec.yaml (AC-5)
"""

import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ...auth import get_current_user
from ...database import get_db
from ...rbac import UserRole, require_role
from ...services.compliance.alert_routing import AlertRoutingService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/alert-routing", tags=["Alert Routing"])

# Valid severity values
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "all"}


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class RoutingRuleCreateRequest(BaseModel):
    """Request body for creating a routing rule."""

    severity: str = Field(
        ...,
        min_length=1,
        max_length=16,
        description="Alert severity filter: critical, high, medium, low, or all",
    )
    alert_type: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Alert type filter or 'all' for any type",
    )
    channel_id: UUID = Field(..., description="Target notification channel UUID")
    enabled: bool = True


class RoutingRuleResponse(BaseModel):
    """Single routing rule response."""

    id: str
    severity: str
    alert_type: str
    channel_id: str
    enabled: bool
    created_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=List[RoutingRuleResponse])
@require_role([UserRole.SUPER_ADMIN])
async def list_routing_rules(
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """List all alert routing rules.

    Returns all routing rules ordered by creation time (newest first).
    """
    service = AlertRoutingService(db)
    return service.list_rules()


@router.post("", response_model=RoutingRuleResponse, status_code=201)
@require_role([UserRole.SUPER_ADMIN])
async def create_routing_rule(
    body: RoutingRuleCreateRequest,
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """Create a new alert routing rule.

    Maps a (severity, alert_type) combination to a notification channel.
    """
    if body.severity not in _VALID_SEVERITIES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid severity. Must be one of: {', '.join(sorted(_VALID_SEVERITIES))}",
        )

    service = AlertRoutingService(db)
    return service.create_rule(
        severity=body.severity,
        alert_type=body.alert_type,
        channel_id=body.channel_id,
        enabled=body.enabled,
    )


@router.delete("/{rule_id}", status_code=204)
@require_role([UserRole.SUPER_ADMIN])
async def delete_routing_rule(
    rule_id: UUID,
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_user),
) -> None:
    """Delete an alert routing rule."""
    service = AlertRoutingService(db)
    deleted = service.delete_rule(rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Routing rule not found")
    return None
