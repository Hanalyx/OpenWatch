"""
Compliance Alert API Endpoints

Endpoints for managing compliance alerts and alert thresholds.

Part of OpenWatch OS Transformation - Alert Thresholds (doc 03).

Endpoint Structure:
    GET    /alerts                  - List alerts (paginated)
    GET    /alerts/stats            - Get alert statistics
    GET    /alerts/{id}             - Get alert by ID
    POST   /alerts/{id}/acknowledge - Acknowledge an alert
    POST   /alerts/{id}/resolve     - Resolve an alert
    GET    /alerts/thresholds       - Get alert threshold configuration
    PUT    /alerts/thresholds       - Update alert thresholds
"""

import logging
from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi import status as http_status
from sqlalchemy.orm import Session

from ...auth import get_current_user
from ...database import User, get_db
from ...schemas.alert_schemas import (
    AlertAcknowledgeRequest,
    AlertListResponse,
    AlertResolveRequest,
    AlertResponse,
    AlertStats,
    AlertThresholds,
    AlertThresholdsUpdate,
)
from ...services.compliance import AlertService, AlertSeverity, AlertStatus

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/alerts", tags=["Compliance Alerts"])


# =============================================================================
# API ENDPOINTS
# =============================================================================


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    status: Optional[str] = Query(None, description="Filter by status (active, acknowledged, resolved)"),
    severity: Optional[str] = Query(None, description="Filter by severity (critical, high, medium, low, info)"),
    alert_type: Optional[str] = Query(None, description="Filter by alert type"),
    host_id: Optional[UUID] = Query(None, description="Filter by host ID"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AlertListResponse:
    """
    List compliance alerts with pagination and filtering.

    Args:
        page: Page number (1-indexed)
        per_page: Items per page (max 100)
        status: Filter by status (active, acknowledged, resolved)
        severity: Filter by severity (critical, high, medium, low, info)
        alert_type: Filter by alert type
        host_id: Filter by host ID
        db: Database session
        current_user: Authenticated user

    Returns:
        Paginated list of alerts
    """
    # Validate status if provided
    if status and status not in [s.value for s in AlertStatus]:
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status: {status}. Valid values: {[s.value for s in AlertStatus]}",
        )

    # Validate severity if provided
    if severity and severity not in [s.value for s in AlertSeverity]:
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid severity: {severity}. Valid values: {[s.value for s in AlertSeverity]}",
        )

    service = AlertService(db)
    result = service.list_alerts(
        page=page,
        per_page=per_page,
        status=status,
        severity=severity,
        alert_type=alert_type,
        host_id=host_id,
    )

    return AlertListResponse(
        items=[_row_to_response(alert) for alert in result["items"]],
        total=result["total"],
        page=result["page"],
        per_page=result["per_page"],
        total_pages=result["total_pages"],
    )


@router.get("/stats", response_model=AlertStats)
async def get_alert_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AlertStats:
    """
    Get alert statistics summary.

    Returns:
        Summary with counts by status, severity, type, and recent activity
    """
    service = AlertService(db)
    stats = service.get_stats()

    return AlertStats(
        total_active=stats.get("total_active", 0),
        total_acknowledged=stats.get("total_acknowledged", 0),
        total_resolved=stats.get("total_resolved", 0),
        by_severity=stats.get("by_severity", {}),
        by_type=stats.get("by_type", {}),
        recent_24h=stats.get("recent_24h", 0),
    )


@router.get("/thresholds", response_model=AlertThresholds)
async def get_alert_thresholds(
    host_id: Optional[UUID] = Query(None, description="Get thresholds for specific host"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AlertThresholds:
    """
    Get alert threshold configuration.

    Gets global thresholds merged with host-specific overrides if host_id provided.

    Args:
        host_id: Optional host ID for host-specific thresholds
        db: Database session
        current_user: Authenticated user

    Returns:
        Alert threshold configuration
    """
    service = AlertService(db)
    thresholds = service.get_thresholds(host_id=host_id)

    return AlertThresholds(
        compliance=thresholds.get("compliance", {}),
        drift=thresholds.get("drift", {}),
        operational=thresholds.get("operational", {}),
    )


@router.put("/thresholds", response_model=AlertThresholds)
async def update_alert_thresholds(
    request: AlertThresholdsUpdate,
    host_id: Optional[UUID] = Query(None, description="Update thresholds for specific host"),
    host_group_id: Optional[int] = Query(None, description="Update thresholds for specific host group"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AlertThresholds:
    """
    Update alert threshold configuration.

    Updates global thresholds if no scope specified, or host/group-specific
    thresholds if host_id or host_group_id provided.

    Requires ADMIN role or higher.

    Args:
        request: Threshold updates
        host_id: Optional host ID for host-specific settings
        host_group_id: Optional host group ID for group-specific settings
        db: Database session
        current_user: Authenticated user (must be ADMIN+)

    Returns:
        Updated threshold configuration
    """
    # Check admin permission
    if current_user.role not in ("super_admin", "security_admin", "admin"):
        raise HTTPException(
            status_code=http_status.HTTP_403_FORBIDDEN,
            detail="Only admins can update alert thresholds",
        )

    service = AlertService(db)

    # Build settings dict from request
    settings = {}
    if request.compliance is not None:
        settings["compliance"] = request.compliance
    if request.drift is not None:
        settings["drift"] = request.drift
    if request.operational is not None:
        settings["operational"] = request.operational

    # Update settings
    service.update_thresholds(
        settings=settings,
        host_id=host_id,
        host_group_id=host_group_id,
    )

    # Return merged thresholds
    thresholds = service.get_thresholds(host_id=host_id)
    return AlertThresholds(
        compliance=thresholds.get("compliance", {}),
        drift=thresholds.get("drift", {}),
        operational=thresholds.get("operational", {}),
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AlertResponse:
    """
    Get alert by ID.

    Args:
        alert_id: Alert UUID
        db: Database session
        current_user: Authenticated user

    Returns:
        Alert details

    Raises:
        HTTPException: 404 if not found
    """
    service = AlertService(db)
    alert = service.get_alert(alert_id)

    if not alert:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found",
        )

    return _row_to_response(alert)


@router.post("/{alert_id}/acknowledge", response_model=AlertResponse)
async def acknowledge_alert(
    alert_id: UUID,
    request: AlertAcknowledgeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AlertResponse:
    """
    Acknowledge an alert.

    Marks the alert as acknowledged by the current user.

    Args:
        alert_id: Alert UUID to acknowledge
        request: Acknowledgment details
        db: Database session
        current_user: Authenticated user

    Returns:
        Updated alert

    Raises:
        HTTPException: 400 if alert is already resolved
        HTTPException: 404 if not found
    """
    service = AlertService(db)
    alert = service.acknowledge_alert(alert_id, int(current_user.id))

    if not alert:
        # Check if it exists
        existing = service.get_alert(alert_id)
        if not existing:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail=f"Alert {alert_id} not found",
            )
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot acknowledge alert: status is '{existing.status}'",
        )

    return _row_to_response(alert)


@router.post("/{alert_id}/resolve", response_model=AlertResponse)
async def resolve_alert(
    alert_id: UUID,
    request: AlertResolveRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AlertResponse:
    """
    Resolve an alert.

    Marks the alert as resolved.

    Args:
        alert_id: Alert UUID to resolve
        request: Resolution details
        db: Database session
        current_user: Authenticated user

    Returns:
        Updated alert

    Raises:
        HTTPException: 400 if alert is already resolved
        HTTPException: 404 if not found
    """
    service = AlertService(db)
    alert = service.resolve_alert(alert_id)

    if not alert:
        # Check if it exists
        existing = service.get_alert(alert_id)
        if not existing:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail=f"Alert {alert_id} not found",
            )
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot resolve alert: status is '{existing.status}'",
        )

    return _row_to_response(alert)


def _row_to_response(alert) -> AlertResponse:
    """Convert alert dict or row to AlertResponse."""

    # Handle both dict and row objects
    def get_val(key, default=None):
        if isinstance(alert, dict):
            return alert.get(key, default)
        return getattr(alert, key, default)

    # Parse datetime strings if needed
    acknowledged_at = get_val("acknowledged_at")
    if isinstance(acknowledged_at, str):
        acknowledged_at = datetime.fromisoformat(acknowledged_at.replace("Z", "+00:00"))

    resolved_at = get_val("resolved_at")
    if isinstance(resolved_at, str):
        resolved_at = datetime.fromisoformat(resolved_at.replace("Z", "+00:00"))

    created_at = get_val("created_at")
    if isinstance(created_at, str):
        created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))

    # Parse UUIDs from strings if needed
    alert_id = get_val("id")
    if isinstance(alert_id, str):
        alert_id = UUID(alert_id)

    host_id = get_val("host_id")
    if isinstance(host_id, str):
        host_id = UUID(host_id)

    scan_id = get_val("scan_id")
    if isinstance(scan_id, str):
        scan_id = UUID(scan_id)

    return AlertResponse(
        id=alert_id,
        alert_type=get_val("alert_type"),
        severity=get_val("severity"),
        title=get_val("title"),
        message=get_val("message"),
        host_id=host_id,
        host_group_id=get_val("host_group_id"),
        rule_id=get_val("rule_id"),
        scan_id=scan_id,
        status=get_val("status"),
        acknowledged_by=get_val("acknowledged_by"),
        acknowledged_at=acknowledged_at,
        resolved_at=resolved_at,
        metadata=get_val("metadata"),
        created_at=created_at,
    )


__all__ = ["router"]
