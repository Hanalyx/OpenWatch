"""
Compliance Posture API Endpoints

Endpoints for querying compliance posture at current or historical points in time.

Part of Phase 2: Temporal Compliance (Aegis Integration Plan)

Endpoint Structure:
    GET    /posture                     - Get current or historical posture
    GET    /posture/history             - Get posture history over time
    GET    /posture/drift               - Analyze drift between two dates
    POST   /posture/snapshot            - Manually create a snapshot
"""

import logging
from datetime import date
from typing import Any, Dict, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi import status as http_status
from sqlalchemy.orm import Session

from ...auth import get_current_user
from ...database import User, get_db
from ...schemas.posture_schemas import (
    DriftAnalysisResponse,
    PostureHistoryResponse,
    PostureResponse,
    SnapshotCreateRequest,
)
from ...services.compliance import TemporalComplianceService
from ...services.licensing import LicenseService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/posture", tags=["Compliance Posture"])


# =============================================================================
# API ENDPOINTS
# =============================================================================


@router.get("", response_model=PostureResponse)
async def get_posture(
    host_id: UUID = Query(..., description="Host UUID"),
    as_of: Optional[date] = Query(None, description="Point-in-time query date (None = current)"),
    include_rule_states: bool = Query(False, description="Include per-rule state details"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PostureResponse:
    """
    Get compliance posture for a host.

    - Without as_of: Returns current posture from latest scan
    - With as_of: Returns historical posture from snapshot (OpenWatch+ required)

    Args:
        host_id: Target host UUID
        as_of: Optional date for historical query
        include_rule_states: Include per-rule state details
        db: Database session
        current_user: Authenticated user

    Returns:
        PostureResponse with compliance scores and rule states

    Raises:
        HTTPException: 403 if historical query without subscription
        HTTPException: 404 if no posture data available
    """
    service = TemporalComplianceService(db)

    # Historical queries require OpenWatch+ subscription
    if as_of:
        license_service = LicenseService()
        if not license_service.has_feature("temporal_queries"):
            raise HTTPException(
                status_code=http_status.HTTP_403_FORBIDDEN,
                detail="Historical posture queries require OpenWatch+ subscription",
            )

    posture = service.get_posture(host_id, as_of, include_rule_states)

    if not posture:
        if as_of:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail=f"No posture snapshot found for host {host_id} on {as_of}",
            )
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"No compliance data available for host {host_id}",
        )

    return posture


@router.get("/history", response_model=PostureHistoryResponse)
async def get_posture_history(
    host_id: UUID = Query(..., description="Host UUID"),
    start_date: Optional[date] = Query(None, description="Start of date range"),
    end_date: Optional[date] = Query(None, description="End of date range"),
    limit: int = Query(30, ge=1, le=365, description="Maximum snapshots to return"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PostureHistoryResponse:
    """
    Get posture history for a host over a time range.

    Requires OpenWatch+ subscription for accessing historical data.

    Args:
        host_id: Target host UUID
        start_date: Start of date range (default: 30 days ago)
        end_date: End of date range (default: today)
        limit: Maximum number of snapshots to return
        db: Database session
        current_user: Authenticated user

    Returns:
        PostureHistoryResponse with list of posture snapshots

    Raises:
        HTTPException: 403 if no subscription
    """
    # History queries require OpenWatch+ subscription
    license_service = LicenseService()
    if not license_service.has_feature("temporal_queries"):
        raise HTTPException(
            status_code=http_status.HTTP_403_FORBIDDEN,
            detail="Posture history queries require OpenWatch+ subscription",
        )

    service = TemporalComplianceService(db)
    history = service.get_posture_history(host_id, start_date, end_date, limit)

    return history


@router.get("/drift", response_model=DriftAnalysisResponse)
async def analyze_drift(
    host_id: UUID = Query(..., description="Host UUID"),
    start_date: date = Query(..., description="Start date for comparison"),
    end_date: date = Query(..., description="End date for comparison"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DriftAnalysisResponse:
    """
    Analyze compliance drift between two dates.

    Returns rules that changed status and overall drift metrics.
    Requires OpenWatch+ subscription.

    Args:
        host_id: Target host UUID
        start_date: Start date for comparison
        end_date: End date for comparison
        db: Database session
        current_user: Authenticated user

    Returns:
        DriftAnalysisResponse with drift metrics and events

    Raises:
        HTTPException: 400 if dates are invalid
        HTTPException: 403 if no subscription
    """
    # Validate dates
    if start_date > end_date:
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail="start_date must be before or equal to end_date",
        )

    # Drift analysis requires OpenWatch+ subscription
    license_service = LicenseService()
    if not license_service.has_feature("temporal_queries"):
        raise HTTPException(
            status_code=http_status.HTTP_403_FORBIDDEN,
            detail="Drift analysis requires OpenWatch+ subscription",
        )

    service = TemporalComplianceService(db)
    drift = service.detect_drift(host_id, start_date, end_date)

    return drift


@router.post("/snapshot", response_model=Dict[str, Any])
async def create_snapshot(
    request: SnapshotCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Manually create a posture snapshot for a host.

    Creates a snapshot of the current compliance posture for historical tracking.
    Snapshots are normally created automatically via scheduled task.

    Args:
        request: Snapshot creation request with host_id
        db: Database session
        current_user: Authenticated user

    Returns:
        Snapshot creation result

    Raises:
        HTTPException: 404 if no scan data available
    """
    service = TemporalComplianceService(db)
    snapshot = service.create_snapshot(request.host_id)

    if not snapshot:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"No scan data available to create snapshot for host {request.host_id}",
        )

    return {
        "success": True,
        "snapshot_id": str(snapshot.id),
        "host_id": str(snapshot.host_id),
        "snapshot_date": snapshot.snapshot_date.isoformat(),
        "compliance_score": snapshot.compliance_score,
    }


__all__ = ["router"]
