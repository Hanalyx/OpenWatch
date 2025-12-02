"""
Drift Events API Endpoints

Provides REST API for retrieving compliance drift events.
Drift events are automatically created by DriftDetectionService when scans deviate from baselines.

Endpoints:
    GET /api/drift-events - List drift events with filtering and pagination
    GET /api/drift-events/{id} - Get specific drift event details
"""

import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..utils.query_builder import QueryBuilder

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/drift-events", tags=["drift-events"])


class DriftEventResponse(BaseModel):
    """Response model for drift event data."""

    id: UUID
    host_id: UUID
    hostname: str  # Joined from hosts table
    scan_id: UUID
    baseline_id: UUID
    drift_type: str
    drift_magnitude: float
    baseline_score: float
    current_score: float
    score_delta: float
    critical_passed_delta: int
    critical_failed_delta: int
    high_passed_delta: int
    high_failed_delta: int
    medium_passed_delta: int
    medium_failed_delta: int
    low_passed_delta: int
    low_failed_delta: int
    detected_at: str

    class Config:
        from_attributes = True


class DriftEventsListResponse(BaseModel):
    """Response model for list of drift events."""

    drift_events: List[DriftEventResponse]
    total: int
    page: int
    per_page: int
    total_pages: int


@router.get(
    "",
    response_model=DriftEventsListResponse,
    summary="List drift events",
    description="Retrieve drift events with optional filtering by host, drift type, and pagination.",
)
async def list_drift_events(
    host_id: Optional[UUID] = Query(None, description="Filter by host ID"),
    drift_type: Optional[str] = Query(None, description="Filter by drift type (major, minor, improvement, stable)"),
    exclude_stable: bool = Query(False, description="Exclude stable drift events"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of events to return"),
    offset: int = Query(0, ge=0, description="Number of events to skip"),
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> DriftEventsListResponse:
    """
    Get list of drift events with optional filtering.

    Supports filtering by host, drift type, and pagination.
    Results are ordered by detected_at DESC (most recent first).

    Security: Requires authentication (analyst or higher role).
    """
    # Build query using QueryBuilder
    builder = (
        QueryBuilder("scan_drift_events sde")
        .select(
            "sde.id",
            "sde.host_id",
            "h.hostname",
            "sde.scan_id",
            "sde.baseline_id",
            "sde.drift_type",
            "sde.drift_magnitude",
            "sde.baseline_score",
            "sde.current_score",
            "sde.score_delta",
            "sde.critical_passed_delta",
            "sde.critical_failed_delta",
            "sde.high_passed_delta",
            "sde.high_failed_delta",
            "sde.medium_passed_delta",
            "sde.medium_failed_delta",
            "sde.low_passed_delta",
            "sde.low_failed_delta",
            "sde.detected_at",
        )
        .join("hosts h", "h.id = sde.host_id", "INNER")
        .order_by("sde.detected_at", "DESC")
    )

    # Apply filters
    if host_id:
        builder.where("sde.host_id = :host_id", host_id, "host_id")

    if drift_type:
        builder.where("sde.drift_type = :drift_type", drift_type, "drift_type")

    if exclude_stable:
        builder.where("sde.drift_type != :stable", "stable", "stable")

    # Get total count
    count_builder = QueryBuilder("scan_drift_events sde").join("hosts h", "h.id = sde.host_id", "INNER")
    if host_id:
        count_builder.where("sde.host_id = :host_id", host_id, "host_id")
    if drift_type:
        count_builder.where("sde.drift_type = :drift_type", drift_type, "drift_type")
    if exclude_stable:
        count_builder.where("sde.drift_type != :stable", "stable", "stable")

    count_query, count_params = count_builder.count_query()
    count_result = db.execute(text(count_query), count_params).fetchone()
    total: int = count_result.total if count_result else 0

    # Apply pagination
    builder.paginate(page=(offset // limit) + 1, per_page=limit)

    # Execute query with parameterization
    # Security: QueryBuilder.build() returns parameterized SQL with separate params dict
    # All user inputs (host_id, drift_type, limit, offset) are bound as parameters
    # This prevents SQL injection by avoiding direct string concatenation
    # Per OWASP SQL Injection Prevention: use parameterized queries
    query, params = builder.build()
    result = db.execute(text(query), params)  # nosec B608 (parameterized via QueryBuilder)
    events = []

    for row in result:
        events.append(
            DriftEventResponse(
                id=row.id,
                host_id=row.host_id,
                hostname=row.hostname,
                scan_id=row.scan_id,
                baseline_id=row.baseline_id,
                drift_type=row.drift_type,
                drift_magnitude=row.drift_magnitude,
                baseline_score=row.baseline_score,
                current_score=row.current_score,
                score_delta=row.score_delta,
                critical_passed_delta=row.critical_passed_delta,
                critical_failed_delta=row.critical_failed_delta,
                high_passed_delta=row.high_passed_delta,
                high_failed_delta=row.high_failed_delta,
                medium_passed_delta=row.medium_passed_delta,
                medium_failed_delta=row.medium_failed_delta,
                low_passed_delta=row.low_passed_delta,
                low_failed_delta=row.low_failed_delta,
                detected_at=row.detected_at.isoformat(),
            )
        )

    total_pages = (total + limit - 1) // limit if total > 0 else 0

    return DriftEventsListResponse(
        drift_events=events,
        total=total,
        page=(offset // limit) + 1,
        per_page=limit,
        total_pages=total_pages,
    )


@router.get(
    "/{event_id}",
    response_model=DriftEventResponse,
    summary="Get drift event details",
    description="Retrieve detailed information about a specific drift event.",
)
async def get_drift_event(
    event_id: UUID,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> DriftEventResponse:
    """
    Get detailed information about a drift event.

    Security: Requires authentication (analyst or higher role).
    """
    builder = (
        QueryBuilder("scan_drift_events sde")
        .select(
            "sde.id",
            "sde.host_id",
            "h.hostname",
            "sde.scan_id",
            "sde.baseline_id",
            "sde.drift_type",
            "sde.drift_magnitude",
            "sde.baseline_score",
            "sde.current_score",
            "sde.score_delta",
            "sde.critical_passed_delta",
            "sde.critical_failed_delta",
            "sde.high_passed_delta",
            "sde.high_failed_delta",
            "sde.medium_passed_delta",
            "sde.medium_failed_delta",
            "sde.low_passed_delta",
            "sde.low_failed_delta",
            "sde.detected_at",
        )
        .join("hosts h", "h.id = sde.host_id", "INNER")
        .where("sde.id = :event_id", event_id, "event_id")
    )

    query, params = builder.build()
    result = db.execute(text(query), params)
    row = result.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail=f"Drift event {event_id} not found")

    return DriftEventResponse(
        id=row.id,
        host_id=row.host_id,
        hostname=row.hostname,
        scan_id=row.scan_id,
        baseline_id=row.baseline_id,
        drift_type=row.drift_type,
        drift_magnitude=row.drift_magnitude,
        baseline_score=row.baseline_score,
        current_score=row.current_score,
        score_delta=row.score_delta,
        critical_passed_delta=row.critical_passed_delta,
        critical_failed_delta=row.critical_failed_delta,
        high_passed_delta=row.high_passed_delta,
        high_failed_delta=row.high_failed_delta,
        medium_passed_delta=row.medium_passed_delta,
        medium_failed_delta=row.medium_failed_delta,
        low_passed_delta=row.low_passed_delta,
        low_failed_delta=row.low_failed_delta,
        detected_at=row.detected_at.isoformat(),
    )
