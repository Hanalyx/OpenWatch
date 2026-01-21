"""
Bulk Scan Operations Endpoints

This module provides endpoints for managing bulk scan operations
across multiple hosts simultaneously.

Endpoints:
    POST /bulk-scan                     - Create bulk scan session
    GET  /bulk-scan/{session_id}/progress - Get bulk scan progress
    POST /bulk-scan/{session_id}/cancel   - Cancel bulk scan session
    GET  /sessions                        - List scan sessions

Architecture Notes:
    - Uses BulkScanOrchestrator for coordinated multi-host scanning
    - Supports staggered execution to avoid resource contention
    - Sessions track overall progress across multiple individual scans
    - Role-based access control for session visibility

Security Notes:
    - All endpoints require JWT authentication
    - Non-admin users only see their own sessions
    - Maximum 100 hosts per bulk scan (DoS prevention)
"""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.auth import get_current_user
from backend.app.database import get_db
from backend.app.routes.scans.models import BulkScanRequest, BulkScanResponse
from backend.app.services.bulk_scan_orchestrator import BulkScanOrchestrator

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Bulk Scan Operations"])


# =============================================================================
# BULK SCAN ENDPOINTS
# =============================================================================


@router.post("/bulk-scan", response_model=BulkScanResponse)
async def create_bulk_scan(
    bulk_scan_request: BulkScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> BulkScanResponse:
    """
    Create and start bulk scan session for multiple hosts.

    Creates a coordinated scan session that executes scans across multiple
    hosts with configurable staggering to avoid resource contention.

    Args:
        bulk_scan_request: Configuration including host IDs, template, and priority.
        background_tasks: FastAPI background task manager.
        db: SQLAlchemy database session.
        current_user: Authenticated user from JWT token.

    Returns:
        BulkScanResponse with session ID, message, and scan IDs.

    Raises:
        HTTPException 400: No host IDs provided or exceeds 100 host limit.
        HTTPException 500: Bulk scan creation failure.

    Example:
        POST /api/scans/bulk-scan
        {
            "host_ids": ["uuid1", "uuid2", "uuid3"],
            "template_id": "auto",
            "priority": "normal",
            "stagger_delay": 30
        }

    Security:
        - Requires authenticated user
        - Maximum 100 hosts per request (DoS prevention)
    """
    try:
        logger.info(f"Bulk scan requested for {len(bulk_scan_request.host_ids)} hosts")

        if not bulk_scan_request.host_ids:
            raise HTTPException(status_code=400, detail="No host IDs provided")

        if len(bulk_scan_request.host_ids) > 100:
            raise HTTPException(status_code=400, detail="Maximum 100 hosts per bulk scan")

        # Initialize orchestrator
        orchestrator = BulkScanOrchestrator(db)

        # Create bulk scan session
        session = await orchestrator.create_bulk_scan_session(
            host_ids=bulk_scan_request.host_ids,
            template_id=bulk_scan_request.template_id or "auto",
            name_prefix=bulk_scan_request.name_prefix or "Bulk Scan",
            priority=bulk_scan_request.priority or "normal",
            user_id=current_user["id"],
            stagger_delay=bulk_scan_request.stagger_delay,
        )

        # Start the bulk scan session
        logger.info(f"Bulk scan session created and started: {session.id}")

        return BulkScanResponse(
            session_id=session.id,
            message=f"Bulk scan session created for {session.total_hosts} hosts",
            total_hosts=session.total_hosts,
            estimated_completion=(
                session.estimated_completion.timestamp() if session.estimated_completion else 0
            ),
            scan_ids=session.scan_ids or [],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating bulk scan: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to create bulk scan: {str(e)}")


@router.get("/bulk-scan/{session_id}/progress")
async def get_bulk_scan_progress(
    session_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get real-time progress of a bulk scan session.

    Returns current status, completion counts, and individual scan progress
    for a bulk scan session.

    Args:
        session_id: UUID of the bulk scan session.
        db: SQLAlchemy database session.
        current_user: Authenticated user from JWT token.

    Returns:
        Dictionary with session status and progress metrics.

    Raises:
        HTTPException 404: Session not found.
        HTTPException 500: Progress retrieval failure.

    Example:
        GET /api/scans/bulk-scan/550e8400-e29b-41d4-a716-446655440000/progress

    Response Format:
        {
            "session_id": "uuid",
            "status": "running",
            "total_hosts": 10,
            "completed_hosts": 5,
            "failed_hosts": 1,
            "running_hosts": 4,
            "progress_percent": 50,
            "individual_scans": [...]
        }

    Security:
        - Requires authenticated user
    """
    try:
        orchestrator = BulkScanOrchestrator(db)
        progress = await orchestrator.get_bulk_scan_progress(session_id)
        return progress

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error getting bulk scan progress: {e}")
        raise HTTPException(status_code=500, detail="Failed to get bulk scan progress")


@router.post("/bulk-scan/{session_id}/cancel")
async def cancel_bulk_scan(
    session_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Cancel a running bulk scan session.

    Cancels the session and all pending/running individual scans within it.

    Args:
        session_id: UUID of the bulk scan session to cancel.
        db: SQLAlchemy database session.
        current_user: Authenticated user from JWT token.

    Returns:
        Success message dictionary.

    Raises:
        HTTPException 404: Session not found.
        HTTPException 500: Cancel operation failure.

    Example:
        POST /api/scans/bulk-scan/550e8400-e29b-41d4-a716-446655440000/cancel

    Security:
        - Requires authenticated user
        - Uses parameterized queries for SQL injection prevention
    """
    try:
        # Update session status to cancelled
        result = db.execute(
            text(
                """
            UPDATE scan_sessions SET status = 'cancelled'
            WHERE id = :session_id
        """
            ),
            {"session_id": session_id},
        )

        # CursorResult has rowcount attribute (SQLAlchemy typing limitation)
        rowcount = getattr(result, "rowcount", 0)
        if rowcount == 0:
            raise HTTPException(status_code=404, detail="Bulk scan session not found")

        # Cancel individual scans that are still pending
        db.execute(
            text(
                """
            UPDATE scans SET status = 'cancelled', error_message = 'Cancelled by user'
            WHERE id IN (
                SELECT unnest(ARRAY(
                    SELECT json_array_elements_text(scan_ids::json)
                    FROM scan_sessions WHERE id = :session_id
                ))
            ) AND status IN ('pending', 'running')
        """
            ),
            {"session_id": session_id},
        )

        db.commit()

        logger.info(f"Bulk scan session cancelled: {session_id}")
        return {"message": "Bulk scan session cancelled successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cancelling bulk scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to cancel bulk scan")


@router.get("/sessions")
async def list_scan_sessions(
    status: Optional[str] = None,
    limit: int = 20,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    List scan sessions for monitoring and management.

    Returns paginated list of bulk scan sessions with status and progress.
    Non-admin users only see their own sessions.

    Args:
        status: Optional filter by session status.
        limit: Maximum number of sessions to return (default 20).
        offset: Number of sessions to skip for pagination.
        db: SQLAlchemy database session.
        current_user: Authenticated user from JWT token.

    Returns:
        Dictionary with sessions array, total count, limit, and offset.

    Raises:
        HTTPException 500: Session list retrieval failure.

    Example:
        GET /api/scans/sessions?status=running&limit=10

    Security:
        - Requires authenticated user
        - Role-based filtering (non-admins see only their sessions)
        - Uses parameterized queries for SQL injection prevention
    """
    try:
        # Build query conditions
        where_conditions: List[str] = []
        params: Dict[str, Any] = {"limit": limit, "offset": offset}

        if status:
            where_conditions.append("status = :status")
            params["status"] = status

        # Add user filtering if not admin
        if current_user.get("role") not in ["SUPER_ADMIN", "SECURITY_ADMIN"]:
            where_conditions.append("created_by = :user_id")
            params["user_id"] = current_user["id"]

        # Get sessions
        base_sessions_query = """
            SELECT id, name, total_hosts, completed_hosts, failed_hosts, running_hosts,
                   status, created_by, created_at, started_at, completed_at, estimated_completion
            FROM scan_sessions
        """

        if where_conditions:
            sessions_query = base_sessions_query + " WHERE " + " AND ".join(where_conditions)
        else:
            sessions_query = base_sessions_query

        sessions_query += " ORDER BY created_at DESC LIMIT :limit OFFSET :offset"

        result = db.execute(text(sessions_query), params)

        sessions = []
        for row in result:
            sessions.append(
                {
                    "session_id": row.id,
                    "name": row.name,
                    "total_hosts": row.total_hosts,
                    "completed_hosts": row.completed_hosts,
                    "failed_hosts": row.failed_hosts,
                    "running_hosts": row.running_hosts,
                    "status": row.status,
                    "created_by": row.created_by,
                    "created_at": (row.created_at.isoformat() if row.created_at else None),
                    "started_at": (row.started_at.isoformat() if row.started_at else None),
                    "completed_at": (row.completed_at.isoformat() if row.completed_at else None),
                    "estimated_completion": (
                        row.estimated_completion.isoformat() if row.estimated_completion else None
                    ),
                }
            )

        # Get total count
        count_sessions_query = "SELECT COUNT(*) as total FROM scan_sessions"
        if where_conditions:
            count_sessions_query += " WHERE " + " AND ".join(where_conditions)

        count_result = db.execute(text(count_sessions_query), params).fetchone()
        total: int = count_result.total if count_result else 0

        return {
            "sessions": sessions,
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    except Exception as e:
        logger.error(f"Error listing scan sessions: {e}")
        raise HTTPException(status_code=500, detail="Failed to list scan sessions")


# =============================================================================
# PUBLIC API EXPORTS
# =============================================================================

__all__ = [
    "router",
    "create_bulk_scan",
    "get_bulk_scan_progress",
    "cancel_bulk_scan",
    "list_scan_sessions",
]
