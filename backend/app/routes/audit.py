"""
Audit Log API Routes for OView Dashboard
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..rbac import RBACManager, UserRole

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/audit", tags=["Audit"])


class AuditEventResponse(BaseModel):
    id: int
    user_id: Optional[int]
    username: Optional[str]
    action: str
    resource_type: str
    resource_id: Optional[str]
    ip_address: str
    user_agent: Optional[str]
    details: Optional[str]
    timestamp: str
    severity: str


class AuditEventsResponse(BaseModel):
    events: List[AuditEventResponse]
    total: int
    page: int
    limit: int


class AuditStatsResponse(BaseModel):
    total_events: int
    login_attempts: int
    failed_logins: int
    scan_operations: int
    admin_actions: int
    security_events: int
    unique_users: int
    unique_ips: int


@router.get("/events", response_model=AuditEventsResponse)  # type: ignore[misc]
async def get_audit_events(
    page: int = Query(1, ge=1),
    limit: int = Query(25, ge=1, le=100),
    search: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    user: Optional[str] = Query(None),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> AuditEventsResponse:
    """
    Get audit events with filtering and pagination
    """
    try:
        # Check permissions
        user_role = UserRole(current_user.get("role", "guest"))
        if not RBACManager.can_access_resource(user_role, "audit", "read"):
            raise HTTPException(status_code=403, detail="Insufficient permissions to view audit logs")

        # Build base query
        query = """
            SELECT al.*, u.username
            FROM audit_logs al
            LEFT JOIN users u ON al.user_id = u.id
            WHERE 1=1
        """

        params: Dict[str, Union[str, int, datetime]] = {}

        # Add filters
        if search:
            query += " AND (al.action ILIKE :search OR al.details ILIKE :search OR al.ip_address ILIKE :search OR u.username ILIKE :search)"
            params["search"] = f"%{search}%"

        if action:
            query += " AND al.action ILIKE :action"
            params["action"] = f"%{action}%"

        if resource_type:
            query += " AND al.resource_type = :resource_type"
            params["resource_type"] = resource_type

        if user:
            query += " AND u.username ILIKE :user"
            params["user"] = f"%{user}%"

        if date_from:
            query += " AND al.timestamp >= :date_from"
            params["date_from"] = date_from

        if date_to:
            query += " AND al.timestamp <= :date_to"
            params["date_to"] = date_to

        # Get total count
        count_query = f"SELECT COUNT(*) as total FROM ({query}) as subquery"
        count_result = db.execute(text(count_query), params)
        total = count_result.fetchone().total

        # Add ordering and pagination
        query += " ORDER BY al.timestamp DESC"
        query += " LIMIT :limit OFFSET :offset"
        params["limit"] = limit
        params["offset"] = (page - 1) * limit

        # Execute query
        result = db.execute(text(query), params)

        events = []
        for row in result:
            # Determine severity based on action
            if "FAILED" in row.action or "ERROR" in row.action:
                event_severity = "error"
            elif "SECURITY" in row.action or "UNAUTHORIZED" in row.action:
                event_severity = "warning"
            elif "ADMIN" in row.action or "DELETE" in row.action:
                event_severity = "warning"
            else:
                event_severity = "info"

            events.append(
                AuditEventResponse(
                    id=row.id,
                    user_id=row.user_id,
                    username=row.username,
                    action=row.action,
                    resource_type=row.resource_type,
                    resource_id=row.resource_id,
                    ip_address=row.ip_address,
                    user_agent=row.user_agent,
                    details=row.details,
                    timestamp=row.timestamp.isoformat() if row.timestamp else None,
                    severity=event_severity,
                )
            )

        return AuditEventsResponse(events=events, total=total, page=page, limit=limit)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving audit events: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve audit events")


@router.get("/stats", response_model=AuditStatsResponse)  # type: ignore[misc]
async def get_audit_stats(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> AuditStatsResponse:
    """
    Get audit statistics for the dashboard
    """
    try:
        # Check permissions
        user_role = UserRole(current_user.get("role", "guest"))
        if not RBACManager.can_access_resource(user_role, "audit", "read"):
            raise HTTPException(status_code=403, detail="Insufficient permissions to view audit logs")

        # Calculate date range
        from datetime import datetime, timedelta

        date_from = datetime.utcnow() - timedelta(days=days)

        # Get statistics
        stats_query = text(
            """
            SELECT
                COUNT(*) as total_events,
                COUNT(CASE WHEN action LIKE '%LOGIN%' THEN 1 END) as login_attempts,
                COUNT(CASE WHEN action LIKE '%LOGIN_FAILED%' OR action LIKE '%AUTH_FAILURE%' THEN 1 END) as failed_logins,
                COUNT(CASE WHEN action LIKE '%SCAN%' THEN 1 END) as scan_operations,
                COUNT(CASE WHEN action LIKE '%ADMIN%' OR action LIKE '%USER_%' OR action LIKE '%DELETE%' THEN 1 END) as admin_actions,
                COUNT(CASE WHEN action LIKE '%SECURITY%' OR action LIKE '%UNAUTHORIZED%' OR action LIKE '%ERROR%' THEN 1 END) as security_events,
                COUNT(DISTINCT user_id) as unique_users,
                COUNT(DISTINCT ip_address) as unique_ips
            FROM audit_logs
            WHERE timestamp >= :date_from
        """
        )

        result = db.execute(stats_query, {"date_from": date_from})
        row = result.fetchone()

        return AuditStatsResponse(
            total_events=row.total_events or 0,
            login_attempts=row.login_attempts or 0,
            failed_logins=row.failed_logins or 0,
            scan_operations=row.scan_operations or 0,
            admin_actions=row.admin_actions or 0,
            security_events=row.security_events or 0,
            unique_users=row.unique_users or 0,
            unique_ips=row.unique_ips or 0,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving audit stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve audit statistics")


@router.post("/log")  # type: ignore[misc]
async def create_audit_log(
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    details: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Create a new audit log entry (for internal use)
    """
    try:
        from datetime import datetime

        # This would typically be called internally by the system
        # For now, we'll create a simple log entry
        insert_query = text(
            """
            INSERT INTO audit_logs (user_id, action, resource_type, resource_id, ip_address, details, timestamp)
            VALUES (:user_id, :action, :resource_type, :resource_id, :ip_address, :details, :timestamp)
        """
        )

        db.execute(
            insert_query,
            {
                "user_id": current_user.get("id"),
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "ip_address": "127.0.0.1",  # This should come from request
                "details": details,
                "timestamp": datetime.utcnow(),
            },
        )

        db.commit()
        return {"message": "Audit log created successfully"}

    except Exception as e:
        logger.error(f"Error creating audit log: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create audit log")


# Helper function to create audit logs from middleware
def log_audit_event(
    db: Session,
    user_id: Optional[int],
    action: str,
    resource_type: str,
    resource_id: Optional[str],
    ip_address: str,
    user_agent: Optional[str],
    details: Optional[str],
) -> None:
    """
    Helper function to create audit log entries from middleware
    """
    try:
        insert_query = text(
            """
            INSERT INTO audit_logs (user_id, action, resource_type, resource_id, ip_address, user_agent, details, timestamp)
            VALUES (:user_id, :action, :resource_type, :resource_id, :ip_address, :user_agent, :details, :timestamp)
        """
        )

        db.execute(
            insert_query,
            {
                "user_id": user_id,
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "details": details,
                "timestamp": datetime.utcnow(),
            },
        )

        db.commit()

    except Exception as e:
        logger.error(f"Error creating audit log entry: {e}")
        db.rollback()
