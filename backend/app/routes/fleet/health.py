"""
Fleet Health Summary Endpoint

Returns fleet-level health metrics for the dashboard widget:
reachable hosts, drift events, failed scans, and maintenance mode counts.
"""

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import User, get_db
from app.rbac import UserRole, require_role

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/fleet", tags=["fleet"])


class FleetHealthSummaryResponse(BaseModel):
    """Response schema for fleet health summary."""

    hosts_reachable: int
    hosts_total: int
    drift_events_24h: int
    failed_scans_24h: int
    hosts_in_maintenance: int


@router.get("/health-summary", response_model=FleetHealthSummaryResponse)
@require_role(
    [
        UserRole.GUEST,
        UserRole.AUDITOR,
        UserRole.SECURITY_ANALYST,
        UserRole.COMPLIANCE_OFFICER,
        UserRole.SECURITY_ADMIN,
        UserRole.SUPER_ADMIN,
    ]
)
async def get_fleet_health_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Fleet-level health summary for dashboard widget."""
    try:
        # 1. Hosts reachable / total
        host_counts = db.execute(
            text(
                "SELECT "
                "COUNT(*) AS total, "
                "COUNT(*) FILTER (WHERE hl.reachability_status = 'reachable') AS reachable "
                "FROM hosts h "
                "LEFT JOIN host_liveness hl ON hl.host_id = h.id "
                "WHERE h.is_active = true"
            )
        ).fetchone()

        hosts_total = host_counts[0] if host_counts else 0
        hosts_reachable = host_counts[1] if host_counts else 0

        # 2. Drift events in last 24h
        drift_row = db.execute(
            text("SELECT COUNT(*) FROM scan_drift_events " "WHERE detected_at >= NOW() - INTERVAL '24 hours'")
        ).fetchone()

        drift_events_24h = drift_row[0] if drift_row else 0

        # 3. Failed scans in last 24h (distinct scan_id from transactions)
        failed_row = db.execute(
            text(
                "SELECT COUNT(DISTINCT scan_id) FROM transactions "
                "WHERE status = :status AND started_at >= NOW() - INTERVAL '24 hours'"
            ),
            {"status": "fail"},
        ).fetchone()

        failed_scans_24h = failed_row[0] if failed_row else 0

        # 4. Hosts in maintenance
        maintenance_row = db.execute(
            text("SELECT COUNT(*) FROM host_schedule " "WHERE maintenance_mode = true")
        ).fetchone()

        hosts_in_maintenance = maintenance_row[0] if maintenance_row else 0

        return {
            "hosts_reachable": hosts_reachable,
            "hosts_total": hosts_total,
            "drift_events_24h": drift_events_24h,
            "failed_scans_24h": failed_scans_24h,
            "hosts_in_maintenance": hosts_in_maintenance,
        }
    except Exception as e:
        logger.error("Error fetching fleet health summary: %s", e)
        raise HTTPException(status_code=500, detail="Failed to fetch fleet health summary")
