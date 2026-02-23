"""
Adaptive Compliance Scheduler API Routes

Endpoints for managing the adaptive compliance scheduling system.
Allows configuration of scan intervals, maintenance windows, and viewing scheduler status.

Part of OpenWatch OS Transformation
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import User, get_db
from app.rbac import UserRole, require_role
from app.services.compliance.compliance_scheduler import compliance_scheduler_service

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/scheduler",
    tags=["compliance-scheduler"],
)


# =============================================================================
# Request/Response Schemas
# =============================================================================


class SchedulerConfigUpdate(BaseModel):
    """Request schema for updating scheduler configuration."""

    enabled: Optional[bool] = None
    # Intervals in minutes for each compliance state
    interval_compliant: Optional[int] = Field(None, ge=60, le=2880)
    interval_mostly_compliant: Optional[int] = Field(None, ge=30, le=2880)
    interval_partial: Optional[int] = Field(None, ge=30, le=2880)
    interval_low: Optional[int] = Field(None, ge=30, le=2880)
    interval_critical: Optional[int] = Field(None, ge=15, le=2880)
    interval_unknown: Optional[int] = Field(None, ge=0, le=2880)
    # Concurrency settings
    max_concurrent_scans: Optional[int] = Field(None, ge=1, le=20)
    scan_timeout_seconds: Optional[int] = Field(None, ge=60, le=3600)


class SchedulerConfigResponse(BaseModel):
    """Response schema for scheduler configuration."""

    enabled: bool
    interval_compliant: int
    interval_mostly_compliant: int
    interval_partial: int
    interval_low: int
    interval_critical: int
    interval_unknown: int
    interval_maintenance: int
    max_interval_minutes: int
    priority_compliant: int
    priority_mostly_compliant: int
    priority_partial: int
    priority_low: int
    priority_critical: int
    priority_unknown: int
    priority_maintenance: int
    max_concurrent_scans: int
    scan_timeout_seconds: int


class SchedulerStatusResponse(BaseModel):
    """Response schema for scheduler status."""

    enabled: bool
    total_hosts: int
    hosts_due: int
    hosts_in_maintenance: int
    by_compliance_state: Dict[str, int]
    next_scheduled_scans: list


class HostScheduleResponse(BaseModel):
    """Response schema for host schedule details."""

    host_id: str
    hostname: str
    compliance_score: Optional[float]
    compliance_state: str
    has_critical_findings: bool
    pass_count: Optional[int]
    fail_count: Optional[int]
    current_interval_minutes: int
    next_scheduled_scan: Optional[datetime]
    last_scan_completed: Optional[datetime]
    maintenance_mode: bool
    maintenance_until: Optional[datetime]
    scan_priority: int
    consecutive_scan_failures: int


class MaintenanceModeRequest(BaseModel):
    """Request schema for setting maintenance mode."""

    enabled: bool
    duration_hours: Optional[int] = Field(None, ge=1, le=168)  # Max 1 week


# =============================================================================
# Scheduler Configuration Endpoints
# =============================================================================


@router.get("/config", response_model=SchedulerConfigResponse)
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
async def get_scheduler_config(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get the current scheduler configuration.

    Returns interval settings, priority levels, and concurrency limits.
    """
    try:
        config = compliance_scheduler_service.get_config(db)

        # Transform nested format to flat API format
        return {
            "enabled": config["enabled"],
            "interval_compliant": config["intervals"]["compliant"],
            "interval_mostly_compliant": config["intervals"]["mostly_compliant"],
            "interval_partial": config["intervals"]["partial"],
            "interval_low": config["intervals"]["low"],
            "interval_critical": config["intervals"]["critical"],
            "interval_unknown": config["intervals"]["unknown"],
            "interval_maintenance": config["intervals"]["maintenance"],
            "max_interval_minutes": config["max_interval_minutes"],
            "priority_compliant": config["priorities"]["compliant"],
            "priority_mostly_compliant": config["priorities"]["mostly_compliant"],
            "priority_partial": config["priorities"]["partial"],
            "priority_low": config["priorities"]["low"],
            "priority_critical": config["priorities"]["critical"],
            "priority_unknown": config["priorities"]["unknown"],
            "priority_maintenance": config["priorities"]["maintenance"],
            "max_concurrent_scans": config["max_concurrent_scans"],
            "scan_timeout_seconds": config["scan_timeout_seconds"],
        }
    except Exception as e:
        logger.error(f"Error getting scheduler config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/config", response_model=SchedulerConfigResponse)
@require_role([UserRole.SECURITY_ADMIN, UserRole.SUPER_ADMIN])
async def update_scheduler_config(
    config: SchedulerConfigUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Update scheduler configuration.

    Only provided fields will be updated. Requires ADMIN role.

    - Intervals are in minutes (min 15, max 2880 = 48 hours)
    - max_concurrent_scans: 1-20 concurrent scans
    - scan_timeout_seconds: 60-3600 seconds
    """
    try:
        # Filter out None values
        flat_data = {k: v for k, v in config.model_dump().items() if v is not None}

        if not flat_data:
            raise HTTPException(status_code=400, detail="No fields to update")

        # Transform flat format to nested format for service
        intervals = {}
        other_params = {}

        for key, value in flat_data.items():
            if key.startswith("interval_"):
                state = key.replace("interval_", "")
                intervals[state] = value
            elif key == "enabled":
                other_params["enabled"] = value
            elif key == "max_concurrent_scans":
                other_params["max_concurrent_scans"] = value
            elif key == "scan_timeout_seconds":
                other_params["scan_timeout_seconds"] = value

        # Call service with transformed parameters
        compliance_scheduler_service.update_config(
            db,
            enabled=other_params.get("enabled"),
            intervals=intervals if intervals else None,
            max_concurrent_scans=other_params.get("max_concurrent_scans"),
            scan_timeout_seconds=other_params.get("scan_timeout_seconds"),
        )

        # Return updated config in flat format
        return await get_scheduler_config(db=db, current_user=current_user)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating scheduler config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/toggle")
@require_role([UserRole.SECURITY_ADMIN, UserRole.SUPER_ADMIN])
async def toggle_scheduler(
    enabled: bool,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Enable or disable the compliance scheduler.

    When disabled, no automatic compliance scans will be dispatched.
    Manual scans can still be triggered.
    """
    try:
        compliance_scheduler_service.update_config(db, {"enabled": enabled})
        return {
            "status": "ok",
            "enabled": enabled,
            "message": f"Compliance scheduler {'enabled' if enabled else 'disabled'}",
        }
    except Exception as e:
        logger.error(f"Error toggling scheduler: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Scheduler Status Endpoints
# =============================================================================


@router.get("/status", response_model=SchedulerStatusResponse)
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
async def get_scheduler_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get current scheduler status and statistics.

    Returns host counts by compliance state and upcoming scans.
    """
    try:
        status = compliance_scheduler_service.get_scheduler_status(db)
        return status
    except Exception as e:
        logger.error(f"Error getting scheduler status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/hosts-due")
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
async def get_hosts_due_for_scan(
    limit: int = 10,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get list of hosts that are due for scanning.

    Returns hosts ordered by priority and scheduled time.
    """
    try:
        hosts_due = compliance_scheduler_service.get_hosts_due_for_scan(db, limit=limit)
        return {
            "hosts_due": len(hosts_due),
            "hosts": hosts_due,
        }
    except Exception as e:
        logger.error(f"Error getting hosts due for scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Host Schedule Endpoints
# =============================================================================


@router.get("/hosts/{host_id}", response_model=HostScheduleResponse)
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
async def get_host_schedule(
    host_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get compliance schedule details for a specific host.

    Returns current compliance state, next scan time, and schedule configuration.
    """
    try:
        schedule = compliance_scheduler_service.get_host_schedule(db, host_id)
        if not schedule:
            raise HTTPException(status_code=404, detail=f"Schedule not found for host {host_id}")
        return schedule
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting host schedule: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/hosts/{host_id}/maintenance")
@require_role([UserRole.SECURITY_ANALYST, UserRole.COMPLIANCE_OFFICER, UserRole.SECURITY_ADMIN, UserRole.SUPER_ADMIN])
async def set_host_maintenance_mode(
    host_id: UUID,
    request: MaintenanceModeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Set maintenance mode for a host.

    When in maintenance mode, the host will not be automatically scanned.
    Maintenance mode will automatically expire after the specified duration.
    """
    try:
        maintenance_until = None
        if request.enabled and request.duration_hours:
            maintenance_until = datetime.now(timezone.utc) + timedelta(hours=request.duration_hours)

        compliance_scheduler_service.set_host_maintenance_mode(
            db,
            host_id,
            enabled=request.enabled,
            maintenance_until=maintenance_until,
        )

        return {
            "status": "ok",
            "host_id": str(host_id),
            "maintenance_mode": request.enabled,
            "maintenance_until": maintenance_until.isoformat() if maintenance_until else None,
        }
    except Exception as e:
        logger.error(f"Error setting maintenance mode: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/hosts/{host_id}/force-scan")
@require_role([UserRole.SECURITY_ANALYST, UserRole.COMPLIANCE_OFFICER, UserRole.SECURITY_ADMIN, UserRole.SUPER_ADMIN])
async def force_host_scan(
    host_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Force an immediate compliance scan for a host.

    This bypasses the normal schedule and queues a scan immediately.
    The scan will be executed by the next available worker.
    """
    try:
        from app.celery_app import celery_app

        # Queue an immediate scan
        task = celery_app.send_task(
            "app.tasks.run_scheduled_kensa_scan",
            args=[str(host_id), 10],  # Priority 10 = highest
            priority=10,
            queue="compliance_scanning",
        )

        return {
            "status": "ok",
            "message": f"Scan queued for host {host_id}",
            "task_id": task.id,
        }
    except Exception as e:
        logger.error(f"Error forcing host scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Initialization Endpoints
# =============================================================================


@router.post("/initialize")
@require_role([UserRole.SECURITY_ADMIN, UserRole.SUPER_ADMIN])
async def initialize_schedules(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Initialize compliance schedules for all hosts that don't have one.

    This should be run after deploying the compliance scheduler to
    bootstrap schedules for existing hosts.
    """
    try:
        from app.celery_app import celery_app

        # Queue the initialization task
        task = celery_app.send_task(
            "app.tasks.initialize_compliance_schedules",
            queue="compliance_scanning",
        )

        return {
            "status": "ok",
            "message": "Schedule initialization queued",
            "task_id": task.id,
        }
    except Exception as e:
        logger.error(f"Error initializing schedules: {e}")
        raise HTTPException(status_code=500, detail=str(e))
