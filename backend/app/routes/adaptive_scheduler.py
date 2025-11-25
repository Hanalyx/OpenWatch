"""
Adaptive Host Monitoring Scheduler API Routes

Provides endpoints for configuring and controlling the adaptive Celery-based
host monitoring scheduler.
"""

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..rbac import Permission, require_permission
from ..services.adaptive_scheduler_service import adaptive_scheduler_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/system/adaptive-scheduler", tags=["Adaptive Scheduler"])


# Pydantic models
class IntervalConfig(BaseModel):
    """Check intervals for each host state (in minutes)"""

    unknown: int = Field(default=0, ge=0, le=60, description="Immediate checks for new hosts")
    online: int = Field(default=15, ge=5, le=60, description="Healthy hosts check interval")
    degraded: int = Field(default=5, ge=1, le=15, description="Partial connectivity check interval")
    critical: int = Field(default=2, ge=1, le=10, description="Severe issues check interval")
    down: int = Field(default=30, ge=10, le=120, description="Completely down check interval")
    maintenance: int = Field(default=60, ge=15, le=1440, description="Maintenance mode check interval")


class PriorityConfig(BaseModel):
    """Celery queue priorities for each host state (1-10, higher = more urgent)"""

    unknown: int = Field(default=10, ge=1, le=10)
    critical: int = Field(default=8, ge=1, le=10)
    degraded: int = Field(default=6, ge=1, le=10)
    online: int = Field(default=4, ge=1, le=10)
    down: int = Field(default=2, ge=1, le=10)
    maintenance: int = Field(default=1, ge=1, le=10)


class SchedulerConfigResponse(BaseModel):
    """Complete scheduler configuration"""

    enabled: bool
    intervals: IntervalConfig
    maintenance_mode: str  # 'skip', 'passive', 'reduced'
    max_concurrent_checks: int
    check_timeout_seconds: int
    retry_on_failure: bool
    priorities: PriorityConfig


class SchedulerConfigUpdate(BaseModel):
    """Partial update for scheduler configuration"""

    enabled: Optional[bool] = None
    intervals: Optional[IntervalConfig] = None
    maintenance_mode: Optional[str] = Field(None, pattern="^(skip|passive|reduced)$")
    max_concurrent_checks: Optional[int] = Field(None, ge=1, le=50)
    check_timeout_seconds: Optional[int] = Field(None, ge=10, le=300)
    retry_on_failure: Optional[bool] = None


class SchedulerStatsResponse(BaseModel):
    """Real-time scheduler statistics"""

    enabled: bool
    hosts_by_state: Dict[str, int]
    total_hosts: int
    overdue_checks: int
    next_check_time: Optional[str]
    max_concurrent_checks: int
    maintenance_mode: str


@router.get("/config", response_model=SchedulerConfigResponse)  # type: ignore[misc]
async def get_scheduler_config(
    db: Session = Depends(get_db), current_user: Dict[str, Any] = Depends(get_current_user)
) -> SchedulerConfigResponse:
    """
    Get current adaptive scheduler configuration.

    Returns all configurable settings including check intervals per host state,
    maintenance mode behavior, and advanced settings.
    """
    try:
        config = adaptive_scheduler_service.get_config(db)

        return SchedulerConfigResponse(
            enabled=config["enabled"],
            intervals=IntervalConfig(**config["intervals"]),
            maintenance_mode=config["maintenance_mode"],
            max_concurrent_checks=config["max_concurrent_checks"],
            check_timeout_seconds=config["check_timeout_seconds"],
            retry_on_failure=config["retry_on_failure"],
            priorities=PriorityConfig(**config["priorities"]),
        )

    except Exception as e:
        logger.error(f"Error getting scheduler config: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve scheduler configuration")


@router.put("/config", response_model=SchedulerConfigResponse)  # type: ignore[misc]
@require_permission(Permission.SYSTEM_CONFIG)
async def update_scheduler_config(
    config_update: SchedulerConfigUpdate,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> SchedulerConfigResponse:
    """
    Update adaptive scheduler configuration.

    Updates one or more scheduler settings. Only provided fields will be updated.
    When enabled state changes, the scheduler will be started or stopped accordingly.

    Requires: SYSTEM_CONFIG permission
    """
    try:
        user_id = current_user.get("id")

        # Convert Pydantic models to dicts if provided
        intervals_dict = None
        if config_update.intervals:
            intervals_dict = config_update.intervals.dict()

        # Update configuration
        updated_config = adaptive_scheduler_service.update_config(
            db,
            enabled=config_update.enabled,
            intervals=intervals_dict,
            maintenance_mode=config_update.maintenance_mode,
            max_concurrent_checks=config_update.max_concurrent_checks,
            check_timeout_seconds=config_update.check_timeout_seconds,
            retry_on_failure=config_update.retry_on_failure,
            user_id=user_id,
        )

        logger.info(f"Scheduler configuration updated by user {user_id}")

        return SchedulerConfigResponse(
            enabled=updated_config["enabled"],
            intervals=IntervalConfig(**updated_config["intervals"]),
            maintenance_mode=updated_config["maintenance_mode"],
            max_concurrent_checks=updated_config["max_concurrent_checks"],
            check_timeout_seconds=updated_config["check_timeout_seconds"],
            retry_on_failure=updated_config["retry_on_failure"],
            priorities=PriorityConfig(**updated_config["priorities"]),
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error updating scheduler config: {e}")
        raise HTTPException(status_code=500, detail="Failed to update scheduler configuration")


@router.post("/start")  # type: ignore[misc]
@require_permission(Permission.SYSTEM_CONFIG)
async def start_scheduler(
    db: Session = Depends(get_db), current_user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Enable the adaptive monitoring scheduler.

    Starts monitoring all active hosts based on their state and configured intervals.
    Hosts will be checked according to their health status (critical hosts more frequently).

    Requires: SYSTEM_CONFIG permission
    """
    try:
        user_id = current_user.get("id")

        # Enable scheduler
        config = adaptive_scheduler_service.update_config(db, enabled=True, user_id=user_id)

        logger.info(f"Adaptive scheduler started by user {user_id}")

        return {
            "message": "Adaptive monitoring scheduler started successfully",
            "enabled": config["enabled"],
            "intervals": config["intervals"],
        }

    except Exception as e:
        logger.error(f"Error starting scheduler: {e}")
        raise HTTPException(status_code=500, detail="Failed to start scheduler")


@router.post("/stop")  # type: ignore[misc]
@require_permission(Permission.SYSTEM_CONFIG)
async def stop_scheduler(
    db: Session = Depends(get_db), current_user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Disable the adaptive monitoring scheduler.

    Stops all automated host monitoring. Manual host checks will still be available.

    Requires: SYSTEM_CONFIG permission
    """
    try:
        user_id = current_user.get("id")

        # Disable scheduler
        config = adaptive_scheduler_service.update_config(db, enabled=False, user_id=user_id)

        logger.info(f"Adaptive scheduler stopped by user {user_id}")

        return {
            "message": "Adaptive monitoring scheduler stopped successfully",
            "enabled": config["enabled"],
        }

    except Exception as e:
        logger.error(f"Error stopping scheduler: {e}")
        raise HTTPException(status_code=500, detail="Failed to stop scheduler")


@router.get("/stats", response_model=SchedulerStatsResponse)  # type: ignore[misc]
async def get_scheduler_stats(
    db: Session = Depends(get_db), current_user: Dict[str, Any] = Depends(get_current_user)
) -> SchedulerStatsResponse:
    """
    Get real-time scheduler statistics.

    Returns current state including:
    - Number of hosts per state (online, degraded, critical, down, maintenance)
    - Number of overdue checks
    - Next scheduled check time
    - Current scheduler configuration
    """
    try:
        stats = adaptive_scheduler_service.get_scheduler_stats(db)

        return SchedulerStatsResponse(
            enabled=stats["enabled"],
            hosts_by_state=stats["hosts_by_state"],
            total_hosts=stats["total_hosts"],
            overdue_checks=stats["overdue_checks"],
            next_check_time=stats["next_check_time"],
            max_concurrent_checks=stats.get("max_concurrent_checks", 10),
            maintenance_mode=stats.get("maintenance_mode", "reduced"),
        )

    except Exception as e:
        logger.error(f"Error getting scheduler stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve scheduler statistics")


@router.post("/reset-defaults")  # type: ignore[misc]
@require_permission(Permission.SYSTEM_CONFIG)
async def reset_to_defaults(
    db: Session = Depends(get_db), current_user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Reset scheduler configuration to default values.

    Restores all settings to their recommended defaults:
    - unknown: 0 min (immediate)
    - online: 15 min
    - degraded: 5 min
    - critical: 2 min
    - down: 30 min
    - maintenance: 60 min
    - maintenance_mode: reduced
    - max_concurrent_checks: 10

    Requires: SYSTEM_CONFIG permission
    """
    try:
        user_id = current_user.get("id")

        # Reset to default intervals
        config = adaptive_scheduler_service.update_config(
            db,
            intervals={
                "unknown": 0,
                "online": 15,
                "degraded": 5,
                "critical": 2,
                "down": 30,
                "maintenance": 60,
            },
            maintenance_mode="reduced",
            max_concurrent_checks=10,
            check_timeout_seconds=30,
            retry_on_failure=True,
            user_id=user_id,
        )

        logger.info(f"Scheduler reset to defaults by user {user_id}")

        return {
            "message": "Scheduler configuration reset to defaults",
            "config": config,
        }

    except Exception as e:
        logger.error(f"Error resetting scheduler: {e}")
        raise HTTPException(status_code=500, detail="Failed to reset scheduler configuration")
