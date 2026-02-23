"""
API endpoints for health monitoring data.

Provides endpoints for retrieving service health, content health,
and combined health summaries.
"""

import logging
from datetime import datetime
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query

from ...auth import get_current_user
from ...database import User
from ...models.health_models import ContentHealthDocument, HealthSummaryDocument, ServiceHealthDocument
from ...services.monitoring import HealthMonitoringService, get_health_monitoring_service

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/health/service", response_model=ServiceHealthDocument)
async def get_service_health(
    current_user: User = Depends(get_current_user),
    health_service: HealthMonitoringService = Depends(get_health_monitoring_service),
) -> ServiceHealthDocument:
    """Get current service health metrics."""
    try:
        return await health_service.collect_service_health()
    except Exception as e:
        logger.error(f"Error retrieving service health: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve service health")


@router.get("/health/content", response_model=ContentHealthDocument)
async def get_content_health(
    current_user: User = Depends(get_current_user),
    health_service: HealthMonitoringService = Depends(get_health_monitoring_service),
) -> ContentHealthDocument:
    """Get content health metrics.

    Note: Detailed content health is now available via the
    Kensa Rule Reference API at /api/rules/reference/stats.
    """
    try:
        return await health_service.collect_content_health()
    except Exception as e:
        logger.error(f"Error retrieving content health: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve content health")


@router.get("/health/summary", response_model=HealthSummaryDocument)
async def get_health_summary(
    current_user: User = Depends(get_current_user),
    health_service: HealthMonitoringService = Depends(get_health_monitoring_service),
) -> HealthSummaryDocument:
    """Get combined health summary."""
    try:
        return await health_service.create_health_summary()
    except Exception as e:
        logger.error(f"Error retrieving health summary: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve health summary")


@router.post("/health/refresh")
async def refresh_health_data(
    current_user: User = Depends(get_current_user),
    health_service: HealthMonitoringService = Depends(get_health_monitoring_service),
) -> Dict[str, str]:
    """Force refresh of all health data."""
    try:
        await health_service.collect_service_health()
        return {
            "status": "success",
            "message": "Health data refreshed successfully",
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        logger.error(f"Error refreshing health data: {e}")
        raise HTTPException(status_code=500, detail="Failed to refresh health data")


@router.get("/health/history/service")
async def get_service_health_history(
    hours: int = Query(default=24, ge=1, le=168, description="Hours of history"),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get service health history.

    Note: Historical health data storage has been removed with MongoDB.
    This endpoint returns an empty history.
    """
    from datetime import timedelta

    return {
        "start_time": (datetime.utcnow() - timedelta(hours=hours)).isoformat(),
        "end_time": datetime.utcnow().isoformat(),
        "data_points": 0,
        "history": [],
    }


@router.get("/health/history/content")
async def get_content_health_history(
    hours: int = Query(default=24, ge=1, le=168, description="Hours of history"),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get content health history.

    Note: Historical health data storage has been removed with MongoDB.
    This endpoint returns an empty history.
    """
    from datetime import timedelta

    return {
        "start_time": (datetime.utcnow() - timedelta(hours=hours)).isoformat(),
        "end_time": datetime.utcnow().isoformat(),
        "data_points": 0,
        "history": [],
    }
