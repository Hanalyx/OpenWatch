"""
API endpoints for health monitoring data.

Provides endpoints for retrieving service health, content health,
and combined health summaries.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

from ....services.health_monitoring_service import get_health_monitoring_service, HealthMonitoringService
from ....models.health_models import (
    ServiceHealthDocument,
    ContentHealthDocument,
    HealthSummaryDocument
)
from ....auth import get_current_user
from ....database import User
import logging

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/health/service", response_model=ServiceHealthDocument)
async def get_service_health(
    current_user: User = Depends(get_current_user),
    health_service: HealthMonitoringService = Depends(get_health_monitoring_service)
) -> ServiceHealthDocument:
    """
    Get current service health metrics.
    
    Returns operational health data including:
    - Core service statuses
    - Database connection health
    - Resource usage (CPU, memory, storage)
    - Recent operation statistics
    - Active alerts
    """
    try:
        # Get latest or collect new
        health_data = await health_service.get_latest_service_health()
        
        # If no data or data is older than 5 minutes, collect fresh
        if not health_data or (datetime.utcnow() - health_data.health_check_timestamp) > timedelta(minutes=5):
            health_data = await health_service.collect_service_health()
            await health_service.save_service_health(health_data)
        
        return health_data
        
    except Exception as e:
        logger.error(f"Error retrieving service health: {type(e).__name__}: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Failed to retrieve service health")


@router.get("/health/content", response_model=ContentHealthDocument)
async def get_content_health(
    current_user: User = Depends(get_current_user),
    health_service: HealthMonitoringService = Depends(get_health_monitoring_service)
) -> ContentHealthDocument:
    """
    Get current content health metrics.
    
    Returns compliance content health data including:
    - Framework coverage statistics
    - Benchmark implementation status
    - Rule distribution and statistics
    - Content integrity validation
    - Performance metrics
    - Content-related alerts
    """
    try:
        # Get latest or collect new
        health_data = await health_service.get_latest_content_health()
        
        # If no data or data is older than 1 hour, collect fresh
        if not health_data or (datetime.utcnow() - health_data.health_check_timestamp) > timedelta(hours=1):
            health_data = await health_service.collect_content_health()
            await health_service.save_content_health(health_data)
        
        return health_data
        
    except Exception as e:
        logger.error(f"Error retrieving content health: {type(e).__name__}: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Failed to retrieve content health")


@router.get("/health/summary", response_model=HealthSummaryDocument)
async def get_health_summary(
    current_user: User = Depends(get_current_user),
    health_service: HealthMonitoringService = Depends(get_health_monitoring_service)
) -> HealthSummaryDocument:
    """
    Get combined health summary.
    
    Returns a quick overview including:
    - Overall system status
    - Key metrics
    - Active issue count
    - Critical alerts
    """
    try:
        # Always generate fresh summary
        summary = await health_service.create_health_summary()
        await health_service.save_health_summary(summary)
        
        return summary
        
    except Exception as e:
        logger.error(f"Error retrieving health summary: {type(e).__name__}: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Failed to retrieve health summary")


@router.post("/health/refresh")
async def refresh_health_data(
    current_user: User = Depends(get_current_user),
    health_service: HealthMonitoringService = Depends(get_health_monitoring_service)
) -> Dict[str, str]:
    """
    Force refresh of all health data.
    
    Triggers immediate collection of:
    - Service health metrics
    - Content health metrics
    - Health summary
    """
    try:
        # Collect all health data
        service_health = await health_service.collect_service_health()
        content_health = await health_service.collect_content_health()
        summary = await health_service.create_health_summary()
        
        # Save all data
        await health_service.save_service_health(service_health)
        await health_service.save_content_health(content_health)
        await health_service.save_health_summary(summary)
        
        return {
            "status": "success",
            "message": "Health data refreshed successfully",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error refreshing health data: {e}")
        raise HTTPException(status_code=500, detail="Failed to refresh health data")


@router.get("/health/history/service")
async def get_service_health_history(
    hours: int = Query(default=24, ge=1, le=168, description="Hours of history to retrieve"),
    current_user: User = Depends(get_current_user),
    health_service: HealthMonitoringService = Depends(get_health_monitoring_service)
) -> Dict[str, Any]:
    """
    Get service health history.
    
    Returns historical service health data for trending and analysis.
    """
    try:
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Query historical data
        history = await ServiceHealthDocument.find(
            ServiceHealthDocument.scanner_id == health_service.scanner_id,
            ServiceHealthDocument.health_check_timestamp >= cutoff_time
        ).sort(ServiceHealthDocument.health_check_timestamp).to_list()
        
        return {
            "start_time": cutoff_time.isoformat(),
            "end_time": datetime.utcnow().isoformat(),
            "data_points": len(history),
            "history": [h.dict() for h in history]
        }
        
    except Exception as e:
        logger.error(f"Error retrieving service health history: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve health history")


@router.get("/health/history/content")
async def get_content_health_history(
    hours: int = Query(default=24, ge=1, le=168, description="Hours of history to retrieve"),
    current_user: User = Depends(get_current_user),
    health_service: HealthMonitoringService = Depends(get_health_monitoring_service)
) -> Dict[str, Any]:
    """
    Get content health history.
    
    Returns historical content health data for trending and analysis.
    """
    try:
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Query historical data
        history = await ContentHealthDocument.find(
            ContentHealthDocument.scanner_id == health_service.scanner_id,
            ContentHealthDocument.health_check_timestamp >= cutoff_time
        ).sort(ContentHealthDocument.health_check_timestamp).to_list()
        
        return {
            "start_time": cutoff_time.isoformat(),
            "end_time": datetime.utcnow().isoformat(),
            "data_points": len(history),
            "history": [h.dict() for h in history]
        }
        
    except Exception as e:
        logger.error(f"Error retrieving content health history: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve health history")