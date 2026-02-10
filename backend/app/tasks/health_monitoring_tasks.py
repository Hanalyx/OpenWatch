"""
Background tasks for health monitoring data collection.

Scheduled tasks that periodically collect and store health metrics.

Note: All tasks are sync (def, not async def) because Celery does not
natively support async tasks. Async service calls are executed via
asyncio.run() with a single event loop per task.

IMPORTANT: Each task must use a single event loop for all async operations
to avoid "Event loop is closed" errors. The HealthMonitoringService singleton
and MongoDB connections are bound to the event loop that created them.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, Dict

from celery.schedules import crontab

from app.celery_app import celery_app

logger = logging.getLogger(__name__)


async def _collect_service_health_async() -> Dict[str, Any]:
    """Async implementation of service health collection.

    All async operations run within a single event loop to avoid
    connection issues with MongoDB/Beanie.
    """
    from app.services.mongo_integration_service import reset_mongo_service
    from app.services.monitoring import get_health_monitoring_service
    from app.services.monitoring.health import reset_health_monitoring_service

    # Reset singletons to ensure fresh MongoDB connections for this event loop
    reset_mongo_service()
    reset_health_monitoring_service()

    health_service = await get_health_monitoring_service()
    service_health = await health_service.collect_service_health()
    await health_service.save_service_health(service_health)
    return {
        "overall_status": service_health.overall_status,
    }


@celery_app.task(name="collect_service_health", time_limit=300, soft_time_limit=240)
def collect_service_health_task() -> Dict[str, Any]:
    """
    Collect service health metrics.

    Runs every 5 minutes to capture operational health data.
    """
    try:
        logger.info("Starting service health collection task")

        # Use a single event loop for all async operations
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(_collect_service_health_async())
        finally:
            loop.close()

        logger.info(f"Service health collected successfully: {result['overall_status']}")

        return {
            "status": "success",
            "timestamp": datetime.utcnow().isoformat(),
            "overall_status": result["overall_status"],
        }

    except Exception as e:
        logger.error(f"Error in service health collection task: {e}")
        return {
            "status": "error",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e),
        }


async def _collect_content_health_async() -> Dict[str, Any]:
    """Async implementation of content health collection.

    All async operations run within a single event loop to avoid
    connection issues with MongoDB/Beanie.
    """
    from app.services.mongo_integration_service import reset_mongo_service
    from app.services.monitoring import get_health_monitoring_service
    from app.services.monitoring.health import reset_health_monitoring_service

    # Reset singletons to ensure fresh MongoDB connections for this event loop
    reset_mongo_service()
    reset_health_monitoring_service()

    health_service = await get_health_monitoring_service()
    content_health = await health_service.collect_content_health()
    await health_service.save_content_health(content_health)
    return {
        "alert_count": len(content_health.alerts_and_recommendations),
    }


@celery_app.task(name="collect_content_health", time_limit=600, soft_time_limit=540)
def collect_content_health_task() -> Dict[str, Any]:
    """
    Collect content health metrics.

    Runs every hour to analyze compliance content effectiveness.
    """
    try:
        logger.info("Starting content health collection task")

        # Use a single event loop for all async operations
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(_collect_content_health_async())
        finally:
            loop.close()

        logger.info(f"Content health collected successfully: {result['alert_count']} alerts")

        return {
            "status": "success",
            "timestamp": datetime.utcnow().isoformat(),
            "alert_count": result["alert_count"],
        }

    except Exception as e:
        logger.error(f"Error in content health collection task: {e}")
        return {
            "status": "error",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e),
        }


async def _update_health_summary_async() -> Dict[str, Any]:
    """Async implementation of health summary update.

    All async operations run within a single event loop to avoid
    connection issues with MongoDB/Beanie.
    """
    from app.services.mongo_integration_service import reset_mongo_service
    from app.services.monitoring import get_health_monitoring_service
    from app.services.monitoring.health import reset_health_monitoring_service

    # Reset singletons to ensure fresh MongoDB connections for this event loop
    reset_mongo_service()
    reset_health_monitoring_service()

    health_service = await get_health_monitoring_service()
    summary = await health_service.create_health_summary()
    await health_service.save_health_summary(summary)
    return {
        "overall_status": summary.overall_health_status,
        "active_issues": summary.active_issues_count,
    }


@celery_app.task(name="update_health_summary", time_limit=300, soft_time_limit=240)
def update_health_summary_task() -> Dict[str, Any]:
    """
    Update combined health summary.

    Runs every 5 minutes to maintain current health overview.
    """
    try:
        logger.info("Starting health summary update task")

        # Use a single event loop for all async operations
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(_update_health_summary_async())
        finally:
            loop.close()

        logger.info(f"Health summary updated: {result['overall_status']}, {result['active_issues']} active issues")

        return {
            "status": "success",
            "timestamp": datetime.utcnow().isoformat(),
            "overall_status": result["overall_status"],
            "active_issues": result["active_issues"],
        }

    except Exception as e:
        logger.error(f"Error in health summary update task: {e}")
        return {
            "status": "error",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e),
        }


async def _cleanup_old_health_data_async(retention_days: int) -> Dict[str, Any]:
    """Async implementation of health data cleanup.

    All async operations run within a single event loop to avoid
    connection issues with MongoDB/Beanie.
    """
    from app.models.health_models import ContentHealthDocument, ServiceHealthDocument
    from app.services.mongo_integration_service import reset_mongo_service
    from app.services.monitoring import get_health_monitoring_service
    from app.services.monitoring.health import reset_health_monitoring_service

    # Reset singletons to ensure fresh MongoDB connections for this event loop
    reset_mongo_service()
    reset_health_monitoring_service()

    # Ensure MongoDB is initialized
    await get_health_monitoring_service()

    cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

    # Delete old service health data
    service_result = await ServiceHealthDocument.find(
        ServiceHealthDocument.health_check_timestamp < cutoff_date
    ).delete()

    # Delete old content health data
    content_result = await ContentHealthDocument.find(
        ContentHealthDocument.health_check_timestamp < cutoff_date
    ).delete()

    return {
        "service_records_deleted": service_result.deleted_count if service_result else 0,
        "content_records_deleted": content_result.deleted_count if content_result else 0,
    }


@celery_app.task(name="cleanup_old_health_data", time_limit=600, soft_time_limit=540)
def cleanup_old_health_data_task(retention_days: int = 7) -> dict:
    """
    Clean up old health monitoring data.

    Runs daily to remove health data older than retention period.
    """
    try:
        logger.info(f"Starting health data cleanup task (retention: {retention_days} days)")

        # Use a single event loop for all async operations
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(_cleanup_old_health_data_async(retention_days))
        finally:
            loop.close()

        logger.info(
            f"Health data cleanup completed: "
            f"{result['service_records_deleted']} service records, "
            f"{result['content_records_deleted']} content records deleted"
        )

        return {
            "status": "success",
            "timestamp": datetime.utcnow().isoformat(),
            "service_records_deleted": result["service_records_deleted"],
            "content_records_deleted": result["content_records_deleted"],
        }

    except Exception as e:
        logger.error(f"Error in health data cleanup task: {e}")
        return {
            "status": "error",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e),
        }


# Schedule configuration for Celery beat
beat_schedule = {
    "collect-service-health": {
        "task": "collect_service_health",
        "schedule": crontab(minute="*/5"),  # Every 5 minutes
        "options": {"queue": "health_monitoring"},
    },
    "collect-content-health": {
        "task": "collect_content_health",
        "schedule": crontab(minute=0),  # Every hour
        "options": {"queue": "health_monitoring"},
    },
    "update-health-summary": {
        "task": "update_health_summary",
        "schedule": crontab(minute="*/5"),  # Every 5 minutes
        "options": {"queue": "health_monitoring"},
    },
    "cleanup-old-health-data": {
        "task": "cleanup_old_health_data",
        "schedule": crontab(hour=2, minute=0),  # Daily at 2 AM
        "options": {"queue": "health_monitoring"},
    },
}
