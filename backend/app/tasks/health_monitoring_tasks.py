"""
Background tasks for health monitoring data collection.

Scheduled tasks that periodically collect and store health metrics.
"""

from datetime import datetime, timedelta
from celery import Celery
from celery.schedules import crontab

from ..core.celery_app import celery_app
from ..services.health_monitoring_service import get_health_monitoring_service
from ..core.logging import logger


@celery_app.task(name="collect_service_health")
async def collect_service_health_task():
    """
    Collect service health metrics.
    
    Runs every 5 minutes to capture operational health data.
    """
    try:
        logger.info("Starting service health collection task")
        
        health_service = await get_health_monitoring_service()
        
        # Collect and save service health
        service_health = await health_service.collect_service_health()
        await health_service.save_service_health(service_health)
        
        logger.info(f"Service health collected successfully: {service_health.overall_status}")
        
        return {
            "status": "success",
            "timestamp": datetime.utcnow().isoformat(),
            "overall_status": service_health.overall_status
        }
        
    except Exception as e:
        logger.error(f"Error in service health collection task: {e}")
        return {
            "status": "error",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }


@celery_app.task(name="collect_content_health")
async def collect_content_health_task():
    """
    Collect content health metrics.
    
    Runs every hour to analyze compliance content effectiveness.
    """
    try:
        logger.info("Starting content health collection task")
        
        health_service = await get_health_monitoring_service()
        
        # Collect and save content health
        content_health = await health_service.collect_content_health()
        await health_service.save_content_health(content_health)
        
        alert_count = len(content_health.alerts_and_recommendations)
        logger.info(f"Content health collected successfully: {alert_count} alerts")
        
        return {
            "status": "success",
            "timestamp": datetime.utcnow().isoformat(),
            "alert_count": alert_count
        }
        
    except Exception as e:
        logger.error(f"Error in content health collection task: {e}")
        return {
            "status": "error",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }


@celery_app.task(name="update_health_summary")
async def update_health_summary_task():
    """
    Update combined health summary.
    
    Runs every 5 minutes to maintain current health overview.
    """
    try:
        logger.info("Starting health summary update task")
        
        health_service = await get_health_monitoring_service()
        
        # Create and save health summary
        summary = await health_service.create_health_summary()
        await health_service.save_health_summary(summary)
        
        logger.info(
            f"Health summary updated: {summary.overall_health_status}, "
            f"{summary.active_issues_count} active issues"
        )
        
        return {
            "status": "success",
            "timestamp": datetime.utcnow().isoformat(),
            "overall_status": summary.overall_health_status,
            "active_issues": summary.active_issues_count
        }
        
    except Exception as e:
        logger.error(f"Error in health summary update task: {e}")
        return {
            "status": "error",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }


@celery_app.task(name="cleanup_old_health_data")
async def cleanup_old_health_data_task(retention_days: int = 7):
    """
    Clean up old health monitoring data.
    
    Runs daily to remove health data older than retention period.
    """
    try:
        logger.info(f"Starting health data cleanup task (retention: {retention_days} days)")
        
        from ..models.health_models import ServiceHealthDocument, ContentHealthDocument
        
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        # Delete old service health data
        service_result = await ServiceHealthDocument.find(
            ServiceHealthDocument.health_check_timestamp < cutoff_date
        ).delete()
        
        # Delete old content health data
        content_result = await ContentHealthDocument.find(
            ContentHealthDocument.health_check_timestamp < cutoff_date
        ).delete()
        
        logger.info(
            f"Health data cleanup completed: "
            f"{service_result.deleted_count} service records, "
            f"{content_result.deleted_count} content records deleted"
        )
        
        return {
            "status": "success",
            "timestamp": datetime.utcnow().isoformat(),
            "service_records_deleted": service_result.deleted_count,
            "content_records_deleted": content_result.deleted_count
        }
        
    except Exception as e:
        logger.error(f"Error in health data cleanup task: {e}")
        return {
            "status": "error",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }


# Schedule configuration for Celery beat
beat_schedule = {
    "collect-service-health": {
        "task": "collect_service_health",
        "schedule": crontab(minute="*/5"),  # Every 5 minutes
        "options": {"queue": "health_monitoring"}
    },
    "collect-content-health": {
        "task": "collect_content_health",
        "schedule": crontab(minute=0),  # Every hour
        "options": {"queue": "health_monitoring"}
    },
    "update-health-summary": {
        "task": "update_health_summary",
        "schedule": crontab(minute="*/5"),  # Every 5 minutes
        "options": {"queue": "health_monitoring"}
    },
    "cleanup-old-health-data": {
        "task": "cleanup_old_health_data",
        "schedule": crontab(hour=2, minute=0),  # Daily at 2 AM
        "options": {"queue": "health_monitoring"}
    }
}