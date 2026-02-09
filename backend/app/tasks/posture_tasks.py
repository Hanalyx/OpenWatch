"""
Posture Snapshot Tasks

Celery tasks for creating and managing compliance posture snapshots.

Part of Phase 2: Temporal Compliance (Aegis Integration Plan)
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict

from celery import shared_task

from app.database import SessionLocal
from app.services.compliance import TemporalComplianceService

logger = logging.getLogger(__name__)


@shared_task(name="create_daily_posture_snapshots")
def create_daily_posture_snapshots() -> Dict[str, Any]:
    """
    Create daily posture snapshots for all active hosts.

    This task should be scheduled to run once per day (e.g., at midnight UTC).
    It creates a snapshot of the current compliance posture for each host,
    enabling historical posture queries.

    Returns:
        Summary of snapshot creation results
    """
    logger.info("Starting daily posture snapshot creation")

    db = SessionLocal()
    try:
        service = TemporalComplianceService(db)
        result = service.create_daily_snapshots_for_all_hosts()

        logger.info(
            "Daily posture snapshots complete: %d created, %d skipped, %d errors",
            result["created"],
            result["skipped"],
            result["errors"],
        )

        return {
            "success": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **result,
        }

    except Exception as e:
        logger.exception("Failed to create daily posture snapshots: %s", e)
        return {
            "success": False,
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    finally:
        db.close()


@shared_task(name="cleanup_old_posture_snapshots")
def cleanup_old_posture_snapshots(retention_days: int = 30) -> Dict[str, Any]:
    """
    Clean up posture snapshots older than the retention period.

    Free tier users have 30-day retention.
    OpenWatch+ subscribers have unlimited retention (pass retention_days=0 to skip).

    Args:
        retention_days: Number of days to retain snapshots (0 = no cleanup)

    Returns:
        Summary of cleanup results
    """
    if retention_days <= 0:
        logger.info("Snapshot cleanup skipped (retention_days=%d)", retention_days)
        return {
            "success": True,
            "deleted": 0,
            "message": "Cleanup skipped - unlimited retention",
        }

    logger.info("Starting posture snapshot cleanup (retention: %d days)", retention_days)

    db = SessionLocal()
    try:
        service = TemporalComplianceService(db)
        deleted = service.cleanup_old_snapshots(retention_days)

        logger.info("Posture snapshot cleanup complete: %d deleted", deleted)

        return {
            "success": True,
            "deleted": deleted,
            "retention_days": retention_days,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.exception("Failed to clean up posture snapshots: %s", e)
        return {
            "success": False,
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    finally:
        db.close()


__all__ = [
    "create_daily_posture_snapshots",
    "cleanup_old_posture_snapshots",
]
