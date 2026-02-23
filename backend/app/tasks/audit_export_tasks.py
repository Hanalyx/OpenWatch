"""
Audit Export Tasks

Celery tasks for generating and managing audit exports.

Part of Phase 6: Audit Queries (Kensa Integration Plan)
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict

from celery import shared_task

from app.database import SessionLocal
from app.services.compliance.audit_export import AuditExportService

logger = logging.getLogger(__name__)


@shared_task(
    name="generate_audit_export",
    bind=True,
    max_retries=3,
    default_retry_delay=60,
)
def generate_audit_export_task(self, export_id: str) -> Dict[str, Any]:
    """
    Generate an audit export file.

    This task is queued when an export is created and handles:
    - Fetching all query results
    - Generating the file in the requested format
    - Updating export status

    Args:
        export_id: UUID of the export to generate

    Returns:
        Summary of export generation
    """
    from uuid import UUID

    logger.info("Starting export generation: %s", export_id)

    db = SessionLocal()
    try:
        service = AuditExportService(db)
        success = service.generate_export(UUID(export_id))

        if success:
            logger.info("Export generation completed: %s", export_id)
            return {
                "success": True,
                "export_id": export_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        else:
            logger.warning("Export generation returned false: %s", export_id)
            return {
                "success": False,
                "export_id": export_id,
                "error": "Generation returned false",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    except Exception as e:
        logger.exception("Export generation failed: %s - %s", export_id, e)

        # Retry with exponential backoff
        try:
            raise self.retry(exc=e)
        except self.MaxRetriesExceededError:
            logger.error(
                "Export generation max retries exceeded: %s",
                export_id,
            )
            return {
                "success": False,
                "export_id": export_id,
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    finally:
        db.close()


@shared_task(name="cleanup_expired_audit_exports")
def cleanup_expired_audit_exports() -> Dict[str, Any]:
    """
    Clean up expired audit exports.

    This task should be scheduled to run daily (e.g., at 2 AM UTC).
    It deletes:
    - Export records past their expires_at date
    - Associated export files from disk

    Returns:
        Summary of cleanup results
    """
    logger.info("Starting audit export cleanup")

    db = SessionLocal()
    try:
        service = AuditExportService(db)
        deleted = service.cleanup_expired_exports()

        logger.info("Audit export cleanup complete: %d deleted", deleted)

        return {
            "success": True,
            "deleted": deleted,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.exception("Audit export cleanup failed: %s", e)
        return {
            "success": False,
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    finally:
        db.close()


__all__ = [
    "generate_audit_export_task",
    "cleanup_expired_audit_exports",
]
