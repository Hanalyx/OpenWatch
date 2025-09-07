"""
Celery tasks for group scan orchestration
"""

import logging
import asyncio
from typing import List, Dict, Any
from sqlalchemy.orm import Session

from ..database import SessionLocal
from ..services.group_scan_service import GroupScanService
from .scan_tasks import execute_scan_task

logger = logging.getLogger(__name__)


def execute_group_scan_task(session_id: str, group_id: int, scan_config: dict):
    """
    Execute scans for all hosts in a group
    Updates progress in real-time via database
    """
    db = SessionLocal()

    try:
        logger.info(f"Starting group scan task for session {session_id}")

        # Initialize group scan service
        group_scan_service = GroupScanService(db)

        # Start the group scan execution
        result = asyncio.run(group_scan_service.start_group_scan_execution(session_id))

        if result:
            logger.info(f"Group scan task completed successfully for session {session_id}")
        else:
            logger.warning(f"Group scan task had no pending hosts for session {session_id}")

    except Exception as e:
        logger.error(f"Group scan task failed for session {session_id}: {e}")

        # Update session status to failed
        try:
            asyncio.run(_update_session_status_to_failed(db, session_id, str(e)))
        except Exception as update_error:
            logger.error(f"Failed to update session status to failed: {update_error}")

        raise
    finally:
        db.close()


async def _update_session_status_to_failed(db: Session, session_id: str, error_message: str):
    """Update group scan session status to failed"""
    from sqlalchemy import text
    from datetime import datetime

    try:
        db.execute(
            text(
                """
            UPDATE group_scan_sessions 
            SET status = 'failed', 
                updated_at = :updated_at, 
                completed_at = :completed_at,
                metadata = COALESCE(metadata, '{}'::jsonb) || :error_metadata::jsonb
            WHERE session_id = :session_id
        """
            ),
            {
                "session_id": session_id,
                "updated_at": datetime.utcnow(),
                "completed_at": datetime.utcnow(),
                "error_metadata": f'{{"error": "{error_message}"}}',
            },
        )

        # Also update any pending host statuses to failed
        db.execute(
            text(
                """
            UPDATE group_scan_host_progress 
            SET status = 'failed', 
                error_message = :error_message,
                updated_at = :updated_at
            WHERE session_id = :session_id AND status = 'pending'
        """
            ),
            {
                "session_id": session_id,
                "error_message": f"Group scan failed: {error_message}",
                "updated_at": datetime.utcnow(),
            },
        )

        db.commit()
        logger.info(f"Updated session {session_id} status to failed")

    except Exception as e:
        logger.error(f"Failed to update session status: {e}")
        db.rollback()


# Celery task wrapper (if Celery is available)
try:
    from celery import current_app

    @current_app.task(bind=True)
    def execute_group_scan_celery_task(self, session_id: str, group_id: int, scan_config: dict):
        """Celery task wrapper for group scan execution"""
        try:
            # Update task ID in database if needed
            db = SessionLocal()
            try:
                from sqlalchemy import text

                db.execute(
                    text(
                        """
                    UPDATE group_scan_sessions 
                    SET metadata = COALESCE(metadata, '{}'::jsonb) || :task_metadata::jsonb
                    WHERE session_id = :session_id
                """
                    ),
                    {
                        "session_id": session_id,
                        "task_metadata": f'{{"celery_task_id": "{self.request.id}"}}',
                    },
                )
                db.commit()
            finally:
                db.close()

            # Execute group scan
            execute_group_scan_task(session_id, group_id, scan_config)

        except Exception as e:
            logger.error(f"Celery group scan task failed for session {session_id}: {e}")

            # Update session with failure
            db = SessionLocal()
            try:
                asyncio.run(_update_session_status_to_failed(db, session_id, str(e)))
            finally:
                db.close()

            raise

except ImportError:
    logger.info("Celery not available for group scan tasks, using background execution only")


def monitor_group_scan_progress(session_id: str):
    """
    Background task to monitor and update group scan progress
    Can be used to handle cleanup, notifications, etc.
    """
    db = SessionLocal()

    try:
        logger.debug(f"Monitoring group scan progress for session {session_id}")

        group_scan_service = GroupScanService(db)
        progress = asyncio.run(group_scan_service.get_scan_progress(session_id))

        # Check if scan is complete and send notifications
        if progress.status.value in ["completed", "failed", "cancelled"]:
            logger.info(f"Group scan {session_id} finished with status: {progress.status.value}")

            # Here you could add webhook notifications, email alerts, etc.
            # For now, just log the completion

        return progress.dict()

    except Exception as e:
        logger.error(f"Error monitoring group scan progress: {e}")
        return None
    finally:
        db.close()


# Celery task wrapper for monitoring
try:

    @current_app.task
    def monitor_group_scan_progress_celery_task(session_id: str):
        """Celery task wrapper for group scan monitoring"""
        return monitor_group_scan_progress(session_id)

except (ImportError, NameError):
    # Celery not available
    pass
