"""
Plugin Update Celery Tasks for Phase 5

Scheduled tasks for checking plugin updates and notifications.

Part of Phase 5: Control Plane (Kensa Integration Plan)
"""

import asyncio
import logging
from typing import Any, Dict

from celery import shared_task
from sqlalchemy import text

from app.database import SessionLocal
from app.plugins.kensa.config import get_kensa_config
from app.plugins.kensa.updater import KensaUpdater

logger = logging.getLogger(__name__)


@shared_task(name="app.tasks.check_kensa_updates")
def check_kensa_updates() -> Dict[str, Any]:
    """
    Check for Kensa updates (scheduled daily).

    This task:
    1. Queries the update registry for new versions
    2. Stores update notifications if available
    3. Optionally notifies administrators

    Returns:
        Update check result summary
    """
    logger.info("Starting scheduled Kensa update check")

    async def _check():
        db = SessionLocal()
        try:
            config = get_kensa_config()

            # Skip if offline mode
            if config.offline_mode:
                logger.info("Kensa update check skipped (offline mode)")
                return {
                    "status": "skipped",
                    "reason": "offline_mode",
                }

            updater = KensaUpdater(db, config)
            result = await updater.check_for_updates()

            if result.error:
                logger.warning(f"Update check returned error: {result.error}")
                return {
                    "status": "error",
                    "error": result.error,
                    "current_version": result.current_version,
                }

            if result.update_available:
                logger.info(f"Kensa update available: {result.current_version} -> " f"{result.latest_version}")

                # Send admin notification
                await _notify_admins_of_update(db, result)

                return {
                    "status": "update_available",
                    "current_version": result.current_version,
                    "latest_version": result.latest_version,
                    "changes_count": len(result.changes),
                }

            logger.info(f"Kensa is up to date (v{result.current_version})")
            return {
                "status": "up_to_date",
                "current_version": result.current_version,
            }

        finally:
            db.close()

    return asyncio.run(_check())


@shared_task(name="app.tasks.cleanup_old_update_records")
def cleanup_old_update_records(retention_days: int = 90) -> Dict[str, Any]:
    """
    Cleanup old update records (scheduled weekly).

    Args:
        retention_days: Days to retain update history

    Returns:
        Cleanup summary
    """
    logger.info(f"Cleaning up update records older than {retention_days} days")

    db = SessionLocal()
    try:
        # Delete old update records
        query = """
            DELETE FROM plugin_updates
            WHERE created_at < CURRENT_TIMESTAMP - INTERVAL ':days days'
            AND status IN ('completed', 'failed', 'rolled_back')
        """
        result = db.execute(text(query), {"days": retention_days})
        updates_deleted = result.rowcount

        # Delete dismissed notifications older than retention period
        notif_query = """
            DELETE FROM plugin_update_notifications
            WHERE dismissed = true
            AND dismissed_at < CURRENT_TIMESTAMP - INTERVAL ':days days'
        """
        notif_result = db.execute(text(notif_query), {"days": retention_days})
        notifications_deleted = notif_result.rowcount

        db.commit()

        logger.info(f"Cleaned up {updates_deleted} update records and " f"{notifications_deleted} notifications")

        return {
            "status": "completed",
            "updates_deleted": updates_deleted,
            "notifications_deleted": notifications_deleted,
        }

    except Exception as e:
        logger.exception(f"Cleanup failed: {e}")
        db.rollback()
        return {
            "status": "failed",
            "error": str(e),
        }

    finally:
        db.close()


@shared_task(name="app.tasks.perform_auto_update")
def perform_auto_update() -> Dict[str, Any]:
    """
    Perform automatic Kensa update if enabled.

    This task:
    1. Checks if auto-update is enabled
    2. Verifies an update is available
    3. Performs the update if conditions are met

    Returns:
        Auto-update result
    """
    logger.info("Checking for auto-update eligibility")

    async def _auto_update():
        db = SessionLocal()
        try:
            config = get_kensa_config()

            # Check if auto-update is enabled
            if not config.auto_update:
                return {
                    "status": "skipped",
                    "reason": "auto_update_disabled",
                }

            updater = KensaUpdater(db, config)

            # Check for updates
            check_result = await updater.check_for_updates()

            if not check_result.update_available:
                return {
                    "status": "skipped",
                    "reason": "no_update_available",
                    "current_version": check_result.current_version,
                }

            if not check_result.openwatch_compatible:
                return {
                    "status": "skipped",
                    "reason": "openwatch_version_incompatible",
                    "message": check_result.compatibility_message,
                }

            # Check for breaking changes
            if check_result.versions and check_result.versions[0].breaking_changes:
                logger.warning("Auto-update skipped due to breaking changes. " "Manual update required.")
                return {
                    "status": "skipped",
                    "reason": "breaking_changes",
                    "breaking_changes": check_result.versions[0].breaking_changes,
                }

            # Get system user ID for audit (user_id=1 is typically system/admin)
            system_user_id = 1

            # Perform update
            logger.info(f"Auto-updating Kensa from {check_result.current_version} " f"to {check_result.latest_version}")

            result = await updater.perform_update(
                version=check_result.latest_version,
                user_id=system_user_id,
                skip_backup=False,
            )

            if result.success:
                # Notify admins of successful auto-update
                await _notify_admins_of_auto_update(
                    db,
                    result.from_version,
                    result.to_version,
                )

                return {
                    "status": "completed",
                    "from_version": result.from_version,
                    "to_version": result.to_version,
                    "update_id": str(result.update_id),
                }
            else:
                return {
                    "status": "failed",
                    "error": result.error,
                    "from_version": result.from_version,
                    "to_version": result.to_version,
                }

        finally:
            db.close()

    return asyncio.run(_auto_update())


async def _notify_admins_of_update(db, update_result) -> None:
    """Send notification to admins about available update."""
    # Get admin users
    query = """
        SELECT id, email, username FROM users
        WHERE role IN ('admin', 'super_admin')
        AND is_active = true
    """
    result = db.execute(text(query))
    admins = result.fetchall()

    if not admins:
        logger.warning("No active admins found to notify about update")
        return

    # Log notification (actual email sending would use NotificationService)
    for admin in admins:
        logger.info(
            f"Notifying admin {admin.username} about Kensa update "
            f"({update_result.current_version} -> {update_result.latest_version})"
        )

    # In a real implementation, you would use NotificationService here:
    # from app.services.notification import NotificationService
    # notification_service = NotificationService()
    # await notification_service.notify_admins(
    #     title="Kensa Update Available",
    #     message=f"Kensa v{update_result.latest_version} is available...",
    #     link="/settings/plugins/kensa",
    # )


async def _notify_admins_of_auto_update(db, from_version: str, to_version: str) -> None:
    """Notify admins of completed auto-update."""
    query = """
        SELECT id, email, username FROM users
        WHERE role IN ('admin', 'super_admin')
        AND is_active = true
    """
    result = db.execute(text(query))
    admins = result.fetchall()

    for admin in admins:
        logger.info(
            f"Notifying admin {admin.username} about completed auto-update " f"({from_version} -> {to_version})"
        )

    # In production, send actual notifications via email/in-app


# Note: Beat schedule is configured in celery_config.py
# Example schedule:
#
# celery_app.conf.beat_schedule = {
#     "check-kensa-updates-daily": {
#         "task": "app.tasks.check_kensa_updates",
#         "schedule": 86400.0,  # 24 hours
#     },
#     "cleanup-old-update-records-weekly": {
#         "task": "app.tasks.cleanup_old_update_records",
#         "schedule": 604800.0,  # 7 days
#         "args": (90,),  # 90 days retention
#     },
#     "check-auto-update-daily": {
#         "task": "app.tasks.perform_auto_update",
#         "schedule": 86400.0,  # 24 hours
#     },
# }
