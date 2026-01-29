"""
Stale scan detection task.

Periodically checks for scans stuck in 'running' or 'pending' state beyond
their expected duration and marks them as failed. Prevents scans from being
stuck indefinitely when the executing worker crashes or the BackgroundTask
is lost on process restart.

Thresholds:
    - running scans: failed after 2 hours
    - pending scans: failed after 30 minutes
"""

import logging
from datetime import datetime, timedelta

from sqlalchemy import text

from app.celery_app import celery_app
from app.database import get_db_session

logger = logging.getLogger(__name__)

RUNNING_TIMEOUT = timedelta(hours=2)
PENDING_TIMEOUT = timedelta(minutes=30)


@celery_app.task(
    name="backend.app.tasks.detect_stale_scans",
    time_limit=120,
    soft_time_limit=90,
)
def detect_stale_scans() -> dict:
    """
    Detect and recover scans stuck in running/pending state.

    Scans that have been running for more than 2 hours or pending for more
    than 30 minutes are marked as failed with a timeout error message.

    Returns:
        dict with counts of recovered scans by previous status.
    """
    now = datetime.utcnow()
    running_cutoff = now - RUNNING_TIMEOUT
    pending_cutoff = now - PENDING_TIMEOUT

    recovered = {"running": 0, "pending": 0}

    try:
        with get_db_session() as db:
            # Mark stale running scans as failed
            result = db.execute(
                text(
                    """
                    UPDATE scans
                    SET status = 'failed',
                        error_message = 'Scan timed out after 2 hours (detected by stale scan recovery)',
                        completed_at = :now
                    WHERE status = 'running'
                      AND started_at < :cutoff
                      AND completed_at IS NULL
                    RETURNING id, host_id, started_at
                    """
                ),
                {"now": now, "cutoff": running_cutoff},
            )

            stale_running = result.fetchall()
            recovered["running"] = len(stale_running)

            for scan in stale_running:
                logger.warning(
                    f"Recovered stale running scan {scan.id} " f"(host={scan.host_id}, started={scan.started_at})"
                )

            # Mark stale pending scans as failed
            result = db.execute(
                text(
                    """
                    UPDATE scans
                    SET status = 'failed',
                        error_message = 'Scan timed out while pending for over 30 minutes',
                        completed_at = :now
                    WHERE status = 'pending'
                      AND created_at < :cutoff
                      AND completed_at IS NULL
                    RETURNING id, host_id, created_at
                    """
                ),
                {"now": now, "cutoff": pending_cutoff},
            )

            stale_pending = result.fetchall()
            recovered["pending"] = len(stale_pending)

            for scan in stale_pending:
                logger.warning(
                    f"Recovered stale pending scan {scan.id} " f"(host={scan.host_id}, created={scan.created_at})"
                )

            db.commit()

            total = recovered["running"] + recovered["pending"]
            if total > 0:
                logger.info(
                    f"Stale scan detection recovered {total} scans "
                    f"({recovered['running']} running, {recovered['pending']} pending)"
                )
            else:
                logger.debug("Stale scan detection: no stuck scans found")

            return recovered

    except Exception as e:
        logger.error(f"Stale scan detection failed: {e}", exc_info=True)
        return {"error": str(e)}
