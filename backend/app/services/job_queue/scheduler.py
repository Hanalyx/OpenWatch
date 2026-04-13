"""Recurring job scheduler -- reads cron config, inserts due jobs.

Polls the recurring_jobs table at a configurable interval and enqueues
jobs whose cron expression matches the current time. Deduplication
prevents double-scheduling within a 60-second window.

Spec: specs/system/job-queue.spec.yaml (AC-6)
"""

import logging
import signal
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import text

from app.database import SessionLocal

from .service import JobQueueService

logger = logging.getLogger(__name__)


def _matches_cron_field(field_value: str, current: int) -> bool:
    """Check if a single cron field matches the current value.

    Supports: wildcard (*), lists (1,5,10), ranges (1-5), steps (*/5).

    Args:
        field_value: Cron field string (e.g. '*', '*/5', '1,15', '0-6').
        current: Current time component value to match against.

    Returns:
        True if the field matches the current value.
    """
    if field_value == "*":
        return True
    for part in field_value.split(","):
        part = part.strip()
        if "/" in part:
            base, step = part.split("/")
            step_int = int(step)
            if base == "*":
                if current % step_int == 0:
                    return True
            continue
        if "-" in part:
            lo, hi = part.split("-")
            if int(lo) <= current <= int(hi):
                return True
            continue
        if int(part) == current:
            return True
    return False


def _is_due(row: Any, now: datetime) -> bool:
    """Check if a recurring job is due based on its cron fields.

    Args:
        row: Database row with cron_minute, cron_hour, cron_day,
             cron_month, cron_weekday columns.
        now: Current UTC datetime.

    Returns:
        True if all five cron fields match the current time.
    """
    return (
        _matches_cron_field(row.cron_minute, now.minute)
        and _matches_cron_field(row.cron_hour, now.hour)
        and _matches_cron_field(row.cron_day, now.day)
        and _matches_cron_field(row.cron_month, now.month)
        and _matches_cron_field(row.cron_weekday, now.weekday())
    )


class Scheduler:
    """Polls recurring_jobs and inserts due jobs into job_queue.

    Attributes:
        check_interval: Seconds between each poll of recurring_jobs.
    """

    def __init__(self, check_interval: float = 10.0):
        self.check_interval = check_interval
        self._running = True

    def run(self) -> None:
        """Main scheduler loop. Runs in a daemon thread — shutdown via _running flag."""
        try:
            signal.signal(
                signal.SIGTERM,
                lambda s, f: setattr(self, "_running", False),
            )
        except ValueError:
            pass  # Not main thread — shutdown handled by daemon thread exit

        logger.info("Scheduler starting (check every %.0fs)", self.check_interval)

        while self._running:
            try:
                self._tick()
            except Exception as exc:
                logger.exception("Scheduler tick failed: %s", exc)
            time.sleep(self.check_interval)

    def _tick(self) -> None:
        """Check for due recurring jobs and enqueue them."""
        db = SessionLocal()
        try:
            now = datetime.now(timezone.utc)
            rows = db.execute(text("SELECT * FROM recurring_jobs WHERE enabled = true")).fetchall()

            service = JobQueueService(db)

            for row in rows:
                # Skip if not due yet (next_run_at in the future)
                if row.next_run_at and row.next_run_at > now:
                    continue

                if not _is_due(row, now):
                    continue

                # Dedup: skip if already enqueued within last 60 seconds
                if row.last_run_at and (now - row.last_run_at).total_seconds() < 60:
                    continue

                # Enqueue the job
                args = row.args if isinstance(row.args, dict) else {}
                service.enqueue(
                    task_name=row.task_name,
                    args=args,
                    queue=row.queue or "default",
                )

                # Update last_run_at and compute next_run_at
                db.execute(
                    text("UPDATE recurring_jobs SET last_run_at = :now, " "next_run_at = :next WHERE id = :id"),
                    {
                        "now": now,
                        "next": now + timedelta(seconds=self.check_interval),
                        "id": row.id,
                    },
                )
                db.commit()

                logger.info(
                    "Scheduled recurring job: %s (%s)",
                    row.name,
                    row.task_name,
                )

        finally:
            db.close()
