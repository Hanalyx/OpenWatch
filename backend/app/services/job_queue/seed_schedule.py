"""Seed the recurring_jobs table from the former Celery Beat schedule.

Translates the 8 active beat_schedule entries from celery_app.py into
recurring_jobs rows. Uses ON CONFLICT DO NOTHING so the script is
idempotent and safe to re-run.

Usage:
    python -m app.services.job_queue.seed_schedule
"""

import logging

from sqlalchemy import text

from app.database import SessionLocal
from app.utils.mutation_builders import InsertBuilder

logger = logging.getLogger(__name__)

# Translations from celery_app.py beat_schedule (lines 136-231).
#
# Celery schedule(300.0)           -> cron_minute="*/5"
# Celery schedule(30.0)            -> cron_minute="*"  (scheduler checks every 10s)
# Celery crontab(hour=2, minute=0) -> cron_minute="0", cron_hour="2"
# Celery schedule(600.0)           -> cron_minute="*/10"
# Celery schedule(120.0)           -> cron_minute="*/2"
# Celery crontab(minute=0)         -> cron_minute="0"
# Celery crontab(hour=0, minute=30)-> cron_minute="30", cron_hour="0"
# Celery crontab(hour=3, minute=0) -> cron_minute="0", cron_hour="3"

SCHEDULE = [
    {
        "name": "ping-all-managed-hosts-every-5-minutes",
        "task_name": "app.tasks.ping_all_managed_hosts",
        "queue": "default",
        "cron_minute": "*/5",
        "cron_hour": "*",
        "cron_day": "*",
        "cron_month": "*",
        "cron_weekday": "*",
    },
    {
        # 30-second interval in Celery. Cron minimum is 1 minute so we use
        # cron_minute="*" (every minute). The scheduler's 10s check_interval
        # provides sub-minute granularity via the dedup window.
        "name": "dispatch-host-checks-every-30-seconds",
        "task_name": "app.tasks.dispatch_host_checks",
        "queue": "host_monitoring",
        "cron_minute": "*",
        "cron_hour": "*",
        "cron_day": "*",
        "cron_month": "*",
        "cron_weekday": "*",
    },
    {
        "name": "discover-all-hosts-os-daily",
        "task_name": "app.tasks.discover_all_hosts_os",
        "queue": "default",
        "cron_minute": "0",
        "cron_hour": "2",
        "cron_day": "*",
        "cron_month": "*",
        "cron_weekday": "*",
    },
    {
        "name": "detect-stale-scans-every-10-minutes",
        "task_name": "app.tasks.detect_stale_scans",
        "queue": "maintenance",
        "cron_minute": "*/10",
        "cron_hour": "*",
        "cron_day": "*",
        "cron_month": "*",
        "cron_weekday": "*",
    },
    {
        "name": "dispatch-compliance-scans-every-2-minutes",
        "task_name": "app.tasks.dispatch_compliance_scans",
        "queue": "compliance_scanning",
        "cron_minute": "*/2",
        "cron_hour": "*",
        "cron_day": "*",
        "cron_month": "*",
        "cron_weekday": "*",
    },
    {
        "name": "expire-compliance-maintenance-hourly",
        "task_name": "app.tasks.expire_compliance_maintenance",
        "queue": "compliance_scanning",
        "cron_minute": "0",
        "cron_hour": "*",
        "cron_day": "*",
        "cron_month": "*",
        "cron_weekday": "*",
    },
    {
        "name": "create-daily-posture-snapshots",
        "task_name": "create_daily_posture_snapshots",
        "queue": "default",
        "cron_minute": "30",
        "cron_hour": "0",
        "cron_day": "*",
        "cron_month": "*",
        "cron_weekday": "*",
    },
    {
        "name": "cleanup-old-posture-snapshots",
        "task_name": "cleanup_old_posture_snapshots",
        "queue": "maintenance",
        "cron_minute": "0",
        "cron_hour": "3",
        "cron_day": "*",
        "cron_month": "*",
        "cron_weekday": "*",
    },
    {
        "name": "enforce-retention-policies-daily",
        "task_name": "app.tasks.enforce_retention",
        "queue": "maintenance",
        "cron_minute": "0",
        "cron_hour": "4",
        "cron_day": "*",
        "cron_month": "*",
        "cron_weekday": "*",
    },
]


def seed() -> int:
    """Insert recurring_jobs rows for all Beat schedule entries.

    Returns:
        Number of entries inserted (0 if all already existed).
    """
    db = SessionLocal()
    inserted = 0
    try:
        for entry in SCHEDULE:
            builder = (
                InsertBuilder("recurring_jobs")
                .columns(
                    "name",
                    "task_name",
                    "queue",
                    "cron_minute",
                    "cron_hour",
                    "cron_day",
                    "cron_month",
                    "cron_weekday",
                    "enabled",
                )
                .values(
                    entry["name"],
                    entry["task_name"],
                    entry["queue"],
                    entry["cron_minute"],
                    entry["cron_hour"],
                    entry["cron_day"],
                    entry["cron_month"],
                    entry["cron_weekday"],
                    True,
                )
                .on_conflict_do_nothing("name")
                .returning("id")
            )
            q, p = builder.build()
            row = db.execute(text(q), p).fetchone()
            if row:
                inserted += 1

        db.commit()
        logger.info(
            "Seeded %d recurring_jobs (%d already existed)",
            inserted,
            len(SCHEDULE) - inserted,
        )
        return inserted
    finally:
        db.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    count = seed()
    print(f"Seeded {count} recurring jobs")
