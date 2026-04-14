"""Seed recurring_jobs table with the 9 baseline schedules.

Revision ID: 054_seed_recurring_jobs
Revises: 053_add_alert_routing_rules
Create Date: 2026-04-14

Background:
    The PostgreSQL job queue's recurring_jobs table drives both the Adaptive
    Host Monitoring Scheduler and the Adaptive Compliance Scanning Scheduler.
    Without seed rows the scheduler polls forever and enqueues nothing --
    silent breakage with no error logs.

    The seed script app.services.job_queue.seed_schedule exists but is never
    invoked by the worker entrypoint, docker-compose, or any startup hook.
    This migration ensures a fresh deploy has the schedules from the moment
    the DB is ready, independent of operator runbooks.

Idempotency:
    Uses ON CONFLICT (name) DO NOTHING so re-running this migration after a
    manual `python -m app.services.job_queue.seed_schedule` is safe. If
    future schedules are added to seed_schedule.SCHEDULE, add them via a
    subsequent migration, not by editing this one.

Schedules seeded (keep in sync with app/services/job_queue/seed_schedule.py):
    1. ping-all-managed-hosts-every-5-minutes     (*/5 * * * *)
    2. dispatch-host-checks-every-30-seconds      (* * * * *)
    3. discover-all-hosts-os-daily                (0 2 * * *)
    4. detect-stale-scans-every-10-minutes        (*/10 * * * *)
    5. dispatch-compliance-scans-every-2-minutes  (*/2 * * * *)
    6. expire-compliance-maintenance-hourly       (0 * * * *)
    7. create-daily-posture-snapshots             (30 0 * * *)
    8. cleanup-old-posture-snapshots              (0 3 * * *)
    9. enforce-retention-policies-daily           (0 4 * * *)
"""

import sqlalchemy as sa

from alembic import op

revision = "054_seed_recurring_jobs"
down_revision = "053_add_alert_routing_rules"
branch_labels = None
depends_on = None


SCHEDULES = [
    {
        "name": "ping-all-managed-hosts-every-5-minutes",
        "task_name": "app.tasks.ping_all_managed_hosts",
        "queue": "default",
        "cron_minute": "*/5",
        "cron_hour": "*",
    },
    {
        # Celery 30s interval. Cron min granularity is 1 min; the scheduler's
        # 10s check_interval + dedup window handle sub-minute cadence.
        "name": "dispatch-host-checks-every-30-seconds",
        "task_name": "app.tasks.dispatch_host_checks",
        "queue": "host_monitoring",
        "cron_minute": "*",
        "cron_hour": "*",
    },
    {
        "name": "discover-all-hosts-os-daily",
        "task_name": "app.tasks.discover_all_hosts_os",
        "queue": "default",
        "cron_minute": "0",
        "cron_hour": "2",
    },
    {
        "name": "detect-stale-scans-every-10-minutes",
        "task_name": "app.tasks.detect_stale_scans",
        "queue": "maintenance",
        "cron_minute": "*/10",
        "cron_hour": "*",
    },
    {
        "name": "dispatch-compliance-scans-every-2-minutes",
        "task_name": "app.tasks.dispatch_compliance_scans",
        "queue": "compliance_scanning",
        "cron_minute": "*/2",
        "cron_hour": "*",
    },
    {
        "name": "expire-compliance-maintenance-hourly",
        "task_name": "app.tasks.expire_compliance_maintenance",
        "queue": "compliance_scanning",
        "cron_minute": "0",
        "cron_hour": "*",
    },
    {
        "name": "create-daily-posture-snapshots",
        "task_name": "create_daily_posture_snapshots",
        "queue": "default",
        "cron_minute": "30",
        "cron_hour": "0",
    },
    {
        "name": "cleanup-old-posture-snapshots",
        "task_name": "cleanup_old_posture_snapshots",
        "queue": "maintenance",
        "cron_minute": "0",
        "cron_hour": "3",
    },
    {
        "name": "enforce-retention-policies-daily",
        "task_name": "app.tasks.enforce_retention",
        "queue": "maintenance",
        "cron_minute": "0",
        "cron_hour": "4",
    },
]


def upgrade() -> None:
    """Insert the 9 baseline recurring job rows, idempotently."""
    stmt = sa.text(
        """
        INSERT INTO recurring_jobs
            (name, task_name, queue, cron_minute, cron_hour,
             cron_day, cron_month, cron_weekday, enabled)
        VALUES
            (:name, :task_name, :queue, :cron_minute, :cron_hour,
             '*', '*', '*', true)
        ON CONFLICT (name) DO NOTHING
        """
    )
    bind = op.get_bind()
    for row in SCHEDULES:
        bind.execute(stmt, row)


def downgrade() -> None:
    """Remove only the rows this migration inserted.

    Matches by name so operator-added schedules are not touched.
    """
    stmt = sa.text("DELETE FROM recurring_jobs WHERE name = :name")
    bind = op.get_bind()
    for row in SCHEDULES:
        bind.execute(stmt, {"name": row["name"]})
