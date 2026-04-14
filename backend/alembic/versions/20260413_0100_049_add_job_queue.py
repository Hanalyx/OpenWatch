"""Add job_queue and recurring_jobs tables for PostgreSQL-native task queue.

Replaces Celery + Redis with SKIP LOCKED-based job dispatch.
See specs/system/job-queue.spec.yaml for full specification.

Revision ID: 049_add_job_queue
Revises: 048_add_host_rule_state
Create Date: 2026-04-13 01:00:00
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "049_add_job_queue"
down_revision = "048_add_host_rule_state"
branch_labels = None
depends_on = None


def upgrade():
    """Create job_queue and recurring_jobs tables."""
    op.create_table(
        "job_queue",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            primary_key=True,
        ),
        sa.Column("task_name", sa.String(255), nullable=False),
        sa.Column(
            "args",
            postgresql.JSONB,
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.String(16),
            nullable=False,
            server_default="pending",
        ),
        sa.Column(
            "priority",
            sa.Integer,
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "queue",
            sa.String(64),
            nullable=False,
            server_default="default",
        ),
        sa.Column(
            "scheduled_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result", postgresql.JSONB, nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column(
            "retry_count",
            sa.Integer,
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "max_retries",
            sa.Integer,
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "timeout_seconds",
            sa.Integer,
            nullable=True,
            server_default="3600",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )

    # Partial index for SKIP LOCKED dequeue performance.
    # Only indexes pending rows, keeping the index small as jobs complete.
    op.execute(
        "CREATE INDEX ix_job_queue_dequeue "
        "ON job_queue (queue, status, priority DESC, scheduled_at ASC) "
        "WHERE status = 'pending'"
    )

    op.create_table(
        "recurring_jobs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            primary_key=True,
        ),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("task_name", sa.String(255), nullable=False),
        sa.Column(
            "args",
            postgresql.JSONB,
            server_default=sa.text("'{}'::jsonb"),
            nullable=True,
        ),
        sa.Column(
            "queue",
            sa.String(64),
            nullable=True,
            server_default="default",
        ),
        sa.Column("cron_minute", sa.String(64), nullable=True, server_default="*"),
        sa.Column("cron_hour", sa.String(64), nullable=True, server_default="*"),
        sa.Column("cron_day", sa.String(64), nullable=True, server_default="*"),
        sa.Column("cron_month", sa.String(64), nullable=True, server_default="*"),
        sa.Column("cron_weekday", sa.String(64), nullable=True, server_default="*"),
        sa.Column("enabled", sa.Boolean, nullable=True, server_default="true"),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=True,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )


def downgrade():
    """Drop job_queue and recurring_jobs tables."""
    op.execute("DROP INDEX IF EXISTS ix_job_queue_dequeue")
    op.drop_table("recurring_jobs")
    op.drop_table("job_queue")
