"""Add compliance scheduler tables for adaptive compliance scanning

Revision ID: 026_compliance_scheduler
Revises: 025_host_monitoring_history
Create Date: 2026-02-09

Creates tables for the Adaptive Compliance Scheduler:
- host_compliance_schedule: Per-host scheduling state and next scan time
- compliance_scheduler_config: Global scheduler configuration (intervals, priorities)

This enables automatic compliance scanning with state-based intervals (max 48 hours).
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# Revision identifiers
revision = "026_compliance_scheduler"
down_revision = "025_host_monitoring_history"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create compliance scheduler tables."""
    conn = op.get_bind()

    # 1. Create host_compliance_schedule table
    result = conn.execute(
        sa.text(
            "SELECT EXISTS (SELECT FROM information_schema.tables " "WHERE table_name = 'host_compliance_schedule')"
        )
    )
    if not result.scalar():
        op.create_table(
            "host_compliance_schedule",
            sa.Column(
                "id",
                postgresql.UUID(as_uuid=True),
                primary_key=True,
                server_default=sa.text("gen_random_uuid()"),
            ),
            sa.Column(
                "host_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("hosts.id", ondelete="CASCADE"),
                nullable=False,
                unique=True,
            ),
            # Current compliance state
            sa.Column(
                "compliance_score",
                sa.Float,
                nullable=True,
            ),
            sa.Column(
                "compliance_state",
                sa.String(20),
                nullable=False,
                server_default="unknown",
            ),
            sa.Column(
                "has_critical_findings",
                sa.Boolean,
                nullable=False,
                server_default="false",
            ),
            sa.Column(
                "pass_count",
                sa.Integer,
                nullable=True,
            ),
            sa.Column(
                "fail_count",
                sa.Integer,
                nullable=True,
            ),
            # Scheduling
            sa.Column(
                "current_interval_minutes",
                sa.Integer,
                nullable=False,
                server_default="1440",  # 24 hours default
            ),
            sa.Column(
                "next_scheduled_scan",
                sa.DateTime(timezone=True),
                nullable=True,
            ),
            sa.Column(
                "last_scan_completed",
                sa.DateTime(timezone=True),
                nullable=True,
            ),
            sa.Column(
                "last_scan_id",
                postgresql.UUID(as_uuid=True),
                nullable=True,
            ),
            # Maintenance mode
            sa.Column(
                "maintenance_mode",
                sa.Boolean,
                nullable=False,
                server_default="false",
            ),
            sa.Column(
                "maintenance_until",
                sa.DateTime(timezone=True),
                nullable=True,
            ),
            # Scan priority (1-10, higher = more urgent)
            sa.Column(
                "scan_priority",
                sa.Integer,
                nullable=False,
                server_default="5",
            ),
            # Failure tracking
            sa.Column(
                "consecutive_scan_failures",
                sa.Integer,
                nullable=False,
                server_default="0",
            ),
            # Audit timestamps
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
        )

        # Index for finding hosts due for scanning
        op.create_index(
            "ix_compliance_schedule_next_scan",
            "host_compliance_schedule",
            ["next_scheduled_scan"],
            postgresql_where=sa.text("maintenance_mode = false"),
        )

        # Index for querying by compliance state
        op.create_index(
            "ix_compliance_schedule_state",
            "host_compliance_schedule",
            ["compliance_state"],
        )

        # Index for priority-based scanning
        op.create_index(
            "ix_compliance_schedule_priority",
            "host_compliance_schedule",
            ["scan_priority"],
        )

    # 2. Create compliance_scheduler_config table (singleton config)
    result = conn.execute(
        sa.text(
            "SELECT EXISTS (SELECT FROM information_schema.tables " "WHERE table_name = 'compliance_scheduler_config')"
        )
    )
    if not result.scalar():
        op.create_table(
            "compliance_scheduler_config",
            sa.Column(
                "id",
                sa.Integer,
                primary_key=True,
            ),
            sa.Column(
                "enabled",
                sa.Boolean,
                nullable=False,
                server_default="true",
            ),
            # Intervals in minutes for each compliance state
            sa.Column(
                "interval_compliant",
                sa.Integer,
                nullable=False,
                server_default="1440",  # 24 hours
            ),
            sa.Column(
                "interval_mostly_compliant",
                sa.Integer,
                nullable=False,
                server_default="720",  # 12 hours
            ),
            sa.Column(
                "interval_partial",
                sa.Integer,
                nullable=False,
                server_default="360",  # 6 hours
            ),
            sa.Column(
                "interval_low",
                sa.Integer,
                nullable=False,
                server_default="120",  # 2 hours
            ),
            sa.Column(
                "interval_critical",
                sa.Integer,
                nullable=False,
                server_default="60",  # 1 hour
            ),
            sa.Column(
                "interval_unknown",
                sa.Integer,
                nullable=False,
                server_default="0",  # Immediate
            ),
            sa.Column(
                "interval_maintenance",
                sa.Integer,
                nullable=False,
                server_default="2880",  # 48 hours (max)
            ),
            # Maximum interval (enforced ceiling)
            sa.Column(
                "max_interval_minutes",
                sa.Integer,
                nullable=False,
                server_default="2880",  # 48 hours
            ),
            # Priority levels (1-10, higher = more urgent)
            sa.Column(
                "priority_compliant",
                sa.Integer,
                nullable=False,
                server_default="3",
            ),
            sa.Column(
                "priority_mostly_compliant",
                sa.Integer,
                nullable=False,
                server_default="4",
            ),
            sa.Column(
                "priority_partial",
                sa.Integer,
                nullable=False,
                server_default="6",
            ),
            sa.Column(
                "priority_low",
                sa.Integer,
                nullable=False,
                server_default="7",
            ),
            sa.Column(
                "priority_critical",
                sa.Integer,
                nullable=False,
                server_default="9",
            ),
            sa.Column(
                "priority_unknown",
                sa.Integer,
                nullable=False,
                server_default="10",
            ),
            sa.Column(
                "priority_maintenance",
                sa.Integer,
                nullable=False,
                server_default="1",
            ),
            # Concurrency and timeout settings
            sa.Column(
                "max_concurrent_scans",
                sa.Integer,
                nullable=False,
                server_default="5",
            ),
            sa.Column(
                "scan_timeout_seconds",
                sa.Integer,
                nullable=False,
                server_default="600",  # 10 minutes
            ),
            # Audit
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
        )

        # Insert default configuration (id=1)
        conn.execute(
            sa.text(
                """
                INSERT INTO compliance_scheduler_config (id)
                VALUES (1)
                ON CONFLICT (id) DO NOTHING
                """
            )
        )


def downgrade() -> None:
    """Drop compliance scheduler tables."""
    # Drop indexes first
    op.drop_index("ix_compliance_schedule_priority", table_name="host_compliance_schedule")
    op.drop_index("ix_compliance_schedule_state", table_name="host_compliance_schedule")
    op.drop_index("ix_compliance_schedule_next_scan", table_name="host_compliance_schedule")

    # Drop tables
    op.drop_table("compliance_scheduler_config")
    op.drop_table("host_compliance_schedule")
