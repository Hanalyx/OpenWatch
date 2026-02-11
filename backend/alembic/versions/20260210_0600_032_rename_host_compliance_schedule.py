"""Rename host_compliance_schedule to host_schedule and remove compliance cache fields

Revision ID: 032_rename_host_schedule
Revises: 031_scan_templates
Create Date: 2026-02-10

This migration:
1. Renames host_compliance_schedule to host_schedule (cleaner name)
2. Removes compliance cache fields (score, state, pass/fail counts)
3. Compliance data now comes from scans + scan_findings tables (single source of truth)

The host_schedule table now only manages scheduling state:
- When to scan (next_scheduled_scan, current_interval_minutes)
- Scan tracking (last_scan_completed, last_scan_id, consecutive_scan_failures)
- Maintenance mode (maintenance_mode, maintenance_until)
- Priority (scan_priority)
"""

import sqlalchemy as sa

from alembic import op

# Revision identifiers
revision = "032_rename_host_schedule"
down_revision = "033_alerts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Rename table and remove compliance cache columns."""
    conn = op.get_bind()

    # Check if old table exists
    result = conn.execute(
        sa.text(
            "SELECT EXISTS (SELECT FROM information_schema.tables " "WHERE table_name = 'host_compliance_schedule')"
        )
    )
    if not result.scalar():
        # Table doesn't exist, nothing to migrate
        return

    # 1. Drop indexes that reference columns we're removing
    op.drop_index("ix_compliance_schedule_state", table_name="host_compliance_schedule")

    # 2. Drop the compliance cache columns
    op.drop_column("host_compliance_schedule", "compliance_score")
    op.drop_column("host_compliance_schedule", "compliance_state")
    op.drop_column("host_compliance_schedule", "has_critical_findings")
    op.drop_column("host_compliance_schedule", "pass_count")
    op.drop_column("host_compliance_schedule", "fail_count")

    # 3. Rename the table
    op.rename_table("host_compliance_schedule", "host_schedule")

    # 4. Rename remaining indexes to match new table name
    op.execute(
        sa.text("ALTER INDEX IF EXISTS ix_compliance_schedule_next_scan " "RENAME TO ix_host_schedule_next_scan")
    )
    op.execute(sa.text("ALTER INDEX IF EXISTS ix_compliance_schedule_priority " "RENAME TO ix_host_schedule_priority"))


def downgrade() -> None:
    """Restore original table name and compliance cache columns."""
    # 1. Rename table back
    op.rename_table("host_schedule", "host_compliance_schedule")

    # 2. Rename indexes back
    op.execute(
        sa.text("ALTER INDEX IF EXISTS ix_host_schedule_next_scan " "RENAME TO ix_compliance_schedule_next_scan")
    )
    op.execute(sa.text("ALTER INDEX IF EXISTS ix_host_schedule_priority " "RENAME TO ix_compliance_schedule_priority"))

    # 3. Add back compliance cache columns
    op.add_column(
        "host_compliance_schedule",
        sa.Column("compliance_score", sa.Float, nullable=True),
    )
    op.add_column(
        "host_compliance_schedule",
        sa.Column(
            "compliance_state",
            sa.String(20),
            nullable=False,
            server_default="unknown",
        ),
    )
    op.add_column(
        "host_compliance_schedule",
        sa.Column(
            "has_critical_findings",
            sa.Boolean,
            nullable=False,
            server_default="false",
        ),
    )
    op.add_column(
        "host_compliance_schedule",
        sa.Column("pass_count", sa.Integer, nullable=True),
    )
    op.add_column(
        "host_compliance_schedule",
        sa.Column("fail_count", sa.Integer, nullable=True),
    )

    # 4. Recreate index for compliance_state
    op.create_index(
        "ix_compliance_schedule_state",
        "host_compliance_schedule",
        ["compliance_state"],
    )
