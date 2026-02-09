"""Add host_monitoring_config table for adaptive scheduler

Revision ID: 021_host_monitoring_config
Revises: 020_compliance_exceptions
Create Date: 2026-02-09

Creates the host_monitoring_config table for the adaptive host monitoring
scheduler. This table stores configuration for state-based check intervals.
"""

import sqlalchemy as sa

from alembic import op

# Revision identifiers
revision = "021_host_monitoring_config"
down_revision = "020_compliance_exceptions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create host_monitoring_config table with default row."""
    # Check if table already exists (idempotent migration)
    conn = op.get_bind()
    result = conn.execute(
        sa.text("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'host_monitoring_config')")
    )
    if result.scalar():
        return

    op.create_table(
        "host_monitoring_config",
        sa.Column("id", sa.Integer, primary_key=True),
        # Enable/disable scheduler
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="true"),
        # Intervals in minutes for each host state
        sa.Column("interval_unknown", sa.Integer, nullable=False, server_default="0"),
        sa.Column("interval_online", sa.Integer, nullable=False, server_default="15"),
        sa.Column("interval_degraded", sa.Integer, nullable=False, server_default="5"),
        sa.Column("interval_critical", sa.Integer, nullable=False, server_default="2"),
        sa.Column("interval_down", sa.Integer, nullable=False, server_default="30"),
        sa.Column("interval_maintenance", sa.Integer, nullable=False, server_default="60"),
        # Maintenance mode: skip, passive, or reduced
        sa.Column("maintenance_mode", sa.String(20), nullable=False, server_default="reduced"),
        # Concurrency and timeout settings
        sa.Column("max_concurrent_checks", sa.Integer, nullable=False, server_default="10"),
        sa.Column("check_timeout_seconds", sa.Integer, nullable=False, server_default="30"),
        sa.Column("retry_on_failure", sa.Boolean, nullable=False, server_default="true"),
        # Priority levels (1-10, higher = more urgent)
        sa.Column("priority_unknown", sa.Integer, nullable=False, server_default="10"),
        sa.Column("priority_critical", sa.Integer, nullable=False, server_default="8"),
        sa.Column("priority_degraded", sa.Integer, nullable=False, server_default="6"),
        sa.Column("priority_online", sa.Integer, nullable=False, server_default="4"),
        sa.Column("priority_down", sa.Integer, nullable=False, server_default="2"),
        sa.Column("priority_maintenance", sa.Integer, nullable=False, server_default="1"),
        # Audit
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )

    # Insert default configuration row
    op.execute(
        """
        INSERT INTO host_monitoring_config (id)
        VALUES (1)
        ON CONFLICT (id) DO NOTHING
        """
    )


def downgrade() -> None:
    """Drop host_monitoring_config table."""
    op.drop_table("host_monitoring_config")
