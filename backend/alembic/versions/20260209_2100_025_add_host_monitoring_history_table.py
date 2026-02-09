"""Add host_monitoring_history table for monitoring check history

Revision ID: 025_host_monitoring_history
Revises: 024_audit_queries
Create Date: 2026-02-09

Creates the host_monitoring_history table to store historical monitoring check
results for each host. This enables analysis of host availability over time.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# Revision identifiers
revision = "025_host_monitoring_history"
down_revision = "024_audit_query_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create host_monitoring_history table."""
    # Check if table already exists (idempotent migration)
    conn = op.get_bind()
    result = conn.execute(
        sa.text("SELECT EXISTS (SELECT FROM information_schema.tables " "WHERE table_name = 'host_monitoring_history')")
    )
    if result.scalar():
        return

    op.create_table(
        "host_monitoring_history",
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
            index=True,
        ),
        sa.Column(
            "check_time",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "monitoring_state",
            sa.String(20),
            nullable=False,
        ),
        sa.Column(
            "previous_state",
            sa.String(20),
            nullable=True,
        ),
        sa.Column(
            "response_time_ms",
            sa.Integer,
            nullable=True,
        ),
        sa.Column(
            "success",
            sa.Boolean,
            nullable=False,
            server_default="false",
        ),
        sa.Column(
            "error_message",
            sa.Text,
            nullable=True,
        ),
        sa.Column(
            "error_type",
            sa.String(50),
            nullable=True,
        ),
    )

    # Create composite index for efficient querying by host and time
    op.create_index(
        "ix_host_monitoring_history_host_time",
        "host_monitoring_history",
        ["host_id", "check_time"],
    )

    # Create index for time-based queries (e.g., checks today)
    op.create_index(
        "ix_host_monitoring_history_check_time",
        "host_monitoring_history",
        ["check_time"],
    )


def downgrade() -> None:
    """Drop host_monitoring_history table."""
    op.drop_index("ix_host_monitoring_history_check_time")
    op.drop_index("ix_host_monitoring_history_host_time")
    op.drop_table("host_monitoring_history")
