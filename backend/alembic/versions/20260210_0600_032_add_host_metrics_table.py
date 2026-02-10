"""Add host_metrics table

Revision ID: 032_host_metrics
Revises: 031_host_audit_events
Create Date: 2026-02-10

Creates table for storing time-series resource metrics:
- host_metrics: CPU, memory, disk, load average, uptime

Part of OpenWatch OS Transformation - Server Intelligence (doc 04).
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# Revision identifiers
revision = "032_host_metrics"
down_revision = "031_host_audit_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create host_metrics table."""
    conn = op.get_bind()

    # Create host_metrics table
    result = conn.execute(
        sa.text("SELECT EXISTS (SELECT FROM information_schema.tables " "WHERE table_name = 'host_metrics')")
    )
    if not result.scalar():
        op.create_table(
            "host_metrics",
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
            ),
            # When metrics were collected
            sa.Column(
                "collected_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
            # CPU metrics
            sa.Column("cpu_usage_percent", sa.Float),
            sa.Column("load_avg_1m", sa.Float),
            sa.Column("load_avg_5m", sa.Float),
            sa.Column("load_avg_15m", sa.Float),
            # Memory metrics (in bytes for precision)
            sa.Column("memory_total_bytes", sa.BigInteger),
            sa.Column("memory_used_bytes", sa.BigInteger),
            sa.Column("memory_available_bytes", sa.BigInteger),
            sa.Column("swap_total_bytes", sa.BigInteger),
            sa.Column("swap_used_bytes", sa.BigInteger),
            # Disk metrics (primary mount, in bytes)
            sa.Column("disk_total_bytes", sa.BigInteger),
            sa.Column("disk_used_bytes", sa.BigInteger),
            sa.Column("disk_available_bytes", sa.BigInteger),
            # System metrics
            sa.Column("uptime_seconds", sa.BigInteger),
            sa.Column("process_count", sa.Integer),
        )

        # Create indexes for efficient querying
        op.create_index("idx_host_metrics_host", "host_metrics", ["host_id"])
        op.create_index(
            "idx_host_metrics_time",
            "host_metrics",
            ["collected_at"],
            postgresql_ops={"collected_at": "DESC"},
        )
        # Compound index for common queries (host + time range)
        op.create_index(
            "idx_host_metrics_host_time",
            "host_metrics",
            ["host_id", "collected_at"],
        )


def downgrade() -> None:
    """Drop host_metrics table."""
    op.drop_table("host_metrics")
