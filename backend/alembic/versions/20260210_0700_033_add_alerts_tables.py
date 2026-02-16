"""Add alerts and alert_notifications tables

Revision ID: 033b_alerts_full
Revises: 032_host_metrics
Create Date: 2026-02-10

Creates tables for the alerting system:
- alerts: Alert records with status tracking
- alert_notifications: Notification delivery tracking
- alert_settings: Per-host alert configuration overrides

Part of OpenWatch OS Transformation - Alert Thresholds (doc 03).
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# Revision identifiers
revision = "033b_alerts_full"
down_revision = "032_host_metrics"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create alerts and alert_notifications tables."""
    conn = op.get_bind()

    # Create alerts table
    result = conn.execute(
        sa.text("SELECT EXISTS (SELECT FROM information_schema.tables " "WHERE table_name = 'alerts')")
    )
    if not result.scalar():
        op.create_table(
            "alerts",
            sa.Column(
                "id",
                postgresql.UUID(as_uuid=True),
                primary_key=True,
                server_default=sa.text("gen_random_uuid()"),
            ),
            # Alert details
            sa.Column("alert_type", sa.String(50), nullable=False),
            sa.Column("severity", sa.String(20), nullable=False),
            sa.Column("title", sa.String(255), nullable=False),
            sa.Column("message", sa.Text),
            # Context - all optional depending on alert type
            sa.Column(
                "host_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("hosts.id", ondelete="CASCADE"),
                nullable=True,
            ),
            sa.Column(
                "host_group_id",
                sa.Integer,
                sa.ForeignKey("host_groups.id", ondelete="CASCADE"),
                nullable=True,
            ),
            sa.Column("rule_id", sa.String(255), nullable=True),
            sa.Column(
                "scan_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("scans.id", ondelete="SET NULL"),
                nullable=True,
            ),
            # State
            sa.Column(
                "status",
                sa.String(20),
                server_default="active",
                nullable=False,
            ),
            sa.Column(
                "acknowledged_by",
                sa.Integer,
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
            # Metadata for additional context
            sa.Column("metadata", postgresql.JSONB, nullable=True),
            # Timestamps
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
        )

        # Create indexes for efficient querying
        op.create_index("idx_alerts_status", "alerts", ["status"])
        op.create_index("idx_alerts_severity", "alerts", ["severity"])
        op.create_index("idx_alerts_host", "alerts", ["host_id"])
        op.create_index("idx_alerts_type", "alerts", ["alert_type"])
        op.create_index(
            "idx_alerts_created",
            "alerts",
            ["created_at"],
            postgresql_ops={"created_at": "DESC"},
        )
        # Compound index for common queries
        op.create_index(
            "idx_alerts_status_severity",
            "alerts",
            ["status", "severity"],
        )
        # Index for deduplication queries
        op.create_index(
            "idx_alerts_dedup",
            "alerts",
            ["alert_type", "host_id", "rule_id", "created_at"],
        )

    # Create alert_notifications table
    result = conn.execute(
        sa.text("SELECT EXISTS (SELECT FROM information_schema.tables " "WHERE table_name = 'alert_notifications')")
    )
    if not result.scalar():
        op.create_table(
            "alert_notifications",
            sa.Column(
                "id",
                postgresql.UUID(as_uuid=True),
                primary_key=True,
                server_default=sa.text("gen_random_uuid()"),
            ),
            sa.Column(
                "alert_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("alerts.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("channel", sa.String(50), nullable=False),
            sa.Column("recipient", sa.String(255), nullable=True),
            sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "status",
                sa.String(20),
                server_default="pending",
                nullable=False,
            ),
            sa.Column("error_message", sa.Text, nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
        )

        # Create indexes
        op.create_index("idx_alert_notif_alert", "alert_notifications", ["alert_id"])
        op.create_index("idx_alert_notif_status", "alert_notifications", ["status"])

    # Create alert_settings table for per-host overrides
    result = conn.execute(
        sa.text("SELECT EXISTS (SELECT FROM information_schema.tables " "WHERE table_name = 'alert_settings')")
    )
    if not result.scalar():
        op.create_table(
            "alert_settings",
            sa.Column(
                "id",
                postgresql.UUID(as_uuid=True),
                primary_key=True,
                server_default=sa.text("gen_random_uuid()"),
            ),
            # Can be host-specific, host-group-specific, or global (both null)
            sa.Column(
                "host_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("hosts.id", ondelete="CASCADE"),
                nullable=True,
            ),
            sa.Column(
                "host_group_id",
                sa.Integer,
                sa.ForeignKey("host_groups.id", ondelete="CASCADE"),
                nullable=True,
            ),
            # Alert thresholds as JSONB for flexibility
            sa.Column(
                "settings",
                postgresql.JSONB,
                server_default=sa.text("'{}'::jsonb"),
                nullable=False,
            ),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
        )

        # Unique constraint - only one setting per host/group combination
        op.create_index(
            "idx_alert_settings_host",
            "alert_settings",
            ["host_id"],
            unique=True,
            postgresql_where=sa.text("host_id IS NOT NULL"),
        )
        op.create_index(
            "idx_alert_settings_group",
            "alert_settings",
            ["host_group_id"],
            unique=True,
            postgresql_where=sa.text("host_group_id IS NOT NULL"),
        )


def downgrade() -> None:
    """Drop alerts tables."""
    op.drop_table("alert_settings")
    op.drop_table("alert_notifications")
    op.drop_table("alerts")
