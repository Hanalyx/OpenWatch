"""Add alert_routing_rules table for per-severity alert dispatch.

Revision ID: 053_add_alert_routing_rules
Revises: 052_add_retention_policies
Create Date: 2026-04-13
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "053_add_alert_routing_rules"
down_revision = "052_add_retention_policies"
branch_labels = None
depends_on = None


def upgrade():
    """Create alert_routing_rules table."""
    op.create_table(
        "alert_routing_rules",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "severity",
            sa.VARCHAR(16),
            nullable=False,
            comment="Alert severity filter: critical, high, medium, low, or all",
        ),
        sa.Column(
            "alert_type",
            sa.VARCHAR(64),
            nullable=False,
            comment="Alert type filter or 'all' for any type",
        ),
        sa.Column(
            "channel_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("notification_channels.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )

    op.create_index(
        "ix_alert_routing_rules_severity_alert_type",
        "alert_routing_rules",
        ["severity", "alert_type"],
    )


def downgrade():
    """Drop alert_routing_rules table."""
    op.drop_index("ix_alert_routing_rules_severity_alert_type")
    op.drop_table("alert_routing_rules")
