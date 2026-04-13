"""Add notification_channels and notification_deliveries tables

Revision ID: 046_add_notification_channels
Revises: 045_add_host_liveness
Create Date: 2026-04-12

Notification dispatch infrastructure for outbound alert delivery.
Channels store encrypted config (Slack webhooks, SMTP creds, webhook
secrets) and deliveries track per-attempt status for audit.
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "046_add_notification_channels"
down_revision = "045_add_host_liveness"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "notification_channels",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("tenant_id", UUID(as_uuid=True), nullable=True),
        sa.Column("channel_type", sa.String(16), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("config_encrypted", sa.Text(), nullable=False),
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default="true",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )

    op.create_table(
        "notification_deliveries",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("alert_id", UUID(as_uuid=True), nullable=True),
        sa.Column(
            "channel_id",
            UUID(as_uuid=True),
            sa.ForeignKey("notification_channels.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("response_code", sa.Integer(), nullable=True),
        sa.Column("response_body", sa.Text(), nullable=True),
        sa.Column(
            "attempted_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )

    # Index for fast delivery lookups by channel
    op.create_index(
        "ix_notification_deliveries_channel_id",
        "notification_deliveries",
        ["channel_id"],
    )

    # Index for delivery lookups by alert
    op.create_index(
        "ix_notification_deliveries_alert_id",
        "notification_deliveries",
        ["alert_id"],
    )


def downgrade():
    op.drop_index("ix_notification_deliveries_alert_id")
    op.drop_index("ix_notification_deliveries_channel_id")
    op.drop_table("notification_deliveries")
    op.drop_table("notification_channels")
