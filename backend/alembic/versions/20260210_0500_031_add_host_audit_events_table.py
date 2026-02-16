"""Add host_audit_events table

Revision ID: 031_host_audit_events
Revises: 030_host_network
Create Date: 2026-02-10

Creates table for storing security audit events:
- host_audit_events: Auth events, sudo usage, service changes, login failures

Part of OpenWatch OS Transformation - Server Intelligence (doc 04).
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# Revision identifiers
revision = "031_host_audit_events"
down_revision = "030_host_network"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create host_audit_events table."""
    conn = op.get_bind()

    # Create host_audit_events table
    result = conn.execute(
        sa.text("SELECT EXISTS (SELECT FROM information_schema.tables " "WHERE table_name = 'host_audit_events')")
    )
    if not result.scalar():
        op.create_table(
            "host_audit_events",
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
            # Event type: auth, sudo, file_access, service, login_failure
            sa.Column("event_type", sa.String(50), nullable=False),
            # When the event occurred
            sa.Column("event_timestamp", sa.DateTime(timezone=True), nullable=False),
            # Who performed the action
            sa.Column("username", sa.String(100)),
            # Where the action originated (IP address)
            sa.Column("source_ip", sa.String(45)),
            # What action was performed
            sa.Column("action", sa.String(100)),
            # Target of the action (file, service, etc.)
            sa.Column("target", sa.String(255)),
            # Result: success, failure
            sa.Column("result", sa.String(20)),
            # Raw log message for reference
            sa.Column("raw_message", sa.Text),
            # Process/service that logged the event
            sa.Column("source_process", sa.String(100)),
            # Additional structured data
            sa.Column("metadata", postgresql.JSONB),
            # When this was collected
            sa.Column(
                "collected_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
        )

        # Create indexes for efficient querying
        op.create_index("idx_host_audit_events_host", "host_audit_events", ["host_id"])
        op.create_index("idx_host_audit_events_type", "host_audit_events", ["event_type"])
        op.create_index(
            "idx_host_audit_events_timestamp",
            "host_audit_events",
            ["event_timestamp"],
            postgresql_ops={"event_timestamp": "DESC"},
        )
        op.create_index("idx_host_audit_events_result", "host_audit_events", ["result"])
        # Compound index for common queries
        op.create_index(
            "idx_host_audit_events_host_type_time",
            "host_audit_events",
            ["host_id", "event_type", "event_timestamp"],
        )


def downgrade() -> None:
    """Drop host_audit_events table."""
    op.drop_table("host_audit_events")
