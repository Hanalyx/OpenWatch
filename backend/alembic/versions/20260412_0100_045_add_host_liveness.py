"""Add host_liveness table for heartbeat monitoring

Revision ID: 045_add_host_liveness
Revises: 044_add_transactions_table
Create Date: 2026-04-12

Dedicated host liveness monitoring independent of compliance scan cadence.
A Celery Beat task pings every managed host every 5 minutes via TCP
connection to the SSH port, recording response time and reachability state.
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "045_add_host_liveness"
down_revision = "044_add_transactions_table"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "host_liveness",
        sa.Column(
            "host_id",
            UUID(as_uuid=True),
            sa.ForeignKey("hosts.id", ondelete="CASCADE"),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("last_ping_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_response_ms", sa.Integer(), nullable=True),
        sa.Column("reachability_status", sa.String(16), nullable=False, server_default="unknown"),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_state_change_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade():
    op.drop_table("host_liveness")
