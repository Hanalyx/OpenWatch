"""Add host_rule_state table for write-on-change compliance state model.

One row per (host_id, rule_id) pair, updated on every scan. Transactions
are only written when the rule's status changes, replacing the
append-every-scan model.

Revision ID: 048_add_host_rule_state
Revises: 047_add_sso_providers
Create Date: 2026-04-12 04:00:00
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "048_add_host_rule_state"
down_revision = "047_add_sso_providers"
branch_labels = None
depends_on = None


def upgrade():
    """Create host_rule_state table with composite primary key."""
    op.create_table(
        "host_rule_state",
        sa.Column(
            "host_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("hosts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("rule_id", sa.VARCHAR(255), nullable=False),
        sa.Column("current_status", sa.VARCHAR(16), nullable=False),
        sa.Column("severity", sa.VARCHAR(16), nullable=True),
        sa.Column("evidence_envelope", postgresql.JSONB, nullable=True),
        sa.Column("framework_refs", postgresql.JSONB, nullable=True),
        sa.Column(
            "first_seen_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "last_checked_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "last_changed_at",
            sa.TIMESTAMP(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "check_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column("previous_status", sa.VARCHAR(16), nullable=True),
        sa.PrimaryKeyConstraint("host_id", "rule_id"),
    )

    # Index for posture queries: "show me all failing rules for host X"
    op.create_index(
        "ix_host_rule_state_host_status",
        "host_rule_state",
        ["host_id", "current_status"],
    )

    # Index for stale-check detection: "which rules haven't been checked recently?"
    op.create_index(
        "ix_host_rule_state_last_checked",
        "host_rule_state",
        ["last_checked_at"],
    )


def downgrade():
    """Drop host_rule_state table and indexes."""
    op.drop_index("ix_host_rule_state_last_checked", table_name="host_rule_state")
    op.drop_index("ix_host_rule_state_host_status", table_name="host_rule_state")
    op.drop_table("host_rule_state")
