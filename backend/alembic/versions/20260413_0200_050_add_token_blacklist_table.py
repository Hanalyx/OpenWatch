"""Add token_blacklist and sso_state tables for Redis replacement.

Revision ID: 050_add_token_blacklist
Revises: 049_add_job_queue
Create Date: 2026-04-13
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "050_add_token_blacklist"
down_revision = "049_add_job_queue"
branch_labels = None
depends_on = None


def upgrade():
    """Create token_blacklist and sso_state tables."""
    op.create_table(
        "token_blacklist",
        sa.Column("jti", sa.String(255), primary_key=True),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_token_blacklist_expires_at",
        "token_blacklist",
        ["expires_at"],
    )

    op.create_table(
        "sso_state",
        sa.Column("state_token", sa.String(255), primary_key=True),
        sa.Column(
            "provider_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_sso_state_expires_at",
        "sso_state",
        ["expires_at"],
    )


def downgrade():
    """Drop token_blacklist and sso_state tables."""
    op.drop_index("ix_sso_state_expires_at", table_name="sso_state")
    op.drop_table("sso_state")
    op.drop_index("ix_token_blacklist_expires_at", table_name="token_blacklist")
    op.drop_table("token_blacklist")
