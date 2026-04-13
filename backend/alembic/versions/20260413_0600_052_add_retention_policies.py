"""Add retention_policies table for data retention policy engine.

Revision ID: 052_add_retention_policies
Revises: 051_add_signing_keys
Create Date: 2026-04-13
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "052_add_retention_policies"
down_revision = "051_add_signing_keys"
branch_labels = None
depends_on = None


def upgrade():
    """Create retention_policies table."""
    op.create_table(
        "retention_policies",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column(
            "resource_type",
            sa.VARCHAR(64),
            nullable=False,
        ),
        sa.Column(
            "retention_days",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("365"),
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
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.UniqueConstraint("tenant_id", "resource_type", name="uq_retention_tenant_resource"),
    )


def downgrade():
    """Drop retention_policies table."""
    op.drop_table("retention_policies")
