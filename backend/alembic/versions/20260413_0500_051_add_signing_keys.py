"""Add deployment_signing_keys table for Ed25519 evidence signing.

Revision ID: 051_add_signing_keys
Revises: 050_add_token_blacklist
Create Date: 2026-04-13
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "051_add_signing_keys"
down_revision = "050_add_token_blacklist"
branch_labels = None
depends_on = None


def upgrade():
    """Create deployment_signing_keys table."""
    op.create_table(
        "deployment_signing_keys",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("private_key_encrypted", sa.Text(), nullable=False),
        sa.Column(
            "active",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "rotated_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade():
    """Drop deployment_signing_keys table."""
    op.drop_table("deployment_signing_keys")
