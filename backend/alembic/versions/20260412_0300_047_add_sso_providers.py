"""Add SSO providers table and extend users table for federated auth.

Revision ID: 047_add_sso_providers
Revises: 046_add_notification_channels
Create Date: 2026-04-12 03:00:00
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "047_add_sso_providers"
down_revision = "046_add_notification_channels"
branch_labels = None
depends_on = None


def upgrade():
    """Create sso_providers table and add SSO columns to users."""
    # Create sso_providers table
    op.create_table(
        "sso_providers",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            primary_key=True,
        ),
        sa.Column("provider_type", sa.VARCHAR(16), nullable=False),
        sa.Column("name", sa.VARCHAR(255), nullable=False),
        sa.Column("config_encrypted", sa.Text(), nullable=False),
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.CheckConstraint(
            "provider_type IN ('saml', 'oidc')",
            name="ck_sso_providers_type",
        ),
    )

    # Add SSO columns to users table
    op.add_column(
        "users",
        sa.Column(
            "sso_provider_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sso_providers.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column(
        "users",
        sa.Column("external_id", sa.VARCHAR(255), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column(
            "last_sso_login_at",
            sa.TIMESTAMP(timezone=True),
            nullable=True,
        ),
    )

    # Partial unique index: (sso_provider_id, external_id) WHERE both NOT NULL
    op.create_index(
        "ix_users_sso_provider_external_id",
        "users",
        ["sso_provider_id", "external_id"],
        unique=True,
        postgresql_where=sa.text("sso_provider_id IS NOT NULL AND external_id IS NOT NULL"),
    )


def downgrade():
    """Remove SSO columns from users and drop sso_providers table."""
    op.drop_index("ix_users_sso_provider_external_id", table_name="users")
    op.drop_column("users", "last_sso_login_at")
    op.drop_column("users", "external_id")
    op.drop_column("users", "sso_provider_id")
    op.drop_table("sso_providers")
