"""Add unified credentials table for centralized authentication

Revision ID: 20250122_1600_add_unified_credentials
Revises: 003
Create Date: 2025-01-22 16:00:00.000000

This migration creates the unified_credentials table that consolidates
authentication across system and host-specific credentials, solving the
issue where system credentials use AES encryption but host credentials only use base64.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "20250122_1600_add_unified_credentials"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create unified_credentials table
    op.create_table(
        "unified_credentials",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False, default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("scope", sa.String(length=50), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("username", sa.String(length=255), nullable=False),
        sa.Column("auth_method", sa.String(length=50), nullable=False),
        # Encrypted credential fields (all use AES-256-GCM)
        sa.Column("encrypted_password", sa.LargeBinary(), nullable=True),
        sa.Column("encrypted_private_key", sa.LargeBinary(), nullable=True),
        sa.Column("encrypted_passphrase", sa.LargeBinary(), nullable=True),
        # SSH key metadata
        sa.Column("ssh_key_fingerprint", sa.String(length=255), nullable=True),
        sa.Column("ssh_key_type", sa.String(length=50), nullable=True),
        sa.Column("ssh_key_bits", sa.Integer(), nullable=True),
        sa.Column("ssh_key_comment", sa.Text(), nullable=True),
        # Management fields
        sa.Column("is_default", sa.Boolean(), nullable=False, default=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, default=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.TIMESTAMP(), nullable=False, default=sa.text("NOW()")),
        sa.Column("updated_at", sa.TIMESTAMP(), nullable=False, default=sa.text("NOW()")),
        sa.PrimaryKeyConstraint("id"),
    )

    # Create indexes for performance
    op.create_index("idx_unified_credentials_scope_target", "unified_credentials", ["scope", "target_id"])
    op.create_index("idx_unified_credentials_default", "unified_credentials", ["scope", "is_default"])
    op.create_index("idx_unified_credentials_active", "unified_credentials", ["is_active"])

    # Create constraints
    op.create_check_constraint(
        "ck_unified_credentials_scope", "unified_credentials", sa.text("scope IN ('system', 'host', 'group')")
    )

    op.create_check_constraint(
        "ck_unified_credentials_auth_method",
        "unified_credentials",
        sa.text("auth_method IN ('ssh_key', 'password', 'both')"),
    )

    # Unique constraint for default credentials per scope/target
    op.create_index(
        "idx_unified_credentials_unique_default",
        "unified_credentials",
        ["scope", "target_id"],
        unique=True,
        postgresql_where=sa.text("is_default = true"),
    )

    # Foreign key to users table - skipped because created_by is UUID
    # but users.id is Integer (type mismatch). The original try/except
    # caught the Python error but left PostgreSQL's transaction in a
    # failed state, breaking subsequent migrations.
    # TODO: Add FK if users.id is migrated to UUID in the future.


def downgrade() -> None:
    # Drop the unified_credentials table and all its constraints/indexes
    op.drop_table("unified_credentials")
