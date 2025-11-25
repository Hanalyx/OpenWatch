"""Add security configuration table

Revision ID: 20250125_1200_add_security_config
Revises: 20250122_1600_add_unified_credentials
Create Date: 2025-01-25 12:00:00.000000

"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "20250125_1200_add_security_config"
down_revision = "20250122_1600_add_unified_credentials"
branch_labels = None
depends_on = None


def upgrade():
    """Add security_config table for hierarchical security policy management"""

    # Create security_config table
    op.create_table(
        "security_config",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("scope", sa.String(length=20), nullable=False),
        sa.Column("target_id", sa.String(), nullable=True),
        sa.Column("config_data", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    # Create unique constraint on scope + target_id
    op.create_index("ix_security_config_scope_target", "security_config", ["scope", "target_id"], unique=True)

    # Create indexes for performance
    op.create_index("ix_security_config_scope", "security_config", ["scope"])
    op.create_index("ix_security_config_created_at", "security_config", ["created_at"])

    # Add check constraints
    op.create_check_constraint(
        "ck_security_config_scope", "security_config", "scope IN ('system', 'org', 'group', 'host')"
    )

    # Ensure system scope has null target_id
    op.create_check_constraint(
        "ck_security_config_system_null_target",
        "security_config",
        "(scope != 'system') OR (scope = 'system' AND target_id IS NULL)",
    )

    # Ensure host/group scope has non-null target_id
    op.create_check_constraint(
        "ck_security_config_target_required",
        "security_config",
        "(scope NOT IN ('host', 'group')) OR (scope IN ('host', 'group') AND target_id IS NOT NULL)",
    )

    # Insert default system configuration
    op.execute(
        """
        INSERT INTO security_config (id, scope, target_id, config_data, created_by, created_at, updated_at)
        VALUES (
            gen_random_uuid()::text,
            'system',
            NULL,
            '{
                "policy_level": "strict",
                "enforce_fips": true,
                "minimum_rsa_bits": 3072,
                "minimum_ecdsa_bits": 256,
                "allow_dsa_keys": false,
                "minimum_password_length": 12,
                "require_complex_passwords": true,
                "allowed_key_types": ["rsa", "ed25519", "ecdsa"]
            }',
            'system',
            NOW(),
            NOW()
        )
    """
    )


def downgrade():
    """Remove security configuration table"""

    # Drop the table and all its constraints/indexes
    op.drop_table("security_config")
