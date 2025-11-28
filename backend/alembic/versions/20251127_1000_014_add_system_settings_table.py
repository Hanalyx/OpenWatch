"""
Add system_settings table for configuration management

Revision ID: 20251127_add_system_settings
Revises: 20251115_per_sev_pass_fail
Create Date: 2025-11-27 10:00:00

This migration adds the system_settings table which stores configurable
system parameters including SSH host key policy, encryption settings,
and other runtime configuration values.

The table is used by:
- UnifiedSSHService for ssh_host_key_policy configuration
- SecurityConfig for encryption and security settings
- Various services needing runtime-configurable parameters

Structure:
- setting_key: Unique identifier for the setting (e.g., 'ssh_host_key_policy')
- setting_value: The value (can be string, JSON, boolean represented as text)
- setting_type: Type hint for parsing ('string', 'json', 'boolean', 'integer')
- is_secure: Flag indicating if value should be encrypted at rest
"""

import sqlalchemy as sa

from alembic import op

revision = "20251127_add_system_settings"
down_revision = "20251115_per_sev_pass_fail"
branch_labels = None
depends_on = None


def upgrade():
    """
    Create system_settings table for storing configurable system parameters.

    This table enables runtime configuration of system behavior without
    requiring application restarts or environment variable changes.
    """
    op.create_table(
        "system_settings",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column(
            "setting_key",
            sa.String(100),
            unique=True,
            nullable=False,
            index=True,
            comment="Unique key identifying the setting (e.g., ssh_host_key_policy)",
        ),
        sa.Column(
            "setting_value",
            sa.Text(),
            nullable=True,
            comment="Setting value as text (parsed based on setting_type)",
        ),
        sa.Column(
            "setting_type",
            sa.String(20),
            nullable=False,
            server_default="string",
            comment="Type hint: string, json, boolean, integer",
        ),
        sa.Column(
            "description",
            sa.Text(),
            nullable=True,
            comment="Human-readable description of the setting",
        ),
        sa.Column(
            "created_by",
            sa.Integer(),
            nullable=True,
            comment="User ID who created the setting",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
            comment="Timestamp when setting was created",
        ),
        sa.Column(
            "modified_by",
            sa.Integer(),
            nullable=True,
            comment="User ID who last modified the setting",
        ),
        sa.Column(
            "modified_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
            comment="Timestamp when setting was last modified",
        ),
        sa.Column(
            "is_secure",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
            comment="If true, value should be encrypted at rest",
        ),
    )

    # Insert default SSH host key policy setting
    # This prevents the "relation system_settings does not exist" error
    # when the worker tries to query SSH settings
    op.execute(
        """
        INSERT INTO system_settings (setting_key, setting_value, setting_type, description, created_at, modified_at, is_secure)
        VALUES (
            'ssh_host_key_policy',
            'auto_add',
            'string',
            'SSH host key verification policy: reject_unknown, auto_add, or warning_only',
            NOW(),
            NOW(),
            false
        )
        """
    )


def downgrade():
    """
    Remove system_settings table.

    Warning: This will delete all stored system configuration.
    """
    op.drop_table("system_settings")
