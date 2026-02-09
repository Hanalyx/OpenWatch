"""Add plugin_updates table for Phase 5

Revision ID: 023_add_plugin_updates
Revises: 022_add_remediation_jobs
Create Date: 2026-02-09

Phase 5: Control Plane - Plugin Update Tracking

This migration creates tables for:
- plugin_updates: Track update history for plugins
- plugin_update_notifications: Store update availability notifications
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

# Revision identifiers
revision = "023_add_plugin_updates"
down_revision = "022_add_remediation_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create plugin update tracking tables."""
    # Check if plugin_updates table already exists (idempotent)
    conn = op.get_bind()
    result = conn.execute(
        sa.text("SELECT EXISTS (SELECT 1 FROM information_schema.tables " "WHERE table_name = 'plugin_updates')")
    )
    if result.scalar():
        return

    # Create plugin_update_status enum
    op.execute(
        """
        DO $$ BEGIN
            CREATE TYPE plugin_update_status AS ENUM (
                'pending',
                'downloading',
                'verifying',
                'installing',
                'completed',
                'failed',
                'rolled_back'
            );
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$;
        """
    )

    # Create plugin_updates table
    op.create_table(
        "plugin_updates",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("plugin_id", sa.String(100), nullable=False, index=True),
        sa.Column("from_version", sa.String(50), nullable=False),
        sa.Column("to_version", sa.String(50), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "pending",
                "downloading",
                "verifying",
                "installing",
                "completed",
                "failed",
                "rolled_back",
                name="plugin_update_status",
                create_type=False,
            ),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("progress", sa.Integer, nullable=False, server_default="0"),
        sa.Column("package_url", sa.String(500)),
        sa.Column("package_checksum", sa.String(128)),
        sa.Column("package_size_bytes", sa.BigInteger),
        sa.Column("backup_path", sa.String(500)),
        sa.Column("manifest", JSONB),
        sa.Column("changes", JSONB),
        sa.Column("error_message", sa.Text),
        sa.Column("initiated_by", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )

    # Create indexes
    op.create_index("ix_plugin_updates_plugin_status", "plugin_updates", ["plugin_id", "status"])
    op.create_index("ix_plugin_updates_created_at", "plugin_updates", ["created_at"])

    # Create plugin_update_notifications table
    op.create_table(
        "plugin_update_notifications",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("plugin_id", sa.String(100), nullable=False, index=True),
        sa.Column("current_version", sa.String(50), nullable=False),
        sa.Column("available_version", sa.String(50), nullable=False),
        sa.Column("min_openwatch_version", sa.String(50)),
        sa.Column("changes", JSONB),
        sa.Column("breaking_changes", JSONB),
        sa.Column("release_notes_url", sa.String(500)),
        sa.Column("dismissed", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("dismissed_by", sa.Integer, sa.ForeignKey("users.id")),
        sa.Column("dismissed_at", sa.DateTime(timezone=True)),
        sa.Column("checked_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
    )

    # Create unique constraint to prevent duplicate notifications
    op.create_index(
        "ix_plugin_update_notifications_unique",
        "plugin_update_notifications",
        ["plugin_id", "available_version"],
        unique=True,
    )

    # Create plugin_registry table for tracking installed plugins
    op.create_table(
        "plugin_registry",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("plugin_id", sa.String(100), nullable=False, unique=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("version", sa.String(50), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("author", sa.String(255)),
        sa.Column("homepage_url", sa.String(500)),
        sa.Column("capabilities", JSONB),
        sa.Column("config", JSONB),
        sa.Column("install_path", sa.String(500)),
        sa.Column("is_builtin", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("is_enabled", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("last_health_check", sa.DateTime(timezone=True)),
        sa.Column("health_status", sa.String(50)),
        sa.Column("installed_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
    )

    # Insert Aegis as built-in plugin
    op.execute(
        """
        INSERT INTO plugin_registry (
            plugin_id, name, version, description, author,
            capabilities, is_builtin, is_enabled
        ) VALUES (
            'aegis',
            'Aegis Compliance Engine',
            '0.1.0',
            'Native SSH-based compliance scanning and remediation engine',
            'Hanalyx',
            '["compliance_check", "remediation", "rollback", "framework_mapping"]'::jsonb,
            true,
            true
        )
        ON CONFLICT (plugin_id) DO NOTHING;
        """
    )


def downgrade() -> None:
    """Drop plugin update tracking tables."""
    op.drop_table("plugin_registry")
    op.drop_table("plugin_update_notifications")
    op.drop_table("plugin_updates")
    op.execute("DROP TYPE IF EXISTS plugin_update_status;")
