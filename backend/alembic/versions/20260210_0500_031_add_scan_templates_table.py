"""Add scan_templates table for PostgreSQL migration

Revision ID: 031_scan_templates
Revises: 030_host_network
Create Date: 2026-02-10

Creates PostgreSQL table to replace MongoDB scan_templates collection.
This is part of the MongoDB deprecation effort.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# Revision identifiers
revision = "031_scan_templates"
down_revision = "030_host_network"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create scan_templates table."""
    conn = op.get_bind()

    # Check if table already exists
    result = conn.execute(
        sa.text("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'scan_templates')")
    )
    if result.scalar():
        return

    op.create_table(
        "scan_templates",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("framework", sa.String(100), nullable=True),
        sa.Column("framework_version", sa.String(50), nullable=True),
        sa.Column("profile_id", sa.String(255), nullable=True),
        sa.Column("rule_filters", postgresql.JSONB, nullable=True, server_default="{}"),
        sa.Column("variables", postgresql.JSONB, nullable=True, server_default="{}"),
        sa.Column("scan_options", postgresql.JSONB, nullable=True, server_default="{}"),
        sa.Column("created_by", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("is_default", sa.Boolean, server_default="false", nullable=False),
        sa.Column("is_shared", sa.Boolean, server_default="false", nullable=False),
        sa.Column("is_quick_template", sa.Boolean, server_default="false", nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False
        ),
    )

    # Create indexes for common queries
    op.create_index("idx_scan_templates_framework", "scan_templates", ["framework"])
    op.create_index("idx_scan_templates_created_by", "scan_templates", ["created_by"])
    op.create_index("idx_scan_templates_is_default", "scan_templates", ["is_default"])
    op.create_index("idx_scan_templates_is_shared", "scan_templates", ["is_shared"])

    # Insert quick templates (static, always available)
    conn.execute(
        sa.text(
            """
            INSERT INTO scan_templates (id, name, description, framework, is_quick_template, is_shared)
            VALUES
                (gen_random_uuid(), 'Quick CIS Scan', 'Fast CIS benchmark compliance check', 'cis-rhel9-v2.0.0', true, true),
                (gen_random_uuid(), 'Quick STIG Scan', 'Fast STIG compliance check', 'stig-rhel9-v2r7', true, true),
                (gen_random_uuid(), 'Full Compliance Scan', 'Complete compliance assessment', 'nist-800-53', true, true)
        """
        )
    )


def downgrade() -> None:
    """Drop scan_templates table."""
    op.drop_index("idx_scan_templates_is_shared", table_name="scan_templates")
    op.drop_index("idx_scan_templates_is_default", table_name="scan_templates")
    op.drop_index("idx_scan_templates_created_by", table_name="scan_templates")
    op.drop_index("idx_scan_templates_framework", table_name="scan_templates")
    op.drop_table("scan_templates")
