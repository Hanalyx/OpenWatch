"""Remove obsolete scap_content table and references

Revision ID: 20250106_scap_cleanup
Revises: 009
Create Date: 2025-01-06 00:00:00.000000

"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "20250106_scap_cleanup"
down_revision = "009"
branch_labels = None
depends_on = None


def upgrade():
    """
    Remove the obsolete scap_content table and all references to it.

    The scap_content table was part of a legacy PostgreSQL-based scanning
    approach that was never used (0 records). OpenWatch now uses MongoDB
    for compliance rules with dynamic XCCDF generation via XCCDFGeneratorService.

    This migration:
    1. Drops foreign key constraints referencing scap_content
    2. Drops columns that referenced scap_content
    3. Drops the scap_content table itself
    """
    # Drop scap_content_compatibility table (created by migration 005).
    # Must be dropped before scap_content because it has a FK to scap_content.id.
    op.drop_index("idx_scap_compatibility_score", table_name="scap_content_compatibility")
    op.drop_index("idx_scap_compatibility_os", table_name="scap_content_compatibility")
    op.drop_index("idx_scap_compatibility_content", table_name="scap_content_compatibility")
    op.drop_table("scap_content_compatibility")

    # Drop FK constraint from host_groups table.
    # Migration 005 created this as 'fk_host_groups_scap_content'.
    op.drop_constraint("fk_host_groups_scap_content", "host_groups", type_="foreignkey")
    op.drop_column("host_groups", "scap_content_id")

    # Drop FK constraint from scans table
    op.drop_constraint("scans_content_id_fkey", "scans", type_="foreignkey")
    op.drop_column("scans", "content_id")

    # Drop the scap_content table entirely
    op.drop_table("scap_content")


def downgrade():
    """
    Restore the scap_content table structure (but not data).

    Note: This only restores the schema, not the data. Since the table
    was never populated (0 records), this is acceptable.
    """
    # Recreate scap_content table
    op.create_table(
        "scap_content",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("file_path", sa.String(length=500), nullable=False),
        sa.Column("content_type", sa.String(length=50), nullable=False),
        sa.Column("profiles", sa.Text(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("version", sa.String(length=50), nullable=True),
        sa.Column("os_family", sa.String(length=50), nullable=True),
        sa.Column("os_version", sa.String(length=100), nullable=True),
        sa.Column("compliance_framework", sa.String(length=100), nullable=True),
        sa.Column("uploaded_by", sa.Integer(), nullable=False),
        sa.Column("uploaded_at", sa.DateTime(), nullable=False),
        sa.Column("file_hash", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["uploaded_by"], ["users.id"]),
    )
    op.create_index("ix_scap_content_id", "scap_content", ["id"])

    # Restore content_id column to scans table
    op.add_column("scans", sa.Column("content_id", sa.Integer(), nullable=True))
    op.create_foreign_key("scans_content_id_fkey", "scans", "scap_content", ["content_id"], ["id"])

    # Restore scap_content_id column to host_groups table
    op.add_column("host_groups", sa.Column("scap_content_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        "host_groups_scap_content_id_fkey", "host_groups", "scap_content", ["scap_content_id"], ["id"]
    )

    # Recreate scap_content_compatibility table (originally from migration 005)
    op.create_table(
        "scap_content_compatibility",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("content_id", sa.Integer(), nullable=False),
        sa.Column(
            "os_family",
            postgresql.ENUM(
                "rhel",
                "centos",
                "fedora",
                "ubuntu",
                "debian",
                "suse",
                "opensuse",
                "windows",
                "windows_server",
                "macos",
                "freebsd",
                "openbsd",
                "solaris",
                name="os_family_type",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("os_version_pattern", sa.String(length=100), nullable=False),
        sa.Column("architecture", sa.String(length=20), nullable=True),
        sa.Column("compatibility_score", sa.Float(), nullable=False),
        sa.Column("supported_profiles", postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column("known_issues", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("last_tested", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["content_id"], ["scap_content.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "content_id", "os_family", "os_version_pattern", "architecture", name="uq_scap_os_compatibility"
        ),
    )
    op.create_index("idx_scap_compatibility_content", "scap_content_compatibility", ["content_id"])
    op.create_index("idx_scap_compatibility_os", "scap_content_compatibility", ["os_family", "os_version_pattern"])
    op.create_index("idx_scap_compatibility_score", "scap_content_compatibility", ["compatibility_score"])
