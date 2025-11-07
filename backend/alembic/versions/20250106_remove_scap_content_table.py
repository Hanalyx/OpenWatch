"""Remove obsolete scap_content table and references

Revision ID: 20250106_scap_cleanup
Revises: 009
Create Date: 2025-01-06 00:00:00.000000

"""

import sqlalchemy as sa

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
    # Drop FK constraint from host_groups table
    op.drop_constraint("host_groups_scap_content_id_fkey", "host_groups", type_="foreignkey")
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
