"""Remove SCAP fields from host_groups table

Revision ID: 034_remove_scap_fields
Revises: 032_rename_host_schedule
Create Date: 2026-02-11 01:00:00.000000

This migration removes the deprecated SCAP-related fields from the host_groups table.
OpenWatch now uses Aegis for compliance scanning, which doesn't require SCAP content
or profile configuration at the group level.

Removed fields:
- scap_content_id: Foreign key to scap_content table (deprecated)
- default_profile_id: SCAP profile ID (deprecated, Aegis uses framework-based scanning)
"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "034_remove_scap_fields"
down_revision = "032_rename_host_schedule"
branch_labels = None
depends_on = None


def upgrade():
    """Remove SCAP-related columns from host_groups table."""
    # Drop foreign key constraint first if it exists
    try:
        op.drop_constraint("host_groups_scap_content_id_fkey", "host_groups", type_="foreignkey")
    except Exception:
        # Constraint may not exist in all environments
        pass

    # Drop the columns
    op.drop_column("host_groups", "scap_content_id")
    op.drop_column("host_groups", "default_profile_id")


def downgrade():
    """Re-add SCAP-related columns to host_groups table."""
    op.add_column("host_groups", sa.Column("scap_content_id", sa.Integer(), nullable=True))
    op.add_column("host_groups", sa.Column("default_profile_id", sa.String(100), nullable=True))

    # Re-create foreign key constraint
    op.create_foreign_key(
        "host_groups_scap_content_id_fkey", "host_groups", "scap_content", ["scap_content_id"], ["id"]
    )
