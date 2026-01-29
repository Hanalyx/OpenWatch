"""Add compatibility fields to Host and ScapContent models

Revision ID: 006
Revises: 005
Create Date: 2025-09-02 16:00:00.000000

"""

import sqlalchemy as sa

from alembic import op

# revision identifiers
revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def _column_exists(table: str, column: str) -> bool:
    """Check if a column already exists in a table."""
    conn = op.get_bind()
    result = conn.execute(
        sa.text("SELECT 1 FROM information_schema.columns " "WHERE table_name = :table AND column_name = :column"),
        {"table": table, "column": column},
    )
    return result.fetchone() is not None


def upgrade() -> None:
    """Add compatibility fields to Host and ScapContent models.

    Note: These columns may already exist from migrations 003 and 005.
    Check before adding to avoid DuplicateColumn errors.
    """

    # Add compatibility fields to hosts table (005 already adds these)
    if not _column_exists("hosts", "os_family"):
        op.add_column("hosts", sa.Column("os_family", sa.String(50), nullable=True))
    if not _column_exists("hosts", "os_version"):
        op.add_column("hosts", sa.Column("os_version", sa.String(100), nullable=True))
    if not _column_exists("hosts", "architecture"):
        op.add_column("hosts", sa.Column("architecture", sa.String(50), nullable=True))
    if not _column_exists("hosts", "last_os_detection"):
        op.add_column("hosts", sa.Column("last_os_detection", sa.DateTime(), nullable=True))

    # Add compatibility fields to scap_content table (003 already adds these)
    if not _column_exists("scap_content", "os_family"):
        op.add_column("scap_content", sa.Column("os_family", sa.String(50), nullable=True))
    if not _column_exists("scap_content", "compliance_framework"):
        op.add_column("scap_content", sa.Column("compliance_framework", sa.String(100), nullable=True))


def downgrade() -> None:
    """Remove compatibility fields from Host and ScapContent models"""

    # Remove fields from scap_content table
    op.drop_column("scap_content", "compliance_framework")
    op.drop_column("scap_content", "os_family")

    # Remove fields from hosts table
    op.drop_column("hosts", "last_os_detection")
    op.drop_column("hosts", "architecture")
    op.drop_column("hosts", "os_version")
    op.drop_column("hosts", "os_family")
